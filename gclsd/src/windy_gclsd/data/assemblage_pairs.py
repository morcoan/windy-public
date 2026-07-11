"""Extract (GclsdInput, ground-truth C) pairs from an Assemblage SQLite DB.

Walks the binaries table, runs ``windy export-gclsd`` for each PE/DLL, then
matches each exported function to its source code via the ``rvas`` and
``functions`` (or ``lines``) tables. Outputs one JSONL line per function:

    {"input": <GclsdInput dict>, "gt_c": "..."}

Supports both the vcpkg DLL dataset and the Windows GitHub PE dataset.
"""

from __future__ import annotations

import argparse
import bisect
import json
import multiprocessing as mp
import os
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from windy_gclsd.contract import GclsdInput


def resolve_column(columns: set[str], *candidates: str) -> str:
    for c in candidates:
        if c in columns:
            return c
    raise ValueError(f"None of {candidates!r} found in columns {columns!r}")


@dataclass
class DbSchema:
    """Discovered column names for an Assemblage SQLite DB."""

    binary_id: str
    binary_path: str
    func_id: str
    func_binary_id: str
    func_source: Optional[str]
    rvas_func_id: str
    rvas_start: str
    rvas_end: Optional[str]
    lines_func_id: Optional[str]
    lines_text: Optional[str]
    lines_address: Optional[str]

    @classmethod
    def discover(cls, conn: sqlite3.Connection) -> "DbSchema":
        def cols(table: str) -> set[str]:
            return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

        bins = cols("binaries")
        funcs = cols("functions")
        rvas = cols("rvas")
        lines = cols("lines")

        func_source = "source_codes" if "source_codes" in funcs else None

        return cls(
            binary_id=resolve_column(bins, "id"),
            binary_path=resolve_column(bins, "path", "binary_path"),
            func_id=resolve_column(funcs, "id"),
            func_binary_id=resolve_column(funcs, "binary_id"),
            func_source=func_source,
            rvas_func_id=resolve_column(rvas, "function_id", "func_id"),
            rvas_start=resolve_column(rvas, "start", "rva_start", "rva"),
            rvas_end=("end" if "end" in rvas else ("rva_end" if "rva_end" in rvas else None)),
            lines_func_id=resolve_column(lines, "function_id", "func_id") if lines else None,
            lines_text=(
                resolve_column(lines, "line", "line_text", "source", "source_code", "code", "text")
                if lines
                else None
            ),
            lines_address=resolve_column(lines, "address", "addr", "va", "rva") if lines else None,
        )


def iter_binaries(
    conn: sqlite3.Connection,
    schema: DbSchema,
    platform: Optional[str],
    limit: Optional[int],
    order_by: str = "func_count",
) -> Iterable[Tuple[int, str]]:
    if order_by == "func_count":
        sql = f"""
            SELECT b.{schema.binary_id}, b.{schema.binary_path}
            FROM binaries b
            JOIN (
                SELECT {schema.func_binary_id} AS binary_id, COUNT(*) AS cnt
                FROM functions
                GROUP BY {schema.func_binary_id}
            ) fc ON b.{schema.binary_id} = fc.binary_id
            WHERE 1=1
        """
    else:
        sql = f"""
            SELECT b.{schema.binary_id}, b.{schema.binary_path}
            FROM binaries b
            WHERE EXISTS (
                SELECT 1 FROM functions f WHERE f.{schema.func_binary_id} = b.{schema.binary_id}
            )
        """
    params: List[str] = []
    if platform:
        sql += " AND b.platform = ?"
        params.append(platform)
    if order_by == "func_count":
        sql += " ORDER BY fc.cnt DESC"
    else:
        sql += f" ORDER BY b.{schema.binary_id}"
    if limit:
        sql += " LIMIT ?"
        params.append(str(limit))
    for row in conn.execute(sql, params):
        yield int(row[0]), str(row[1])


def load_function_sources_for_binary(
    conn: sqlite3.Connection,
    schema: DbSchema,
    binary_id: int,
) -> List[Tuple[int, int, int, str, str]]:
    """Return sorted list of (start, end, func_id, name, source_code) for one binary.

    Prefers the full function body stored in ``functions.source_codes`` when
    available; otherwise falls back to concatenating per-line source from the
    ``lines`` table.
    """
    end_col = f"r.{schema.rvas_end}" if schema.rvas_end else "NULL"
    cur = conn.execute(
        f"""
        SELECT f.{schema.func_id}, f.{schema.func_binary_id}, r.{schema.rvas_start}, {end_col}, f.name
        FROM functions f
        JOIN rvas r ON f.{schema.func_id} = r.{schema.rvas_func_id}
        WHERE f.{schema.func_binary_id} = ?
        """,
        (binary_id,),
    )
    func_info: Dict[int, Tuple[int, int, str]] = {}  # func_id -> (start, end, name)
    for func_id, _, start, maybe_end, name in cur.fetchall():
        fid = int(func_id)
        end_val = int(maybe_end) if maybe_end is not None else int(start)
        func_info[fid] = (int(start), end_val, name)

    if not func_info:
        return []

    source_by_func: Dict[int, str] = {}
    func_ids = list(func_info.keys())

    # 1. Try to load full bodies from functions.source_codes.
    bodies_loaded: set[int] = set()
    if schema.func_source:
        for i in range(0, len(func_ids), 500):
            chunk_ids = func_ids[i : i + 500]
            placeholders = ",".join("?" * len(chunk_ids))
            cur = conn.execute(
                f"""
                SELECT {schema.func_id}, {schema.func_source}
                FROM functions
                WHERE {schema.func_id} IN ({placeholders})
                """,
                tuple(chunk_ids),
            )
            for func_id, text in cur.fetchall():
                fid = int(func_id)
                text = (text or "").strip()
                if text:
                    source_by_func[fid] = text
                    bodies_loaded.add(fid)

    # 2. Fallback to per-line source for any function without a body.
    needs_lines = [fid for fid in func_ids if fid not in bodies_loaded]
    if needs_lines and schema.lines_text:
        for i in range(0, len(needs_lines), 500):
            chunk_ids = needs_lines[i : i + 500]
            placeholders = ",".join("?" * len(chunk_ids))
            cur = conn.execute(
                f"""
                SELECT {schema.lines_func_id}, {schema.lines_text}
                FROM lines
                WHERE {schema.lines_func_id} IN ({placeholders})
                ORDER BY {schema.lines_address}
                """,
                tuple(chunk_ids),
            )
            grouped: Dict[int, List[str]] = {}
            for func_id, text in cur.fetchall():
                grouped.setdefault(int(func_id), []).append(text or "")
            for fid, lines in grouped.items():
                source_by_func[fid] = "\n".join(lines).strip()

    rows = [
        (start, end, fid, name, source_by_func.get(fid, ""))
        for fid, (start, end, name) in func_info.items()
    ]
    rows.sort(key=lambda x: x[0])
    return rows


def _match_rva(
    db_rows: List[Tuple[int, int, int, str, str]],
    rva: int,
    threshold: int,
) -> Optional[Tuple[int, str, str]]:
    """Find the best DB function for a windy entry RVA.

    Preference order:
    1. Exact start match.
    2. Range containment (entry falls inside [start, end]).
    3. Nearest start within ``threshold`` bytes.
    """
    if not db_rows:
        return None
    starts = [r[0] for r in db_rows]

    idx = bisect.bisect_left(starts, rva)
    candidates: List[Tuple[int, int, str, str, str]] = []

    def consider(pos: int) -> None:
        if 0 <= pos < len(db_rows):
            start, end, fid, name, src = db_rows[pos]
            if start <= rva <= end:
                candidates.append((0, start, fid, name, src))
            else:
                dist = abs(rva - start)
                if dist <= threshold:
                    candidates.append((dist, start, fid, name, src))

    consider(idx)
    consider(idx - 1)

    # Exact start takes priority, then containment (distance 0), then nearest.
    candidates.sort(key=lambda c: (c[0], c[1]))
    if candidates:
        _, _, fid, name, src = candidates[0]
        return fid, name, src
    return None


def process_binary(
    binary_id: int,
    binary_path: str,
    binary_dir: Path,
    windy_exe: Path,
    min_insns: int,
    min_gt_len: int,
    rva_threshold: int,
    db_path: Path,
    schema_kwargs: Dict[str, Optional[str]],
) -> Tuple[int, int, List[str]]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro".replace("\\", "/"), uri=True)
    schema = DbSchema(**schema_kwargs)

    pe_path = binary_dir / binary_path.replace("\\", "/").lstrip("/")
    if not pe_path.exists():
        conn.close()
        return 0, 0, []

    db_rows = load_function_sources_for_binary(conn, schema, binary_id)
    if not db_rows:
        conn.close()
        return 0, 0, []

    fd, tmp_path = tempfile.mkstemp(suffix=".gclsd.jsonl")
    os.close(fd)
    try:
        proc = subprocess.run(
            [
                str(windy_exe),
                "export-gclsd",
                str(pe_path),
                "--output",
                tmp_path,
                "--min-insns",
                str(min_insns),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        conn.close()
        return 0, 0, []
    else:
        if proc.returncode != 0:
            conn.close()
            return 0, 0, []

        matched = 0
        skipped = 0
        lines: List[str] = []
        with open(tmp_path, "r", encoding="utf-8") as f:
            for raw in f:
                gclsd = GclsdInput.model_validate_json(raw)
                rva = gclsd.entry_va - gclsd.image_base
                entry = _match_rva(db_rows, rva, rva_threshold)
                if entry is None:
                    skipped += 1
                    continue
                func_id, name, gt_c = entry
                if not gt_c or len(gt_c) < min_gt_len:
                    skipped += 1
                    continue
                record = {"input": json.loads(raw), "gt_c": gt_c}
                lines.append(json.dumps(record, ensure_ascii=False))
                matched += 1
        conn.close()
        return matched, skipped, lines
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _worker_init(args: Tuple[Path, Path, Path, int, int, int, Dict[str, Optional[str]]]):
    global _worker_state
    _worker_state = args


def _worker_process(batch: List[Tuple[int, str]]) -> Tuple[int, int, List[str]]:
    db_path, binary_dir, windy_exe, min_insns, min_gt_len, rva_threshold, schema_kwargs = _worker_state
    total_matched = 0
    total_skipped = 0
    all_lines: List[str] = []
    for binary_id, binary_path in batch:
        matched, skipped, lines = process_binary(
            binary_id,
            binary_path,
            binary_dir,
            windy_exe,
            min_insns,
            min_gt_len,
            rva_threshold,
            db_path,
            schema_kwargs,
        )
        total_matched += matched
        total_skipped += skipped
        all_lines.extend(lines)
    return total_matched, total_skipped, all_lines


def chunk(items: Sequence, size: int) -> Iterable[Sequence]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract GCLSD pairs from Assemblage")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--windy-exe", type=Path, default=Path("target/debug/windy.exe"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--platform", type=str, default=None)
    parser.add_argument("--min-insns", type=int, default=5)
    parser.add_argument("--min-gt-len", type=int, default=20)
    parser.add_argument("--rva-threshold", type=int, default=64)
    parser.add_argument("--order-by", type=str, default="func_count", choices=["func_count", "id"])
    args = parser.parse_args()

    output_path: Path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(f"file:{args.db}?mode=ro".replace("\\", "/"), uri=True)
    schema = DbSchema.discover(conn)
    print(f"Discovered schema: {schema}")

    binaries = list(iter_binaries(conn, schema, args.platform, args.limit, args.order_by))
    conn.close()
    print(f"Processing {len(binaries)} binaries with {args.workers} workers")

    schema_kwargs = {
        "binary_id": schema.binary_id,
        "binary_path": schema.binary_path,
        "func_id": schema.func_id,
        "func_binary_id": schema.func_binary_id,
        "func_source": schema.func_source,
        "rvas_func_id": schema.rvas_func_id,
        "rvas_start": schema.rvas_start,
        "rvas_end": schema.rvas_end,
        "lines_func_id": schema.lines_func_id,
        "lines_text": schema.lines_text,
        "lines_address": schema.lines_address,
    }
    worker_args = (
        args.db,
        args.binary_dir,
        args.windy_exe,
        args.min_insns,
        args.min_gt_len,
        args.rva_threshold,
        schema_kwargs,
    )

    batch_size = max(1, len(binaries) // (args.workers * 4))
    batches = list(chunk(binaries, batch_size))

    total_matched = 0
    total_skipped = 0
    with open(output_path, "w", encoding="utf-8") as out_f:
        with mp.Pool(
            processes=args.workers,
            initializer=_worker_init,
            initargs=(worker_args,),
        ) as pool:
            for matched, skipped, lines in pool.imap_unordered(_worker_process, batches):
                total_matched += matched
                total_skipped += skipped
                for line in lines:
                    out_f.write(line + "\n")

    denom = total_matched + total_skipped
    match_rate = total_matched / denom if denom else 0.0
    print(
        f"Done: {total_matched} matched, {total_skipped} skipped, "
        f"match_rate={match_rate:.2%}, output={output_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
