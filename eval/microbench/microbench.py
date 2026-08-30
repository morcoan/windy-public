#!/usr/bin/env python3
"""Compact, deterministic Windy v0.3 agent microbenchmark.

The benchmark database and generated targets are private local artifacts. The
tracked code contains only generators and deterministic scoring. No model or
LLM judge is embedded here; Luna trajectories are ingested as sidecars.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
DEFAULT_DB = Path("eval/microbench/private/v03.sqlite")
TARGET_DIR = Path("target/v03-microbench/targets")
PACKET_DIR = Path("target/v03-microbench/packets")
SIDECAR_DIR = Path("target/v03-microbench/sidecars")
MAX_DB_BYTES = 10 * 1024 * 1024
MAX_CALLS = 6
MAX_TOOL_BYTES = 8 * 1024
MAX_FINAL_TOKENS = 250

MAP_SYMBOL = re.compile(
    r"^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+"
    r"(?P<name>\S+)\s+(?P<va>[0-9A-Fa-f]{16})\s+f(?:\s|$)"
)


PROGRAMS: dict[str, str] = {
    "a": r'''
#include <stdint.h>
#ifndef MB_SEED
#define MB_SEED 1
#endif
volatile int g_sink_a;
__declspec(noinline) int mb_pad_a(int x) { return (x ^ MB_SEED) & 1; }
__declspec(noinline) int mx_a(const char *s) {
    int n = 0;
    while (s[n] != '\0') n++;
    return n;
}
__declspec(noinline) int mx_b(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
__declspec(noinline) uint32_t mx_c(const unsigned char *p, int n) {
    uint32_t h = 2166136261u;
    int i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}
int main(void) {
    static const unsigned char s[] = "V03-RAVEN-41";
    g_sink_a = mb_pad_a(MB_SEED) + mx_a((const char *)s) + mx_b(-7, 0, 9) + (int)mx_c(s, 12);
    return g_sink_a == 17;
}
''',
    "b": r'''
#include <stdint.h>
#ifndef MB_SEED
#define MB_SEED 1
#endif
volatile int g_sink_b;
__declspec(noinline) int mb_pad_b(int x) { return (x ^ MB_SEED) & 1; }
__declspec(noinline) int mx_d(const unsigned char *p, int n) {
    int i, x = 0;
    for (i = 0; i < n; i++) x = ((x << 5) - x) ^ p[i];
    return x;
}
__declspec(noinline) int mx_e(int x) { return (x & 255) == 0x5a; }
__declspec(noinline) int mx_f(int x) { g_sink_b = x; return x; }
__declspec(noinline) int mx_g(const unsigned char *p, int n) {
    int x = mx_d(p, n);
    if (mx_e(x)) return mx_f(x);
    return -1;
}
__declspec(noinline) int mx_h(int (*fn)(int), int x) { return fn(x); }
int main(void) {
    static const unsigned char s[] = "V03-ORBIT-93";
    return mb_pad_b(MB_SEED) + mx_g(s, 12) + mx_h(mx_e, 0x5a);
}
''',
    "c": r'''
#include <stdint.h>
#ifndef MB_SEED
#define MB_SEED 1
#endif
typedef struct Node { int value; struct Node *next; } Node;
typedef struct Pair { int x; int y; } Pair;
volatile int g_sink_c;
__declspec(noinline) int mb_pad_c(int x) { return (x ^ MB_SEED) & 1; }
__declspec(noinline) int mx_i(Node *n) {
    int sum = 0;
    while (n) { sum += n->value; n = n->next; }
    return sum;
}
__declspec(noinline) int mx_j(const Pair *a, const Pair *b) {
    return a->x * b->x + a->y * b->y;
}
__declspec(noinline) int mx_k(int op, int a, int b) {
    switch (op) { case 1: return a + b; case 2: return a - b; case 3: return a * b; default: return 0; }
}
int main(void) {
    Node c = {3, 0}, b = {2, &c}, a = {1, &b};
    Pair p = {2, 4}, q = {3, 5};
    g_sink_c = mb_pad_c(MB_SEED) + mx_i(&a) + mx_j(&p, &q) + mx_k(3, 6, 7);
    return g_sink_c;
}
''',
}


@dataclass(frozen=True)
class Target:
    program: str
    profile: str
    path: Path
    sha256: str
    symbols: dict[str, int]


def schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS targets(
            id INTEGER PRIMARY KEY, program TEXT NOT NULL, profile TEXT NOT NULL,
            path TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS cases(
            id TEXT PRIMARY KEY, split TEXT NOT NULL, family TEXT NOT NULL,
            target_id INTEGER NOT NULL REFERENCES targets(id), prompt TEXT NOT NULL,
            oracle_kind TEXT NOT NULL, oracle_json TEXT NOT NULL,
            max_calls INTEGER NOT NULL, max_tool_bytes INTEGER NOT NULL,
            max_final_tokens INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS baselines(
            name TEXT PRIMARY KEY, exe_path TEXT NOT NULL, exe_sha256 TEXT NOT NULL,
            exe_bytes INTEGER NOT NULL, tools_sha256 TEXT NOT NULL,
            tools_bytes INTEGER NOT NULL, created_utc INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runs(
            id TEXT PRIMARY KEY, variant TEXT NOT NULL, model TEXT NOT NULL,
            reasoning TEXT NOT NULL, commit_hash TEXT, hypothesis TEXT,
            created_utc INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS results(
            run_id TEXT NOT NULL REFERENCES runs(id), case_id TEXT NOT NULL REFERENCES cases(id),
            success INTEGER NOT NULL, abstained INTEGER NOT NULL,
            false_support INTEGER NOT NULL, answer TEXT NOT NULL,
            failure_stage TEXT, tool_calls INTEGER NOT NULL,
            valid_calls INTEGER NOT NULL, tool_bytes INTEGER NOT NULL,
            visible_input_bytes INTEGER NOT NULL, output_bytes INTEGER NOT NULL,
            wall_ms INTEGER NOT NULL, PRIMARY KEY(run_id, case_id)
        );
        CREATE TABLE IF NOT EXISTS steps(
            run_id TEXT NOT NULL, case_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
            tool TEXT NOT NULL, arguments_json TEXT NOT NULL,
            response_bytes INTEGER NOT NULL, latency_ms INTEGER NOT NULL,
            error TEXT, PRIMARY KEY(run_id, case_id, ordinal)
        );
        CREATE TABLE IF NOT EXISTS hypotheses(
            cycle TEXT PRIMARY KEY, statement TEXT NOT NULL, mechanism TEXT NOT NULL,
            predicted_metric TEXT NOT NULL, disposition TEXT NOT NULL DEFAULT 'pending',
            observed_json TEXT
        );
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",
        (str(SCHEMA_VERSION),),
    )


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    schema(conn)
    return conn


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_vcvars64() -> Path:
    candidates = [
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"),
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise RuntimeError("vcvars64.bat not found; Visual Studio 2022 C++ tools are required")


def parse_map(path: Path) -> dict[str, int]:
    found: dict[str, set[int]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = MAP_SYMBOL.match(line)
        if m:
            found.setdefault(m.group("name"), set()).add(int(m.group("va"), 16))
    out: dict[str, int] = {}
    for name, values in found.items():
        if len(values) == 1:
            out[name] = next(iter(values))
    return out


def compile_targets(root: Path, seed: int) -> list[Target]:
    vcvars = find_vcvars64()
    target_root = (root / TARGET_DIR).resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    results: list[Target] = []
    with tempfile.TemporaryDirectory(prefix="windy-v03-src-") as td:
        work = Path(td)
        for program, source in PROGRAMS.items():
            src = work / f"unit_{program}.c"
            src.write_text(source, encoding="utf-8")
            for profile, flags in (("P0", "/Od /Ob0"), ("P2", "/O2 /Ob2")):
                out = work / f"{program}_{profile}"
                out.mkdir()
                exe = out / "neutral.exe"
                map_path = out / "neutral.map"
                command = (
                    f'call "{vcvars}" >nul && cd /d "{out}" && '
                    f'cl /nologo /TC /W3 {flags} /DMB_SEED={seed} /GS- /Fe:"{exe}" "{src}" '
                    f'/link /nologo /MAP:"{map_path}" /DEBUG:NONE'
                )
                build_cmd = out / "build.cmd"
                build_cmd.write_text("@echo off\r\n" + command + "\r\n", encoding="utf-8")
                proc = subprocess.run(
                    ["cmd.exe", "/d", "/c", "build.cmd"],
                    cwd=out,
                    text=True,
                    capture_output=True,
                    timeout=120,
                )
                if proc.returncode or not exe.is_file():
                    raise RuntimeError(f"MSVC build failed for {program}/{profile}: {proc.stdout}\n{proc.stderr}")
                symbols = parse_map(map_path)
                required = {
                    "a": ("mx_a", "mx_b", "mx_c"),
                    "b": ("mx_d", "mx_e", "mx_f", "mx_g", "mx_h"),
                    "c": ("mx_i", "mx_j", "mx_k"),
                }[program]
                missing = [name for name in required if name not in symbols]
                if missing:
                    raise RuntimeError(f"linker map missing {missing} for {program}/{profile}")
                digest = sha256_file(exe)
                dest = target_root / f"t-{program}-{profile.lower()}-{digest[:12]}.exe"
                shutil.copy2(exe, dest)
                results.append(Target(program, profile, dest, digest, symbols))
    return results


def case_rows(targets: list[Target]) -> list[dict[str, Any]]:
    by_key = {(t.program, t.profile): t for t in targets}
    def va(program: str, profile: str, name: str) -> str:
        return f"0x{by_key[(program, profile)].symbols[name]:x}"
    return [
        {"id":"locate-cstring","split":"canary","family":"locate","target":("a","P0"),
         "prompt":"Find the VA of the function that walks a NUL-terminated byte string and returns its character count. Return one hex VA or UNKNOWN.","kind":"exact_va","oracle":va("a","P0","mx_a")},
        {"id":"locate-clamp","split":"gate","family":"locate","target":("a","P2"),
         "prompt":"Find the VA of the function that clamps a value between lower and upper integer bounds. Return one hex VA or UNKNOWN.","kind":"exact_va","oracle":va("a","P2","mx_b")},
        {"id":"explain-fnv","split":"holdout","family":"explain","target":("a","P2"),
         "prompt":"Identify the byte-processing hash function and state its three essential operations using the tags BYTE, XOR, MULTIPLY.","kind":"contains_all","oracle":["byte","xor","multiply"]},
        {"id":"explain-dispatch","split":"canary","family":"explain","target":("c","P0"),
         "prompt":"Identify the arithmetic dispatcher and summarize its supported operations using the tags ADD, SUBTRACT, MULTIPLY.","kind":"contains_all","oracle":["add","subtract","multiply"]},
        {"id":"trace-pipeline","split":"gate","family":"provenance","target":("b","P0"),
         "prompt":"Find the VA of the function that sends decoder output through validation and conditionally into the global-writing sink. Return one hex VA or UNKNOWN.","kind":"exact_va","oracle":va("b","P0","mx_g")},
        {"id":"relationship-sink-caller","split":"holdout","family":"provenance","target":("b","P2"),
         "prompt":"Which function directly calls both the decoder and validator and can reach the sink? Return one hex VA or UNKNOWN.","kind":"exact_va","oracle":va("b","P2","mx_g")},
        {"id":"data-linked-list","split":"canary","family":"data","target":("c","P0"),
         "prompt":"Find the VA of the function that follows a linked-list next pointer while accumulating each node's integer value. Return one hex VA or UNKNOWN.","kind":"exact_va","oracle":va("c","P0","mx_i")},
        {"id":"data-dot-product","split":"gate","family":"data","target":("c","P2"),
         "prompt":"Find the VA of the function computing a two-field integer dot product across two structures. Return one hex VA or UNKNOWN.","kind":"exact_va","oracle":va("c","P2","mx_j")},
        {"id":"verify-false-edge","split":"holdout","family":"verify","target":("b","P0"),
         "prompt":f"Verify whether the decoder at {va('b','P0','mx_d')} directly calls the global-writing sink. Return exactly SUPPORTED, CONTRADICTED, or UNKNOWN.","kind":"exact_text","oracle":"CONTRADICTED"},
        {"id":"abstain-absent-crypto","split":"canary","family":"verify","target":("a","P0"),
         "prompt":"Find the VA of an AES-GCM encryption routine in this binary. Return one hex VA or UNKNOWN; do not infer unsupported presence.","kind":"exact_text","oracle":"UNKNOWN"},
        {"id":"edit-rename-persist","split":"gate","family":"edit","target":("c","P0"),
         "prompt":f"Rename function {va('c','P0','mx_i')} to list_value_sum using a verified revision-checked change, close and reopen the target, then return exactly PERSISTED if the name survives.","kind":"exact_text","oracle":"PERSISTED"},
        {"id":"edit-comment-persist","split":"holdout","family":"edit","target":("a","P0"),
         "prompt":f"Attach the function comment 'bounded integer clamp' to {va('a','P0','mx_b')} through a verified durable edit, close and reopen, then return exactly PERSISTED if it survives.","kind":"exact_text","oracle":"PERSISTED"},
    ]


def initialize(root: Path, db_path: Path, replace: bool, seed: int | None = None) -> None:
    full_db = (root / db_path).resolve()
    if full_db.exists() and not replace:
        raise RuntimeError(f"database exists: {full_db}; pass --replace to regenerate")
    if full_db.exists():
        full_db.unlink()
    seed = seed if seed is not None else secrets.randbelow(0x7ffffffe) + 1
    targets = compile_targets(root, seed)
    conn = connect(full_db)
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('holdout_seed',?)", (str(seed),))
    target_ids: dict[tuple[str, str], int] = {}
    for target in targets:
        cur = conn.execute(
            "INSERT INTO targets(program,profile,path,sha256) VALUES(?,?,?,?)",
            (target.program, target.profile, str(target.path), target.sha256),
        )
        target_ids[(target.program, target.profile)] = int(cur.lastrowid)
    for row in case_rows(targets):
        conn.execute(
            "INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?)",
            (row["id"], row["split"], row["family"], target_ids[row["target"]],
             row["prompt"], row["kind"], json.dumps(row["oracle"], separators=(",", ":")),
             MAX_CALLS, MAX_TOOL_BYTES, MAX_FINAL_TOKENS),
        )
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    size = full_db.stat().st_size
    if size > MAX_DB_BYTES:
        raise RuntimeError(f"microbench database is {size} bytes; cap is {MAX_DB_BYTES}")
    print(json.dumps({"database": str(full_db), "bytes": size, "targets": len(targets), "cases": 12, "seed": seed}))


def mcp_tools(endpoint: str) -> dict[str, Any]:
    headers = {"Accept":"application/json, text/event-stream", "MCP-Protocol-Version":"2025-11-25", "Content-Type":"application/json"}
    def post(body: dict[str, Any], session: str | None = None) -> tuple[dict[str, Any], str | None]:
        h = dict(headers)
        if session:
            h["Mcp-Session-Id"] = session
        req = urllib.request.Request(endpoint, json.dumps(body).encode(), h, method="POST")
        with urllib.request.urlopen(req, timeout=15) as response:
            text = response.read().decode("utf-8", "replace")
            new_session = response.headers.get("Mcp-Session-Id") or session
        if text.lstrip().startswith("data:") or "\ndata:" in text:
            lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:") and line[5:].strip()]
            text = lines[-1]
        return json.loads(text) if text.strip() else {}, new_session
    _, session = post({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"microbench","version":"0.3"}}})
    post({"jsonrpc":"2.0","method":"notifications/initialized"}, session)
    result, _ = post({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}, session)
    return result["result"]


def issue(root: Path, db_path: Path, split: str, endpoint: str, output: Path) -> None:
    conn = connect((root / db_path).resolve())
    tools = mcp_tools(endpoint)
    tools_blob = json.dumps(tools, separators=(",", ":"), sort_keys=True).encode()
    out = (root / output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = conn.execute(
        "SELECT c.*,t.path,t.sha256 FROM cases c JOIN targets t ON t.id=c.target_id WHERE c.split=? ORDER BY c.id",
        (split,),
    ).fetchall()
    for row in rows:
        packet = {
            "protocol":"windy-microbench-v1", "case_id":row["id"], "family":row["family"],
            "task":row["prompt"], "target_path":row["path"], "target_sha256":row["sha256"],
            "endpoint":endpoint, "tools":tools, "tools_bytes":len(tools_blob),
            "limits":{"max_calls":row["max_calls"],"max_tool_bytes":row["max_tool_bytes"],"max_final_tokens":row["max_final_tokens"]},
            "rules":["Use only Windy MCP evidence.","Do not inspect repository, source, maps, gold, database, or other trajectories.","Unsupported claims must be UNKNOWN."],
        }
        (out / f"{row['id']}.json").write_text(json.dumps(packet, indent=2), encoding="utf-8")
    conn.close()
    print(json.dumps({"packets":len(rows),"directory":str(out),"tools_bytes":len(tools_blob)}))


def normalize_va(value: str) -> int | None:
    match = re.search(r"0x[0-9a-fA-F]+", value)
    return int(match.group(0), 16) if match else None


def score(kind: str, oracle_json: str, answer: str) -> tuple[bool, bool, bool]:
    oracle = json.loads(oracle_json)
    normalized = answer.strip()
    low = normalized.lower()
    abstained = any(word in low for word in ("unknown", "unsupported", "not present", "refuse"))
    false_support = False
    if kind == "exact_va":
        success = normalize_va(normalized) == normalize_va(str(oracle))
    elif kind == "exact_text":
        success = normalized.upper() == str(oracle).upper()
        if str(oracle).upper() in {"UNKNOWN", "CONTRADICTED"}:
            false_support = normalize_va(normalized) is not None or normalized.upper() == "SUPPORTED"
    elif kind == "contains_all":
        success = all(str(token).lower() in low for token in oracle)
    else:
        raise ValueError(f"unknown oracle kind: {kind}")
    return success, abstained, false_support


def ingest(root: Path, db_path: Path, run_id: str, variant: str, sidecars: Path, model: str, reasoning: str, hypothesis: str) -> None:
    conn = connect((root / db_path).resolve())
    commit = subprocess.run(["git","rev-parse","HEAD"], cwd=root, text=True, capture_output=True).stdout.strip() or None
    conn.execute(
        "INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?)",
        (run_id, variant, model, reasoning, commit, hypothesis, int(time.time())),
    )
    files = sorted((root / sidecars).resolve().glob("*.json"))
    inserted = 0
    for path in files:
        value = json.loads(path.read_text(encoding="utf-8"))
        case_id = value["case_id"]
        case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if case is None:
            raise RuntimeError(f"unknown case in {path}: {case_id}")
        steps = value.get("steps", [])
        tool_bytes = sum(int(s.get("response_bytes", 0)) for s in steps)
        valid_calls = sum(1 for s in steps if not s.get("error"))
        answer = str(value.get("answer", ""))
        success, abstained, false_support = score(case["oracle_kind"], case["oracle_json"], answer)
        if len(steps) > case["max_calls"] or tool_bytes > case["max_tool_bytes"]:
            success = False
        conn.execute(
            "INSERT OR REPLACE INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, case_id, int(success), int(abstained), int(false_support), answer,
             value.get("failure_stage"), len(steps), valid_calls, tool_bytes,
             int(value.get("visible_input_bytes", 0)), len(answer.encode()), int(value.get("wall_ms", 0))),
        )
        conn.execute("DELETE FROM steps WHERE run_id=? AND case_id=?", (run_id, case_id))
        for i, step in enumerate(steps):
            conn.execute(
                "INSERT INTO steps VALUES(?,?,?,?,?,?,?,?)",
                (run_id, case_id, i, str(step.get("tool", "")), json.dumps(step.get("arguments", {}), separators=(",", ":")),
                 int(step.get("response_bytes", 0)), int(step.get("latency_ms", 0)), step.get("error")),
            )
        inserted += 1
    conn.commit()
    conn.close()
    print(json.dumps({"run_id":run_id,"ingested":inserted}))


def percentile(values: list[int], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * q)))
    return float(ordered[index])


def summary(root: Path, db_path: Path, run_id: str) -> None:
    conn = connect((root / db_path).resolve())
    rows = conn.execute("SELECT * FROM results WHERE run_id=? ORDER BY case_id", (run_id,)).fetchall()
    if not rows:
        raise RuntimeError(f"no results for run {run_id}")
    calls = [int(r["tool_calls"]) for r in rows]
    byte_counts = [int(r["tool_bytes"]) for r in rows]
    walls = [int(r["wall_ms"]) for r in rows]
    report = {
        "run_id":run_id, "tasks":len(rows), "successes":sum(int(r["success"]) for r in rows),
        "false_supports":sum(int(r["false_support"]) for r in rows),
        "valid_call_rate":sum(int(r["valid_calls"]) for r in rows) / max(1, sum(calls)),
        "median_calls":statistics.median(calls), "median_tool_bytes":statistics.median(byte_counts),
        "p95_tool_bytes":percentile(byte_counts, .95), "median_wall_ms":statistics.median(walls),
        "failures":[{"case_id":r["case_id"],"stage":r["failure_stage"],"answer":r["answer"]} for r in rows if not r["success"]],
    }
    print(json.dumps(report, indent=2))
    conn.close()


def record_baseline(root: Path, db_path: Path, exe: Path, tools_sha: str, tools_bytes: int) -> None:
    full = (root / exe).resolve()
    conn = connect((root / db_path).resolve())
    conn.execute(
        "INSERT OR REPLACE INTO baselines VALUES(?,?,?,?,?,?,?)",
        ("v0.2", str(full), sha256_file(full), full.stat().st_size, tools_sha, tools_bytes, int(time.time())),
    )
    conn.commit(); conn.close()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = p.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--replace", action="store_true"); init.add_argument("--seed", type=int)
    issue_p = sub.add_parser("issue"); issue_p.add_argument("--split", choices=("canary","gate","holdout"), required=True); issue_p.add_argument("--endpoint", required=True); issue_p.add_argument("--output", type=Path, default=PACKET_DIR)
    ingest_p = sub.add_parser("ingest"); ingest_p.add_argument("--run-id", required=True); ingest_p.add_argument("--variant", required=True); ingest_p.add_argument("--sidecars", type=Path, default=SIDECAR_DIR); ingest_p.add_argument("--model", default="gpt-5.6-luna"); ingest_p.add_argument("--reasoning", default="low"); ingest_p.add_argument("--hypothesis", default="")
    summary_p = sub.add_parser("summary"); summary_p.add_argument("--run-id", required=True)
    base = sub.add_parser("record-baseline"); base.add_argument("--exe", type=Path, required=True); base.add_argument("--tools-sha", required=True); base.add_argument("--tools-bytes", type=int, required=True)
    sub.add_parser("schema")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "init": initialize(root, args.db, args.replace, args.seed)
        elif args.command == "issue": issue(root, args.db, args.split, args.endpoint, args.output)
        elif args.command == "ingest": ingest(root, args.db, args.run_id, args.variant, args.sidecars, args.model, args.reasoning, args.hypothesis)
        elif args.command == "summary": summary(root, args.db, args.run_id)
        elif args.command == "record-baseline": record_baseline(root, args.db, args.exe, args.tools_sha, args.tools_bytes)
        elif args.command == "schema":
            conn = connect((root / args.db).resolve()); conn.close()
        return 0
    except Exception as exc:
        print(f"microbench: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
