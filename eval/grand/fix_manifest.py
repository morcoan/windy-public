#!/usr/bin/env python3
"""Regenerate the Grand manifest from built PEs and linker MAP identities."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
INV = json.loads((ROOT / "inventory.json").read_text(encoding="utf-8"))
MAP_SYMBOL = re.compile(
    r"^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+"
    r"(?P<name>\S+)\s+(?P<va>[0-9A-Fa-f]{16})\s+f(?:\s|$)"
)


def parse_map(path: Path) -> dict[str, set[int]]:
    """Return callable linker symbols without consulting either decompiler."""
    symbols: dict[str, set[int]] = {}
    if not path.exists():
        return symbols
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = MAP_SYMBOL.match(line)
        if match:
            symbols.setdefault(match.group("name"), set()).add(
                int(match.group("va"), 16)
            )
    return symbols


def load_gold(prog: dict[str, Any]) -> list[dict[str, Any]]:
    gold_rel = (
        prog.get("gold") or f"eval/grand/gold/{prog['program_id']}.json"
    ).replace("\\", "/")
    gold_path = ROOT.parents[1] / gold_rel
    gold = json.loads(gold_path.read_text(encoding="utf-8-sig"))
    return gold["functions"]


def symbol_vas(symbols: dict[str, set[int]], name: str) -> set[int]:
    # x64 C symbols are undecorated. The underscore fallback keeps this parser
    # useful if the fixture compiler is later exercised for x86 diagnostics.
    return symbols.get(name, set()) | symbols.get(f"_{name}", set())


def function_map(
    prog: dict[str, Any],
    profile: str,
    all_symbols: dict[tuple[str, str], dict[str, set[int]]],
) -> list[dict[str, Any]]:
    pid = prog["program_id"]
    symbols = all_symbols.get((pid, profile), {})
    p0_symbols = all_symbols.get((pid, "P0"), {})
    owners: dict[int, str] = {}
    result: list[dict[str, Any]] = []
    for function in load_gold(prog):
        function_id = function["id"]
        source_name = function.get("source_name") or function_id
        vas = symbol_vas(symbols, source_name)
        if len(vas) > 1:
            raise RuntimeError(
                f"ambiguous linker identity for {pid} {profile} {source_name}: "
                f"{sorted(hex(va) for va in vas)}"
            )
        if vas:
            va = next(iter(vas))
            folded_to = owners.get(va)
            if folded_to is None:
                owners[va] = function_id
                status = "present"
                entry_va = f"0x{va:x}"
            else:
                status = "folded"
                entry_va = None
            result.append(
                {
                    "function_id": function_id,
                    "source_name": source_name,
                    "status": status,
                    "entry_va": entry_va,
                    "folded_to": folded_to,
                }
            )
            continue

        was_emitted_unoptimized = bool(symbol_vas(p0_symbols, source_name))
        result.append(
            {
                "function_id": function_id,
                "source_name": source_name,
                "status": (
                    "inlined_only"
                    if profile != "P0" and was_emitted_unoptimized
                    else "missing"
                ),
                "entry_va": None,
                "folded_to": None,
            }
        )
    return result


def fresh_ghidra_export(json_path: Path, pe_path: Path) -> bool:
    if not json_path.exists() or json_path.stat().st_size <= 200:
        return False
    if json_path.stat().st_mtime_ns < pe_path.stat().st_mtime_ns:
        return False
    try:
        value = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(value, list) and len(value) > 0


def main() -> None:
    all_symbols: dict[tuple[str, str], dict[str, set[int]]] = {}
    for prog in INV["programs"]:
        for profile in ("P0", "P1", "P2", "P3"):
            map_path = ROOT / "bin" / profile / f"{prog['program_id']}.map"
            symbols = parse_map(map_path)
            pe_path = ROOT / "bin" / profile / f"{prog['program_id']}.exe"
            if pe_path.exists() and not symbols:
                raise RuntimeError(f"missing or empty linker MAP for {pe_path}")
            all_symbols[(prog["program_id"], profile)] = symbols

    bins: list[dict] = []
    for prog in INV["programs"]:
        pid = prog["program_id"]
        gold = (prog.get("gold") or f"eval/grand/gold/{pid}.json").replace("\\", "/")
        for pr in ("P0", "P1", "P2", "P3"):
            pe = ROOT / "bin" / pr / f"{pid}.exe"
            if not pe.exists():
                continue
            sha = hashlib.sha256(pe.read_bytes()).hexdigest()
            g = ROOT / "bin" / pr / f"{pid}_ghidra.json"
            ghidra_is_fresh = fresh_ghidra_export(g, pe)
            bins.append(
                {
                    "program_id": pid,
                    "profile": pr,
                    "pe_path": f"eval/grand/bin/{pr}/{pid}.exe",
                    "sha256": sha,
                    "pack_tags": prog.get("pack_tags", []),
                    "kind": prog.get("kind", "atomic"),
                    "gold_path": gold,
                    "ghidra_export": (
                        f"eval/grand/bin/{pr}/{pid}_ghidra.json"
                        if ghidra_is_fresh
                        else None
                    ),
                    "ghidra_sha256": (
                        hashlib.sha256(g.read_bytes()).hexdigest()
                        if ghidra_is_fresh
                        else None
                    ),
                    "function_map": function_map(prog, pr, all_symbols),
                }
            )
    man = {
        "suite": "windy_grand_decompilation_benchmark_v1",
        "program_count": len(INV["programs"]),
        "binary_count": len(bins),
        "profiles": ["P0", "P1", "P2", "P3"],
        "build_provenance": {
            "architecture": "x86_64-pc-windows-msvc",
            "compiler": "Microsoft C/C++ 19.44.35228",
            "linker": "Microsoft Incremental Linker 14.44.35228.0",
            "profile_flags": {
                "P0": "/Od /Ob0",
                "P1": "/O1",
                "P2": "/O2 /Ob2",
                "P3": "/O2 /GL /LTCG",
            },
            "identity_source": "MSVC linker MAP callable symbols",
        },
        "ghidra_provenance": {
            "version": "11.3.2_PUBLIC",
            "java": "Temurin OpenJDK 17.0.13+11",
            "analysis": "default full auto-analysis",
            "exporter": "eval/grand/ExportDecomp.java",
            "scope": "linker-allowlisted authored target functions only",
        },
        "binaries": bins,
    }
    out = ROOT / "manifest.json"
    out.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} with {len(bins)} binaries")


if __name__ == "__main__":
    main()
