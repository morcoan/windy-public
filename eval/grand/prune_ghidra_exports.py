#!/usr/bin/env python3
"""Keep only authored benchmark functions in Ghidra comparison exports.

Full headless analysis necessarily discovers the statically linked MSVC runtime.
Those functions are not benchmark targets and their derived pseudocode is not a
release input. The linker-derived manifest is the sole allowlist.
"""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "eval" / "grand" / "manifest.json"


def parse_va(value: str) -> int:
    return int(value, 0)


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    pruned = 0
    kept = 0
    for binary in manifest["binaries"]:
        expected = {
            parse_va(function["entry_va"])
            for function in binary.get("function_map", [])
            if function.get("status") == "present" and function.get("entry_va")
        }
        if not expected:
            continue
        path = ROOT / "eval" / "grand" / "bin" / binary["profile"] / (
            f"{binary['program_id']}_ghidra.json"
        )
        if not path.exists():
            continue
        entries = json.loads(path.read_text(encoding="utf-8-sig"))
        selected = [entry for entry in entries if int(entry["entry_va"]) in expected]
        found = {int(entry["entry_va"]) for entry in selected}
        missing = expected - found
        if missing:
            values = ", ".join(hex(value) for value in sorted(missing))
            raise RuntimeError(
                f"Ghidra export {path} missed linker targets: {values}"
            )
        path.write_text(json.dumps(selected, indent=2) + "\n", encoding="utf-8")
        pruned += 1
        kept += len(selected)
    print(f"pruned {pruned} Ghidra exports to {kept} authored functions")


if __name__ == "__main__":
    main()
