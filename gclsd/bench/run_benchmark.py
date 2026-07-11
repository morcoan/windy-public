"""Benchmark: compare LLM4Decompile vs Ghidra vs ground truth.

Compiles sample.c -> sample.exe (MSVC), then runs three decompilers
on the three target functions (add, strlen_local, max3) and prints
side-by-side output for human comparison.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Force UTF-8 so Ghidra/decompile output with special chars prints on Windows.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

BENCH_DIR = Path(__file__).resolve().parent
WINDY_ROOT = BENCH_DIR.parent.parent
SAMPLE_EXE = BENCH_DIR / "sample.exe"
EXPORT_JSONL = BENCH_DIR / "sample_export.jsonl"
GHIDRA_OUTPUT = BENCH_DIR / "ghidra_output.json"
GROUND_TRUTH = BENCH_DIR / "sample.c"

#sys.path.insert(0, str(WINDY_ROOT / "gclsd" / "src"))
os.environ["PYTHONPATH"] = str(WINDY_ROOT / "gclsd" / "src")

TARGET_FUNCTIONS = {"add", "strlen_local", "max3"}

# Entry VAs discovered by matching Ghidra output to known C source.
# (Compiled without PDB, so names are FUN_xxx / sub_xxx)
TARGET_ENTRY_VAS = {
    "add": 0x140001000,
    "max3": 0x140001060,
    # strlen_local is at 0x140001020 — between add and max3
    "strlen_local": 0x140001020,
}


def load_windy_exports() -> dict:
    """Load target functions from windy's GCLSD export, matching by entry VA."""
    results = {}
    with open(EXPORT_JSONL) as f:
        for line in f:
            obj = json.loads(line)
            for name, va in TARGET_ENTRY_VAS.items():
                if obj["entry_va"] == va:
                    results[name] = obj
                    break
    return results


def load_ghidra_output() -> dict:
    """Run Ghidra headless and parse decompiled functions."""
    if GHIDRA_OUTPUT.exists():
        with open(GHIDRA_OUTPUT) as f:
            data = json.load(f)
        return {d["name"]: d for d in data}

    java_home = r"D:\tools\jdk-21.0.5+11"
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home
    env["PATH"] = f"{java_home}\\bin;{env['PATH']}"

    ghidra = r"D:\tools\ghidra_11.3.2_PUBLIC\support\analyzeHeadless.bat"
    proj_dir = str(BENCH_DIR / "ghidra_proj")
    proj_name = "BenchProj"
    script_dir = str(BENCH_DIR)
    exe = str(SAMPLE_EXE)

    print("Running Ghidra headless (this takes ~20-40s)...")
    t0 = time.time()
    proc = subprocess.run(
        [ghidra, proj_dir, proj_name,
         "-import", exe, "-deleteProject",
         "-scriptPath", script_dir,
         "-postScript", "decompile_to_file.py"],
        capture_output=True, text=True, env=env, timeout=180,
    )
    elapsed = time.time() - t0
    print(f"  Ghidra done ({elapsed:.0f}s)")

    if not GHIDRA_OUTPUT.exists():
        print("  STDERR (last 500 chars):")
        print(proc.stderr[-500:] if proc.stderr else "(empty)")
        raise RuntimeError("Ghidra did not produce output file")

    with open(GHIDRA_OUTPUT) as f:
        data = json.load(f)
    return {d["name"]: d for d in data}


def llm4decompile(gclsd_input: dict, model_slot: str = "quality") -> str:
    """Run LLM4Decompile on a windy-exported function."""
    import windy_gclsd.server as srv
    from windy_gclsd.contract import GclsdInput

    parsed = GclsdInput.model_validate(gclsd_input)
    lm = srv._ensure_loaded(model_slot)
    asm = srv.build_asm_text(parsed)
    return srv._generate(lm, asm)


def truncate(text: str, max_lines: int = 40) -> str:
    lines = text.strip().split("\n")
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n  // ... ({len(lines) - max_lines} more lines)"
    return "\n".join(lines)


def main():
    print("=" * 70)
    print("  DECOMPILER BENCHMARK: LLM4Decompile vs Ghidra vs Ground Truth")
    print("=" * 70)

    # Ground truth
    print("\n--- Loading ground truth ---")
    gt = GROUND_TRUTH.read_text()

    # Windy exports
    print("--- Loading windy exports ---")
    windy_funcs = load_windy_exports()
    for name in sorted(TARGET_FUNCTIONS):
        if name not in windy_funcs:
            print(f"  WARNING: {name} not found in windy export!")
        else:
            f = windy_funcs[name]
            print(f"  {name}: {len(f['instructions'])} instrs, "
                  f"{len(f['blocks'])} blocks, entry=0x{f['entry_va']:x}")

    # Ghidra
    print("\n--- Running Ghidra ---")
    try:
        ghidra_funcs = load_ghidra_output()
        print(f"  Ghidra decompiled {len(ghidra_funcs)} functions total")
    except Exception as e:
        print(f"  Ghidra failed: {e}")
        ghidra_funcs = {}

    # LLM4Decompile
    print("\n--- Running LLM4Decompile (6.7b quality) ---")
    llm_results = {}
    import windy_gclsd.server as srv
    srv._ensure_loaded("quality")
    for name in sorted(TARGET_FUNCTIONS):
        if name not in windy_funcs:
            continue
        t0 = time.time()
        try:
            result = llm4decompile(windy_funcs[name], "quality")
            elapsed = time.time() - t0
            llm_results[name] = result
            print(f"  {name}: done ({elapsed:.1f}s)")
        except Exception as e:
            print(f"  {name}: FAILED - {e}")
            llm_results[name] = f"// error: {e}"

    # Print comparison
    print("\n" + "=" * 70)
    print("  RESULTS: Side-by-Side Comparison")
    print("=" * 70)

    for name in sorted(TARGET_FUNCTIONS):
        print(f"\n{'─' * 70}")
        print(f"  FUNCTION: {name}")
        print(f"{'─' * 70}")

        # Ground truth
        print(f"\n  ▶ GROUND TRUTH (from sample.c):")
        # Extract just this function from the source
        pattern = rf"(int {name}\([^)]*\)\s*\{{.*?\n\}})"
        match = re.search(pattern, gt, re.DOTALL)
        if match:
            for line in match.group(1).split("\n"):
                print(f"    {line}")
        else:
            print(f"    (could not extract from source)")

        # Ghidra
        print(f"\n  ▶ GHIDRA (headless decompiler):")
        target_va = TARGET_ENTRY_VAS.get(name)
        ghidra_match = None
        for gname, gdata in ghidra_funcs.items():
            if gdata.get("entry_va") == target_va:
                ghidra_match = gdata
                break
        if ghidra_match:
            print(f"    [Ghidra name: {ghidra_match['name']}]")
            for line in truncate(ghidra_match["pseudocode"]).split("\n"):
                print(f"    {line}")
        else:
            print(f"    (not found at 0x{target_va:x})")

        # LLM4Decompile
        print(f"\n  ▶ LLM4DECOMPILE 6.7B:")
        for line in truncate(llm_results.get(name, "(not run)")).split("\n"):
            print(f"    {line}")

    print(f"\n{'=' * 70}")
    print("  BENCHMARK COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
