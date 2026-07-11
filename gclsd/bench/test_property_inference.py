"""Test: property inference + bug hunting on decompiled code.

Instead of the full Charon→Aeneas→Leanstral pipeline (needs Lean 4 toolchain),
we test the *capability* directly: give the model Ghidra's decompiled output,
ask it to infer properties and check for bugs.

This tests the Leanstral 1.5 workflow ("infer properties, prove or disprove")
using Magistral as a proxy reasoning model.

We test with:
  1. Ghidra's correct decompile of `add` → should find no bugs
  2. A PURPOSEFULLY BUGGED version of `add` (overflow) → should catch it
  3. Ghidra's correct decompile of `strlen_local` → should find no bugs
  4. A PURPOSEFULLY BUGGED `strlen_local` (off-by-one) → should catch it
"""
import json, sys, os, urllib.request, pathlib

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

API_KEY = open(pathlib.Path(__file__).parent / "_mistral_key.txt").read().strip()
URL = "https://api.mistral.ai/v1/chat/completions"
MODEL = "magistral-medium-latest"

BENCH_DIR = pathlib.Path(__file__).parent

# Load Ghidra's decompilation of our test functions
with open(BENCH_DIR / "ghidra_output.json") as f:
    ghidra = {g["entry_va"]: g for g in json.load(f)}

ADD_VA = 0x140001000
STRLEN_VA = 0x140001020

# Ghidra's correct decompiles
ghidra_add = ghidra[ADD_VA]["pseudocode"].strip()
ghidra_strlen = ghidra[STRLEN_VA]["pseudocode"].strip()

# Purposefully bugged versions (introducing real bugs)
BUGGY_ADD = """int FUN_140001000(int param_1, int param_2)
{
  return param_1 * 2 + param_2;
}"""

BUGGY_STRLEN = """int FUN_140001020(longlong param_1)
{
  int local_18;
  local_18 = 0;
  // BUG: off-by-one, checks next byte instead of current
  while (*(char *)(param_1 + local_18 + 1) != '\\0') {
    local_18 = local_18 + 1;
  }
  return local_18;
}"""

PROMPT = """You are a formal verification expert. Your job is to infer properties of C code and check for bugs.

Given a decompiled C function, you must:
1. INFER plausible correctness properties (things that SHOULD be true about this function)
2. CHECK each property — try to prove it holds, or find a counterexample

Property categories to check:
- Integer overflow: can any arithmetic overflow?
- Off-by-one errors: are loop bounds correct?
- Null pointer dereference: can any pointer be NULL?
- Return value correctness: does the function return what its name/structure implies?
- Memory safety: any out-of-bounds access?

For each property, state:
- PROPERTY: (what you're checking)
- VERDICT: SAFE | BUG FOUND
- EVIDENCE: (proof or counterexample)

After checking all properties, give a final summary:
PROPERTIES CHECKED: N
BUGS FOUND: M (list each)
FUNCTION IS: SAFE | HAS BUGS

=== FUNCTION TO ANALYZE ===
{code}
"""

def call_mistral(prompt):
    payload = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 8192,
        "temperature": 0.0,
    }).encode()
    req = urllib.request.Request(URL, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    })
    with urllib.request.urlopen(req, timeout=180) as resp:
        result = json.loads(resp.read())
    msg = result["choices"][0]["message"]["content"]
    if isinstance(msg, list):
        texts = []
        for block in msg:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(block.get("text", ""))
            elif isinstance(block, dict) and block.get("type") == "thinking":
                for item in block.get("thinking", []):
                    if isinstance(item, dict):
                        texts.append(item.get("text", ""))
        return "\n".join(texts)
    return str(msg)

def truncate(text, max_lines=30):
    lines = text.strip().split("\n")
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n  // ... ({len(lines)-max_lines} more lines)"
    return "\n".join(lines)

tests = [
    ("add (Ghidra correct)", ghidra_add, "SAFE"),
    ("add (introduced bug: *2+)", BUGGY_ADD, "HAS BUGS"),
    ("strlen_local (Ghidra correct)", ghidra_strlen, "SAFE"),
    ("strlen_local (introduced off-by-one)", BUGGY_STRLEN, "HAS BUGS"),
]

print("=" * 60)
print(f"  PROPERTY INFERENCE + BUG HUNTING TEST ({MODEL})")
print("=" * 60)

results = []
for name, code, expected_verdict in tests:
    print(f"\n{'─' * 60}")
    print(f"  TEST: {name}")
    print(f"  Expected: {expected_verdict}")
    print(f"{'─' * 60}")

    prompt = PROMPT.format(code=code)
    response = call_mistral(prompt)

    resp_upper = response.upper()
    found_bugs = "BUG FOUND" in resp_upper or "BUGS FOUND: 1" in resp_upper or "BUGS FOUND: 2" in resp_upper
    is_safe = "FUNCTION IS: SAFE" in resp_upper or "BUGS FOUND: 0" in resp_upper

    if expected_verdict == "HAS BUGS":
        passed = found_bugs and not is_safe
    else:
        passed = is_safe and not found_bugs

    results.append((name, expected_verdict, passed))
    status = "✅" if passed else "❌"
    print(f"\n  {status} Verdict: {'BUGS FOUND' if found_bugs else 'SAFE' if is_safe else 'UNCLEAR'}")
    print()
    for line in truncate(response, 25).split("\n"):
        print(f"  {line}")

print(f"\n{'=' * 60}")
print("  SUMMARY")
print(f"{'=' * 60}")
passed = sum(1 for _, _, p in results if p)
for name, expected, p in results:
    print(f"  {name:45s} expected={expected:10s} -> {'✅ PASS' if p else '❌ FAIL'}")
print(f"\n  Score: {passed}/{len(results)}")
