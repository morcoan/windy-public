"""Test: can a strong Mistral model verify a decompile?

Tests the 'prove-the-decompile' idea:
1. Give model the asm + a WRONG C decompile
2. Ask: are they equivalent? find the bug.
3. Then give it the CORRECT C, ask same question.
"""
import json, sys, os, urllib.request, urllib.error, pathlib

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

API_KEY = open(pathlib.Path(__file__).parent / "_mistral_key.txt").read().strip()
URL = "https://api.mistral.ai/v1/chat/completions"
MODEL = "magistral-medium-latest"  # Mistral's reasoning model

os.environ["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[2] / "gclsd" / "src")
import windy_gclsd.server as srv
from windy_gclsd.contract import GclsdInput

# Load add() asm from export
with open(pathlib.Path(__file__).parent / "sample_export.jsonl") as f:
    for line in f:
        obj = json.loads(line)
        if obj["entry_va"] == 0x140001000:
            parsed = GclsdInput.model_validate(obj)
            ASM = srv.build_asm_text(parsed)
            break

WRONG_C = """int sub_140001000(void *ptr, int aa, int bb) {
    return 2*aa + bb;
}"""

CORRECT_C = """int add(int a, int b) {
    return a + b;
}"""

def call_mistral(prompt):
    payload = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096,
        "temperature": 0.0,
    }).encode()
    req = urllib.request.Request(URL, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:300]}"

PROMPT_TEMPLATE = """You are a reverse-engineering verification expert.

Below is x86-64 assembly in AT&T syntax (Capstone output). Following it is a candidate C decompilation.

Verify whether the C correctly implements the assembly semantics. Check:
1. Number of parameters (x64 calling convention: first 4 int args in ecx, edx, r8, r9)
2. Arithmetic correctness (trace each instruction)
3. Return value

If WRONG: explain the bug and provide the correct C.
If CORRECT: say "VERIFIED CORRECT" and explain why.

=== ASSEMBLY ===
{asm}

=== CANDIDATE C ===
{candidate_c}

=== VERIFICATION ==="""

print("=" * 60)
print(f"  Testing model: {MODEL}")
print("=" * 60)
print(f"\nASM:\n{ASM}")

# Test 1: Wrong decompile
print(f"\n{'='*60}")
print("  TEST 1: Wrong decompile (2*aa + bb)")
print(f"{'='*60}")
print(f"\nCandidate C:\n{WRONG_C}")
prompt1 = PROMPT_TEMPLATE.format(asm=ASM, candidate_c=WRONG_C)
print("\n--- Model response: ---\n")
resp1 = call_mistral(prompt1)
print(resp1)

# Test 2: Correct decompile
print(f"\n{'='*60}")
print("  TEST 2: Correct decompile (a + b)")
print(f"{'='*60}")
print(f"\nCandidate C:\n{CORRECT_C}")
prompt2 = PROMPT_TEMPLATE.format(asm=ASM, candidate_c=CORRECT_C)
print("\n--- Model response: ---\n")
resp2 = call_mistral(prompt2)
print(resp2)

# Summary
print(f"\n{'='*60}")
print("  VERDICT")
print(f"{'='*60}")
caught = any(w in resp1.upper() for w in ["WRONG", "INCORRECT", "ERROR", "BUG", "NOT MATCH", "MISMATCH"])
confirmed = "VERIFIED" in resp2.upper() or "CORRECT" in resp2.upper()
print(f"  Caught wrong decompile?   {'✅ YES' if caught else '❌ NO'}")
print(f"  Confirmed correct one?    {'✅ YES' if confirmed else '❌ NO'}")
