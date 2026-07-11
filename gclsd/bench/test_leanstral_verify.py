"""Test: can Leanstral (via Mistral API) verify a decompile?

We give it:
1. The asm of our `add` function (AT&T syntax)
2. The WRONG decompile from LLM4Decompile: `return 2*aa + bb;`
3. Ask: "do these match? if not, find the bug."

If the model can catch the error, the verification loop is viable.
"""
import json
import sys
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

API_KEY = open(__file__.replace("test_leanstral_verify.py", "_mistral_key.txt")).read().strip()
MODEL = "labs-leanstral-1-5"
URL = "https://api.mistral.ai/v1/chat/completions"

ASM = """func0:
pushq\t%rbp
movq\t%rsp, %rbp
movl\t$1, %eax
popq\t%rbp
retq"""

# Wait — let me re-check the actual asm. The ground truth was add(a,b) = a+b.
# MSVC compiles it. Let me use the actual windy export asm.
import pathlib, os
os.environ["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[2] / "gclsd" / "src")

import windy_gclsd.server as srv
from windy_gclsd.contract import GclsdInput

# Load the exported function at 0x140001000 (add)
with open(pathlib.Path(__file__).parent / "sample_export.jsonl") as f:
    for line in f:
        obj = json.loads(line)
        if obj["entry_va"] == 0x140001000:
            parsed = GclsdInput.model_validate(obj)
            ASM_TEXT = srv.build_asm_text(parsed)
            break

WRONG_DECOMPILE = """int sub_140001000 (void * ptr , int aa , int bb )
{ return 2*aa +bb; }"""

CORRECT_DECOMPILE = """int add(int a, int b) {
    return a + b;
}"""

PROMPT = f"""You are a reverse-engineering verification expert.

Below is x86-64 assembly in AT&T syntax (from objdump), followed by a candidate C decompilation.

Your task: Verify whether the C code correctly implements the semantics of the assembly.
Check:
1. Does the C function have the correct number of parameters?
2. Does the C function compute the same result as the assembly?
3. Are there any arithmetic errors?

If the C is WRONG, explain exactly what's wrong and what the correct C should be.
If the C is CORRECT, say "VERIFIED: CORRECT" and explain why.

=== ASSEMBLY ===
{ASM_TEXT}

=== CANDIDATE C ===
{WRONG_DECOMPILE}

=== YOUR VERIFICATION ==="""


def call_mistral(prompt, model=MODEL, temperature=0.0, max_tokens=2048):
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode()
    req = urllib.request.Request(URL, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read())
    return result["choices"][0]["message"]["content"]


print("=" * 60)
print("  TEST 1: Can Leanstral catch a WRONG decompile?")
print("=" * 60)
print(f"\nASM:\n{ASM_TEXT}")
print(f"\nWRONG C:\n{WRONG_DECOMPILE}")
print("\n--- Leanstral says: ---\n")
response1 = call_mistral(PROMPT)
print(response1)

print("\n" + "=" * 60)
print("  TEST 2: Can Leanstral confirm a CORRECT decompile?")
print("=" * 60)

PROMPT2 = PROMPT.replace(WRONG_DECOMPILE, CORRECT_DECOMPILE)
print(f"\nCORRECT C:\n{CORRECT_DECOMPILE}")
print("\n--- Leanstral says: ---\n")
response2 = call_mistral(PROMPT2)
print(response2)

print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
caught_wrong = "WRONG" in response1.upper() or "INCORRECT" in response1.upper() or "ERROR" in response1.upper()
confirmed_right = "VERIFIED" in response2.upper() or "CORRECT" in response2.upper()
print(f"  Caught wrong decompile?  {'YES' if caught_wrong else 'NO'}")
print(f"  Confirmed correct one?   {'YES' if confirmed_right else 'NO'}")
