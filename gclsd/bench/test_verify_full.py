"""Full benchmark: can a reasoning model verify decompiles?

Tests all 3 functions (add, max3, strlen_local) with:
- The WRONG LLM4Decompile output
- The CORRECT ground truth
"""
import json, sys, os, urllib.request, pathlib

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

API_KEY = open(pathlib.Path(__file__).parent / "_mistral_key.txt").read().strip()
URL = "https://api.mistral.ai/v1/chat/completions"
MODEL = "magistral-medium-latest"

os.environ["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[2] / "gclsd" / "src")
import windy_gclsd.server as srv
from windy_gclsd.contract import GclsdInput

BENCH_DIR = pathlib.Path(__file__).parent

# Load all 3 functions' asm
FUNCS = {
    "add":          {"va": 0x140001000, "correct": "int add(int a, int b) {\n    return a + b;\n}",
                     "wrong": "int sub_140001000(void *ptr, int aa, int bb) {\n    return 2*aa + bb;\n}"},
    "max3":         {"va": 0x140001060, "correct": "int max3(int a, int b, int c) {\n    int m = a;\n    if (b > m) m = b;\n    if (c > m) m = c;\n    return m;\n}",
                     "wrong": "int sub_(int a, int b) {\n    return (a < b ? a : ((b > c ? b : c)));\n}"},
    "strlen_local": {"va": 0x140001020, "correct": "int strlen_local(const char *s) {\n    int n = 0;\n    while (s[n]) { n = n + 1; }\n    return n;\n}",
                     "wrong": 'int sub_140001020() {\n    int i;\n    char *p = "abcdefghijklmnop";\n    for (i = 0; p[i] != 0; i++);\n    return i;\n}'},
}

# Load asm for each
with open(BENCH_DIR / "sample_export.jsonl") as f:
    for line in f:
        obj = json.loads(line)
        for name, info in FUNCS.items():
            if obj["entry_va"] == info["va"]:
                parsed = GclsdInput.model_validate(obj)
                info["asm"] = srv.build_asm_text(parsed)
                break

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
    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read())
    # The magistral model returns content as a list of blocks:
    #   [{"type": "thinking", "thinking": [{"type": "text", "text": "..."}]}
    #    {"type": "text", "text": "..."}]
    # We need to extract ALL text from both thinking and answer blocks.
    msg = result["choices"][0]["message"]["content"]
    all_text = []
    if isinstance(msg, list):
        for block in msg:
            if not isinstance(block, dict):
                all_text.append(str(block))
                continue
            btype = block.get("type", "")
            if btype == "text":
                all_text.append(block.get("text", ""))
            elif btype == "thinking":
                # thinking blocks have nested list of text items
                for item in block.get("thinking", []):
                    if isinstance(item, dict) and item.get("type") == "text":
                        all_text.append(item.get("text", ""))
                    elif isinstance(item, str):
                        all_text.append(item)
    elif isinstance(msg, str):
        all_text.append(msg)
    return "\n".join(all_text)

PROMPT_TEMPLATE = """You are a reverse-engineering verification expert.

Below is x86-64 assembly in AT&T syntax. Following it is a candidate C decompilation.

Verify whether the C correctly implements the assembly. Check:
1. Number of parameters (Windows x64: first 4 int/ptr args in rcx, rdx, r8, r9)
2. Arithmetic correctness (trace each instruction)
3. Return value

If WRONG: say "VERDICT: WRONG" then explain the bug and provide correct C.
If CORRECT: say "VERDICT: CORRECT" then explain why.

=== ASSEMBLY ===
{asm}

=== CANDIDATE C ===
{candidate_c}
"""

def truncate(text, max_lines=25):
    lines = text.strip().split("\n")
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n  // ... ({len(lines)-max_lines} more lines)"
    return "\n".join(lines)

print("=" * 60)
print(f"  DECOMPILE VERIFICATION BENCHMARK ({MODEL})")
print("=" * 60)

results = []
for name, info in FUNCS.items():
    asm = info["asm"]
    for test_label, candidate_c in [("WRONG", info["wrong"]), ("CORRECT", info["correct"])]:
        prompt = PROMPT_TEMPLATE.format(asm=asm, candidate_c=candidate_c)
        response = call_mistral(prompt)
        resp_upper = response.upper()
        is_correct = "VERDICT: CORRECT" in resp_upper or "CODE IS CORRECT" in resp_upper or "C CODE IS CORRECT" in resp_upper
        is_wrong = "VERDICT: WRONG" in resp_upper or "C IS WRONG" in resp_upper or "CODE IS WRONG" in resp_upper or "INCORRECT" in resp_upper or "CANDIDATE IS WRONG" in resp_upper
        expected = test_label == "CORRECT"
        passed = (expected and is_correct) or (not expected and is_wrong)
        results.append((name, test_label, passed))
        status = "✅" if passed else "❌"
        verdict = "CORRECT" if is_correct else ("WRONG" if is_wrong else "UNCLEAR")
        print(f"\n{status} {name} / {test_label}: {verdict}")
        # Print first few lines of reasoning
        for line in truncate(response, 8).split("\n"):
            print(f"  {line}")

print(f"\n{'='*60}")
print("  SUMMARY")
print(f"{'='*60}")
passed_count = sum(1 for _, _, p in results if p)
total = len(results)
for name, label, passed in results:
    print(f"  {name:15s} {label:8s} -> {'✅ PASS' if passed else '❌ FAIL'}")
print(f"\n  Score: {passed_count}/{total}")
