"""Find our 3 target functions by matching Ghidra decompiled output patterns."""
import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('gclsd/bench/ghidra_output.json') as f:
    gfuncs = json.load(f)

print(f"Searching {len(gfuncs)} Ghidra functions for our targets...\n")

# Pattern: "add" function: should have "a + b" or "param_1 + param_2" in a tiny function
# Pattern: "strlen_local": should have a while loop with char comparison, increment n
# Pattern: "max3": should have comparisons (>) with 3 params, multiple if branches

for g in gfuncs:
    code = g['pseudocode']
    name = g['name']
    entry = g['entry_va']
    lines = code.strip().split('\n')
    
    # Skip huge CRT functions
    if len(lines) > 30:
        continue
    
    # Look for add: tiny function with + and return
    if 'param_1 + param_2' in code and 'return' in code and len(lines) < 6:
        print(f"=== LIKELY 'add' ({name} @ 0x{entry:x}) ===")
        print(code.strip())
        print()
    
    # Look for strlen: while loop with null check
    if 'while' in code and ('\\0' in code or '0x0' in code or '!= 0' in code) and 'return' in code:
        if len(lines) < 20:
            print(f"=== LIKELY 'strlen_local' ({name} @ 0x{entry:x}) ===")
            print(code.strip())
            print()
    
    # Look for max3: 3 params, comparisons
    if 'param_3' in code and ('>' in code or '<' in code) and 'return' in code:
        if len(lines) < 15:
            print(f"=== LIKELY 'max3' ({name} @ 0x{entry:x}) ===")
            print(code.strip())
            print()
