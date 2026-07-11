"""Helper: find the smallest functions in a windy export."""
import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('gclsd/bench/sample_export.jsonl') as f:
    funcs = [json.loads(l) for l in f]

funcs.sort(key=lambda x: len(x['instructions']))
print("Smallest 15 functions:")
for fn in funcs[:15]:
    n = len(fn['instructions'])
    entry = fn['entry_va']
    # Show first 3 mnemonics for identification
    mnems = [i['mnemonic'] for i in fn['instructions'][:5]]
    print(f"  {fn['name']:30s}  {n:3d} instrs  0x{entry:x}  first5={mnems}")

# Also search Ghidra output for same entry VAs
print("\nMatching in Ghidra output:")
with open('gclsd/bench/ghidra_output.json') as f:
    gfuncs = json.load(f)
gfunc_by_va = {g['entry_va']: g for g in gfuncs}

for fn in funcs[:15]:
    va = fn['entry_va']
    if va in gfunc_by_va:
        gname = gfunc_by_va[va]['name']
        print(f"  0x{va:x}: windy={fn['name']}  ghidra={gname}")
    else:
        print(f"  0x{va:x}: windy={fn['name']}  ghidra=NOT FOUND")
