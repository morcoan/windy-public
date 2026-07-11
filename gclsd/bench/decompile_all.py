# Ghidra headless script: decompile all functions and write to stdout as JSON.
# @category Analysis
# @runtime Jython

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)

results = []
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)
monitor = ConsoleTaskMonitor()

for func in funcs:
    name = func.getName()
    entry = func.getEntryPoint().getOffset()
    res = decomp.decompileFunction(func, 60, monitor)
    if res and res.decompileCompleted():
        code = res.getDecompiledFunction().getC()
    else:
        code = "// decompile failed"
    results.append({"name": name, "entry_va": entry, "pseudocode": code})

print("===GHIDRA_OUTPUT_START===")
print(json.dumps(results))
print("===GHIDRA_OUTPUT_END===")
