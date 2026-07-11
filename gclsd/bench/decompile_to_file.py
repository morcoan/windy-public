# Ghidra headless script: decompile all functions and write JSON to a file.
# @category Analysis
# @runtime Jython

import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

output_file = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), "ghidra_output.json")

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

f = open(output_file, "w")
f.write(json.dumps(results))
f.close()

print("Wrote %d functions to %s" % (len(results), output_file))
