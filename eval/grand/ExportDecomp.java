// Ghidra headless script: export function decompilations as JSON array.
// @category Windy
// @menupath

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExportDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = System.getProperty("windy.export", null);
        if (outPath == null || outPath.isEmpty()) {
            String[] args = getScriptArgs();
            if (args != null && args.length > 0) {
                outPath = args[0];
            }
        }
        if (outPath == null || outPath.isEmpty()) {
            printerr("No export path. Pass script arg or -Dwindy.export=");
            return;
        }
        File requestedOutput = new File(outPath);
        File outputDirectory = requestedOutput.isDirectory()
            ? requestedOutput
            : requestedOutput.getParentFile();
        String programName = currentProgram.getName();
        if (programName.toLowerCase().endsWith(".exe")) {
            programName = programName.substring(0, programName.length() - 4);
        }
        if (requestedOutput.isDirectory()) {
            outPath = new File(requestedOutput, programName + "_ghidra.json.tmp").getPath();
        }

        installTargetFunctions(outputDirectory, programName);

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        List<String> entries = new ArrayList<>();

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isThunk()) continue;
            String name = f.getName();
            // Skip CRT noise by size/entry where possible; still export all non-thunk.
            DecompileResults res = ifc.decompileFunction(f, 30, monitor);
            String pseudo = "";
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                pseudo = res.getDecompiledFunction().getC();
            }
            if (pseudo == null) pseudo = "";
            // Cap huge CRT dumps
            if (pseudo.length() > 80000) {
                pseudo = pseudo.substring(0, 80000);
            }
            long va = f.getEntryPoint().getOffset();
            String esc = jsonEscape(pseudo);
            String nesc = jsonEscape(name);
            entries.add(String.format(
                "{\"entry_va\": %d, \"pseudocode\": \"%s\", \"name\": \"%s\"}",
                va, esc, nesc));
        }
        ifc.dispose();

        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        for (int i = 0; i < entries.size(); i++) {
            sb.append(entries.get(i));
            if (i + 1 < entries.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("]\n");

        try (FileWriter fw = new FileWriter(outPath)) {
            fw.write(sb.toString());
        }
        println("Wrote " + entries.size() + " functions to " + outPath);
    }

    private static String jsonEscape(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"': b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private void installTargetFunctions(File outputDirectory, String programName) throws Exception {
        if (outputDirectory == null) return;
        File targetsFile = new File(outputDirectory, programName + "_ghidra_targets.txt");
        if (!targetsFile.isFile()) return;

        List<Address> targets = new ArrayList<>();
        for (String raw : Files.readAllLines(targetsFile.toPath())) {
            String value = raw.trim();
            if (value.isEmpty() || value.startsWith("#")) continue;
            if (value.startsWith("0x") || value.startsWith("0X")) value = value.substring(2);
            targets.add(toAddr(Long.parseUnsignedLong(value, 16)));
        }
        if (targets.isEmpty()) return;

        FunctionManager manager = currentProgram.getFunctionManager();
        Set<Address> overlappingEntries = new HashSet<>();
        for (Address target : targets) {
            Function containing = manager.getFunctionContaining(target);
            if (containing != null && !containing.getEntryPoint().equals(target)) {
                overlappingEntries.add(containing.getEntryPoint());
            }
        }
        for (Address entry : overlappingEntries) {
            manager.removeFunction(entry);
        }

        // Reserve tail-called entries first so their caller cannot absorb them.
        targets.sort(Comparator.reverseOrder());
        for (Address target : targets) {
            if (manager.getFunctionAt(target) == null) {
                disassemble(target);
                Function created = createFunction(target, null);
                if (created == null) {
                    throw new IllegalStateException("Could not create linker target at " + target);
                }
            }
        }
        analyzeChanges(currentProgram);
    }
}
