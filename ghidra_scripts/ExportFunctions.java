// ExportFunctions.java — RE Toolkit Ghidra Export Script
//
// Decompiles every non-external, non-thunk function in the current program
// and writes a JSONL file compatible with the local LLM analyzer pipeline.
//
// Output schema per line:
// {
//   "binaryName":        "sample.exe",
//   "functionName":      "FUN_1400139a0",
//   "entryPoint":        "0x1400139a0",
//   "decompiledCode":    "void FUN_... { ... }",
//   "calledFunctions":   ["sub_140010000", "malloc"],
//   "referencedStrings": ["error: bad input"],
//   "xrefCount":         3
// }
//
// Usage (GUI):
//   Window > Script Manager > navigate to this file > Run
//   A file-chooser dialog will ask where to save the JSONL output.
//
// Usage (headless):
//   analyzeHeadless <project_dir> <project_name> \
//     -process <binary> \
//     -postScript ExportFunctions.java "/path/to/output.jsonl"
//   The first script argument is used as the output path.
//
// @author  RE Toolkit
// @category ReversEngineeringToolkit
// @menupath Tools.RE Toolkit.Export Functions to JSONL
// @toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportFunctions extends GhidraScript {

    // --- Tunables -----------------------------------------------------------

    /** Decompilation timeout per function (seconds). */
    private static final int DECOMPILE_TIMEOUT_SECS = 30;

    /**
     * Maximum length of the decompiled code string kept in the output.
     * Very large functions (>20 k chars) overwhelm the LLM context window.
     * The code is truncated and a marker comment is appended.
     */
    private static final int MAX_DECOMPILE_CHARS = 16_000;

    /**
     * Maximum number of referenced strings collected per function.
     * Keeps the JSONL payload manageable.
     */
    private static final int MAX_STRINGS = 50;

    /** Maximum length of a single string value included in output. */
    private static final int MAX_STRING_LEN = 256;

    // -----------------------------------------------------------------------

    @Override
    public void run() throws Exception {

        // ---- Determine output path ----------------------------------------
        File outFile;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            // Headless: path supplied as script argument
            outFile = new File(args[0]);
        } else {
            // GUI: ask the user
            outFile = askFile("Save JSONL export to...", "Export");
        }
        if (outFile == null) {
            println("Export cancelled.");
            return;
        }

        String binaryName = currentProgram.getName();
        println("Binary : " + binaryName);
        println("Output : " + outFile.getAbsolutePath());

        // ---- Initialize decompiler ----------------------------------------
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.toggleSyntaxTree(false);    // C code only, skip syntax tree
        decomp.toggleCCode(true);

        if (!decomp.openProgram(currentProgram)) {
            printerr("Failed to open program in decompiler.");
            return;
        }

        // ---- Collect functions --------------------------------------------
        FunctionIterator funcIter =
            currentProgram.getFunctionManager().getFunctions(true);

        List<Function> functions = new ArrayList<>();
        while (funcIter.hasNext()) {
            Function f = funcIter.next();
            // Skip externals (no body) and thunks (just forwarding stubs)
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            functions.add(f);
        }

        println("Functions to export: " + functions.size());
        monitor.initialize(functions.size());
        monitor.setMessage("Exporting functions...");

        // ---- Write JSONL --------------------------------------------------
        int successCount = 0;
        int skipCount    = 0;
        int errorCount   = 0;

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(
                    new FileOutputStream(outFile), StandardCharsets.UTF_8))) {

            ReferenceManager refMgr = currentProgram.getReferenceManager();
            Listing           listing = currentProgram.getListing();

            for (Function func : functions) {
                if (monitor.isCancelled()) {
                    println("Export cancelled by user.");
                    break;
                }

                monitor.setMessage("Decompiling: " + func.getName());

                try {
                    // -- Decompile --
                    DecompileResults result =
                        decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECS, monitor);

                    if (!result.decompileCompleted()) {
                        String err = result.getErrorMessage();
                        println("  SKIP " + func.getName() + " — " +
                            (err != null ? err : "decompilation did not complete"));
                        skipCount++;
                        monitor.incrementProgress(1);
                        continue;
                    }

                    String code = result.getDecompiledFunction().getC();
                    if (code == null || code.trim().isEmpty()) {
                        skipCount++;
                        monitor.incrementProgress(1);
                        continue;
                    }

                    // Truncate very large functions
                    boolean truncated = false;
                    if (code.length() > MAX_DECOMPILE_CHARS) {
                        code = code.substring(0, MAX_DECOMPILE_CHARS);
                        code += "\n/* ... truncated: function exceeded " +
                            MAX_DECOMPILE_CHARS + " chars ... */";
                        truncated = true;
                    }

                    // -- Called functions (callees) --
                    List<String> calledFunctions = new ArrayList<>();
                    Set<Function> callees = func.getCalledFunctions(monitor);
                    if (callees != null) {
                        for (Function callee : callees) {
                            calledFunctions.add(callee.getName());
                        }
                    }

                    // -- Referenced strings --
                    List<String> referencedStrings =
                        collectReferencedStrings(func, refMgr, listing);

                    // -- XRef count (number of references TO this function) --
                    int xrefCount = 0;
                    ghidra.program.model.symbol.ReferenceIterator refIter =
                        refMgr.getReferencesTo(func.getEntryPoint());
                    if (refIter != null) {
                        while (refIter.hasNext()) {
                            refIter.next();
                            xrefCount++;
                        }
                    }

                    // -- Entry point address --
                    String entryPoint =
                        "0x" + func.getEntryPoint().toString().toLowerCase();

                    // -- Emit JSONL line --
                    String line = buildJsonLine(
                        binaryName,
                        func.getName(),
                        entryPoint,
                        code,
                        calledFunctions,
                        referencedStrings,
                        xrefCount
                    );

                    writer.println(line);
                    writer.flush();      // flush each line so partial output survives crashes
                    successCount++;

                } catch (Exception ex) {
                    printerr("  ERROR " + func.getName() + ": " + ex.getMessage());
                    errorCount++;
                }

                monitor.incrementProgress(1);
            }
        } finally {
            decomp.dispose();
        }

        // ---- Summary -------------------------------------------------------
        println("");
        println("Export complete.");
        println("  Exported : " + successCount);
        println("  Skipped  : " + skipCount);
        println("  Errors   : " + errorCount);
        println("  Output   : " + outFile.getAbsolutePath());

        if (!isRunningHeadless()) {
            popup("Export complete.\n" +
                  successCount + " functions exported to:\n" +
                  outFile.getAbsolutePath());
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Walk all addresses in the function body and collect string values that
     * are referenced by instructions in that body.
     */
    private List<String> collectReferencedStrings(
            Function func, ReferenceManager refMgr, Listing listing) {

        Set<String> seen = new LinkedHashSet<>();
        AddressSetView body = func.getBody();
        AddressIterator addrIter = body.getAddresses(true);

        while (addrIter.hasNext() && seen.size() < MAX_STRINGS) {
            Address addr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            if (refs == null) continue;

            for (Reference ref : refs) {
                if (seen.size() >= MAX_STRINGS) break;
                if (!ref.getReferenceType().isData()) continue;

                Address target = ref.getToAddress();
                Data data = listing.getDataAt(target);
                if (data == null) continue;

                Object val = data.getValue();
                if (!(val instanceof String)) continue;

                String s = (String) val;
                // Skip empty, whitespace-only, or very long strings
                if (s.isBlank() || s.length() > MAX_STRING_LEN) continue;
                // Skip strings that are just whitespace or control chars
                if (s.chars().allMatch(c -> c < 32)) continue;

                seen.add(s);
            }
        }

        return new ArrayList<>(seen);
    }

    /**
     * Build a single JSONL line for one function.
     * Uses manual JSON construction to avoid any external dependency.
     */
    private String buildJsonLine(
            String binaryName,
            String functionName,
            String entryPoint,
            String decompiledCode,
            List<String> calledFunctions,
            List<String> referencedStrings,
            int xrefCount) {

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"binaryName\":")        .append(jsonStr(binaryName))       .append(",");
        sb.append("\"functionName\":")       .append(jsonStr(functionName))     .append(",");
        sb.append("\"entryPoint\":")         .append(jsonStr(entryPoint))       .append(",");
        sb.append("\"decompiledCode\":")     .append(jsonStr(decompiledCode))   .append(",");
        sb.append("\"calledFunctions\":")    .append(jsonStrArray(calledFunctions))  .append(",");
        sb.append("\"referencedStrings\":")  .append(jsonStrArray(referencedStrings)).append(",");
        sb.append("\"xrefCount\":")          .append(xrefCount);
        sb.append("}");
        return sb.toString();
    }

    /** JSON-encode a string value (including surrounding quotes). */
    private String jsonStr(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) {
                        // Escape other control characters (JSON unicode escape)
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    /** JSON-encode a list of strings as a JSON array. */
    private String jsonStrArray(List<String> items) {
        if (items == null || items.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(jsonStr(items.get(i)));
        }
        sb.append("]");
        return sb.toString();
    }
}
