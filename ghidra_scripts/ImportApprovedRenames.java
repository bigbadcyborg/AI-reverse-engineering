// ImportApprovedRenames.java — RE Toolkit: Iteration 6
//
// Purpose:
//   Read an approved-renames JSON file produced by the Python toolkit and apply
//   the analyst-approved function renames and plate comments to the current Ghidra
//   program. An import log is written alongside the approved file.
//
// Safety rules enforced by this script:
//   1. Only entries with "approved": true are processed.
//   2. If the current function name is NOT auto-generated (i.e., it looks like a
//      meaningful human-assigned name rather than FUN_XXXXXXXX), the rename is
//      skipped — unless "allow_overwrite": true is set on that specific entry.
//   3. Functions not found at the given address are logged and skipped.
//   4. All changes are wrapped in a single Ghidra transaction; on error the
//      transaction is rolled back.
//
// Approved file format (JSON array, snake_case keys):
// [
//   {
//     "entry_point":    "0x1400139a0",   <- hex address (with or without 0x)
//     "old_name":       "FUN_1400139a0",
//     "new_name":       "read_file",
//     "confidence":     "high",
//     "reason":         "...",
//     "approved":       true,
//     "comment":        "Plate comment text",  <- empty string = no comment
//     "allow_overwrite": false
//   }
// ]
//
// Import log format (JSONL, written next to the approved file):
// {"timestamp":"...","entry_point":"...","old_name":"...","new_name":"...",
//  "action":"renamed","note":""}
//
// Actions in the log:
//   renamed               — rename (and optional comment) successfully applied
//   commented_only        — name was already correct; comment applied
//   skipped_not_approved  — entry has approved=false
//   skipped_not_found     — no function at the given address
//   skipped_meaningful    — current name appears meaningful; allow_overwrite=false
//   skipped_no_change     — new_name equals the current name; comment still applied
//   error                 — unexpected exception
//
// Usage (GUI mode):
//   Run the script from the Script Manager. You will be prompted for:
//     1. The approved renames JSON file
//     2. (Optional) the import log path — defaults to <approved_file>_import_log.jsonl
//
// Usage (headless mode):
//   analyzeHeadless <project_root> <project_name> \
//       -process <binary_name> \
//       -scriptPath <path_to_ghidra_scripts> \
//       -postScript ImportApprovedRenames.java <approved.json> [import_log.jsonl]
//
//@category RE Toolkit

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;
import java.util.regex.Pattern;

public class ImportApprovedRenames extends GhidraScript {

    // Regex matching Ghidra's auto-generated placeholder names.
    // A name matching this pattern is safe to overwrite without allow_overwrite=true.
    private static final Pattern AUTO_GENERATED = Pattern.compile(
        "^(FUN_|sub_|thunk_FUN_|thunk_|LAB_|DAT_|UNK_|off_|unk_)[0-9a-fA-F]+$",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public void run() throws Exception {
        // ---- Resolve file paths -----------------------------------------------
        File approvedFile;
        File logFile;

        String[] scriptArgs = getScriptArgs();

        if (isRunningHeadless()) {
            if (scriptArgs == null || scriptArgs.length < 1) {
                printerr("Usage: ImportApprovedRenames <approved_renames.json> [import_log.jsonl]");
                return;
            }
            approvedFile = new File(scriptArgs[0]);
            logFile = (scriptArgs.length >= 2)
                ? new File(scriptArgs[1])
                : defaultLogFile(approvedFile);
        } else {
            approvedFile = askFile("Select approved renames JSON file", "Open");
            if (approvedFile == null) {
                printerr("No file selected. Aborting.");
                return;
            }
            // In GUI mode the log goes next to the approved file
            logFile = defaultLogFile(approvedFile);
        }

        if (!approvedFile.exists()) {
            printerr("Approved renames file not found: " + approvedFile.getAbsolutePath());
            return;
        }

        println("Approved renames file : " + approvedFile.getAbsolutePath());
        println("Import log            : " + logFile.getAbsolutePath());

        // ---- Parse the approved renames JSON ------------------------------------
        String content = new String(Files.readAllBytes(approvedFile.toPath()));
        JsonArray entries;
        try {
            entries = JsonParser.parseString(content).getAsJsonArray();
        } catch (Exception e) {
            printerr("Failed to parse approved renames JSON: " + e.getMessage());
            return;
        }

        int total     = entries.size();
        int approved  = 0;
        int renamed   = 0;
        int commented = 0;
        int skipped   = 0;
        int errors    = 0;

        // ---- Open transaction and log file --------------------------------------
        int txId = currentProgram.startTransaction("RE Toolkit: Import Approved Renames");
        boolean txSuccess = false;
        Listing listing = currentProgram.getListing();

        try (BufferedWriter logWriter = new BufferedWriter(new FileWriter(logFile))) {

            for (JsonElement element : entries) {
                JsonObject obj = element.getAsJsonObject();

                boolean isApproved = obj.has("approved") && obj.get("approved").getAsBoolean();
                String entryPoint  = getString(obj, "entry_point");
                String oldName     = getString(obj, "old_name");
                String newName     = getString(obj, "new_name");
                String comment     = getString(obj, "comment");
                boolean allowOver  = obj.has("allow_overwrite") && obj.get("allow_overwrite").getAsBoolean();

                // ---- Skip unapproved entries ------------------------------------
                if (!isApproved) {
                    skipped++;
                    writeLogLine(logWriter, entryPoint, oldName, newName,
                        "skipped_not_approved", "approved=false");
                    continue;
                }

                approved++;

                // ---- Resolve address --------------------------------------------
                Address addr = resolveAddress(entryPoint);
                if (addr == null) {
                    skipped++;
                    errors++;
                    writeLogLine(logWriter, entryPoint, oldName, newName,
                        "skipped_not_found", "could not parse address: " + entryPoint);
                    printerr("Cannot parse address: " + entryPoint);
                    continue;
                }

                // ---- Get function -----------------------------------------------
                Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    skipped++;
                    writeLogLine(logWriter, entryPoint, oldName, newName,
                        "skipped_not_found", "no function at " + addr);
                    println("No function at " + addr + " — skipping.");
                    continue;
                }

                String currentName = func.getName();

                // ---- Apply plate comment if provided ----------------------------
                boolean commentApplied = false;
                if (comment != null && !comment.isEmpty()) {
                    try {
                        listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment);
                        commentApplied = true;
                    } catch (Exception e) {
                        printerr("Failed to set comment at " + addr + ": " + e.getMessage());
                    }
                }

                // ---- Check if rename is needed ----------------------------------
                if (currentName.equals(newName)) {
                    // Name is already what we want
                    String note = commentApplied ? "comment applied" : "no changes needed";
                    writeLogLine(logWriter, entryPoint, oldName, newName,
                        "skipped_no_change", note);
                    if (commentApplied) commented++;
                    else skipped++;
                    continue;
                }

                // ---- Guard: do not overwrite meaningful names -------------------
                boolean currentIsAuto = AUTO_GENERATED.matcher(currentName).matches();
                if (!currentIsAuto && !allowOver) {
                    String note = "current name '" + currentName + "' appears meaningful; "
                        + "set allow_overwrite=true to override";
                    writeLogLine(logWriter, entryPoint, oldName, newName,
                        "skipped_meaningful", note);
                    println("Skipping " + addr + ": current name '" + currentName
                        + "' looks meaningful (allow_overwrite=false).");
                    skipped++;
                    continue;
                }

                // ---- Apply rename ------------------------------------------------
                try {
                    func.setName(newName, SourceType.USER_DEFINED);
                    renamed++;
                    String note = commentApplied ? "comment applied" : "";
                    String action = commentApplied ? "renamed" : "renamed";
                    writeLogLine(logWriter, entryPoint, currentName, newName, action, note);
                    println("Renamed: " + currentName + " -> " + newName + " @ " + addr);
                } catch (Exception e) {
                    errors++;
                    writeLogLine(logWriter, entryPoint, oldName, newName,
                        "error", e.getMessage());
                    printerr("Error renaming " + oldName + " @ " + addr + ": " + e.getMessage());
                }
            }

            txSuccess = true;

        } catch (IOException e) {
            printerr("Failed to write import log: " + e.getMessage());
            txSuccess = false;
        } finally {
            currentProgram.endTransaction(txId, txSuccess);
        }

        // ---- Summary ------------------------------------------------------------
        println("");
        println("=== Import Complete ===");
        println("Total entries   : " + total);
        println("Approved        : " + approved);
        println("Renamed         : " + renamed);
        println("Comment-only    : " + commented);
        println("Skipped         : " + skipped);
        println("Errors          : " + errors);
        println("Log             : " + logFile.getAbsolutePath());

        if (!txSuccess) {
            printerr("Transaction was rolled back due to an error.");
        }
    }

    // ---- Helpers ----------------------------------------------------------------

    private File defaultLogFile(File approvedFile) {
        String name = approvedFile.getName();
        int dot = name.lastIndexOf('.');
        String base = (dot > 0) ? name.substring(0, dot) : name;
        return new File(approvedFile.getParentFile(), base + "_import_log.jsonl");
    }

    /** Return a JSON string value or empty string if absent. */
    private String getString(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return "";
    }

    /**
     * Parse a hex address string such as "0x1400139a0" or "1400139a0".
     * Returns null if the string cannot be resolved.
     */
    private Address resolveAddress(String addrStr) {
        if (addrStr == null || addrStr.isEmpty()) return null;
        // Strip leading "0x" / "0X" prefix that Ghidra's address factory does not expect
        String hex = addrStr.startsWith("0x") || addrStr.startsWith("0X")
            ? addrStr.substring(2)
            : addrStr;
        try {
            return currentProgram.getAddressFactory().getAddress(hex);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Append a single JSONL log record.
     *
     * Fields:
     *   timestamp, entry_point, old_name, new_name, action, note
     */
    private void writeLogLine(
            BufferedWriter writer,
            String entryPoint,
            String oldName,
            String newName,
            String action,
            String note) throws IOException {

        String timestamp = Instant.now().toString();
        writer.write(buildLogJson(timestamp, entryPoint, oldName, newName, action, note));
        writer.newLine();
        writer.flush();
    }

    /** Build a JSON log record without external library for maximum portability. */
    private String buildLogJson(
            String timestamp,
            String entryPoint,
            String oldName,
            String newName,
            String action,
            String note) {

        return "{"
            + "\"timestamp\":" + jsonString(timestamp) + ","
            + "\"entry_point\":" + jsonString(entryPoint) + ","
            + "\"old_name\":" + jsonString(oldName) + ","
            + "\"new_name\":" + jsonString(newName) + ","
            + "\"action\":" + jsonString(action) + ","
            + "\"note\":" + jsonString(note)
            + "}";
    }

    /** Escape a string for inclusion in a JSON value. */
    private String jsonString(String value) {
        if (value == null) return "\"\"";
        return "\"" + value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
            + "\"";
    }
}
