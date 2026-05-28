# Local LLM Reverse Engineering Toolkit

A local-first AI assistant for reverse engineering. It analyzes decompiled code using a locally running LLM — no data leaves your machine.

---

## Purpose

This tool sits between a decompiler (e.g. Ghidra, Binary Ninja, IDA) and the analyst. It takes exported decompiled function data, sends it to a local LLM, and returns structured summaries, rename suggestions, and behavioral hypotheses.

Intended users:

- Cybersecurity students and CTF participants
- Reverse engineers and malware analysts working in isolated labs
- Defensive security researchers
- Developers analyzing their own compiled binaries

---

## Important Limitations and Safe Use

> **This tool is designed to assist lawful reverse engineering only.**

- **Do not use this tool to analyze software you do not have the legal right to reverse engineer.**
- All analysis is produced by a language model and **may be incorrect**. Treat every output as a hypothesis to be validated, not a ground truth.
- The tool does **not** automatically rename symbols or modify any project files. All suggestions require explicit analyst approval.
- Running analysis locally means no external API calls are made and no decompiled code is sent to third-party services. It is your responsibility to ensure your LLM backend is also running locally and not proxying requests externally.
- Malware analysis should be performed inside an **isolated, offline lab environment**. This tool does not provide sandboxing.

---

## Architecture Overview

```
Decompiler (Ghidra / BN / IDA)
    ↓  export script
JSON / JSONL function data
    ↓  import
Local LLM Analyzer  ←── local LLM (Ollama / llama.cpp / LM Studio)
    ↓
Structured JSON analysis
    ↓
Markdown reports  |  Rename suggestions  |  Searchable knowledge base
```

---

## Project Structure

```
AI-reverse-engineering-platform/
├── src/                    # Core Python package
│   ├── __init__.py
│   ├── cli.py              # Entry point (argparse CLI)
│   ├── importer.py         # Load JSON/JSONL decompiled function data
│   ├── analyzer.py         # Send functions to local LLM, parse responses
│   ├── reporter.py         # Generate Markdown reports
│   ├── renamer.py          # Generate and display rename suggestions
│   ├── approver.py         # Build approved-renames files for Ghidra import
│   ├── db.py               # SQLite search database (FTS5 full-text search)
│   └── storage.py          # Persist analysis results locally
├── data/
│   ├── input/              # Drop exported decompiled function files here
│   └── output/             # JSON analysis results are written here
├── prompts/                # LLM prompt templates
│   ├── summarize.txt
│   ├── rename.txt
│   └── behavior.txt
├── reports/                # Generated Markdown reports
├── ghidra_scripts/         # Ghidra helper scripts
│   ├── ExportFunctions.java        # Export decompiled functions to JSONL
│   ├── ImportApprovedRenames.java  # Apply approved renames/comments to Ghidra
│   └── run_headless_export.bat     # Wrapper for headless export on Windows
├── config.json             # Runtime configuration (model, endpoint, limits)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Installation

Requires **Python 3.10+** and a running local LLM backend (e.g. [Ollama](https://ollama.com)).

```bash
git clone <repo-url>
cd AI-reverse-engineering-platform
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Configuration

Edit `config.json` before running:

```json
{
  "llm": {
    "backend": "ollama",
    "base_url": "http://localhost:11434",
    "model": "codellama:13b-instruct"
  },
  "analysis": {
    "max_functions_per_run": 50,
    "context_window_chars": 8000
  },
  "output": {
    "report_dir": "reports/",
    "data_dir": "data/output/"
  }
}
```

Supported backends: `ollama`, `llamacpp` (OpenAI-compatible endpoint).

---

## Commands

> All commands are run from the project root with the virtual environment activated.

### Analyze a set of exported functions

```bash
python -m src.cli analyze --input data/input/functions.jsonl --output data/output/results.json
```

### Generate a Markdown report from stored analysis

```bash
python -m src.cli report --input data/output/results.json --out reports/analysis.md
```

### Show rename suggestions

```bash
python -m src.cli rename --input data/output/results.json
```

### Generate focused rename suggestions (with reasoning)

```bash
# Run the dedicated rename LLM prompt on raw functions
python -m src.cli suggest-renames --input data/input/functions.jsonl \
    --output data/output/renames.jsonl

# Or derive suggestions from existing analysis results (no LLM call)
python -m src.cli suggest-renames --from-analysis data/output/results.jsonl \
    --output data/output/renames.jsonl
```

### Create an approved renames file for Ghidra import

```bash
python -m src.cli approve-renames \
    --input  data/output/renames.jsonl \
    --output data/output/approved_renames.json \
    --min-confidence medium
```

The output is a **human-editable JSON file**. Review it, then flip any
`"approved": false` entries to `true` (or vice-versa) before loading it into
Ghidra. You can also set a custom `"comment"` on each entry — it will be
written as a plate comment on that function's entry point.

### Import approved renames into Ghidra

1. Open your binary in Ghidra.
2. Open the **Script Manager** (`Window → Script Manager`).
3. Add the `ghidra_scripts/` directory to the script paths.
4. Run **`ImportApprovedRenames`**.
5. Select your `approved_renames.json` file when prompted.

An `approved_renames_import_log.jsonl` is written alongside the approved file
with a per-function record of what was renamed, skipped, or errored.

**Headless execution:**

```bat
analyzeHeadless <project_root> <project_name> ^
    -process <binary_name> ^
    -scriptPath ghidra_scripts ^
    -postScript ImportApprovedRenames.java ^
        data\output\approved_renames.json ^
        data\output\import_log.jsonl
```

### Load analysis results into the search database

```bash
python -m src.cli ingest --input data/output/results.jsonl
```

Re-ingesting the same file upserts (updates) existing rows — safe to run after each analysis pass.

### Search analyzed functions

```bash
# Full-text search (BM25 ranked)
python -m src.cli search --query "file parsing"
python -m src.cli search --query "command dispatcher"

# Filter by category
python -m src.cli search --category crypto
python -m src.cli search --category network
python -m src.cli search --category file_io

# Filter by confidence
python -m src.cli search --confidence low

# Combine filters
python -m src.cli search --query "socket" --category network --limit 10

# Database overview
python -m src.cli search --stats
```

Category values produced by the LLM: `file_io`, `network`, `crypto`, `process`,
`registry`, `memory`, `string_ops`, `math`, `error_handling`.

### Check LLM backend connectivity

```bash
python -m src.cli ping
```

---

## Full Workflow (Ghidra → Toolkit → Ghidra)

```
1. Export functions from Ghidra
   → ExportFunctions.java  →  data/input/functions.jsonl

2. Analyze with local LLM
   → python -m src.cli analyze  →  data/output/results.jsonl

3. Generate report
   → python -m src.cli report   →  reports/analysis.md

4. Generate rename suggestions
   → python -m src.cli suggest-renames  →  data/output/renames.jsonl

5. Create approved renames file (review + edit)
   → python -m src.cli approve-renames  →  data/output/approved_renames.json

6. Import approved renames into Ghidra
   → ImportApprovedRenames.java  →  (functions renamed in Ghidra)
                                 →  approved_renames_import_log.jsonl
```

---

## Input Format

The tool accepts JSON or JSONL files. Each function entry should follow this schema:

```json
{
  "name": "FUN_00401a30",
  "address": "0x00401a30",
  "decompiled": "void FUN_00401a30(char *param_1) {\n  ...\n}",
  "callers": ["FUN_00401000"],
  "callees": ["strcmp", "malloc"],
  "strings": ["error: bad input"],
  "imports": []
}
```

Fields `callers`, `callees`, `strings`, and `imports` are optional but improve analysis quality.

---

## Output Format

Each analyzed function produces a JSON object:

```json
{
  "name": "FUN_00401a30",
  "address": "0x00401a30",
  "summary": "Validates a user-supplied string against a known pattern...",
  "suggested_name": "validate_input_string",
  "suggested_params": ["input_str"],
  "behavior_tags": ["input-validation", "string-comparison"],
  "confidence": "medium",
  "notes": "Uses strcmp; may be vulnerable to timing attacks."
}
```

---

## Roadmap

| Iteration | Goal | Status |
|-----------|------|--------|
| 0 | Project setup, documentation, repo structure | Done |
| 1 | Core CLI: import → analyze → store | Done |
| 2 | Batch analysis with JSONL streaming and error logging | Done |
| 3 | Markdown report generation | Done |
| 4 | Ghidra export script (ExportFunctions.java) | Done |
| 5 | Rename suggestions with confidence + reasoning | Done |
| 6 | Approved Ghidra import (ImportApprovedRenames.java) | Done |
| 7 | SQLite search: category/confidence filters + FTS5 keyword search | Done |
| 8 | Local embeddings and semantic search | Future |
| 9 | Function clustering, call graph analysis | Future |
| 10 | Local web dashboard | Future |
| 11 | Multi-model comparison | Future |

---

## License

MIT — see `LICENSE`.
