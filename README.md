# Local LLM Reverse Engineering Toolkit

A local-first AI assistant for reverse engineering. It analyzes decompiled code using a locally running LLM — no data leaves your machine.

---

## Quick Start

Install dependencies and verify your local LLM:

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
python -m src.cli ping
```

### Fastest path (Dashboard-first)

```bash
python -m src.cli dashboard
```

Then open `http://localhost:5000` and drag/drop your Ghidra-exported `.jsonl` file.
The dashboard will run LLM analysis and ingest results automatically.

### CLI path

```bash
# 1) Analyze
python -m src.cli analyze --input data/input/functions.jsonl --output data/output/results.jsonl

# 2) Ingest for search/dashboard (include decompiled code viewer)
python -m src.cli ingest --input data/output/results.jsonl --source-functions data/input/functions.jsonl

# 3) Dashboard / report / search
python -m src.cli dashboard
python -m src.cli report --input data/output/results.jsonl --out reports/analysis.md
python -m src.cli search --query "crypto"
```

---

## From C Source to JSONL (Ghidra)

The repo includes [`test_target.c`](test_target.c), a small multi-function sample binary (file I/O, crypto-like XOR, network, process spawn) for exercising the full pipeline. Use it only on systems and binaries you are allowed to analyze.

### 1. Compile the test program

Use **`-O0 -g`** so Ghidra’s decompiler keeps distinct, readable functions (optimization can inline or merge them).

**Windows (MinGW-w64 / MSYS2)**

```bash
gcc -o re_test_target.exe test_target.c -lws2_32 -O0 -g
```

**Linux**

```bash
gcc -o re_test_target test_target.c -O0 -g
```

**macOS**

```bash
gcc -o re_test_target test_target.c -O0 -g
```

Optional: create a minimal config file next to the binary so `read_config` has something to open:

```ini
server=127.0.0.1
token=0123456789abcdef
```

Save as `app.cfg` in the same directory you run the program from.

### 2. Import the binary into Ghidra

1. Install [Ghidra](https://ghidra-sre.org/) (10.x or 11.x).
2. **File → New Project** → Non-Shared Project → choose a folder and name.
3. **File → Import File** → select `re_test_target.exe` (or your built binary).
4. Accept the default format/language when prompted, then **Analyze** with default options and wait for analysis to finish.

### 3. Export functions to JSONL (GUI)

1. Copy or symlink this repo’s `ghidra_scripts/` folder into Ghidra’s script path, **or** add it once:
   - **Edit → Tool Options → Script Directories** → add the path to `ghidra_scripts/`.
2. Open **Window → Script Manager**.
3. Filter for **ExportFunctions** (menu path: **Tools → RE Toolkit → Export Functions to JSONL**).
4. Run the script.
5. When prompted, save as e.g. `data/input/re_test_target.jsonl`.

Each line in the file is one JSON object with fields such as `functionName`, `entryPoint`, `decompiledCode`, `calledFunctions`, and `referencedStrings` (the Python importer normalizes the last two to `callees` / `strings`).

### 4. Export functions to JSONL (headless, Windows)

Set `GHIDRA_HOME` to your Ghidra install folder (the directory that contains `support\analyzeHeadless.bat`), then run the wrapper from the repo root.

**PowerShell** (use `$env:`, not `set` — `set` only works in Command Prompt):

```powershell
$env:GHIDRA_HOME = "C:\Users\sully\Documents\ghidra_12.1_PUBLIC"
.\ghidra_scripts\run_headless_export.ps1 re_test_target.exe data\input\re_test_target.jsonl
```

Or pass the Ghidra path on one line:

```powershell
.\ghidra_scripts\run_headless_export.ps1 re_test_target.exe data\input\re_test_target.jsonl `
    -GhidraHome "C:\Users\sully\Documents\ghidra_12.1_PUBLIC"
```

**Command Prompt (cmd):**

```bat
set GHIDRA_HOME=C:\Users\sully\Documents\ghidra_12.1_PUBLIC
ghidra_scripts\run_headless_export.bat re_test_target.exe data\input\re_test_target.jsonl
```

This imports the binary, runs analysis, executes `ExportFunctions.java`, and writes the JSONL path you pass as the second argument.

**Headless without the batch file** (any OS):

```bash
$GHIDRA_HOME/support/analyzeHeadless \
  /path/to/ghidra_project_dir HeadlessExport \
  -import /path/to/re_test_target \
  -postScript ExportFunctions.java /path/to/output.jsonl \
  -scriptPath /path/to/ghidra_scripts \
  -deleteProject
```

On Windows, use `analyzeHeadless.bat` under `%GHIDRA_HOME%\support\`.

### 5. Feed the JSONL into the toolkit

**Dashboard:** start `python -m src.cli dashboard` and drag `re_test_target.jsonl` onto the page.

**CLI:**

```bash
python -m src.cli analyze \
  --input  data/input/re_test_target.jsonl \
  --output data/output/re_test_results.jsonl

python -m src.cli ingest \
  --input data/output/re_test_results.jsonl \
  --source-functions data/input/re_test_target.jsonl
```

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
│   ├── dashboard.py        # Local Flask web dashboard
│   └── storage.py          # Persist analysis results locally
├── web/
│   ├── templates/          # Jinja2 HTML templates (base, index, function detail)
│   └── static/             # CSS — dark theme, category badges, layout
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
│   ├── run_headless_export.bat     # Headless export wrapper (cmd)
│   └── run_headless_export.ps1     # Headless export wrapper (PowerShell)
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
    "model": "llama3.2:1b",
    "timeout_seconds": 120,
    "temperature": 0.2
  },
  "analysis": {
    "max_functions_per_run": 0,
    "context_window_chars": 8000,
    "batch_size": 5
  },
  "output": {
    "report_dir": "reports/",
    "data_dir": "data/output/",
    "db_path": "data/output/analysis.db"
  },
  "logging": {
    "level": "INFO",
    "log_file": "data/output/run.log"
  }
}
```

Supported backends: `ollama`, `llamacpp` (OpenAI-compatible endpoint).

---

## Commands

> All commands are run from the project root with the virtual environment activated.

### Analyze a set of exported functions

```bash
python -m src.cli analyze --input data/input/functions.jsonl --output data/output/results.jsonl
```

### Generate a Markdown report from stored analysis

```bash
python -m src.cli report --input data/output/results.jsonl --out reports/analysis.md
```

### Show rename suggestions

```bash
python -m src.cli rename --input data/output/results.jsonl
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

### Start the local web dashboard

```bash
python -m src.cli dashboard
```

Opens `http://localhost:5000` automatically. Features:
- **Function list** with live search (no page reload via HTMX)
- **Category and confidence filters** in sidebar
- **Decompiled code viewer** with C syntax highlighting
- **LLM summary** with side effects and uncertainties
- **Rename approval buttons** — writes directly to `approved_renames.json`
- **Approved Renames** page showing pending Ghidra import queue
- **Export Report** button — generates and downloads a Markdown report
- **Drag-and-drop JSONL import** — uploads raw function exports, runs LLM analysis in the background, and ingests into SQLite with progress tracking
- **Live LLM progress** — during import, the progress card shows the current function name, phase (building prompt, waiting on Ollama, parsing response), model badge, elapsed time, and an estimated time remaining. Runtime scales with function count and model speed (local models often take several seconds per function).

Options:
```bash
python -m src.cli dashboard --port 8080 --no-browser
```

### Load analysis results into the search database

```bash
python -m src.cli ingest \
    --input data/output/results.jsonl \
    --source-functions data/input/functions.jsonl
```

Re-ingesting the same file upserts (updates) existing rows — safe to run after each analysis pass.
If `--source-functions` is provided, decompiled code is stored and shown in the dashboard code viewer.

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

### Dashboard-first workflow (optional)

```
1. Start dashboard
   → python -m src.cli dashboard

2. Drag and drop Ghidra JSONL on the page
   → /api/upload (background LLM analysis + ingest)
   → data/output/analysis.db updated
   → Function list auto-refreshes

3. Review functions and approve/reject renames in UI
   → data/output/approved_renames.json

4. Export report from dashboard
   → reports/dashboard_export_<timestamp>.md
```

---

## Input Format

The tool accepts JSON or JSONL files. Canonical function input uses this schema:

```json
{
  "functionName": "FUN_00101230",
  "entryPoint": "0x00101230",
  "decompiledCode": "int FUN_00101230(char *path) { ... }",
  "callees": ["strcmp", "malloc"],
  "strings": ["error: bad input"],
  "xrefCount": 3
}
```

Ghidra export compatibility:
- `calledFunctions` is normalized to `callees`
- `referencedStrings` is normalized to `strings`

Required fields: `functionName`, `entryPoint`, `decompiledCode`.

---

## Output Format

Each analyzed function produces a JSON object (JSONL line):

```json
{
  "function_name": "FUN_00101230",
  "entry_point": "0x00101230",
  "summary": "Attempts to open a file and returns whether it succeeded.",
  "suggested_name": "check_file_exists",
  "category": "file_io",
  "confidence": "medium",
  "side_effects": ["reads filesystem metadata"],
  "uncertainties": [],
  "raw_response": "{...}"
}
```

Dedicated rename suggestions (`suggest-renames`) are written separately as JSONL with:
`entry_point`, `old_name`, `new_name`, `confidence`, `reason`.

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
| 8 | Local web dashboard with code viewer and rename approval | Done |
| 9 | Local embeddings and semantic search | Future |
| 10 | Function clustering, call graph analysis | Future |
| 11 | Multi-model comparison | Future |

---

## License

MIT — see `LICENSE`.
