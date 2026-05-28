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
│   └── storage.py          # Persist analysis results locally
├── data/
│   ├── input/              # Drop exported decompiled function files here
│   └── output/             # JSON analysis results are written here
├── prompts/                # LLM prompt templates
│   ├── summarize.txt
│   ├── rename.txt
│   └── behavior.txt
├── reports/                # Generated Markdown reports
├── ghidra_scripts/         # Ghidra export/import helper scripts (future)
│   └── ExportFunctions.java
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

### Check LLM backend connectivity

```bash
python -m src.cli ping
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

| Iteration | Goal |
|-----------|------|
| 0 | Project setup, documentation, repo structure |
| 1 | Core CLI: import → analyze → store → report |
| 2 | Ghidra export script, rename import script |
| 3 | Function clustering, call graph analysis |
| 4 | Local web dashboard, vector search |
| 5 | Multi-model comparison |

---

## License

MIT — see `LICENSE`.
