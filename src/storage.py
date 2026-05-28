"""
Storage: persist and load analysis results as JSON or JSONL files.

JSON  (.json)  — full array, loaded all at once. Good for small runs and
                 compatibility with report/rename commands.
JSONL (.jsonl) — one result per line, written incrementally during batch
                 runs so partial output is saved even if the run is
                 interrupted. Preferred for 100+ function batches.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Iterator, Sequence

from src.analyzer import AnalysisResult


# ------------------------------------------------------------------
# JSON (array) format — backward-compatible
# ------------------------------------------------------------------

def save_results(results: Sequence[AnalysisResult], path: str | Path) -> None:
    """Serialize all results to a JSON array file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [dataclasses.asdict(r) for r in results]
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------
# JSONL (streaming) format — preferred for batch runs
# ------------------------------------------------------------------

def init_jsonl(path: str | Path) -> None:
    """
    Create (or truncate) the JSONL output file and ensure its parent
    directory exists. Call once before starting a batch run.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def append_result_jsonl(result: AnalysisResult, path: str | Path) -> None:
    """Append a single result as one JSON line. Thread-safe for sequential use."""
    path = Path(path)
    line = json.dumps(dataclasses.asdict(result), ensure_ascii=False)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def load_results_jsonl(path: str | Path) -> list[AnalysisResult]:
    """Load all results from a JSONL file."""
    path = Path(path)
    results = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}:{lineno}: invalid JSON line — {exc}"
                ) from exc
            results.append(AnalysisResult(**entry))
    return results


# ------------------------------------------------------------------
# Auto-detecting loader — used by report/rename commands
# ------------------------------------------------------------------

def load_results(path: str | Path) -> list[AnalysisResult]:
    """
    Load analysis results from either a .json or .jsonl file.
    Dispatches automatically based on file extension.
    """
    path = Path(path)
    if path.suffix.lower() == ".jsonl":
        return load_results_jsonl(path)
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return [AnalysisResult(**entry) for entry in data]


# ------------------------------------------------------------------
# Error log (JSONL)
# ------------------------------------------------------------------

def append_error_jsonl(
    path: str | Path,
    function: dict,
    error: Exception,
    timestamp: str,
) -> None:
    """
    Append a structured error record to the error log JSONL file.

    Each line contains: timestamp, function_name, entry_point, error_type, error_message.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": timestamp,
        "function_name": function.get("functionName", ""),
        "entry_point": function.get("entryPoint", ""),
        "error_type": type(error).__name__,
        "error_message": str(error),
    }
    line = json.dumps(record, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
