"""
Importer: load decompiled function data from JSON or JSONL files.

Expected input schema per function:
{
    "name":        str,           # e.g. "FUN_00401a30"
    "address":     str,           # e.g. "0x00401a30"
    "decompiled":  str,           # raw decompiled C pseudocode
    "callers":     list[str],     # optional: functions that call this one
    "callees":     list[str],     # optional: functions called by this one
    "strings":     list[str],     # optional: string literals referenced
    "imports":     list[str]      # optional: external imports used
}
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

# Iteration 1: implement load_json and load_jsonl


def load(path: str | Path) -> Iterator[dict]:
    """
    Load function entries from a JSON or JSONL file.

    Yields one dict per function. Raises ValueError for unsupported formats.
    """
    raise NotImplementedError("Iteration 1: importer.load not yet implemented.")


def load_json(path: Path) -> Iterator[dict]:
    """Load from a JSON file containing a list of function objects."""
    raise NotImplementedError("Iteration 1: importer.load_json not yet implemented.")


def load_jsonl(path: Path) -> Iterator[dict]:
    """Load from a JSONL file (one JSON object per line)."""
    raise NotImplementedError("Iteration 1: importer.load_jsonl not yet implemented.")
