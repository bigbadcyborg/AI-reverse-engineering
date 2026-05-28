"""
Importer: load decompiled function data from JSON or JSONL files.

Accepted input schema per function (all optional fields may be omitted):
{
    "functionName":  str,        # e.g. "FUN_00401a30"
    "entryPoint":    str,        # e.g. "0x00401a30"
    "decompiledCode": str,       # raw decompiled C pseudocode
    "callers":       list[str],  # functions that call this one
    "callees":       list[str],  # functions called by this one
    "strings":       list[str],  # string literals referenced
    "imports":       list[str]   # external imports used
}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator


def load(path: str | Path) -> Iterator[dict]:
    """
    Load function entries from a JSON or JSONL file.

    - .json  — expects either a single object or a list of objects
    - .jsonl — one JSON object per line, blank lines are skipped

    Raises ValueError for unsupported file extensions.
    """
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".jsonl":
        yield from _load_jsonl(path)
    elif suffix == ".json":
        yield from _load_json(path)
    else:
        raise ValueError(
            f"Unsupported file format '{suffix}'. Expected .json or .jsonl."
        )


def _load_json(path: Path) -> Iterator[dict]:
    """Load from a JSON file containing a single object or a list of objects."""
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)

    if isinstance(data, list):
        for entry in data:
            yield _validate(entry, path)
    elif isinstance(data, dict):
        yield _validate(data, path)
    else:
        raise ValueError(
            f"{path}: top-level JSON value must be an object or array of objects, "
            f"got {type(data).__name__}"
        )


def _load_jsonl(path: Path) -> Iterator[dict]:
    """Load from a JSONL file — one JSON object per line."""
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON — {exc}") from exc
            yield _validate(entry, path)


def _validate(entry: dict, path: Path) -> dict:
    """Raise ValueError if required fields are missing."""
    required = ("functionName", "entryPoint", "decompiledCode")
    missing = [k for k in required if k not in entry]
    if missing:
        raise ValueError(
            f"{path}: function entry is missing required field(s): {missing}. "
            f"Got keys: {list(entry.keys())}"
        )
    return entry
