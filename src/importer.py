"""
Importer: load decompiled function data from JSON or JSONL files.

Accepts two schemas — both are normalized to the canonical form before analysis.

Canonical schema (used by sample fixtures and earlier iterations):
{
    "functionName":  str,        # e.g. "FUN_00401a30"
    "entryPoint":    str,        # e.g. "0x00401a30"
    "decompiledCode": str,       # raw decompiled C pseudocode
    "callers":       list[str],  # functions that call this one       (optional)
    "callees":       list[str],  # functions called by this one       (optional)
    "strings":       list[str],  # string literals referenced         (optional)
    "imports":       list[str]   # external imports used              (optional)
}

Ghidra export schema (produced by ghidra_scripts/ExportFunctions.java):
{
    "binaryName":        str,        # name of the binary being analyzed
    "functionName":      str,        # same as canonical
    "entryPoint":        str,        # same as canonical
    "decompiledCode":    str,        # same as canonical
    "calledFunctions":   list[str],  # normalized -> "callees"
    "referencedStrings": list[str],  # normalized -> "strings"
    "xrefCount":         int         # passed through, not used by analyzer
}

Both formats are detected automatically. Ghidra-specific field names are
aliased to their canonical equivalents so the prompt template always receives
"callees" and "strings" regardless of which tool produced the input.

Invalid entry points (empty, "0", "0x0") and duplicate entry points are skipped
with a warning rather than aborting the whole file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)

_INVALID_ENTRY_POINTS = frozenset({"", "0", "0x0"})


def is_valid_entry_point(entry_point: str) -> bool:
    """Return False for missing or clearly invalid Ghidra addresses."""
    normalized = (entry_point or "").strip().lower()
    return normalized not in _INVALID_ENTRY_POINTS


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

    seen: set[str] = set()
    if isinstance(data, list):
        for i, entry in enumerate(data, start=1):
            prepared = _prepare_entry(entry, path, seen, line_hint=str(i))
            if prepared is not None:
                yield prepared
    elif isinstance(data, dict):
        prepared = _prepare_entry(data, path, seen)
        if prepared is not None:
            yield prepared
    else:
        raise ValueError(
            f"{path}: top-level JSON value must be an object or array of objects, "
            f"got {type(data).__name__}"
        )


def _load_jsonl(path: Path) -> Iterator[dict]:
    """Load from a JSONL file — one JSON object per line."""
    seen: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON — {exc}") from exc
            prepared = _prepare_entry(entry, path, seen, line_hint=str(lineno))
            if prepared is not None:
                yield prepared


def _normalize(entry: dict) -> dict:
    """
    Normalize Ghidra export field names to the canonical schema.

    This is non-destructive: canonical names are added as aliases when the
    Ghidra names are present. Entries that already use canonical names are
    returned unchanged.
    """
    if "calledFunctions" in entry and "callees" not in entry:
        entry["callees"] = entry["calledFunctions"]

    if "referencedStrings" in entry and "strings" not in entry:
        entry["strings"] = entry["referencedStrings"]

    return entry


def _prepare_entry(
    entry: dict,
    path: Path,
    seen_entry_points: set[str],
    *,
    line_hint: str | None = None,
) -> dict | None:
    """Normalize, validate, and dedupe; return None to skip a row."""
    entry = _normalize(entry)
    loc = f"{path}:{line_hint}" if line_hint else str(path)
    ep = entry.get("entryPoint", "")

    if not is_valid_entry_point(ep):
        log.warning("%s: skipping invalid entryPoint %r", loc, ep)
        return None

    if ep in seen_entry_points:
        log.warning(
            "%s: skipping duplicate entryPoint %r (%s)",
            loc,
            ep,
            entry.get("functionName", "?"),
        )
        return None

    required = ("functionName", "entryPoint", "decompiledCode")
    missing = [k for k in required if k not in entry]
    if missing:
        raise ValueError(
            f"{loc}: function entry is missing required field(s): {missing}. "
            f"Got keys: {list(entry.keys())}"
        )

    seen_entry_points.add(ep)
    return entry
