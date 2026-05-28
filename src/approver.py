"""
Approver: create, load, and manage approved rename files.

The approved rename file is the gating artifact between the AI analysis pipeline
and any modifications to a Ghidra project. Nothing is applied to Ghidra without
an entry in this file that is explicitly marked approved=True.

Workflow:
  1. python -m src.cli suggest-renames --input functions.jsonl \
         --output renames.jsonl
  2. python -m src.cli approve-renames --input renames.jsonl \
         --output approved.json --min-confidence medium
  3. (Analyst reviews and edits approved.json in any text editor)
  4. Run ImportApprovedRenames.java inside Ghidra

Approved file format (JSON array, human-editable):
[
  {
    "entry_point":    "0x1400139a0",
    "old_name":       "FUN_1400139a0",
    "new_name":       "read_file",
    "confidence":     "high",
    "reason":         "Calls ReadFile API; returns byte count.",
    "approved":       true,
    "comment":        "Calls ReadFile API; returns byte count.",
    "allow_overwrite": false
  },
  ...
]

Fields:
  entry_point    — hex address of the function entry point
  old_name       — original decompiler-assigned name (for reference only)
  new_name       — identifier to apply in Ghidra
  confidence     — low | medium | high (from the rename LLM pass)
  reason         — evidence for the name (from the rename LLM pass)
  approved       — MUST be true for the Ghidra script to apply this rename
  comment        — plate comment set on the function in Ghidra (empty = no comment)
  allow_overwrite— if false (default), the Ghidra script will NOT apply the rename
                   if the current function name is already meaningful (non-auto-generated)
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from src.renamer import RenameResult, VALID_CONFIDENCE

# Confidence ordering for threshold filtering
CONFIDENCE_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

# Regex matching Ghidra's auto-generated name patterns — safe to overwrite
_AUTO_GENERATED_RE = re.compile(
    r"^(FUN_|sub_|thunk_FUN_|thunk_|LAB_|DAT_|UNK_|off_|unk_)[0-9a-fA-F]+$",
    re.IGNORECASE,
)


def is_auto_generated_name(name: str) -> bool:
    """Return True if the name looks like a Ghidra auto-generated placeholder."""
    return bool(_AUTO_GENERATED_RE.match(name))


@dataclass
class ApprovedRename:
    """
    A single analyst-approved rename ready for Ghidra import.

    approved=True  → the Ghidra script will apply this rename.
    approved=False → the entry is included for reference only and is skipped.
    """

    entry_point: str
    old_name: str
    new_name: str
    confidence: str
    reason: str
    approved: bool = True
    comment: str = ""
    allow_overwrite: bool = False


# ------------------------------------------------------------------
# Building approved files from rename suggestions
# ------------------------------------------------------------------

def _make_entry(
    suggestion: RenameResult,
    *,
    approved: bool,
    add_comment: bool,
    allow_overwrite: bool,
) -> ApprovedRename:
    comment = suggestion.reason.strip() if add_comment and suggestion.reason else ""
    return ApprovedRename(
        entry_point=suggestion.entry_point,
        old_name=suggestion.old_name,
        new_name=suggestion.new_name,
        confidence=suggestion.confidence,
        reason=suggestion.reason,
        approved=approved,
        comment=comment,
        allow_overwrite=allow_overwrite,
    )


def create_approved_file(
    suggestions: Sequence[RenameResult],
    out_path: str | Path,
    *,
    min_confidence: str = "medium",
    add_comment: bool = True,
    allow_overwrite: bool = False,
) -> tuple[list[ApprovedRename], list[ApprovedRename]]:
    """
    Build an approved renames JSON file from a sequence of RenameResult suggestions.

    Args:
        suggestions:     rename suggestions produced by the LLM rename pass
        out_path:        destination .json file
        min_confidence:  minimum confidence level to auto-approve (low/medium/high)
        add_comment:     if True, copy the reason into the Ghidra comment field
        allow_overwrite: if True, approved entries will overwrite meaningful names
                         in Ghidra (dangerous — use only after careful review)

    Returns:
        (approved_entries, skipped_entries) — both are written to the file;
        approved entries have approved=True, skipped entries have approved=False.
    """
    min_level = CONFIDENCE_ORDER.get(min_confidence, 1)

    approved: list[ApprovedRename] = []
    skipped: list[ApprovedRename] = []

    for s in suggestions:
        level = CONFIDENCE_ORDER.get(s.confidence, 0)
        # Skip suggestions that didn't produce a useful name
        no_useful_name = (
            not s.new_name
            or s.new_name == s.old_name
            or is_auto_generated_name(s.new_name)
        )
        if level >= min_level and not no_useful_name:
            approved.append(_make_entry(
                s,
                approved=True,
                add_comment=add_comment,
                allow_overwrite=allow_overwrite,
            ))
        else:
            skipped.append(_make_entry(
                s,
                approved=False,
                add_comment=False,
                allow_overwrite=False,
            ))

    # Write approved entries first, then skipped (makes it easy to review the file)
    save_approved_renames(approved + skipped, out_path)
    return approved, skipped


# ------------------------------------------------------------------
# Serialization
# ------------------------------------------------------------------

def save_approved_renames(
    entries: Sequence[ApprovedRename], path: str | Path
) -> None:
    """Write approved rename entries to a JSON array file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [dataclasses.asdict(e) for e in entries]
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def load_approved_renames(path: str | Path) -> list[ApprovedRename]:
    """Load approved rename entries from a JSON array file."""
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return [ApprovedRename(**entry) for entry in data]


def count_approved(entries: Sequence[ApprovedRename]) -> int:
    """Return the number of entries with approved=True."""
    return sum(1 for e in entries if e.approved)
