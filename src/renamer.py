"""
Renamer: generate, validate, display, and export rename suggestions.

Two usage modes:

1. From analysis results (AnalysisResult JSONL) — fast, no LLM call needed.
   The suggested_name and confidence come from the existing summarize pass.
   The reason is derived from the function summary.

2. From raw functions (JSON/JSONL) via the dedicated rename prompt — runs a
   focused LLM pass that produces a name, confidence, and a one-sentence reason
   grounded in specific code evidence.

The RenameResult type is the canonical suggestion artifact. It is never applied
to any project automatically — it is strictly read-only output for analyst review.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.table import Table

from src.analyzer import AnalysisResult

console = Console(highlight=False, legacy_windows=False)

# Valid C/Python identifier: starts with letter or underscore, rest alphanumeric/_
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Patterns considered "no suggestion" (model returned the original name unchanged
# or a generic placeholder that adds no information)
_GENERIC_NAMES = re.compile(
    r"^(unknown|func|function|sub|FUN_|DAT_|LAB_|UNK_|thunk_)", re.IGNORECASE
)

VALID_CONFIDENCE = {"low", "medium", "high"}


@dataclass
class RenameResult:
    """
    A single reviewed rename suggestion.

    Fields match the Iteration 5 output schema:
        entryPoint  — hex address of the function
        oldName     — original decompiler-assigned name
        newName     — suggested human-readable identifier
        confidence  — low | medium | high
        reason      — one sentence citing evidence for the name choice
    """

    entry_point: str
    old_name: str
    new_name: str
    confidence: str
    reason: str


# ------------------------------------------------------------------
# Identifier helpers
# ------------------------------------------------------------------

def is_valid_identifier(name: str) -> bool:
    """Return True if name is a valid C/Python identifier with no spaces."""
    return bool(name) and bool(_IDENTIFIER_RE.match(name))


def sanitize_identifier(name: str) -> str:
    """
    Convert a potentially invalid LLM-suggested name to a valid identifier.

    Transformations applied in order:
      1. Strip leading/trailing whitespace
      2. Replace runs of spaces, hyphens, and dots with underscores
      3. Remove any remaining characters not in [A-Za-z0-9_]
      4. Prepend underscore if the result starts with a digit
      5. Fall back to "unknown_function" if nothing remains
    """
    name = name.strip()
    name = re.sub(r"[\s\-\.]+", "_", name)
    name = re.sub(r"[^A-Za-z0-9_]", "", name)
    if name and name[0].isdigit():
        name = "_" + name
    return name or "unknown_function"


def is_informative(name: str) -> bool:
    """Return False if the suggested name is a generic placeholder."""
    return not bool(_GENERIC_NAMES.match(name))


# ------------------------------------------------------------------
# Build RenameResult from an AnalysisResult (no LLM call)
# ------------------------------------------------------------------

def from_analysis_result(result: AnalysisResult) -> RenameResult | None:
    """
    Derive a RenameResult from an existing AnalysisResult.

    Returns None if the analysis produced no useful name suggestion
    (i.e. the suggested name is identical to the original or is generic).
    """
    name = result.suggested_name.strip()
    if not name or name.lower() == result.function_name.lower():
        return None

    # Validate / sanitize
    original_name = name
    if not is_valid_identifier(name):
        name = sanitize_identifier(name)

    confidence = result.confidence if result.confidence in VALID_CONFIDENCE else "low"

    # Build reason from the summary; fall back to category if no summary
    if result.summary:
        reason = result.summary.split(".")[0].strip() + "."
    else:
        reason = f"Categorized as {result.category}."

    if original_name != name:
        reason = f"[name sanitized from '{original_name}'] {reason}"

    return RenameResult(
        entry_point=result.entry_point,
        old_name=result.function_name,
        new_name=name,
        confidence=confidence,
        reason=reason,
    )


def from_analysis_results(results: Sequence[AnalysisResult]) -> list[RenameResult]:
    """Convert a sequence of AnalysisResults to RenameResults, skipping None."""
    out = []
    for r in results:
        suggestion = from_analysis_result(r)
        if suggestion is not None:
            out.append(suggestion)
    return out


# ------------------------------------------------------------------
# Display
# ------------------------------------------------------------------

def display_rename_results(suggestions: Sequence[RenameResult]) -> None:
    """Print a rich table of RenameResult suggestions."""
    confidence_color = {"high": "green", "medium": "yellow", "low": "red"}

    table = Table(
        title="Rename Suggestions",
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Entry Point", style="dim", no_wrap=True)
    table.add_column("Old Name", style="yellow")
    table.add_column("New Name", style="green bold")
    table.add_column("Confidence", justify="center", no_wrap=True)
    table.add_column("Reason")

    for s in suggestions:
        color = confidence_color.get(s.confidence, "white")
        conf_cell = f"[{color}]{s.confidence}[/{color}]"
        # Highlight low-confidence rows more visibly
        name_style = "green bold" if s.confidence != "low" else "yellow"
        table.add_row(
            s.entry_point,
            s.old_name,
            f"[{name_style}]{s.new_name}[/{name_style}]",
            conf_cell,
            s.reason,
        )

    console.print(table)
    low = sum(1 for s in suggestions if s.confidence == "low")
    if low:
        console.print(
            f"\n[yellow]Note:[/yellow] {low} suggestion(s) marked [red]low[/red] confidence "
            "— do not apply without manual review."
        )


def display_suggestions(results: Sequence[AnalysisResult]) -> None:
    """Display rename suggestions derived from AnalysisResult objects (legacy path)."""
    suggestions = from_analysis_results(results)
    if not suggestions:
        console.print("[yellow]No rename suggestions generated.[/yellow]")
        return
    display_rename_results(suggestions)


# ------------------------------------------------------------------
# Export
# ------------------------------------------------------------------

def export_rename_map(
    suggestions: Sequence[RenameResult] | Sequence[AnalysisResult],
    out_path: str | Path,
) -> None:
    """
    Write a JSON map of { old_name: new_name } to out_path.

    Accepts either RenameResult or AnalysisResult sequences.
    Only entries where the suggested name differs from the original are included.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rename_map: dict[str, str] = {}
    for item in suggestions:
        if isinstance(item, RenameResult):
            if item.new_name and item.new_name != item.old_name:
                rename_map[item.old_name] = item.new_name
        else:
            # AnalysisResult
            if item.suggested_name and item.suggested_name != item.function_name:
                rename_map[item.function_name] = item.suggested_name

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(rename_map, fh, indent=2, ensure_ascii=False)
