"""
Renamer: display rename suggestions and export rename maps from analysis results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.table import Table

from src.analyzer import AnalysisResult

console = Console(highlight=False, legacy_windows=False)


def display_suggestions(results: Sequence[AnalysisResult]) -> None:
    """Print a rich table of rename suggestions to stdout."""
    table = Table(
        title="Rename Suggestions",
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Entry Point", style="dim", no_wrap=True)
    table.add_column("Original Name", style="yellow")
    table.add_column("Suggested Name", style="green bold")
    table.add_column("Category", style="magenta")
    table.add_column("Confidence", justify="center")

    confidence_color = {"high": "green", "medium": "yellow", "low": "red"}

    for r in results:
        color = confidence_color.get(r.confidence, "white")
        table.add_row(
            r.entry_point,
            r.function_name,
            r.suggested_name or "—",
            r.category,
            f"[{color}]{r.confidence}[/{color}]",
        )

    console.print(table)


def export_rename_map(results: Sequence[AnalysisResult], out_path: str | Path) -> None:
    """
    Write a JSON map of { original_name: suggested_name } to out_path.

    Intended for future use by a Ghidra import script.
    Only includes entries where a suggested name differs from the original.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rename_map = {
        r.function_name: r.suggested_name
        for r in results
        if r.suggested_name and r.suggested_name != r.function_name
    }

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(rename_map, fh, indent=2, ensure_ascii=False)
