"""
Renamer: extract and display rename suggestions from stored analysis results.

Future iterations will generate Ghidra-compatible rename scripts.

Iteration 1: implement display_suggestions and export_rename_map.
"""

from __future__ import annotations

from typing import Sequence

from src.analyzer import AnalysisResult


def display_suggestions(results: Sequence[AnalysisResult]) -> None:
    """Print a human-readable table of rename suggestions to stdout."""
    raise NotImplementedError("Iteration 1: renamer.display_suggestions not yet implemented.")


def export_rename_map(results: Sequence[AnalysisResult], out_path: str) -> None:
    """
    Write a JSON map of { original_name: suggested_name } to out_path.

    Intended for future use by a Ghidra import script.
    """
    raise NotImplementedError("Iteration 1: renamer.export_rename_map not yet implemented.")
