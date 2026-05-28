"""
Storage: persist and load analysis results as local JSON files.

Iteration 1: implement save_results and load_results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from src.analyzer import AnalysisResult


def save_results(results: Sequence[AnalysisResult], path: str | Path) -> None:
    """Serialize analysis results to a JSON file at path."""
    raise NotImplementedError("Iteration 1: storage.save_results not yet implemented.")


def load_results(path: str | Path) -> list[AnalysisResult]:
    """Deserialize analysis results from a JSON file at path."""
    raise NotImplementedError("Iteration 1: storage.load_results not yet implemented.")
