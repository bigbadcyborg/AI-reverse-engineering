"""
Reporter: generate Markdown reports from stored analysis results.

Iteration 1: implement generate_report using Jinja2 templates.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from src.analyzer import AnalysisResult


def generate_report(results: Sequence[AnalysisResult], out_path: str | Path) -> None:
    """
    Render a Markdown report for the given analysis results and write it to out_path.

    Iteration 1: implement using a Jinja2 template.
    """
    raise NotImplementedError("Iteration 1: reporter.generate_report not yet implemented.")
