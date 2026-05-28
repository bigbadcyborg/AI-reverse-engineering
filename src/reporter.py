"""
Reporter: generate Markdown reports from stored analysis results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from jinja2 import Environment, FileSystemLoader

from src.analyzer import AnalysisResult

PROMPT_DIR = Path(__file__).parent.parent / "prompts"


def generate_report(results: Sequence[AnalysisResult], out_path: str | Path) -> None:
    """
    Render a Markdown report for the given analysis results and write it to out_path.

    Uses prompts/report.md.j2 as the Jinja2 template.
    Creates parent directories as needed.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(PROMPT_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    template = env.get_template("report.md.j2")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rendered = template.render(results=results, timestamp=timestamp)

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(rendered)
