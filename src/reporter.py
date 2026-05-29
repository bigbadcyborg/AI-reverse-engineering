"""
Reporter: generate structured Markdown reports from analysis results.

The report is organized into eight sections:
  1. Overview          — stats table, category breakdown, confidence distribution
  2. High-Priority     — crypto, network, registry, and selected process functions
  3. File I/O          — file_io category
  4. Network           — network category
  5. Crypto            — crypto category
  6. Rename Suggestions— validated rename suggestions only
  7. Low-Confidence    — results where confidence == "low"
  8. Manual Review Queue — results with non-empty uncertainties (post-filtered)
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from jinja2 import Environment, FileSystemLoader

from src.analyzer import AnalysisResult
from src.postprocess import is_high_priority
from src.renamer import is_informative, is_valid_identifier

PROMPT_DIR = Path(__file__).parent.parent / "prompts"


def _is_actionable_rename(result: AnalysisResult) -> bool:
    name = (result.suggested_name or "").strip()
    if not name:
        return False
    if name.lower() == (result.function_name or "").lower():
        return False
    if not is_valid_identifier(name):
        return False
    return is_informative(name)


def _build_context(
    results: Sequence[AnalysisResult],
    source: str | None,
) -> dict:
    results = list(results)

    high_priority = [r for r in results if is_high_priority(r)]
    file_io = [r for r in results if r.category == "file_io"]
    network = [r for r in results if r.category == "network"]
    crypto = [r for r in results if r.category == "crypto"]

    rename_suggestions = [r for r in results if _is_actionable_rename(r)]

    low_confidence = [r for r in results if r.confidence == "low"]

    review_queue = [r for r in results if r.uncertainties]

    category_counts = sorted(
        Counter(r.category for r in results).items(),
        key=lambda x: -x[1],
    )
    confidence_counts = Counter(r.confidence for r in results)

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "source": source or "unknown",
        "results": results,
        "total_count": len(results),
        # Grouped sections
        "high_priority": high_priority,
        "file_io_functions": file_io,
        "network_functions": network,
        "crypto_functions": crypto,
        "rename_suggestions": rename_suggestions,
        "low_confidence": low_confidence,
        "review_queue": review_queue,
        # Stats
        "category_counts": category_counts,
        "confidence_counts": dict(confidence_counts),
        # Counts for overview table
        "high_priority_count": len(high_priority),
        "review_queue_count": len(review_queue),
        "low_confidence_count": len(low_confidence),
        "rename_count": len(rename_suggestions),
    }


def generate_report(
    results: Sequence[AnalysisResult],
    out_path: str | Path,
    source: str | None = None,
) -> None:
    """
    Render a structured Markdown report and write it to out_path.

    Args:
        results: analyzed function results
        out_path: destination .md file
        source: optional label for the input file (shown in report header)
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
    context = _build_context(results, source)
    rendered = template.render(**context)

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(rendered)
