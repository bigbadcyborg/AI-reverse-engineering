"""
Storage: persist and load analysis results as local JSON files.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Sequence

from src.analyzer import AnalysisResult


def save_results(results: Sequence[AnalysisResult], path: str | Path) -> None:
    """Serialize analysis results to a JSON file, creating parent directories as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = [dataclasses.asdict(r) for r in results]
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def load_results(path: str | Path) -> list[AnalysisResult]:
    """Deserialize analysis results from a previously saved JSON file."""
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)

    return [AnalysisResult(**entry) for entry in data]
