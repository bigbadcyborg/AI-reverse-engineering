"""
Progress reporting for batch LLM analysis.

Used by the CLI (Rich) and dashboard (HTMX polling) to show per-function
and per-phase status while Ollama/llama.cpp processes decompiled code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

# Phases emitted during analyze_function and batch runs
PHASE_QUEUED = "queued"
PHASE_LOADING = "loading"
PHASE_PROMPTING = "prompting"
PHASE_WAITING_LLM = "waiting_llm"
PHASE_PARSING = "parsing"
PHASE_INGESTING = "ingesting"
PHASE_RUNNING = "running"
PHASE_COMPLETE = "complete"
PHASE_ERROR = "error"

PHASE_LABELS: dict[str, str] = {
    PHASE_QUEUED: "Queued",
    PHASE_LOADING: "Loading",
    PHASE_PROMPTING: "Building prompt",
    PHASE_WAITING_LLM: "Waiting for LLM",
    PHASE_PARSING: "Parsing response",
    PHASE_INGESTING: "Saving to database",
    PHASE_RUNNING: "Running",
    PHASE_COMPLETE: "Complete",
    PHASE_ERROR: "Error",
}


@dataclass
class ProgressUpdate:
    """Single progress snapshot for UI or logging."""

    phase: str
    current: int  # 1-based index of function being processed (0 if N/A)
    total: int
    completed: int = 0  # functions fully finished (for progress bar value)
    function_name: str = ""
    entry_point: str = ""
    message: str = ""
    errors: int = 0
    model: str = ""
    last_error: str = ""


ProgressCallback = Callable[[ProgressUpdate], None]


def format_progress_message(
    phase: str,
    function_name: str,
    *,
    model: str = "",
    backend: str = "ollama",
) -> str:
    """Build a short human-readable status line for the current phase."""
    name = function_name or "unknown"
    if phase == PHASE_LOADING:
        return "Loading function records..."
    if phase == PHASE_PROMPTING:
        return f"Building prompt for {name}..."
    if phase == PHASE_WAITING_LLM:
        backend_label = "Ollama" if backend == "ollama" else "LLM"
        model_part = f" ({model})" if model else ""
        return f"Waiting for {backend_label}{model_part} — {name}..."
    if phase == PHASE_PARSING:
        return f"Parsing LLM response for {name}..."
    if phase == PHASE_INGESTING:
        return "Saving results to database..."
    if phase == PHASE_COMPLETE:
        return "Analysis complete."
    if phase == PHASE_ERROR:
        return "Analysis stopped due to an error."
    return PHASE_LABELS.get(phase, phase)


def elapsed_seconds_since(iso_timestamp: str) -> int:
    """Seconds since an ISO UTC timestamp string, or 0 if invalid."""
    if not iso_timestamp:
        return 0
    try:
        started = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
    except (ValueError, TypeError):
        return 0


def estimate_eta_seconds(elapsed: int, done: int, total: int) -> int | None:
    """Rough ETA in seconds from average time per completed item."""
    if done <= 0 or total <= done or elapsed <= 0:
        return None
    remaining = total - done
    return int((elapsed / done) * remaining)
