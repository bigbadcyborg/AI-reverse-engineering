"""
Analyzer: send decompiled function data to a local LLM and parse structured responses.

Supports backends:
  - ollama  (http://localhost:11434)
  - llamacpp (any OpenAI-compatible /v1/chat/completions endpoint)

Each function is analyzed independently. The LLM is expected to return a JSON
object matching the AnalysisResult schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisResult:
    """Structured output for a single analyzed function."""

    name: str
    address: str
    summary: str = ""
    suggested_name: str = ""
    suggested_params: list[str] = field(default_factory=list)
    behavior_tags: list[str] = field(default_factory=list)
    confidence: str = "low"   # low | medium | high
    notes: str = ""
    raw_response: str = ""


class Analyzer:
    """
    Wraps a local LLM backend and analyzes decompiled functions.

    Iteration 1: implement __init__, ping, and analyze_function.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        # config is the parsed config.json["llm"] section
        self.config = config

    def ping(self) -> bool:
        """Return True if the LLM backend is reachable."""
        raise NotImplementedError("Iteration 1: Analyzer.ping not yet implemented.")

    def analyze_function(self, function: dict[str, Any]) -> AnalysisResult:
        """
        Send a single function to the LLM and return a structured AnalysisResult.

        Raises RuntimeError if the backend is unreachable or returns an unparseable response.
        """
        raise NotImplementedError("Iteration 1: Analyzer.analyze_function not yet implemented.")
