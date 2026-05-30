"""Tests for src.reporter high-priority filtering."""

from __future__ import annotations

from src.analyzer import AnalysisResult
from src.reporter import _build_context


def test_high_priority_excludes_runtime_and_invalid_names():
    results = [
        AnalysisResult(
            function_name="xor_crypt",
            entry_point="0x1",
            category="crypto",
            confidence="high",
            suggested_name="xor_crypt",
        ),
        AnalysisResult(
            function_name="__dyn_tls_init",
            entry_point="0x2",
            category="crypto",
            confidence="medium",
            suggested_name="__dyn_tls_init",
        ),
        AnalysisResult(
            function_name="FUN_hash",
            entry_point="0x3",
            category="crypto",
            confidence="high",
            suggested_name="Hash Function",
        ),
    ]
    ctx = _build_context(results, "test.jsonl")
    assert ctx["high_priority_count"] == 1
    assert ctx["high_priority"][0].function_name == "xor_crypt"
