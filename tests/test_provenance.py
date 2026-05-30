"""Tests for analysis provenance metadata."""

from __future__ import annotations

from src.analyzer import Analyzer


def test_build_result_stamps_provenance():
    analyzer = Analyzer({"backend": "ollama", "model": "test:7b", "base_url": "http://localhost:11434"})
    function = {
        "functionName": "main",
        "entryPoint": "0x1000",
        "decompiledCode": "int main(){return 0;}\n" * 10,
    }
    parsed = {
        "entryPoint": "0x1000",
        "suggestedName": "main",
        "summary": "Entry point.",
        "category": "unknown",
        "confidence": "medium",
        "sideEffects": [],
        "uncertainties": [],
    }
    result = analyzer._build_result(function, parsed, "{}", None, run_id="run-xyz")
    assert result.run_id == "run-xyz"
    assert result.model == "test:7b"
    assert result.backend == "ollama"
    assert result.prompt_version
    assert result.postprocess_version
    assert result.analyzed_at
