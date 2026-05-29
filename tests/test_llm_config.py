"""Tests for src.llm_config — no live LLM required."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.llm_config import (
    parse_ollama_models,
    parse_openai_models,
    save_config,
    update_llm_section,
)


def test_parse_ollama_models():
    payload = {
        "models": [
            {"name": "llama3.2:1b"},
            {"name": "codellama:13b-instruct"},
        ]
    }
    assert parse_ollama_models(payload) == ["codellama:13b-instruct", "llama3.2:1b"]


def test_parse_openai_models():
    payload = {"data": [{"id": "gpt-4"}, {"id": "local-model"}]}
    assert parse_openai_models(payload) == ["gpt-4", "local-model"]


def test_update_llm_section_model():
    cfg = {"llm": {"model": "old", "backend": "ollama", "base_url": "http://localhost:11434"}}
    llm = update_llm_section(cfg, model="new_model")
    assert llm["model"] == "new_model"
    assert cfg["llm"]["model"] == "new_model"


def test_update_llm_section_rejects_empty_model():
    cfg = {"llm": {"model": "x"}}
    with pytest.raises(ValueError, match="non-empty"):
        update_llm_section(cfg, model="  ")


def test_update_llm_section_rejects_invalid_backend():
    cfg = {"llm": {"backend": "ollama"}}
    with pytest.raises(ValueError, match="backend"):
        update_llm_section(cfg, backend="invalid")


def test_save_config_atomic(tmp_path: Path):
    path = tmp_path / "config.json"
    data = {"llm": {"model": "test"}}
    save_config(path, data)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["llm"]["model"] == "test"
