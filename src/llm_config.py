"""
LLM configuration helpers: list models from local backends, merge settings, save config.json.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx

VALID_BACKENDS = frozenset({"ollama", "llamacpp"})

# Module-level cache: (cache_key, monotonic_ts, models, error)
_models_cache: dict[str, tuple[float, list[str], str | None]] = {}
_CACHE_TTL_SEC = 30.0


def _cache_key(llm_cfg: dict[str, Any]) -> str:
    backend = llm_cfg.get("backend", "ollama")
    base = (llm_cfg.get("base_url", "") or "").rstrip("/")
    return f"{backend}|{base}"


def parse_ollama_models(payload: dict[str, Any]) -> list[str]:
    models = payload.get("models") or []
    names: list[str] = []
    for item in models:
        if isinstance(item, dict):
            name = item.get("name") or item.get("model")
            if name:
                names.append(str(name))
    return sorted(set(names), key=str.lower)


def parse_openai_models(payload: dict[str, Any]) -> list[str]:
    data = payload.get("data") or []
    names: list[str] = []
    for item in data:
        if isinstance(item, dict) and item.get("id"):
            names.append(str(item["id"]))
    return sorted(set(names), key=str.lower)


def fetch_models_from_backend(llm_cfg: dict[str, Any]) -> tuple[list[str], str | None]:
    """
    Query the configured backend for available model names.

    Returns:
        (model_names, error_message) — error is set when the request fails.
    """
    backend = llm_cfg.get("backend", "ollama")
    base_url = (llm_cfg.get("base_url", "http://localhost:11434") or "").rstrip("/")
    url = (
        f"{base_url}/api/tags"
        if backend == "ollama"
        else f"{base_url}/v1/models"
    )
    try:
        resp = httpx.get(url, timeout=10.0)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        return [], str(exc)

    if backend == "ollama":
        return parse_ollama_models(payload), None
    return parse_openai_models(payload), None


def list_models(
    llm_cfg: dict[str, Any],
    *,
    refresh: bool = False,
) -> tuple[list[str], bool, str | None]:
    """
    Return model names, using a short TTL cache unless refresh=True.

    Returns:
        (models, reachable, error)
    """
    key = _cache_key(llm_cfg)
    now = time.monotonic()

    if not refresh and key in _models_cache:
        ts, models, err = _models_cache[key]
        if now - ts < _CACHE_TTL_SEC:
            return models, err is None, err

    models, err = fetch_models_from_backend(llm_cfg)
    _models_cache[key] = (now, models, err)
    return models, err is None, err


def invalidate_models_cache() -> None:
    """Clear cached model lists (e.g. after base_url change)."""
    _models_cache.clear()


def update_llm_section(
    config: dict[str, Any],
    *,
    model: str | None = None,
    backend: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """
    Merge validated LLM fields into config['llm']. Returns the updated llm dict.
    """
    llm = dict(config.get("llm") or {})

    if model is not None:
        model = model.strip()
        if not model:
            raise ValueError("model must be a non-empty string")
        llm["model"] = model

    if backend is not None:
        backend = backend.strip().lower()
        if backend not in VALID_BACKENDS:
            raise ValueError(f"backend must be one of: {', '.join(sorted(VALID_BACKENDS))}")
        llm["backend"] = backend

    if base_url is not None:
        base_url = base_url.strip().rstrip("/")
        if not base_url:
            raise ValueError("base_url must be a non-empty string")
        llm["base_url"] = base_url

    config["llm"] = llm
    return llm


def save_config(config_path: Path, config: dict[str, Any]) -> None:
    """Write config JSON atomically."""
    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = config_path.with_suffix(config_path.suffix + ".tmp")
    text = json.dumps(config, indent=2) + "\n"
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(config_path)
