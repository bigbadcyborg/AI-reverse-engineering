"""
Analyzer: send decompiled function data to a local LLM and return structured results.

Supported backends:
  ollama   — native Ollama API  (POST /api/generate, format: "json")
  llamacpp — OpenAI-compatible  (POST /v1/chat/completions, response_format: json_object)

Output schema (AnalysisResult):
  function_name  : original name as imported
  entry_point    : address string
  summary        : plain-English description
  suggested_name : camelCase rename suggestion
  category       : behavioral category label
  confidence     : low | medium | high
  side_effects   : list of observable side effects
  uncertainties  : list of things requiring human review
  raw_response   : verbatim LLM output for debugging

rename_function() returns a RenameResult (defined in src.renamer) using the
dedicated rename.txt prompt. The import is deferred to avoid a circular import.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.postprocess import BatchContext
    from src.progress import ProgressCallback

import httpx
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

PROMPT_DIR = Path(__file__).parent.parent / "prompts"

VALID_CATEGORIES = {
    "file_io", "network", "crypto", "memory", "string_ops", "math",
    "control_flow", "input_validation", "process", "registry",
    "error_handling", "runtime", "unknown",
}
VALID_CONFIDENCE = {"low", "medium", "high"}


@dataclass
class AnalysisResult:
    """Structured output for a single analyzed function."""

    function_name: str
    entry_point: str
    summary: str = ""
    suggested_name: str = ""
    category: str = "unknown"
    confidence: str = "low"
    side_effects: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    raw_response: str = ""


class Analyzer:
    """Wraps a local LLM backend and analyzes decompiled functions one at a time."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.backend = config.get("backend", "ollama")
        self.base_url = config.get("base_url", "http://localhost:11434").rstrip("/")
        self.model = config.get("model", "codellama:13b-instruct")
        self.timeout = float(config.get("timeout_seconds", 120))
        self.temperature = float(config.get("temperature", 0.2))

        self._jinja = Environment(
            loader=FileSystemLoader(str(PROMPT_DIR)),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        """Return True if the configured LLM backend is reachable."""
        check_url = (
            f"{self.base_url}/api/tags"
            if self.backend == "ollama"
            else f"{self.base_url}/v1/models"
        )
        try:
            resp = httpx.get(check_url, timeout=10.0)
            return resp.status_code == 200
        except Exception:
            return False

    def list_models(self, *, refresh: bool = False) -> tuple[list[str], bool, str | None]:
        """
        List model names from the configured backend.

        Returns:
            (models, reachable, error_message)
        """
        from src.llm_config import list_models as _list_models

        llm_cfg = {
            "backend": self.backend,
            "base_url": self.base_url,
            "model": self.model,
        }
        return _list_models(llm_cfg, refresh=refresh)

    def rename_function(self, function: dict[str, Any]) -> "RenameResult":
        """
        Run the dedicated rename prompt on a single function.

        Returns a RenameResult with a validated identifier, confidence level,
        and a one-sentence reason grounded in code evidence.

        The suggested name is validated as a proper identifier and sanitized if
        necessary (spaces replaced with underscores, etc.). When sanitization
        changes the name, confidence is capped at "medium" and the original
        raw suggestion is noted in the reason.

        Raises:
            TemplateNotFound — if prompts/rename.txt is missing
            httpx.HTTPError  — on network / HTTP errors
            RuntimeError     — if the LLM response cannot be parsed as JSON
        """
        from src.renamer import (
            RenameResult,
            is_valid_identifier,
            sanitize_identifier,
        )

        prompt = self._render_prompt("rename.txt", function)
        raw = self._call_llm(prompt)
        parsed = self._parse_json(raw)

        new_name = parsed.get("newName", "").strip()
        confidence = parsed.get("confidence", "low")
        reason = parsed.get("reason", "").strip()

        if confidence not in VALID_CONFIDENCE:
            confidence = "low"

        # Validate identifier and sanitize if needed
        if not is_valid_identifier(new_name):
            original = new_name
            new_name = sanitize_identifier(new_name)
            note = f"[name sanitized from '{original}'] "
            reason = note + reason
            # Demote confidence if the name had to be fixed
            if confidence == "high":
                confidence = "medium"

        return RenameResult(
            entry_point=function.get("entryPoint", ""),
            old_name=function.get("functionName", ""),
            new_name=new_name,
            confidence=confidence,
            reason=reason,
        )

    def analyze_function(
        self,
        function: dict[str, Any],
        *,
        on_progress: "ProgressCallback | None" = None,
        batch_context: "BatchContext | None" = None,
    ) -> AnalysisResult:
        """
        Send a single function to the LLM and return a structured AnalysisResult.

        Raises:
            TemplateNotFound  — if prompts/summarize.txt is missing
            httpx.HTTPError   — on network / HTTP errors
            RuntimeError      — if the LLM response cannot be parsed as JSON
        """
        from src.progress import (
            PHASE_PARSING,
            PHASE_PROMPTING,
            PHASE_WAITING_LLM,
            ProgressUpdate,
            format_progress_message,
        )

        name = function.get("functionName", function.get("entry_point", "unknown"))
        ep = function.get("entryPoint", function.get("entry_point", ""))

        def _emit(phase: str) -> None:
            if on_progress:
                on_progress(
                    ProgressUpdate(
                        phase=phase,
                        current=0,
                        total=0,
                        function_name=name,
                        entry_point=ep,
                        message=format_progress_message(
                            phase, name, model=self.model, backend=self.backend
                        ),
                        model=self.model,
                    )
                )

        _emit(PHASE_PROMPTING)
        prompt = self._render_prompt("summarize.txt", function)
        _emit(PHASE_WAITING_LLM)
        raw = self._call_llm(prompt)
        _emit(PHASE_PARSING)
        parsed = self._parse_json(raw)
        return self._build_result(function, parsed, raw, batch_context)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _render_prompt(self, template_name: str, function: dict[str, Any]) -> str:
        try:
            tmpl = self._jinja.get_template(template_name)
        except TemplateNotFound:
            raise TemplateNotFound(
                f"Prompt template not found: {PROMPT_DIR / template_name}"
            )
        return tmpl.render(**function)

    def _call_llm(self, prompt: str) -> str:
        if self.backend == "ollama":
            return self._call_ollama(prompt)
        return self._call_llamacpp(prompt)

    def _call_ollama(self, prompt: str) -> str:
        url = f"{self.base_url}/api/generate"
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.temperature},
        }
        resp = httpx.post(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()["response"]

    def _call_llamacpp(self, prompt: str) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
        }
        resp = httpx.post(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    @staticmethod
    def _parse_json(raw: str) -> dict:
        """
        Parse JSON from the LLM response.

        Some models wrap their JSON in markdown fences even when instructed not to.
        This strips common fence patterns before parsing.
        """
        cleaned = raw.strip()
        # Strip optional ```json ... ``` fences
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"LLM returned a response that could not be parsed as JSON.\n"
                f"Error: {exc}\n"
                f"Raw response (first 500 chars):\n{raw[:500]}"
            ) from exc

    @staticmethod
    def _build_result(
        function: dict[str, Any],
        parsed: dict,
        raw: str,
        batch_context: "BatchContext | None" = None,
    ) -> AnalysisResult:
        from src.postprocess import refine

        category = parsed.get("category", "unknown")
        if category not in VALID_CATEGORIES:
            category = "unknown"

        confidence = parsed.get("confidence", "low")
        if confidence not in VALID_CONFIDENCE:
            confidence = "low"

        result = AnalysisResult(
            function_name=function.get("functionName", ""),
            entry_point=parsed.get("entryPoint", function.get("entryPoint", "")),
            summary=parsed.get("summary", ""),
            suggested_name=parsed.get("suggestedName", ""),
            category=category,
            confidence=confidence,
            side_effects=parsed.get("sideEffects", []),
            uncertainties=parsed.get("uncertainties", []),
            raw_response=raw,
        )
        return refine(result, function, batch_context)
