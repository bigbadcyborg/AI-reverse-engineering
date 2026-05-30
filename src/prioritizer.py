"""
Rank decompiled functions before LLM analysis (xref, callees, naming signals).
"""

from __future__ import annotations

import re
from typing import Any

from src.postprocess import RUNTIME_NAME_PATTERNS, is_runtime_function

_SECURITY_CALLEES = re.compile(
    r"(?i)\b(send|recv|connect|socket|createprocess|system|crypt|wsastartup|bind|listen)\b"
)


def _code_lines(function: dict[str, Any]) -> int:
    code = function.get("decompiledCode") or function.get("decompiled_code") or ""
    return len([ln for ln in code.splitlines() if ln.strip()])


def score_function(function: dict[str, Any]) -> int:
    """Higher score = analyze sooner."""
    name = function.get("functionName") or function.get("function_name") or ""
    callees = function.get("callees") or function.get("calledFunctions") or []
    strings = function.get("strings") or function.get("referencedStrings") or []
    xref = int(function.get("xrefCount") or function.get("xref_count") or 0)

    score = 0

    if name and not name.upper().startswith("FUN_"):
        score += 2

    score += min(xref, 10)

    sec_hits = 0
    blob = " ".join(callees).lower()
    for m in _SECURITY_CALLEES.finditer(blob):
        sec_hits += 1
        if sec_hits >= 3:
            break
    score += min(sec_hits * 3, 9)

    if strings:
        score += 1

    if _code_lines(function) >= 8:
        score += 1

    if is_runtime_function(name, list(callees)):
        score -= 20
    else:
        for pat in RUNTIME_NAME_PATTERNS:
            if pat.search(name):
                score -= 20
                break

    return score


def prioritize(
    functions: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
    *,
    skip_runtime: bool | None = None,
    min_score: int | None = None,
) -> list[dict[str, Any]]:
    """
    Sort functions by priority score (descending).

    Config keys (under ``analysis``):
      sort_by: "priority" | "file" (default priority)
      skip_runtime: drop CRT/runtime helpers
      priority_min_score: minimum score to include
    """
    cfg = (config or {}).get("analysis") or {}
    sort_by = cfg.get("sort_by", "priority")
    if sort_by != "priority":
        return list(functions)

    do_skip = skip_runtime if skip_runtime is not None else bool(cfg.get("skip_runtime", False))
    floor = min_score if min_score is not None else int(cfg.get("priority_min_score", 0))

    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for idx, fn in enumerate(functions):
        sc = score_function(fn)
        if do_skip and sc < 0:
            continue
        if sc < floor:
            continue
        ranked.append((sc, idx, fn))

    ranked.sort(key=lambda t: (-t[0], t[1]))
    return [fn for _, _, fn in ranked]
