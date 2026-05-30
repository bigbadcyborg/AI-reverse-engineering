"""
Deterministic refinement of LLM analysis results.

Applied after JSON parse in Analyzer._build_result and before DB/report ingest.
See change-report-5-29-26.md for rationale.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Sequence

from src.analyzer import AnalysisResult, VALID_CONFIDENCE
from src.renamer import is_informative, is_valid_identifier, sanitize_identifier

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

MIN_CODE_LINES_FOR_HIGH = 8

# Ghidra / decompiler noise — not actionable for malware triage
UNCERTAINTY_NOISE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"unknown calling convention",
        r"unresolved local var",
        r"parameter storage is locked",
        r"could not recover jumptable",
        r"treating indirect jump as call",
        r"warning:\s*enum",
        r"decompilation process",
        r"decompiled function does not handle errors",
    )
]

# Generic side effects often hallucinated on trivial functions
GENERIC_SIDE_EFFECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^writes to filesystem$",
        r"^allocates heap memory$",
        r"^modifies caller-supplied buffer$",
        r"^write to filesystem$",
        r"^allocate heap memory$",
    )
]

SIDE_EFFECT_EVIDENCE: dict[str, tuple[str, ...]] = {
    "filesystem": ("fopen", "fread", "fwrite", "fclose", "createfile", "writefile", "readfile"),
    "heap": ("malloc", "calloc", "realloc", "free", "heapalloc"),
    "buffer": ("memcpy", "memmove", "strcpy", "strncpy", "memset"),
}

RUNTIME_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^__mingw",
        r"^__gnu",
        r"^__gcc_",
        r"^_pei386",
        r"^WinMain",
        r"mainCRTStartup",
        r"^atexit$",
        r"^__do_global",
        r"^__dyn_tls",
        r"^__tlreg",
        r"^_FindPE",
        r"^_GetPE",
        r"^_ValidateImage",
        r"^__mingw_GetSection",
        r"^__report_error",
        r"^vfprintf$",
        r"^fprintf$",
        r"^snprintf$",
        r"^_fpreset$",
        r"^___chkstk",
    )
]

NETWORK_SIGNALS = (
    "connect", "socket", "send", "recv", "wsastartup", "wsa", "inet_",
    "bind", "listen", "accept", "gethostbyname",
)
FILE_IO_SIGNALS = (
    "fopen", "fread", "fwrite", "fclose", "createfile", "readfile", "writefile",
)
CRYPTO_SIGNALS = ("crypt", "bcrypt", "xor", "encrypt", "decrypt", "hash")
PROCESS_SIGNALS = ("createprocess", "shellexecute", "system", "winexec", "spawn")

HIGH_PRIORITY_PROCESS_ALLOWLIST = re.compile(
    r"(execute_command|createprocess|shellexecute|winexec|spawn|system\s*\()",
    re.IGNORECASE,
)

HIGH_PRIORITY_CATEGORIES = frozenset({"crypto", "network", "registry"})

NETWORK_PRIMARY_NAMES = re.compile(
    r"(send_beacon|recv_command|connect_to_host)",
    re.IGNORECASE,
)


@dataclass
class BatchContext:
    """Tracks suggested names across a batch for disambiguation."""

    name_to_entries: dict[str, list[str]] = field(default_factory=dict)


def _cap_confidence(current: str, cap: str) -> str:
    if CONFIDENCE_ORDER.get(current, 0) > CONFIDENCE_ORDER.get(cap, 1):
        return cap
    return current


def _addr_suffix(entry_point: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", entry_point)
    return digits[-4:].lower() if len(digits) >= 4 else digits.lower() or "0000"


def is_runtime_function(function_name: str, callees: list[str]) -> bool:
    name = function_name or ""
    for pat in RUNTIME_NAME_PATTERNS:
        if pat.search(name):
            return True
    # Heavily PE/CRT callees only
    if name.startswith("_") and not any(
        s in name.lower() for s in ("command", "beacon", "crypt", "config", "log")
    ):
        crt_hits = sum(1 for c in callees if c.startswith("_") or "mingw" in c.lower())
        if callees and crt_hits >= len(callees):
            return True
    return False


def filter_uncertainties(items: list[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        text = (item or "").strip()
        if not text:
            continue
        if any(p.search(text) for p in UNCERTAINTY_NOISE_PATTERNS):
            continue
        out.append(text)
    return out


def _evidence_blob(function: dict[str, Any]) -> str:
    callees = function.get("callees") or function.get("calledFunctions") or []
    code = function.get("decompiledCode") or function.get("decompiled_code") or ""
    strings = function.get("strings") or function.get("referencedStrings") or []
    parts = [c.lower() for c in callees]
    parts.append(code.lower())
    parts.extend(s.lower() for s in strings)
    return " ".join(parts)


def _count_signals(blob: str, signals: tuple[str, ...]) -> int:
    return sum(1 for s in signals if s in blob)


def _callee_blob(callees: list[str]) -> str:
    return " ".join(c.lower() for c in callees)


def _has_network_callees(callees: list[str]) -> bool:
    blob = _callee_blob(callees)
    return any(s in blob for s in ("send", "recv", "connect", "socket", "bind", "listen", "accept"))


def infer_category_from_signals(
    blob: str,
    current: str,
    *,
    strong_only: bool = True,
    callees: list[str] | None = None,
    function_name: str = "",
) -> str | None:
    callees = callees or []
    callee_blob = _callee_blob(callees)

    if NETWORK_PRIMARY_NAMES.search(function_name):
        if current != "network":
            return "network"

    if _has_network_callees(callees):
        net_in_callees = sum(1 for s in NETWORK_SIGNALS if s in callee_blob)
        fio_in_callees = sum(1 for s in FILE_IO_SIGNALS if s in callee_blob)
        if net_in_callees > 0 and net_in_callees >= fio_in_callees and current != "network":
            return "network"

    scores = {
        "network": _count_signals(blob, NETWORK_SIGNALS),
        "file_io": _count_signals(blob, FILE_IO_SIGNALS),
        "crypto": _count_signals(blob, CRYPTO_SIGNALS),
        "process": _count_signals(blob, PROCESS_SIGNALS),
    }
    if _has_network_callees(callees) and scores["network"] >= scores["file_io"]:
        scores["file_io"] = max(0, scores["file_io"] - 1)
    best_cat = max(scores, key=lambda k: scores[k])
    best_score = scores[best_cat]
    if best_score == 0:
        return None
    threshold = 2 if strong_only else 1
    if best_score < threshold:
        if best_score == 1 and best_cat == "network":
            return "network" if current != "network" else None
        return None
    if best_cat == current:
        return None
    return best_cat


def filter_side_effects(items: list[str], evidence_blob: str) -> list[str]:
    out: list[str] = []
    for item in items:
        text = (item or "").strip()
        if not text:
            continue
        if not any(p.search(text) for p in GENERIC_SIDE_EFFECT_PATTERNS):
            out.append(text)
            continue
        lower = evidence_blob
        kept = False
        if "filesystem" in text.lower() or "file" in text.lower():
            kept = any(e in lower for e in SIDE_EFFECT_EVIDENCE["filesystem"])
        elif "heap" in text.lower() or "alloc" in text.lower():
            kept = any(e in lower for e in SIDE_EFFECT_EVIDENCE["heap"])
        elif "buffer" in text.lower():
            kept = any(e in lower for e in SIDE_EFFECT_EVIDENCE["buffer"])
        if kept:
            out.append(text)
    return out


def _code_line_count(function: dict[str, Any]) -> int:
    code = function.get("decompiledCode") or function.get("decompiled_code") or ""
    lines = [ln for ln in code.splitlines() if ln.strip() and not ln.strip().startswith("/*")]
    return len(lines)


def sanitize_suggested_name(
    result: AnalysisResult,
) -> tuple[str, bool, bool]:
    """
    Returns (name, was_sanitized, cleared_as_uninformative).
    """
    name = (result.suggested_name or "").strip()
    if not name:
        return "", False, False

    original = name
    if name.lower() == (result.function_name or "").lower():
        return name, False, False

    if not is_informative(name):
        return "", False, True

    sanitized = False
    if not is_valid_identifier(name):
        name = sanitize_identifier(name)
        sanitized = name != original

    if not name or not is_informative(name):
        return "", sanitized, True

    return name, sanitized, False


def disambiguate_name(name: str, entry_point: str, ctx: BatchContext | None) -> tuple[str, bool]:
    if not ctx or not name:
        return name, False
    entries = ctx.name_to_entries.get(name, [])
    if entry_point in entries:
        return name, False
    if not entries:
        ctx.name_to_entries.setdefault(name, []).append(entry_point)
        return name, False
    # Collision with a different entry point
    suffixed = f"{name}_{_addr_suffix(entry_point)}"
    ctx.name_to_entries.setdefault(suffixed, []).append(entry_point)
    return suffixed, True


def register_suggested_name(name: str, entry_point: str, ctx: BatchContext | None) -> None:
    if ctx and name and entry_point:
        if entry_point not in ctx.name_to_entries.get(name, []):
            ctx.name_to_entries.setdefault(name, []).append(entry_point)


def calibrate_confidence(
    result: AnalysisResult,
    function: dict[str, Any],
    *,
    was_sanitized: bool,
    cleared_name: bool,
    is_runtime: bool,
    name_disambiguated: bool,
) -> str:
    conf = result.confidence if result.confidence in VALID_CONFIDENCE else "low"

    if cleared_name:
        conf = _cap_confidence(conf, "low")
    if was_sanitized or name_disambiguated:
        conf = _cap_confidence(conf, "medium")
    if is_runtime:
        conf = _cap_confidence(conf, "medium")
    if result.category in ("unknown", "runtime"):
        conf = _cap_confidence(conf, "medium")
    if result.uncertainties:
        conf = _cap_confidence(conf, "medium")
    if _code_line_count(function) < MIN_CODE_LINES_FOR_HIGH:
        conf = _cap_confidence(conf, "low")

    callees = function.get("callees") or function.get("calledFunctions") or []
    strings = function.get("strings") or function.get("referencedStrings") or []
    if not callees and not strings and _code_line_count(function) < MIN_CODE_LINES_FOR_HIGH:
        conf = _cap_confidence(conf, "low")

    # Promote to high only when criteria met
    has_good_name = bool(result.suggested_name) and is_valid_identifier(result.suggested_name)
    name_ok = has_good_name or (
        result.function_name
        and not result.function_name.upper().startswith("FUN_")
        and is_informative(result.function_name)
    )
    if (
        name_ok
        and not result.uncertainties
        and result.category not in ("unknown", "runtime")
        and not is_runtime
        and _code_line_count(function) >= MIN_CODE_LINES_FOR_HIGH
        and conf != "low"
    ):
        conf = "high"

    return conf


def is_high_priority(
    result: AnalysisResult,
    *,
    callees: list[str] | None = None,
) -> bool:
    callees = callees or []
    if result.confidence == "low":
        return False
    if is_runtime_function(result.function_name, callees):
        return False
    if result.category == "runtime":
        return False
    name = (result.suggested_name or result.function_name or "").strip()
    if name and not is_valid_identifier(name):
        return False
    if result.category in HIGH_PRIORITY_CATEGORIES:
        return True
    if result.category == "process":
        combined = f"{result.function_name} {result.summary}"
        return bool(HIGH_PRIORITY_PROCESS_ALLOWLIST.search(combined))
    return False


def filter_high_priority(
    results: Sequence[AnalysisResult],
    function_map: dict[str, dict[str, Any]] | None = None,
) -> list[AnalysisResult]:
    """Hardened high-priority list for reports and exports."""
    out: list[AnalysisResult] = []
    for r in results:
        fn = (function_map or {}).get(r.entry_point, {})
        callees = fn.get("callees") or fn.get("calledFunctions") or []
        if is_high_priority(r, callees=list(callees)):
            out.append(r)
    return out


def refine(
    result: AnalysisResult,
    function: dict[str, Any],
    batch_context: BatchContext | None = None,
) -> AnalysisResult:
    """Apply all post-processing rules to a single AnalysisResult."""
    callees = list(function.get("callees") or function.get("calledFunctions") or [])
    evidence = _evidence_blob(function)

    result.uncertainties = filter_uncertainties(list(result.uncertainties))
    result.side_effects = filter_side_effects(list(result.side_effects), evidence)

    runtime = is_runtime_function(result.function_name, callees)
    if runtime:
        result.category = "runtime"

    inferred = infer_category_from_signals(
        evidence,
        result.category,
        callees=callees,
        function_name=result.function_name,
    )
    if inferred:
        result.category = inferred

    name, was_sanitized, cleared = sanitize_suggested_name(result)
    if cleared:
        result.suggested_name = ""
    else:
        result.suggested_name = name

    if result.suggested_name and batch_context:
        disambiguated, collided = disambiguate_name(
            result.suggested_name, result.entry_point, batch_context
        )
        result.suggested_name = disambiguated
        register_suggested_name(result.suggested_name, result.entry_point, batch_context)
        name_disambiguated = collided
    else:
        name_disambiguated = False
        if result.suggested_name and batch_context:
            register_suggested_name(result.suggested_name, result.entry_point, batch_context)

    if was_sanitized and result.suggested_name:
        note = f"[name sanitized to '{result.suggested_name}']"
        if note not in result.uncertainties:
            result.uncertainties = list(result.uncertainties) + [note]

    result.confidence = calibrate_confidence(
        result,
        function,
        was_sanitized=was_sanitized,
        cleared_name=cleared,
        is_runtime=runtime,
        name_disambiguated=name_disambiguated,
    )

    return result
