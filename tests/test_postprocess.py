"""Tests for src.postprocess — no LLM required."""

from __future__ import annotations

from src.analyzer import AnalysisResult
from src.postprocess import (
    BatchContext,
    filter_uncertainties,
    infer_category_from_signals,
    is_high_priority,
    is_runtime_function,
    refine,
)


def _result(**kwargs) -> AnalysisResult:
    defaults = dict(
        function_name="FUN_00101000",
        entry_point="0x00101000",
        summary="Does something.",
        suggested_name="",
        category="unknown",
        confidence="high",
        side_effects=[],
        uncertainties=[],
    )
    defaults.update(kwargs)
    return AnalysisResult(**defaults)


def _fn(code: str = "", callees: list[str] | None = None) -> dict:
    return {
        "functionName": "FUN_test",
        "entryPoint": "0x00101000",
        "decompiledCode": code,
        "callees": callees or [],
    }


def test_sanitize_hash_function_caps_confidence():
    r = _result(suggested_name="Hash Function", confidence="high")
    fn = _fn(code="int x;\n" * 10 + "return x ^ key;\n")
    out = refine(r, fn)
    assert " " not in out.suggested_name
    assert out.suggested_name == "Hash_Function"
    assert out.confidence in ("medium", "low")


def test_crt_classified_runtime_not_high_priority():
    r = _result(
        function_name="__tmainCRTStartup",
        category="process",
        confidence="high",
    )
    fn = _fn(code="void f() {\n}\n" * 5)
    out = refine(r, fn)
    assert out.category == "runtime"
    assert not is_high_priority(out)


def test_callee_connect_overrides_file_io():
    r = _result(category="file_io", function_name="send_beacon", confidence="high")
    fn = _fn(
        code="socket();\nconnect();\n" + "x();\n" * 8,
        callees=["socket", "connect", "send"],
    )
    out = refine(r, fn)
    assert out.category == "network"


def test_uncertainty_noise_stripped():
    noisy = [
        "Unknown calling convention",
        "Unresolved local var: int x@[??]",
        "Real behavioral question about buffer bounds",
    ]
    filtered = filter_uncertainties(noisy)
    assert len(filtered) == 1
    assert "buffer bounds" in filtered[0]


def test_duplicate_rename_disambiguation():
    ctx = BatchContext()
    r1 = _result(
        suggested_name="ConnectToHost",
        entry_point="0x001019c0",
        confidence="high",
    )
    fn1 = _fn(code="connect();\n" * 10, callees=["connect"])
    out1 = refine(r1, fn1, ctx)
    assert out1.suggested_name == "ConnectToHost"

    r2 = _result(
        suggested_name="ConnectToHost",
        entry_point="0x00102800",
        confidence="high",
    )
    fn2 = _fn(code="connect();\n" * 10, callees=["connect"])
    out2 = refine(r2, fn2, ctx)
    assert out2.suggested_name != "ConnectToHost"
    assert "19c0" in out2.suggested_name or "2800" in out2.suggested_name
    assert out2.confidence in ("medium", "low", "high")


def test_execute_command_is_high_priority_process():
    r = _result(
        function_name="execute_command",
        category="process",
        summary="Runs execute_command via CreateProcess",
        confidence="high",
    )
    fn = _fn(code="CreateProcess();\n" * 10, callees=["CreateProcess"])
    out = refine(r, fn)
    assert is_high_priority(out)


def test_infer_network_single_strong_signal():
    blob = "socket connect send"
    assert infer_category_from_signals(blob, "file_io") == "network"


def test_is_runtime_mingw_prefix():
    assert is_runtime_function("__mingw_TLScallback", [])
