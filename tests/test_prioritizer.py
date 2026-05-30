"""Tests for src.prioritizer."""

from __future__ import annotations

from src.prioritizer import prioritize, score_function


def test_named_c2_scores_above_crt():
    c2 = {
        "functionName": "xor_crypt",
        "entryPoint": "0x140001531",
        "xrefCount": 5,
        "calledFunctions": ["xor"],
        "decompiledCode": "line\n" * 12,
    }
    crt = {
        "functionName": "__mingw_TLScallback",
        "entryPoint": "0x140002810",
        "xrefCount": 1,
        "calledFunctions": [],
        "decompiledCode": "x();\n",
    }
    assert score_function(c2) > score_function(crt)


def test_prioritize_puts_c2_first():
    functions = [
        {"functionName": "__do_global_ctors", "entryPoint": "0x1", "xrefCount": 0},
        {"functionName": "main", "entryPoint": "0x2", "xrefCount": 8, "decompiledCode": "x\n" * 10},
        {"functionName": "FUN_00101000", "entryPoint": "0x3", "xrefCount": 1},
    ]
    ordered = prioritize(functions, {"analysis": {"sort_by": "priority"}})
    assert ordered[0]["functionName"] == "main"


def test_skip_runtime_excludes_crt():
    functions = [
        {"functionName": "__mingw_thr_run_key_dtors", "entryPoint": "0x1"},
        {"functionName": "connect_to_host", "entryPoint": "0x2", "xrefCount": 3},
    ]
    ordered = prioritize(
        functions,
        {"analysis": {"sort_by": "priority", "skip_runtime": True}},
    )
    names = [f["functionName"] for f in ordered]
    assert "connect_to_host" in names
    assert "__mingw_thr_run_key_dtors" not in names
