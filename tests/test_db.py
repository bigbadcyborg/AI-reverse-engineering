"""Tests for src.db run history and migrations."""

from __future__ import annotations

from pathlib import Path

from src.analyzer import AnalysisResult
from src import db


def _result(ep: str, name: str = "FUN_x") -> AnalysisResult:
    return AnalysisResult(
        function_name=name,
        entry_point=ep,
        summary="test",
        category="network",
        confidence="high",
        run_id="run-a",
        model="test-model",
        backend="ollama",
    )


def test_two_runs_same_entry_point_coexist(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db.init_db(db_path)
    db.create_run(db_path, run_id="run-a", label="A", model="m1")
    db.create_run(db_path, run_id="run-b", label="B", model="m2")

    r1 = _result("0x1000")
    r1.run_id = "run-a"
    r1.category = "network"
    r2 = _result("0x1000")
    r2.run_id = "run-b"
    r2.category = "crypto"

    db.ingest_results([r1], db_path, run_id="run-a")
    db.ingest_results([r2], db_path, run_id="run-b")

    a = db.get_function(db_path, "0x1000", run_id="run-a")
    b = db.get_function(db_path, "0x1000", run_id="run-b")
    assert a is not None and b is not None
    assert a["category"] == "network"
    assert b["category"] == "crypto"


def test_list_runs_newest_first(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db.init_db(db_path)
    db.create_run(db_path, run_id="old", label="old")
    db.create_run(db_path, run_id="new", label="new")
    db.complete_run(db_path, "old", function_count=1)
    db.complete_run(db_path, "new", function_count=2)

    runs = db.list_runs(db_path)
    assert runs[0]["run_id"] == "new"


def test_resolve_run_id_defaults_to_latest(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db.init_db(db_path)
    db.create_run(db_path, run_id="r1")
    db.create_run(db_path, run_id="r2")
    assert db.resolve_run_id(db_path, None) == "r2"


def test_search_scoped_to_run(tmp_path: Path):
    db_path = tmp_path / "test.db"
    db.init_db(db_path)
    db.create_run(db_path, run_id="run-a")
    db.create_run(db_path, run_id="run-b")

    only_a = _result("0x2000", "alpha_fn")
    only_a.run_id = "run-a"
    only_b = _result("0x3000", "beta_fn")
    only_b.run_id = "run-b"

    db.ingest_results([only_a], db_path, run_id="run-a")
    db.ingest_results([only_b], db_path, run_id="run-b")

    rows_a = db.search(db_path, run_id="run-a", limit=10)
    assert len(rows_a) == 1
    assert rows_a[0]["function_name"] == "alpha_fn"
