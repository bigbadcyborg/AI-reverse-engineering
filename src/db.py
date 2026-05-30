"""
Database: SQLite-backed storage and full-text search for analysis results.

Schema
------
analysis_runs
    Metadata for each batch analysis (model, prompt/postprocess versions, counts).

functions
    One row per analyzed function per run. Unique on (run_id, entry_point).

functions_fts
    FTS5 virtual table kept in sync via triggers.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from src.analyzer import AnalysisResult

LEGACY_RUN_ID = "legacy"

_DDL_ANALYSIS_RUNS = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id              TEXT PRIMARY KEY,
    label               TEXT NOT NULL DEFAULT '',
    model               TEXT NOT NULL DEFAULT '',
    backend             TEXT NOT NULL DEFAULT '',
    prompt_version      TEXT NOT NULL DEFAULT '',
    postprocess_version TEXT NOT NULL DEFAULT '',
    source_input        TEXT NOT NULL DEFAULT '',
    started_at          TEXT NOT NULL DEFAULT '',
    completed_at        TEXT NOT NULL DEFAULT '',
    function_count      INTEGER NOT NULL DEFAULT 0,
    error_count         INTEGER NOT NULL DEFAULT 0
);
"""

_DDL_FUNCTIONS = """
CREATE TABLE IF NOT EXISTS functions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT    NOT NULL DEFAULT 'legacy',
    entry_point     TEXT    NOT NULL,
    function_name   TEXT    NOT NULL DEFAULT '',
    suggested_name  TEXT    NOT NULL DEFAULT '',
    summary         TEXT    NOT NULL DEFAULT '',
    category        TEXT    NOT NULL DEFAULT '',
    confidence      TEXT    NOT NULL DEFAULT '',
    side_effects    TEXT    NOT NULL DEFAULT '[]',
    uncertainties   TEXT    NOT NULL DEFAULT '[]',
    decompiled_code TEXT    NOT NULL DEFAULT '',
    source_file     TEXT    NOT NULL DEFAULT '',
    ingested_at     TEXT    NOT NULL DEFAULT '',
    embedding       BLOB,
    UNIQUE (run_id, entry_point),
    FOREIGN KEY (run_id) REFERENCES analysis_runs(run_id)
);
"""

_DDL_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS functions_fts USING fts5(
    entry_point    UNINDEXED,
    function_name,
    suggested_name,
    summary,
    side_effects,
    category       UNINDEXED,
    confidence     UNINDEXED,
    content        = 'functions',
    content_rowid  = 'id',
    tokenize       = 'porter ascii'
);
"""

_DDL_FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS functions_ai AFTER INSERT ON functions BEGIN
    INSERT INTO functions_fts(rowid, entry_point, function_name, suggested_name,
                              summary, side_effects, category, confidence)
    VALUES (new.id, new.entry_point, new.function_name, new.suggested_name,
            new.summary, new.side_effects, new.category, new.confidence);
END;

CREATE TRIGGER IF NOT EXISTS functions_ad AFTER DELETE ON functions BEGIN
    INSERT INTO functions_fts(functions_fts, rowid, entry_point, function_name,
                              suggested_name, summary, side_effects, category, confidence)
    VALUES ('delete', old.id, old.entry_point, old.function_name, old.suggested_name,
            old.summary, old.side_effects, old.category, old.confidence);
END;

CREATE TRIGGER IF NOT EXISTS functions_au AFTER UPDATE ON functions BEGIN
    INSERT INTO functions_fts(functions_fts, rowid, entry_point, function_name,
                              suggested_name, summary, side_effects, category, confidence)
    VALUES ('delete', old.id, old.entry_point, old.function_name, old.suggested_name,
            old.summary, old.side_effects, old.category, old.confidence);
    INSERT INTO functions_fts(rowid, entry_point, function_name, suggested_name,
                              summary, side_effects, category, confidence)
    VALUES (new.id, new.entry_point, new.function_name, new.suggested_name,
            new.summary, new.side_effects, new.category, new.confidence);
END;
"""


def _connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(c[1] == column for c in cols)


def _migrate_legacy_schema(conn: sqlite3.Connection) -> None:
    """Upgrade pre-run-history databases to analysis_runs + run_id."""
    if not _table_exists(conn, "functions"):
        return
    if _column_exists(conn, "functions", "run_id"):
        return

    conn.executescript(_DDL_ANALYSIS_RUNS)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        """
        INSERT OR IGNORE INTO analysis_runs
            (run_id, label, started_at, completed_at, function_count)
        VALUES (?, ?, ?, ?, (SELECT COUNT(*) FROM functions))
        """,
        (LEGACY_RUN_ID, "Legacy import (pre-run-history)", now, now),
    )

    conn.executescript(
        """
        DROP TRIGGER IF EXISTS functions_ai;
        DROP TRIGGER IF EXISTS functions_ad;
        DROP TRIGGER IF EXISTS functions_au;
        DROP TABLE IF EXISTS functions_fts;

        CREATE TABLE functions_migrated (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id          TEXT    NOT NULL DEFAULT 'legacy',
            entry_point     TEXT    NOT NULL,
            function_name   TEXT    NOT NULL DEFAULT '',
            suggested_name  TEXT    NOT NULL DEFAULT '',
            summary         TEXT    NOT NULL DEFAULT '',
            category        TEXT    NOT NULL DEFAULT '',
            confidence      TEXT    NOT NULL DEFAULT '',
            side_effects    TEXT    NOT NULL DEFAULT '[]',
            uncertainties   TEXT    NOT NULL DEFAULT '[]',
            decompiled_code TEXT    NOT NULL DEFAULT '',
            source_file     TEXT    NOT NULL DEFAULT '',
            ingested_at     TEXT    NOT NULL DEFAULT '',
            embedding       BLOB,
            UNIQUE (run_id, entry_point)
        );

        INSERT INTO functions_migrated
            (id, run_id, entry_point, function_name, suggested_name, summary,
             category, confidence, side_effects, uncertainties, decompiled_code,
             source_file, ingested_at, embedding)
        SELECT id, 'legacy', entry_point, function_name, suggested_name, summary,
               category, confidence, side_effects, uncertainties,
               COALESCE(decompiled_code, ''), source_file, ingested_at, embedding
        FROM functions;

        DROP TABLE functions;
        ALTER TABLE functions_migrated RENAME TO functions;
        """
    )
    conn.executescript(_DDL_FTS + _DDL_FTS_TRIGGERS)
    conn.execute(
        """
        INSERT INTO functions_fts(rowid, entry_point, function_name, suggested_name,
                                    summary, side_effects, category, confidence)
        SELECT id, entry_point, function_name, suggested_name, summary,
               side_effects, category, confidence
        FROM functions
        """
    )


def init_db(db_path: str | Path) -> None:
    """Create schema and apply migrations."""
    with _connect(db_path) as conn:
        conn.executescript(_DDL_ANALYSIS_RUNS)
        if not _table_exists(conn, "functions"):
            conn.executescript(_DDL_FUNCTIONS + _DDL_FTS + _DDL_FTS_TRIGGERS)
        else:
            _migrate_legacy_schema(conn)
            if not _table_exists(conn, "functions_fts"):
                conn.executescript(_DDL_FTS + _DDL_FTS_TRIGGERS)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_run(
    db_path: str | Path,
    *,
    label: str = "",
    model: str = "",
    backend: str = "",
    prompt_version: str = "",
    postprocess_version: str = "",
    source_input: str = "",
    run_id: str | None = None,
) -> str:
    """Insert a new analysis run row and return run_id."""
    rid = run_id or uuid.uuid4().hex
    now = _utc_now()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO analysis_runs
                (run_id, label, model, backend, prompt_version, postprocess_version,
                 source_input, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                label,
                model,
                backend,
                prompt_version,
                postprocess_version,
                source_input,
                now,
            ),
        )
    return rid


def complete_run(
    db_path: str | Path,
    run_id: str,
    *,
    function_count: int = 0,
    error_count: int = 0,
) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE analysis_runs SET
                completed_at = ?,
                function_count = ?,
                error_count = ?
            WHERE run_id = ?
            """,
            (_utc_now(), function_count, error_count, run_id),
        )


def list_runs(db_path: str | Path, *, limit: int = 50) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM analysis_runs
            ORDER BY rowid DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_run(db_path: str | Path, run_id: str) -> dict[str, Any] | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM analysis_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return dict(row) if row else None


def resolve_run_id(db_path: str | Path, run_id: str | None = None) -> str | None:
    """Return run_id if valid, else latest run, else legacy, else None."""
    if not Path(db_path).exists():
        return None
    init_db(db_path)
    with _connect(db_path) as conn:
        if run_id:
            row = conn.execute(
                "SELECT run_id FROM analysis_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row:
                return run_id
        row = conn.execute(
            """
            SELECT run_id FROM analysis_runs
            ORDER BY rowid DESC
            LIMIT 1
            """
        ).fetchone()
        if row:
            return row["run_id"]
        count = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
        if count:
            return LEGACY_RUN_ID
    return None


def ensure_run_for_ingest(
    db_path: str | Path,
    results: Sequence[AnalysisResult],
    *,
    source_file: str = "",
    label: str = "",
) -> str:
    """Use run_id from results or create a synthetic ingest run."""
    init_db(db_path)
    run_ids = {r.run_id for r in results if r.run_id}
    if len(run_ids) == 1:
        rid = next(iter(run_ids))
        if get_run(db_path, rid):
            return rid
    from src.versions import POSTPROCESS_VERSION, prompt_version_for

    first = results[0] if results else None
    return create_run(
        db_path,
        label=label or f"Ingest {source_file or 'results'}",
        model=first.model if first else "",
        backend=first.backend if first else "",
        prompt_version=first.prompt_version if first else prompt_version_for("summarize.txt"),
        postprocess_version=first.postprocess_version if first else POSTPROCESS_VERSION,
        source_input=source_file,
        run_id=first.run_id if first and first.run_id else None,
    )


def ingest_results(
    results: Sequence[AnalysisResult],
    db_path: str | Path,
    *,
    source_file: str = "",
    decompiled_code_map: dict[str, str] | None = None,
    run_id: str | None = None,
) -> tuple[int, int]:
    """
    Insert or update analysis results for a run.

    Returns (inserted, updated) counts.
    """
    init_db(db_path)
    if not results:
        return 0, 0

    if run_id:
        rid = run_id
    elif results[0].run_id:
        rid = results[0].run_id
    else:
        rid = ensure_run_for_ingest(
            db_path, results, source_file=source_file, label=f"Ingest {source_file}"
        )

    if not get_run(db_path, rid):
        from src.versions import POSTPROCESS_VERSION, prompt_version_for

        first = results[0]
        create_run(
            db_path,
            run_id=rid,
            label=f"Ingest {source_file or rid[:8]}",
            model=first.model,
            backend=first.backend,
            prompt_version=first.prompt_version or prompt_version_for("summarize.txt"),
            postprocess_version=first.postprocess_version or POSTPROCESS_VERSION,
            source_input=source_file,
        )

    now = _utc_now()
    inserted = 0
    updated = 0
    dcode_map = decompiled_code_map or {}

    with _connect(db_path) as conn:
        for r in results:
            row_run = r.run_id or rid
            existing = conn.execute(
                "SELECT id FROM functions WHERE run_id = ? AND entry_point = ?",
                (row_run, r.entry_point),
            ).fetchone()

            side_effects_json = json.dumps(r.side_effects, ensure_ascii=False)
            uncertainties_json = json.dumps(r.uncertainties, ensure_ascii=False)
            decompiled_code = dcode_map.get(r.entry_point, "")

            if existing:
                conn.execute(
                    """
                    UPDATE functions SET
                        function_name   = ?,
                        suggested_name  = ?,
                        summary         = ?,
                        category        = ?,
                        confidence      = ?,
                        side_effects    = ?,
                        uncertainties   = ?,
                        decompiled_code = CASE WHEN ? != '' THEN ? ELSE decompiled_code END,
                        source_file     = ?,
                        ingested_at     = ?
                    WHERE run_id = ? AND entry_point = ?
                    """,
                    (
                        r.function_name,
                        r.suggested_name or "",
                        r.summary or "",
                        r.category or "",
                        r.confidence or "",
                        side_effects_json,
                        uncertainties_json,
                        decompiled_code,
                        decompiled_code,
                        source_file,
                        now,
                        row_run,
                        r.entry_point,
                    ),
                )
                updated += 1
            else:
                conn.execute(
                    """
                    INSERT INTO functions
                        (run_id, entry_point, function_name, suggested_name, summary,
                         category, confidence, side_effects, uncertainties,
                         decompiled_code, source_file, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row_run,
                        r.entry_point,
                        r.function_name,
                        r.suggested_name or "",
                        r.summary or "",
                        r.category or "",
                        r.confidence or "",
                        side_effects_json,
                        uncertainties_json,
                        decompiled_code,
                        source_file,
                        now,
                    ),
                )
                inserted += 1

        conn.execute(
            """
            UPDATE analysis_runs SET
                function_count = (SELECT COUNT(*) FROM functions WHERE run_id = ?),
                completed_at = ?
            WHERE run_id = ?
            """,
            (rid, now, rid),
        )

    return inserted, updated


def search(
    db_path: str | Path,
    *,
    query: str | None = None,
    category: str | None = None,
    confidence: str | None = None,
    run_id: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    rid = resolve_run_id(db_path, run_id)
    if rid is None:
        return []

    with _connect(db_path) as conn:
        rows = _run_search(
            conn,
            query=query,
            category=category,
            confidence=confidence,
            run_id=rid,
            limit=limit,
        )
    return [_deserialize_row(r) for r in rows]


def get_function(
    db_path: str | Path,
    entry_point: str,
    *,
    run_id: str | None = None,
) -> dict[str, Any] | None:
    rid = resolve_run_id(db_path, run_id)
    if rid is None:
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM functions WHERE run_id = ? AND entry_point = ?",
            (rid, entry_point),
        ).fetchone()
    if row is None:
        return None
    return _deserialize_row(row)


def all_results_as_analysis(
    db_path: str | Path,
    *,
    run_id: str | None = None,
) -> list[AnalysisResult]:
    rid = resolve_run_id(db_path, run_id)
    if rid is None:
        return []

    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM functions WHERE run_id = ? ORDER BY ingested_at DESC",
            (rid,),
        ).fetchall()

    results: list[AnalysisResult] = []
    run_meta = get_run(db_path, rid) or {}
    for row in rows:
        d = _deserialize_row(row)
        results.append(
            AnalysisResult(
                function_name=d["function_name"],
                entry_point=d["entry_point"],
                summary=d["summary"],
                suggested_name=d["suggested_name"],
                category=d["category"],
                confidence=d["confidence"],
                side_effects=d["side_effects"],
                uncertainties=d["uncertainties"],
                raw_response="",
                run_id=d.get("run_id", rid),
                model=run_meta.get("model", ""),
                backend=run_meta.get("backend", ""),
                prompt_version=run_meta.get("prompt_version", ""),
                postprocess_version=run_meta.get("postprocess_version", ""),
            )
        )
    return results


def get_stats(
    db_path: str | Path,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    rid = resolve_run_id(db_path, run_id)
    if rid is None:
        return {
            "total": 0,
            "by_category": {},
            "by_confidence": {},
            "sources": [],
            "run_id": None,
        }

    with _connect(db_path) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM functions WHERE run_id = ?", (rid,)
        ).fetchone()[0]

        by_category = {
            row["category"]: row["cnt"]
            for row in conn.execute(
                "SELECT category, COUNT(*) AS cnt FROM functions WHERE run_id = ? "
                "GROUP BY category ORDER BY cnt DESC",
                (rid,),
            ).fetchall()
        }

        by_confidence = {
            row["confidence"]: row["cnt"]
            for row in conn.execute(
                "SELECT confidence, COUNT(*) AS cnt FROM functions WHERE run_id = ? "
                "GROUP BY confidence ORDER BY cnt DESC",
                (rid,),
            ).fetchall()
        }

        sources = [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT source_file FROM functions "
                "WHERE run_id = ? AND source_file != ''",
                (rid,),
            ).fetchall()
        ]

    return {
        "total": total,
        "by_category": by_category,
        "by_confidence": by_confidence,
        "sources": sources,
        "run_id": rid,
    }


def _run_search(
    conn: sqlite3.Connection,
    *,
    query: str | None,
    category: str | None,
    confidence: str | None,
    run_id: str,
    limit: int,
) -> list[sqlite3.Row]:
    params: list[Any] = []

    if query:
        sql = """
            SELECT f.*
            FROM functions f
            JOIN functions_fts fts ON f.id = fts.rowid
            WHERE functions_fts MATCH ?
              AND f.run_id = ?
        """
        params.extend([_fts_query(query), run_id])

        if category:
            sql += " AND f.category = ?"
            params.append(category)
        if confidence:
            sql += " AND f.confidence = ?"
            params.append(confidence)

        sql += " ORDER BY rank"
    else:
        sql = "SELECT * FROM functions WHERE run_id = ?"
        params.append(run_id)

        if category:
            sql += " AND category = ?"
            params.append(category)
        if confidence:
            sql += " AND confidence = ?"
            params.append(confidence)

        sql += " ORDER BY ingested_at DESC"

    if limit and limit > 0:
        sql += f" LIMIT {int(limit)}"

    return conn.execute(sql, params).fetchall()


def _fts_query(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('"') or any(op in raw for op in ("AND", "OR", "NOT", "NEAR")):
        return raw
    terms = [f"{word.strip()}*" for word in raw.split() if word.strip()]
    return " AND ".join(terms)


def _deserialize_row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for field in ("side_effects", "uncertainties"):
        raw = d.get(field, "[]")
        try:
            d[field] = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            d[field] = []
    return d
