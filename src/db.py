"""
Database: SQLite-backed storage and full-text search for analysis results.

Schema
------
functions
    One row per analyzed function. Mirrors AnalysisResult fields.
    entry_point is the unique key — re-ingesting the same address upserts.

functions_fts
    FTS5 virtual table over function_name, suggested_name, summary, and
    side_effects text. Rebuilt in full after every ingest batch.

Usage
-----
    from src.db import init_db, ingest_results, search, get_stats

    db_path = "data/output/analysis.db"
    init_db(db_path)
    ingest_results(results, db_path, source_file="results.jsonl")

    rows = search(db_path, query="command dispatch", confidence="high")
    stats = get_stats(db_path)

Search precedence
-----------------
When --query is given the results are ordered by FTS relevance (BM25 rank).
Category and confidence filters are AND-ed on top of the FTS match.
When no --query is given the filters are applied directly to the main table.

Future extension points
-----------------------
The 'embedding' BLOB column is reserved for local vector embeddings (iteration 8).
A separate embeddings_index table will be added at that point.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from src.analyzer import AnalysisResult

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL_FUNCTIONS = """
CREATE TABLE IF NOT EXISTS functions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_point   TEXT    UNIQUE NOT NULL,
    function_name TEXT    NOT NULL DEFAULT '',
    suggested_name TEXT   NOT NULL DEFAULT '',
    summary       TEXT    NOT NULL DEFAULT '',
    category      TEXT    NOT NULL DEFAULT '',
    confidence    TEXT    NOT NULL DEFAULT '',
    side_effects  TEXT    NOT NULL DEFAULT '[]',   -- JSON array
    uncertainties TEXT    NOT NULL DEFAULT '[]',   -- JSON array
    source_file   TEXT    NOT NULL DEFAULT '',
    ingested_at   TEXT    NOT NULL DEFAULT '',
    embedding     BLOB                             -- reserved for iteration 8
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

# Triggers keep the FTS content table in sync with the main table.
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


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def _connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db(db_path: str | Path) -> None:
    """Create the database schema if it does not already exist."""
    with _connect(db_path) as conn:
        conn.executescript(_DDL_FUNCTIONS + _DDL_FTS + _DDL_FTS_TRIGGERS)


def ingest_results(
    results: Sequence[AnalysisResult],
    db_path: str | Path,
    *,
    source_file: str = "",
) -> tuple[int, int]:
    """
    Insert or update analysis results in the database.

    Existing rows with the same entry_point are replaced (upsert).
    The FTS triggers keep the search index in sync automatically.

    Returns:
        (inserted, updated) counts
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inserted = 0
    updated = 0

    with _connect(db_path) as conn:
        for r in results:
            # Check whether this entry_point already exists
            existing = conn.execute(
                "SELECT id FROM functions WHERE entry_point = ?", (r.entry_point,)
            ).fetchone()

            side_effects_json  = json.dumps(r.side_effects,  ensure_ascii=False)
            uncertainties_json = json.dumps(r.uncertainties, ensure_ascii=False)

            if existing:
                conn.execute(
                    """
                    UPDATE functions SET
                        function_name  = ?,
                        suggested_name = ?,
                        summary        = ?,
                        category       = ?,
                        confidence     = ?,
                        side_effects   = ?,
                        uncertainties  = ?,
                        source_file    = ?,
                        ingested_at    = ?
                    WHERE entry_point = ?
                    """,
                    (
                        r.function_name,
                        r.suggested_name or "",
                        r.summary or "",
                        r.category or "",
                        r.confidence or "",
                        side_effects_json,
                        uncertainties_json,
                        source_file,
                        now,
                        r.entry_point,
                    ),
                )
                updated += 1
            else:
                conn.execute(
                    """
                    INSERT INTO functions
                        (entry_point, function_name, suggested_name, summary,
                         category, confidence, side_effects, uncertainties,
                         source_file, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        r.entry_point,
                        r.function_name,
                        r.suggested_name or "",
                        r.summary or "",
                        r.category or "",
                        r.confidence or "",
                        side_effects_json,
                        uncertainties_json,
                        source_file,
                        now,
                    ),
                )
                inserted += 1

    return inserted, updated


def search(
    db_path: str | Path,
    *,
    query: str | None = None,
    category: str | None = None,
    confidence: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """
    Search analyzed functions.

    Args:
        query:      Full-text keyword search (BM25 ranked). Searched across
                    function_name, suggested_name, summary, and side_effects.
        category:   Exact match on the category field (e.g. "crypto", "file_io").
        confidence: Exact match on confidence (low | medium | high).
        limit:      Maximum number of results (default 20, 0 = unlimited).

    Returns:
        List of row dicts with deserialized side_effects and uncertainties lists.
    """
    with _connect(db_path) as conn:
        rows = _run_search(conn, query=query, category=category,
                           confidence=confidence, limit=limit)
    return [_deserialize_row(r) for r in rows]


def get_stats(db_path: str | Path) -> dict[str, Any]:
    """
    Return summary statistics about the database contents.

    Returns:
        {
          "total": int,
          "by_category": {"crypto": 5, "file_io": 12, ...},
          "by_confidence": {"low": 3, "medium": 20, "high": 10},
          "sources": ["results.jsonl", ...],
        }
    """
    with _connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]

        by_category = {
            row["category"]: row["cnt"]
            for row in conn.execute(
                "SELECT category, COUNT(*) AS cnt FROM functions "
                "GROUP BY category ORDER BY cnt DESC"
            ).fetchall()
        }

        by_confidence = {
            row["confidence"]: row["cnt"]
            for row in conn.execute(
                "SELECT confidence, COUNT(*) AS cnt FROM functions "
                "GROUP BY confidence ORDER BY cnt DESC"
            ).fetchall()
        }

        sources = [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT source_file FROM functions WHERE source_file != ''"
            ).fetchall()
        ]

    return {
        "total": total,
        "by_category": by_category,
        "by_confidence": by_confidence,
        "sources": sources,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_search(
    conn: sqlite3.Connection,
    *,
    query: str | None,
    category: str | None,
    confidence: str | None,
    limit: int,
) -> list[sqlite3.Row]:
    """Build and execute the appropriate SQL query."""

    params: list[Any] = []

    if query:
        # FTS5 match — join main table to get all columns, rank by relevance
        sql = """
            SELECT f.*
            FROM functions f
            JOIN functions_fts fts ON f.id = fts.rowid
            WHERE functions_fts MATCH ?
        """
        params.append(_fts_query(query))

        if category:
            sql += " AND f.category = ?"
            params.append(category)
        if confidence:
            sql += " AND f.confidence = ?"
            params.append(confidence)

        sql += " ORDER BY rank"
    else:
        # No text query — filter directly on the main table
        sql = "SELECT * FROM functions WHERE 1=1"

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
    """
    Convert a plain-text query into an FTS5 query string.

    Multi-word input becomes an implicit AND of prefix matches so that
    "file parse" finds functions mentioning both "file" and "parse".
    Quotes and special FTS5 operators are passed through unchanged if the
    user wraps their query in quotes (e.g. '"exact phrase"').
    """
    raw = raw.strip()
    # If the user already wrote a quoted phrase or uses FTS operators, pass through
    if raw.startswith('"') or any(op in raw for op in ("AND", "OR", "NOT", "NEAR")):
        return raw
    # Otherwise turn each word into a prefix match term
    terms = [f"{word.strip()}*" for word in raw.split() if word.strip()]
    return " AND ".join(terms)


def _deserialize_row(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a sqlite3.Row to a plain dict, deserializing JSON list columns."""
    d = dict(row)
    for field in ("side_effects", "uncertainties"):
        raw = d.get(field, "[]")
        try:
            d[field] = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            d[field] = []
    return d
