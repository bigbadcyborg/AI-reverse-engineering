"""
Dashboard: local Flask web interface for the RE Toolkit.

Start via CLI:
    python -m src.cli dashboard

Then open http://localhost:5000 in any browser.

Features:
  - Function list with live search (HTMX, no page reload)
  - Category and confidence filters
  - Decompiled code viewer with C syntax highlighting (Prism.js)
  - LLM summary, side effects, and uncertainty viewer
  - Rename approval/rejection buttons (writes to approved_renames.json)
  - One-click Markdown report export

The dashboard reads from the SQLite database populated by `ingest`.
It writes back to the approved_renames.json file used by ImportApprovedRenames.java.

All data stays on-device. No external requests are made by the server.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

# Paths resolved relative to the project root (one level up from src/)
_ROOT = Path(__file__).parent.parent


def create_app(config: dict) -> Flask:
    """
    Flask application factory.

    Args:
        config: parsed config.json as a dict
    """
    app = Flask(
        __name__,
        template_folder=str(_ROOT / "web" / "templates"),
        static_folder=str(_ROOT / "web" / "static"),
        static_url_path="/static",
    )
    app.secret_key = "retool-local-dashboard"  # session flash messages only

    db_path = Path(config.get("output", {}).get("db_path", "data/output/analysis.db"))
    report_dir = Path(config.get("output", {}).get("report_dir", "reports"))
    approved_path = db_path.parent / "approved_renames.json"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _db_exists() -> bool:
        return db_path.exists()

    def _load_approvals() -> dict[str, bool]:
        """Return entry_point -> approved mapping from approved_renames.json."""
        if not approved_path.exists():
            return {}
        try:
            from src.approver import load_approved_renames
            entries = load_approved_renames(approved_path)
            return {e.entry_point: e.approved for e in entries}
        except Exception:
            return {}

    def _save_approval(entry_point: str, approved: bool, fn_row: dict) -> None:
        """Update or create an entry in approved_renames.json."""
        from src.approver import ApprovedRename, load_approved_renames, save_approved_renames

        if approved_path.exists():
            entries = load_approved_renames(approved_path)
        else:
            entries = []

        # Update existing entry or add new one
        found = False
        for e in entries:
            if e.entry_point == entry_point:
                e.approved = approved
                found = True
                break

        if not found:
            reason = (fn_row.get("summary") or "")[:300]
            entries.append(ApprovedRename(
                entry_point=entry_point,
                old_name=fn_row.get("function_name", ""),
                new_name=fn_row.get("suggested_name", ""),
                confidence=fn_row.get("confidence", "low"),
                reason=reason,
                approved=approved,
                comment=reason,
                allow_overwrite=False,
            ))

        save_approved_renames(entries, approved_path)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        if not _db_exists():
            return render_template("no_db.html", db_path=db_path)

        from src import db

        stats = db.get_stats(db_path)
        q        = request.args.get("q", "").strip()
        category = request.args.get("category", "").strip()
        confidence = request.args.get("confidence", "").strip()
        limit    = int(request.args.get("limit", 50))

        functions = db.search(
            db_path,
            query=q or None,
            category=category or None,
            confidence=confidence or None,
            limit=limit,
        )

        return render_template(
            "index.html",
            stats=stats,
            functions=functions,
            q=q,
            category=category,
            confidence=confidence,
            limit=limit,
        )

    @app.route("/api/search")
    def api_search():
        """HTMX endpoint — returns only the function list partial."""
        if not _db_exists():
            return "<p>Database not found. Run <code>ingest</code> first.</p>"

        from src import db

        q          = request.args.get("q", "").strip()
        category   = request.args.get("category", "").strip()
        confidence = request.args.get("confidence", "").strip()
        limit      = int(request.args.get("limit", 50))

        functions = db.search(
            db_path,
            query=q or None,
            category=category or None,
            confidence=confidence or None,
            limit=limit,
        )

        return render_template("partials/function_list.html", functions=functions, limit=limit)

    @app.route("/function/<path:entry_point>")
    def function_detail(entry_point: str):
        if not _db_exists():
            return redirect(url_for("index"))

        from src import db

        fn = db.get_function(db_path, entry_point)
        if fn is None:
            flash(f"Function {entry_point!r} not found in database.", "error")
            return redirect(url_for("index"))

        approvals = _load_approvals()
        approval_status = None
        if entry_point in approvals:
            approval_status = "approved" if approvals[entry_point] else "rejected"
        elif fn.get("suggested_name") and fn["suggested_name"] != fn["function_name"]:
            approval_status = "pending"

        return render_template(
            "function.html",
            fn=fn,
            approval_status=approval_status,
        )

    @app.route("/api/approve", methods=["POST"])
    def api_approve():
        """Toggle rename approval for a single function. Returns HTML partial."""
        entry_point = request.form.get("entry_point", "")
        approved    = request.form.get("approved", "false").lower() == "true"

        if not _db_exists() or not entry_point:
            return "<span>Error: invalid request</span>", 400

        from src import db

        fn = db.get_function(db_path, entry_point)
        if fn is None:
            return "<span>Function not found</span>", 404

        _save_approval(entry_point, approved, fn)

        approval_status = "approved" if approved else "rejected"
        return render_template(
            "partials/approve_section.html",
            fn=fn,
            approval_status=approval_status,
        )

    @app.route("/report")
    def export_report():
        """Generate a Markdown report from all DB contents and serve it."""
        if not _db_exists():
            flash("Database not found. Run ingest first.", "error")
            return redirect(url_for("index"))

        from src import db, reporter

        results = db.all_results_as_analysis(db_path)
        if not results:
            flash("No analysis results in database.", "error")
            return redirect(url_for("index"))

        report_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = report_dir / f"dashboard_export_{ts}.md"
        reporter.generate_report(results, str(out_path), source="dashboard export")

        # Offer the file as a download
        return send_file(
            str(out_path.resolve()),
            as_attachment=True,
            download_name=out_path.name,
            mimetype="text/markdown",
        )

    @app.route("/approved")
    def approved_list():
        """Show all entries in approved_renames.json."""
        entries: list[Any] = []
        if approved_path.exists():
            from src.approver import load_approved_renames
            entries = load_approved_renames(approved_path)

        return render_template("approved.html", entries=entries, approved_path=approved_path)

    # ------------------------------------------------------------------
    # Template filters
    # ------------------------------------------------------------------

    @app.template_filter("short_addr")
    def short_addr(addr: str) -> str:
        """Trim leading zeros from an address for compact display."""
        if addr.startswith("0x") or addr.startswith("0X"):
            return "0x" + addr[2:].lstrip("0") or "0x0"
        return addr

    @app.template_filter("truncate_nl")
    def truncate_nl(text: str, length: int = 100) -> str:
        """Truncate at the first newline or at length, whichever comes first."""
        if not text:
            return ""
        text = text.split("\n")[0]
        if len(text) > length:
            return text[:length] + "..."
        return text

    return app
