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

import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    jsonify,
    make_response,
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
    uploads_dir = _ROOT / "data" / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    # In-memory import jobs (local process only)
    _jobs: dict[str, dict[str, Any]] = {}
    _jobs_lock = threading.Lock()

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

    def _update_job(job_id: str, **updates: Any) -> None:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id].update(updates)

    def _run_analysis_job(job_id: str, jsonl_path: Path) -> None:
        from src import db, importer
        from src.analyzer import Analyzer

        try:
            llm_cfg = config.get("llm", {})
            analyzer = Analyzer(llm_cfg)

            _update_job(job_id, status="loading", message="Loading input file...")
            functions = list(importer.load(str(jsonl_path)))
            total = len(functions)
            if total == 0:
                _update_job(
                    job_id,
                    status="error",
                    message="The uploaded file has no valid function records.",
                    total=0,
                )
                return

            _update_job(
                job_id,
                status="running",
                message="Analyzing functions with local LLM...",
                total=total,
                done=0,
                errors=0,
            )

            results = []
            decompiled_code_map: dict[str, str] = {}
            errors = 0

            for idx, fn in enumerate(functions, start=1):
                ep = fn.get("entryPoint", "") or fn.get("entry_point", "")
                if ep:
                    decompiled = fn.get("decompiledCode", "") or fn.get("decompiled_code", "")
                    if decompiled:
                        decompiled_code_map[ep] = decompiled

                try:
                    result = analyzer.analyze_function(fn)
                    results.append(result)
                except Exception:
                    errors += 1
                finally:
                    _update_job(job_id, done=idx, errors=errors)

            if not results:
                _update_job(
                    job_id,
                    status="error",
                    message="Analysis failed for all functions. Check your model/server.",
                )
                return

            _update_job(job_id, status="ingesting", message="Loading results into database...")
            db.init_db(db_path)
            inserted, updated = db.ingest_results(
                results,
                db_path,
                source_file=jsonl_path.name,
                decompiled_code_map=decompiled_code_map,
            )

            _update_job(
                job_id,
                status="complete",
                message=(
                    f"Import complete: {len(results)} analyzed, "
                    f"{inserted} inserted, {updated} updated, {errors} errors."
                ),
                inserted=inserted,
                updated=updated,
            )
        except Exception as exc:
            _update_job(job_id, status="error", message=f"Import failed: {exc}")

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
            upload_job=None,
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

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        up = request.files.get("file")
        if up is None or not up.filename:
            return jsonify({"error": "No file uploaded."}), 400
        if not up.filename.lower().endswith(".jsonl"):
            return jsonify({"error": "Only .jsonl files are supported."}), 400

        from src.analyzer import Analyzer

        analyzer = Analyzer(config.get("llm", {}))
        if not analyzer.ping():
            return jsonify({
                "error": (
                    "LLM backend is not reachable. "
                    "Start Ollama/local server and try again."
                )
            }), 503

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = f"{ts}_{uuid.uuid4().hex}_{Path(up.filename).name}"
        out_path = uploads_dir / safe_name
        up.save(out_path)

        job_id = uuid.uuid4().hex
        with _jobs_lock:
            _jobs[job_id] = {
                "id": job_id,
                "status": "queued",
                "message": "Queued...",
                "total": 0,
                "done": 0,
                "errors": 0,
            }

        thread = threading.Thread(
            target=_run_analysis_job,
            args=(job_id, out_path),
            daemon=True,
        )
        thread.start()

        return jsonify({"job_id": job_id})

    @app.route("/api/job/<job_id>")
    def api_job(job_id: str):
        with _jobs_lock:
            job = dict(_jobs.get(job_id, {}))
        if not job:
            return make_response(render_template(
                "partials/progress_bar.html",
                job={"id": job_id, "status": "error", "message": "Job not found."},
            ), 404)

        response = make_response(render_template("partials/progress_bar.html", job=job))
        if job.get("status") in {"complete", "error"}:
            response.headers["HX-Trigger"] = "jobComplete"
        return response

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
