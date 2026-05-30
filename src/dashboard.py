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
    session,
    url_for,
)

# Paths resolved relative to the project root (one level up from src/)
_ROOT = Path(__file__).parent.parent


_ACTIVE_JOB_STATUSES = frozenset({"queued", "running", "loading", "ingesting"})


def create_app(config: dict, *, config_path: Path | None = None) -> Flask:
    """
    Flask application factory.

    Args:
        config: parsed config.json as a dict (mutated when LLM settings change)
        config_path: path to config.json for persistence (default: project config.json)
    """
    runtime_config = config
    resolved_config_path = Path(config_path or _ROOT / "config.json")
    _config_lock = threading.Lock()

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

    def _get_llm_config() -> dict[str, Any]:
        with _config_lock:
            return dict(runtime_config.get("llm") or {})

    def _has_active_import_job() -> bool:
        with _jobs_lock:
            return any(
                j.get("status") in _ACTIVE_JOB_STATUSES for j in _jobs.values()
            )

    def _llm_settings_context(*, refresh_models: bool = False, message: str = "", error: str = "") -> dict[str, Any]:
        from src.analyzer import Analyzer

        llm_cfg = _get_llm_config()
        analyzer = Analyzer(llm_cfg)
        reachable = analyzer.ping()
        models, _, models_error = analyzer.list_models(refresh=refresh_models)
        current_model = llm_cfg.get("model", "")
        if current_model and current_model not in models:
            models = sorted(set(models) | {current_model}, key=str.lower)
        return {
            "backend": llm_cfg.get("backend", "ollama"),
            "base_url": llm_cfg.get("base_url", ""),
            "model": current_model,
            "reachable": reachable,
            "models": models,
            "models_error": models_error or "",
            "message": message,
            "error": error,
        }

    def _selected_run_id() -> str | None:
        from src import db

        if not _db_exists():
            return None
        run_param = request.args.get("run", "").strip()
        if run_param:
            return db.resolve_run_id(db_path, run_param)
        session_run = session.get("run_id", "").strip()
        if session_run:
            resolved = db.resolve_run_id(db_path, session_run)
            if resolved:
                return resolved
        return db.resolve_run_id(db_path, None)

    def _runs_context() -> dict[str, Any]:
        from src import db

        if not _db_exists():
            return {"runs": [], "selected_run_id": None, "selected_run": None}
        db.init_db(db_path)
        runs = db.list_runs(db_path)
        selected = _selected_run_id()
        selected_run = db.get_run(db_path, selected) if selected else None
        return {
            "runs": runs,
            "selected_run_id": selected,
            "selected_run": selected_run,
        }

    def _run_query_suffix(run_id: str | None) -> str:
        if run_id:
            return f"run={run_id}"
        return ""

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
        from src import batch, db, importer
        from src.analyzer import Analyzer
        from src.prioritizer import prioritize
        from src.progress import PHASE_INGESTING, ProgressUpdate
        from src.versions import POSTPROCESS_VERSION, prompt_version_for

        try:
            llm_cfg = _get_llm_config()
            analyzer = Analyzer(llm_cfg)
            model_name = llm_cfg.get("model", "")
            backend_name = llm_cfg.get("backend", "ollama")

            _update_job(
                job_id,
                status="loading",
                phase="loading",
                message="Loading input file...",
                model=model_name,
                backend=backend_name,
                started_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            functions = list(importer.load(str(jsonl_path)))
            functions = prioritize(functions, runtime_config)
            total = len(functions)
            if total == 0:
                _update_job(
                    job_id,
                    status="error",
                    phase="error",
                    message="The uploaded file has no valid function records.",
                    total=0,
                )
                return

            db.init_db(db_path)
            run_id = db.create_run(
                db_path,
                label=f"Import {jsonl_path.name}",
                model=model_name,
                backend=backend_name,
                prompt_version=prompt_version_for("summarize.txt"),
                postprocess_version=POSTPROCESS_VERSION,
                source_input=str(jsonl_path),
            )

            _update_job(
                job_id,
                status="running",
                phase="running",
                message="Starting LLM analysis...",
                total=total,
                done=0,
                errors=0,
                run_id=run_id,
            )

            def on_progress(update: ProgressUpdate) -> None:
                if update.phase == "error":
                    status = "error"
                else:
                    status = "running"
                _update_job(
                    job_id,
                    status=status,
                    phase=update.phase,
                    message=update.message,
                    done=update.completed,
                    total=update.total or total,
                    errors=update.errors,
                    current_function=update.function_name,
                    entry_point=update.entry_point,
                    model=update.model or model_name,
                )

            results, errors, decompiled_code_map = batch.run_batch_analysis(
                functions,
                analyzer,
                run_id=run_id,
                on_progress=on_progress,
            )

            if not results:
                _update_job(
                    job_id,
                    status="error",
                    phase="error",
                    message="Analysis failed for all functions. Check your model/server.",
                )
                return

            _update_job(
                job_id,
                status="ingesting",
                phase=PHASE_INGESTING,
                message="Loading results into database...",
            )
            inserted, updated = db.ingest_results(
                results,
                db_path,
                source_file=jsonl_path.name,
                decompiled_code_map=decompiled_code_map,
                run_id=run_id,
            )
            db.complete_run(
                db_path,
                run_id,
                function_count=len(results),
                error_count=errors,
            )

            _update_job(
                job_id,
                status="complete",
                phase="complete",
                done=total,
                message=(
                    f"Import complete: {len(results)} analyzed, "
                    f"{inserted} inserted, {updated} updated, {errors} errors. "
                    f"Run {run_id[:8]}…"
                ),
                inserted=inserted,
                updated=updated,
                run_id=run_id,
            )
        except Exception as exc:
            _update_job(
                job_id,
                status="error",
                phase="error",
                message=f"Import failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        if not _db_exists():
            return render_template("no_db.html", db_path=db_path)

        from src import db

        run_param = request.args.get("run", "").strip()
        if run_param and db.resolve_run_id(db_path, run_param):
            session["run_id"] = run_param

        run_id = _selected_run_id()
        stats = db.get_stats(db_path, run_id=run_id)
        q        = request.args.get("q", "").strip()
        category = request.args.get("category", "").strip()
        confidence = request.args.get("confidence", "").strip()
        limit    = int(request.args.get("limit", 50))

        functions = db.search(
            db_path,
            query=q or None,
            category=category or None,
            confidence=confidence or None,
            run_id=run_id,
            limit=limit,
        )
        runs_ctx = _runs_context()

        return render_template(
            "index.html",
            stats=stats,
            functions=functions,
            q=q,
            category=category,
            confidence=confidence,
            limit=limit,
            upload_job=None,
            **runs_ctx,
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
        run_id     = request.args.get("run", "").strip() or _selected_run_id()

        functions = db.search(
            db_path,
            query=q or None,
            category=category or None,
            confidence=confidence or None,
            run_id=run_id,
            limit=limit,
        )

        return render_template(
            "partials/function_list.html",
            functions=functions,
            limit=limit,
            selected_run_id=run_id,
        )

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        up = request.files.get("file")
        if up is None or not up.filename:
            return jsonify({"error": "No file uploaded."}), 400
        if not up.filename.lower().endswith(".jsonl"):
            return jsonify({"error": "Only .jsonl files are supported."}), 400

        from src.analyzer import Analyzer

        analyzer = Analyzer(_get_llm_config())
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
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        upload_llm = _get_llm_config()
        with _jobs_lock:
            _jobs[job_id] = {
                "id": job_id,
                "status": "queued",
                "phase": "queued",
                "message": "Queued...",
                "total": 0,
                "done": 0,
                "errors": 0,
                "current_function": "",
                "entry_point": "",
                "model": upload_llm.get("model", ""),
                "backend": upload_llm.get("backend", "ollama"),
                "started_at": started_at,
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
        from src.progress import (
            PHASE_LABELS,
            elapsed_seconds_since,
            estimate_eta_seconds,
        )

        with _jobs_lock:
            job = dict(_jobs.get(job_id, {}))
        if not job:
            return make_response(render_template(
                "partials/progress_bar.html",
                job={"id": job_id, "status": "error", "message": "Job not found."},
            ), 404)

        elapsed = elapsed_seconds_since(job.get("started_at", ""))
        done = job.get("done", 0) or 0
        total = job.get("total", 0) or 0
        job["elapsed_seconds"] = elapsed
        eta = estimate_eta_seconds(elapsed, done, total)
        job["eta_seconds"] = eta
        m, s = divmod(elapsed, 60)
        job["elapsed_display"] = f"{m}:{s:02d}"
        if eta is not None:
            em, es = divmod(eta, 60)
            job["eta_display"] = f"{em}:{es:02d}"
        else:
            job["eta_display"] = None
        phase = job.get("phase", job.get("status", ""))
        job["phase_label"] = PHASE_LABELS.get(phase, phase.replace("_", " ").title())

        response = make_response(render_template("partials/progress_bar.html", job=job))
        if job.get("status") in {"complete", "error"}:
            if job.get("status") == "complete" and job.get("run_id"):
                response.headers["HX-Trigger"] = json.dumps(
                    {"jobComplete": {"run_id": job["run_id"]}}
                )
            else:
                response.headers["HX-Trigger"] = "jobComplete"
        return response

    @app.route("/api/llm/settings", methods=["GET"])
    def api_llm_settings_get():
        refresh = request.args.get("refresh", "").lower() in ("1", "true", "yes")
        ctx = _llm_settings_context(refresh_models=refresh)
        return render_template("partials/llm_settings.html", **ctx)

    @app.route("/api/llm/models", methods=["GET"])
    def api_llm_models():
        refresh = request.args.get("refresh", "1").lower() in ("1", "true", "yes")
        ctx = _llm_settings_context(refresh_models=refresh)
        return render_template("partials/llm_settings.html", **ctx)

    @app.route("/api/llm/settings", methods=["POST"])
    def api_llm_settings_post():
        from src.analyzer import Analyzer
        from src.llm_config import invalidate_models_cache, save_config, update_llm_section

        if _has_active_import_job():
            ctx = _llm_settings_context(
                error="Cannot change model while an import is in progress.",
            )
            return render_template("partials/llm_settings.html", **ctx), 409

        model = (request.form.get("model") or "").strip()
        if not model and request.is_json:
            body = request.get_json(silent=True) or {}
            model = (body.get("model") or "").strip()
        if not model:
            ctx = _llm_settings_context(error="Select or enter a model name.")
            return render_template("partials/llm_settings.html", **ctx), 400

        try:
            with _config_lock:
                update_llm_section(runtime_config, model=model)
                save_config(resolved_config_path, runtime_config)
            invalidate_models_cache()
        except ValueError as exc:
            ctx = _llm_settings_context(error=str(exc))
            return render_template("partials/llm_settings.html", **ctx), 400

        llm_cfg = _get_llm_config()
        analyzer = Analyzer(llm_cfg)
        reachable = analyzer.ping()
        msg = f"Model set to {llm_cfg.get('model', model)}."
        if not reachable:
            msg += " Backend is not reachable — start Ollama before importing."
        ctx = _llm_settings_context(refresh_models=True, message=msg)
        return render_template("partials/llm_settings.html", **ctx)

    @app.route("/api/runs", methods=["GET"])
    def api_runs_get():
        return render_template("partials/run_selector.html", **_runs_context())

    @app.route("/api/runs", methods=["POST"])
    def api_runs_post():
        run_id = (request.form.get("run_id") or "").strip()
        if run_id:
            session["run_id"] = run_id
        return redirect(request.referrer or url_for("index", run=run_id))

    @app.route("/function/<path:entry_point>")
    def function_detail(entry_point: str):
        if not _db_exists():
            return redirect(url_for("index"))

        from src import db

        run_id = _selected_run_id()
        fn = db.get_function(db_path, entry_point, run_id=run_id)
        if fn is None:
            flash(f"Function {entry_point!r} not found in database.", "error")
            return redirect(url_for("index", run=run_id or None))

        approvals = _load_approvals()
        approval_status = None
        if entry_point in approvals:
            approval_status = "approved" if approvals[entry_point] else "rejected"
        elif fn.get("suggested_name") and fn["suggested_name"] != fn["function_name"]:
            approval_status = "pending"

        runs_ctx = _runs_context()
        return render_template(
            "function.html",
            fn=fn,
            approval_status=approval_status,
            **runs_ctx,
        )

    @app.route("/api/approve", methods=["POST"])
    def api_approve():
        """Toggle rename approval for a single function. Returns HTML partial."""
        entry_point = request.form.get("entry_point", "")
        approved    = request.form.get("approved", "false").lower() == "true"

        if not _db_exists() or not entry_point:
            return "<span>Error: invalid request</span>", 400

        from src import db

        fn = db.get_function(db_path, entry_point, run_id=_selected_run_id())
        if fn is None:
            return "<span>Function not found</span>", 404

        _save_approval(entry_point, approved, fn)

        approval_status = "approved" if approved else "rejected"
        return render_template(
            "partials/approve_section.html",
            fn=fn,
            approval_status=approval_status,
        )

    @app.route("/api/reanalyze", methods=["POST"])
    def api_reanalyze():
        from src import db, importer
        from src.analyzer import Analyzer, AnalysisResult

        entry_point = (request.form.get("entry_point") or "").strip()
        focus_note = (request.form.get("focus") or "").strip()
        if not entry_point or not _db_exists():
            return "<span class=\"flash-error\">Invalid re-analyze request.</span>", 400

        run_id = _selected_run_id()
        if not run_id:
            return "<span class=\"flash-error\">No analysis run selected.</span>", 400

        fn_row = db.get_function(db_path, entry_point, run_id=run_id)
        if fn_row is None:
            return "<span>Function not found</span>", 404

        source_path = None
        for src in (fn_row.get("source_file") or "",):
            if not src:
                continue
            candidate = uploads_dir / src
            if candidate.is_file():
                source_path = candidate
                break
            for up in uploads_dir.glob(f"*_{src}"):
                source_path = up
                break

        function: dict[str, Any] = {
            "functionName": fn_row.get("function_name", ""),
            "entryPoint": fn_row.get("entry_point", entry_point),
            "decompiledCode": fn_row.get("decompiled_code", ""),
        }
        if source_path and source_path.is_file():
            for raw in importer.load(str(source_path)):
                if raw.get("entryPoint") == entry_point:
                    function = raw
                    break

        analyzer = Analyzer(_get_llm_config())
        if not analyzer.ping():
            return "<span class=\"flash-error\">LLM backend unreachable.</span>", 503

        prior = AnalysisResult(
            function_name=fn_row["function_name"],
            entry_point=fn_row["entry_point"],
            summary=fn_row["summary"],
            suggested_name=fn_row["suggested_name"],
            category=fn_row["category"],
            confidence=fn_row["confidence"],
            side_effects=fn_row["side_effects"],
            uncertainties=fn_row["uncertainties"],
        )
        result = analyzer.reanalyze_function(
            function,
            focus_note=focus_note,
            prior_result=prior,
            run_id=run_id,
        )
        code = function.get("decompiledCode", "") or fn_row.get("decompiled_code", "")
        dmap = {result.entry_point: code} if code else None
        db.ingest_results(
            [result],
            db_path,
            source_file=fn_row.get("source_file", ""),
            decompiled_code_map=dmap,
            run_id=run_id,
        )
        fn_updated = db.get_function(db_path, entry_point, run_id=run_id) or fn_row
        return render_template(
            "partials/analysis_summary.html",
            fn=fn_updated,
        )

    @app.route("/report")
    def export_report():
        """Generate a Markdown report from all DB contents and serve it."""
        if not _db_exists():
            flash("Database not found. Run ingest first.", "error")
            return redirect(url_for("index"))

        from src import db, reporter

        run_id = _selected_run_id()
        results = db.all_results_as_analysis(db_path, run_id=run_id)
        if not results:
            flash("No analysis results in database.", "error")
            return redirect(url_for("index"))

        report_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = report_dir / f"dashboard_export_{ts}.md"
        run_meta = db.get_run(db_path, run_id) if run_id else None
        source_label = "dashboard export"
        if run_meta:
            source_label = f"dashboard export ({run_meta.get('model', '')} {run_id[:8]})"
        reporter.generate_report(results, str(out_path), source=source_label)

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

    @app.context_processor
    def inject_run_context():
        if not _db_exists():
            return {"selected_run_id": None, "runs": []}
        try:
            ctx = _runs_context()
            return ctx
        except Exception:
            return {"selected_run_id": None, "runs": []}

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
