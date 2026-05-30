"""
Entry point for the reverse engineering toolkit CLI.

Usage:
    python -m src.cli <command> [options]

Commands:
    analyze        Import functions from JSON/JSONL, run LLM analysis, save results
    report         Generate a Markdown report from stored analysis results
    rename         Display rename suggestions from stored analysis results
    suggest-renames Generate focused rename suggestions with confidence and reasoning
    approve-renames Create an approved renames file from suggestions for Ghidra import
    ingest         Load analysis results into the SQLite search database
    search         Search and filter analyzed functions in the database
    reanalyze      Re-analyze one function with optional analyst focus
    dashboard      Start the local web dashboard
    ping           Check connectivity to the configured local LLM backend
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

console = Console(highlight=False, legacy_windows=False)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _load_config(path: str) -> dict:
    config_path = Path(path)
    if not config_path.exists():
        console.print(f"[red]Config file not found:[/red] {config_path}")
        sys.exit(1)
    with config_path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _setup_logging(config: dict) -> None:
    level_name = config.get("logging", {}).get("level", "INFO")
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=False)],
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_error_log(output_path: Path) -> Path:
    """Derive a default error log path from the output path."""
    return output_path.parent / (output_path.stem + "_errors.jsonl")


# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------

def cmd_ping(args: argparse.Namespace) -> None:
    """Verify that the local LLM backend is reachable."""
    from src.analyzer import Analyzer

    config = _load_config(args.config)
    _setup_logging(config)
    analyzer = Analyzer(config["llm"])

    console.print(
        f"Pinging [cyan]{config['llm']['backend']}[/cyan] "
        f"at [cyan]{config['llm']['base_url']}[/cyan] "
        f"(model: [cyan]{config['llm']['model']}[/cyan]) ..."
    )

    if analyzer.ping():
        console.print("[green][OK] Backend is reachable.[/green]")
    else:
        console.print(
            "[red][FAIL] Backend is not reachable.[/red] "
            "Make sure Ollama (or your LLM server) is running and "
            "the base_url in config.json is correct."
        )
        sys.exit(1)


def cmd_analyze(args: argparse.Namespace) -> None:
    """
    Import decompiled functions and analyze them with the local LLM.

    Results are written to the output file as JSONL incrementally — one line
    per successfully analyzed function. If a function fails, the error is
    logged to the error log and analysis continues with the next function.
    """
    from src import batch, db, importer, storage
    from src.analyzer import Analyzer
    from src.prioritizer import prioritize
    from src.progress import PHASE_LABELS, ProgressUpdate
    from src.versions import POSTPROCESS_VERSION, prompt_version_for

    config = _load_config(args.config)
    _setup_logging(config)
    log = logging.getLogger(__name__)

    analyzer = Analyzer(config["llm"])
    out_path = Path(args.output)
    error_log_path = Path(args.error_log) if args.error_log else _default_error_log(out_path)
    run_id = uuid.uuid4().hex

    # Connectivity check first
    console.print("Checking LLM backend connectivity ...")
    if not analyzer.ping():
        console.print(
            "[red]Cannot reach LLM backend.[/red] "
            "Run [bold]python -m src.cli ping[/bold] for details."
        )
        sys.exit(1)
    console.print("[green]Backend OK.[/green]\n")

    # Load all functions (even JSONL loads fully — sizes are analyst-scale, not big-data)
    console.print(f"Loading functions from [cyan]{args.input}[/cyan] ...")
    try:
        functions = list(importer.load(args.input))
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Failed to load input:[/red] {exc}")
        sys.exit(1)

    # Prioritize then apply optional --limit (top N by score when sort_by=priority)
    functions = prioritize(
        functions,
        config,
        skip_runtime=args.skip_runtime,
    )
    max_fn = args.limit if args.limit is not None else config.get("analysis", {}).get("max_functions_per_run", 0)
    if max_fn and max_fn > 0 and len(functions) > max_fn:
        console.print(
            f"[yellow]Limiting to top {max_fn} of {len(functions)} functions by priority "
            f"(--limit / max_functions_per_run).[/yellow]"
        )
        functions = functions[:max_fn]

    total = len(functions)
    console.print(f"Loaded [bold]{total}[/bold] function(s). Writing output to [cyan]{out_path}[/cyan]")
    console.print(f"Run ID: [dim]{run_id}[/dim]\n")

    # Initialize fresh output file
    storage.init_jsonl(out_path)

    success_count = 0
    error_count = 0

    progress_cols = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ]

    def _phase_label(phase: str) -> str:
        return PHASE_LABELS.get(phase, phase.replace("_", " "))

    with Progress(*progress_cols, console=console, transient=False) as progress:
        task = progress.add_task("Analyzing...", total=total)

        def on_progress(update: ProgressUpdate) -> None:
            label = _phase_label(update.phase)
            fn_label = update.function_name or "unknown"
            progress.update(
                task,
                completed=update.completed,
                description=(
                    f"[cyan]{label}[/cyan] [yellow]{fn_label}[/yellow] "
                    f"({update.current}/{update.total})"
                ),
            )

        def on_success(result) -> None:
            nonlocal success_count
            storage.append_result_jsonl(result, out_path)
            success_count += 1
            log.debug("OK: %s -> %s", result.function_name, result.suggested_name)

        def on_error(fn, exc) -> None:
            nonlocal error_count
            error_count += 1
            name = fn.get("functionName", fn.get("entryPoint", "unknown"))
            ts = _utc_now()
            log.error("[%s] Failed: %s: %s", ts, name, exc)
            log.debug("Traceback:", exc_info=True)
            storage.append_error_jsonl(error_log_path, fn, exc, ts)

        _, error_count, _ = batch.run_batch_analysis(
            functions,
            analyzer,
            run_id=run_id,
            on_progress=on_progress,
            on_success=on_success,
            on_error=on_error,
        )

        progress.update(task, completed=total, description="[green]Done[/green]")

    # Summary
    console.print()
    if error_count == 0:
        console.print(
            f"[green]Batch complete.[/green] "
            f"[bold]{success_count}[/bold] / {total} functions analyzed successfully."
        )
    else:
        console.print(
            f"[yellow]Batch complete with errors.[/yellow] "
            f"[bold]{success_count}[/bold] succeeded, "
            f"[bold red]{error_count}[/bold red] failed."
        )
        console.print(f"Error details: [cyan]{error_log_path}[/cyan]")

    console.print(f"Results: [cyan]{out_path}[/cyan]")

    if args.ingest:
        db_path = Path(args.db or config.get("output", {}).get("db_path", "data/output/analysis.db"))
        db.init_db(db_path)
        db.create_run(
            db_path,
            run_id=run_id,
            label=f"CLI analyze {Path(args.input).name}",
            model=analyzer.model,
            backend=analyzer.backend,
            prompt_version=prompt_version_for("summarize.txt"),
            postprocess_version=POSTPROCESS_VERSION,
            source_input=str(args.input),
        )
        results = storage.load_results_jsonl(out_path)
        decompiled_code_map = {
            fn.get("entryPoint", ""): fn.get("decompiledCode", "")
            for fn in functions
            if fn.get("entryPoint") and fn.get("decompiledCode")
        }
        db.complete_run(
            db_path,
            run_id,
            function_count=success_count,
            error_count=error_count,
        )
        inserted, updated = db.ingest_results(
            results,
            db_path,
            source_file=out_path.name,
            decompiled_code_map=decompiled_code_map,
            run_id=run_id,
        )
        console.print(
            f"[green]Ingested into[/green] [cyan]{db_path}[/cyan] "
            f"({inserted} inserted, {updated} updated)."
        )

    if success_count == 0:
        sys.exit(1)


def cmd_report(args: argparse.Namespace) -> None:
    """Generate a Markdown report from previously stored analysis results."""
    from src import reporter, storage

    config = _load_config(args.config)
    _setup_logging(config)

    results = storage.load_results(args.input)
    console.print(f"Loaded {len(results)} result(s) from [cyan]{args.input}[/cyan]")

    reporter.generate_report(results, args.out, source=args.input)
    console.print(f"[green]Report written to[/green] [cyan]{args.out}[/cyan]")


def cmd_rename(args: argparse.Namespace) -> None:
    """Display rename suggestions from analysis results or a rename suggestions file."""
    from src import renamer, storage

    config = _load_config(args.config)
    _setup_logging(config)

    # Auto-detect: RenameResult JSONL vs AnalysisResult JSONL
    if storage.is_rename_suggestions_file(args.input):
        suggestions = storage.load_rename_suggestions(args.input)
        console.print(f"Loaded {len(suggestions)} rename suggestion(s) from [cyan]{args.input}[/cyan]")
        renamer.display_rename_results(suggestions)
        if args.export:
            renamer.export_rename_map(suggestions, args.export)
            console.print(f"[green]Rename map exported to[/green] [cyan]{args.export}[/cyan]")
    else:
        results = storage.load_results(args.input)
        console.print(f"Loaded {len(results)} analysis result(s) from [cyan]{args.input}[/cyan]")
        renamer.display_suggestions(results)
        if args.export:
            renamer.export_rename_map(results, args.export)
            console.print(f"[green]Rename map exported to[/green] [cyan]{args.export}[/cyan]")


def cmd_suggest_renames(args: argparse.Namespace) -> None:
    """
    Generate focused rename suggestions using the dedicated rename LLM prompt.

    Two input modes:
      --input PATH          Run the rename prompt on raw function JSON/JSONL.
      --from-analysis PATH  Derive suggestions from existing analysis results
                            without making any LLM calls.
    """
    from src import importer, renamer, storage
    from src.analyzer import Analyzer

    config = _load_config(args.config)
    _setup_logging(config)
    log = logging.getLogger(__name__)

    out_path = Path(args.output)
    error_log_path = Path(args.error_log) if args.error_log else _default_error_log(out_path)

    # ---- Mode 1: derive from existing AnalysisResult JSONL (no LLM) --------
    if args.from_analysis:
        results = storage.load_results(args.from_analysis)
        console.print(
            f"Deriving rename suggestions from [cyan]{args.from_analysis}[/cyan] "
            f"({len(results)} result(s)) — no LLM call needed."
        )
        suggestions = renamer.from_analysis_results(results)
        storage.save_rename_suggestions(suggestions, out_path)
        console.print(
            f"[green]Done.[/green] {len(suggestions)} suggestion(s) saved to "
            f"[cyan]{out_path}[/cyan]"
        )
        renamer.display_rename_results(suggestions)
        return

    # ---- Mode 2: run rename LLM prompt on raw function JSONL ----------------
    if not args.input:
        console.print("[red]Provide either --input or --from-analysis.[/red]")
        sys.exit(1)

    analyzer = Analyzer(config["llm"])

    console.print("Checking LLM backend connectivity ...")
    if not analyzer.ping():
        console.print(
            "[red]Cannot reach LLM backend.[/red] "
            "Run [bold]python -m src.cli ping[/bold] for details."
        )
        sys.exit(1)
    console.print("[green]Backend OK.[/green]\n")

    try:
        functions = list(importer.load(args.input))
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Failed to load input:[/red] {exc}")
        sys.exit(1)

    max_fn = args.limit if args.limit is not None else config.get("analysis", {}).get("max_functions_per_run", 0)
    if max_fn and max_fn > 0 and len(functions) > max_fn:
        console.print(f"[yellow]Limiting to first {max_fn} functions.[/yellow]")
        functions = functions[:max_fn]

    total = len(functions)
    console.print(f"Loaded [bold]{total}[/bold] function(s). Output: [cyan]{out_path}[/cyan]\n")

    suggestions: list = []
    error_count = 0

    progress_cols = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ]

    with Progress(*progress_cols, console=console, transient=False) as progress:
        task = progress.add_task("Generating renames...", total=total)

        for fn in functions:
            name = fn.get("functionName", fn.get("entryPoint", "unknown"))
            progress.update(task, description=f"[yellow]{name}[/yellow]")

            try:
                suggestion = analyzer.rename_function(fn)
                suggestions.append(suggestion)
                log.debug("OK: %s -> %s [%s]", name, suggestion.new_name, suggestion.confidence)
            except Exception as exc:
                error_count += 1
                ts = _utc_now()
                log.error("[%s] Failed: %s: %s", ts, name, exc)
                log.debug("Traceback:", exc_info=True)
                storage.append_error_jsonl(error_log_path, fn, exc, ts)
            finally:
                progress.advance(task)

        progress.update(task, description="Done")

    storage.save_rename_suggestions(suggestions, out_path)

    console.print()
    if error_count == 0:
        console.print(
            f"[green]Done.[/green] [bold]{len(suggestions)}[/bold] / {total} "
            "suggestions generated."
        )
    else:
        console.print(
            f"[yellow]Done with errors.[/yellow] "
            f"[bold]{len(suggestions)}[/bold] succeeded, "
            f"[bold red]{error_count}[/bold red] failed. "
            f"See [cyan]{error_log_path}[/cyan]"
        )

    console.print(f"Suggestions: [cyan]{out_path}[/cyan]\n")
    renamer.display_rename_results(suggestions)

    if suggestions == 0:
        sys.exit(1)


def cmd_ingest(args: argparse.Namespace) -> None:
    """
    Load analysis results from a JSON/JSONL file into the SQLite search database.

    Re-ingesting the same file updates existing rows (upsert on entry_point).
    Run this after every 'analyze' run to keep the search index current.

    Pass --source-functions to include decompiled code in the database, which
    enables the code viewer in the local dashboard.
    """
    from src import db, importer, storage

    config = _load_config(args.config)
    _setup_logging(config)

    db_path = Path(args.db or config.get("output", {}).get("db_path", "data/output/analysis.db"))
    input_path = args.input

    console.print(f"Loading results from [cyan]{input_path}[/cyan] ...")
    try:
        results = storage.load_results(input_path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Failed to load results:[/red] {exc}")
        sys.exit(1)

    if not results:
        console.print("[yellow]No results found in input file.[/yellow]")
        sys.exit(0)

    # Optionally load decompiled code from the source functions file
    decompiled_code_map: dict[str, str] = {}
    if args.source_functions:
        console.print(f"Loading decompiled code from [cyan]{args.source_functions}[/cyan] ...")
        try:
            functions = list(importer.load(args.source_functions))
            for fn in functions:
                ep = fn.get("entryPoint", fn.get("entry_point", ""))
                code = fn.get("decompiledCode", fn.get("decompiled_code", ""))
                if ep and code:
                    decompiled_code_map[ep] = code
            console.print(f"Loaded decompiled code for [bold]{len(decompiled_code_map)}[/bold] function(s).")
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[yellow]Warning: could not load source functions:[/yellow] {exc}")

    console.print(f"Initializing database at [cyan]{db_path}[/cyan] ...")
    db.init_db(db_path)

    source_label = Path(input_path).name
    run_id = args.run_id or None
    if not run_id and results and results[0].run_id:
        run_id = results[0].run_id

    if not run_id:
        run_id = db.ensure_run_for_ingest(
            db_path,
            results,
            source_file=source_label,
            label=f"Ingest {source_label}",
        )
        db.complete_run(
            db_path,
            run_id,
            function_count=len(results),
            error_count=0,
        )
    elif not db.get_run(db_path, run_id):
        first = results[0]
        from src.versions import POSTPROCESS_VERSION, prompt_version_for

        db.create_run(
            db_path,
            run_id=run_id,
            label=f"Ingest {source_label}",
            model=first.model,
            backend=first.backend,
            prompt_version=first.prompt_version or prompt_version_for("summarize.txt"),
            postprocess_version=first.postprocess_version or POSTPROCESS_VERSION,
            source_input=source_label,
        )

    inserted, updated = db.ingest_results(
        results, db_path,
        source_file=source_label,
        decompiled_code_map=decompiled_code_map or None,
        run_id=run_id,
    )

    console.print(
        f"[green]Ingest complete.[/green] "
        f"[bold]{inserted}[/bold] inserted, [bold]{updated}[/bold] updated "
        f"({len(results)} total). Run: [cyan]{run_id}[/cyan]"
    )

    stats = db.get_stats(db_path, run_id=run_id)
    console.print(
        f"Database total: [bold]{stats['total']}[/bold] functions across "
        f"[bold]{len(stats['by_category'])}[/bold] categories."
    )


def cmd_dashboard(args: argparse.Namespace) -> None:
    """
    Start the local web dashboard on http://localhost:<port>.

    The dashboard reads from the SQLite database populated by 'ingest'.
    It does not require the LLM backend to be running.

    A browser window is opened automatically unless --no-browser is passed.
    Stop the server with Ctrl-C.
    """
    try:
        from flask import Flask  # noqa: F401 — just to check it's installed
    except ImportError:
        console.print(
            "[red]Flask is not installed.[/red] "
            "Run [bold]pip install flask[/bold] and try again."
        )
        sys.exit(1)

    from src.dashboard import create_app

    config = _load_config(args.config)
    _setup_logging(config)

    host = args.host
    port = args.port
    url  = f"http://{host}:{port}"

    console.print(f"Starting dashboard at [cyan]{url}[/cyan]")
    console.print("Press [bold]Ctrl-C[/bold] to stop.\n")

    app = create_app(config, config_path=Path(args.config).resolve())

    if not args.no_browser:
        import threading
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    app.run(host=host, port=port, debug=False, use_reloader=False)


def cmd_search(args: argparse.Namespace) -> None:
    """
    Search and filter analyzed functions stored in the SQLite database.

    Filters are AND-ed together. When --query is provided, results are ranked
    by full-text relevance (BM25). Otherwise results are ordered by ingest time.

    Example usage:
        python -m src.cli search --query "file parsing"
        python -m src.cli search --category crypto
        python -m src.cli search --confidence low
        python -m src.cli search --query "command" --confidence high
        python -m src.cli search --stats
    """
    from rich.table import Table

    from src import db

    config = _load_config(args.config)
    _setup_logging(config)

    db_path = Path(args.db or config.get("output", {}).get("db_path", "data/output/analysis.db"))

    if not Path(db_path).exists():
        console.print(
            f"[red]Database not found:[/red] {db_path}\n"
            "Run [bold]python -m src.cli ingest[/bold] first."
        )
        sys.exit(1)

    # ---- Stats mode -----------------------------------------------------------
    if args.stats:
        run_id = db.resolve_run_id(db_path, args.run_id)
        stats = db.get_stats(db_path, run_id=run_id)
        console.print(f"\n[bold]Database:[/bold] {db_path}")
        if run_id:
            console.print(f"[bold]Run:[/bold] {run_id}")
        console.print(f"[bold]Total functions:[/bold] {stats['total']}\n")

        cat_table = Table(title="By Category", show_header=True, min_width=40)
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Count", justify="right")
        for cat, cnt in stats["by_category"].items():
            cat_table.add_row(cat or "(none)", str(cnt))
        console.print(cat_table)

        conf_table = Table(title="By Confidence", show_header=True, min_width=40)
        conf_table.add_column("Confidence")
        conf_table.add_column("Count", justify="right")
        _conf_colors = {"high": "green", "medium": "yellow", "low": "red"}
        for conf, cnt in stats["by_confidence"].items():
            color = _conf_colors.get(conf, "white")
            conf_table.add_row(f"[{color}]{conf or '(none)'}[/{color}]", str(cnt))
        console.print(conf_table)

        if stats["sources"]:
            console.print(f"\n[bold]Source files:[/bold] {', '.join(stats['sources'])}")
        return

    # ---- Search mode ----------------------------------------------------------
    if not args.query and not args.category and not args.confidence:
        console.print(
            "[yellow]No filters provided.[/yellow] "
            "Use --query, --category, --confidence, or --stats.\n"
            "Run [bold]python -m src.cli search --help[/bold] for examples."
        )
        sys.exit(0)

    rows = db.search(
        db_path,
        query=args.query or None,
        category=args.category or None,
        confidence=args.confidence or None,
        run_id=args.run_id,
        limit=args.limit,
    )

    if not rows:
        console.print("[yellow]No matching functions found.[/yellow]")
        return

    _conf_colors = {"high": "green", "medium": "yellow", "low": "red"}

    table = Table(
        title=f"Search Results ({len(rows)})",
        show_header=True,
        expand=True,
    )
    table.add_column("Address", style="dim", no_wrap=True, min_width=14)
    table.add_column("Name -> Suggestion", min_width=30)
    table.add_column("Category", min_width=12)
    table.add_column("Conf.", min_width=8)
    table.add_column("Summary")

    for row in rows:
        ep        = row["entry_point"]
        old_name  = row["function_name"] or ""
        new_name  = row["suggested_name"] or ""
        cat       = row["category"] or ""
        conf      = row["confidence"] or ""
        summary   = (row["summary"] or "")[:120]
        if len(row["summary"] or "") > 120:
            summary += "..."

        color = _conf_colors.get(conf, "white")

        name_cell = (
            f"[dim]{old_name}[/dim] -> [bold]{new_name}[/bold]"
            if new_name and new_name != old_name
            else old_name
        )

        table.add_row(
            ep,
            name_cell,
            cat,
            f"[{color}]{conf}[/{color}]",
            summary,
        )

    console.print(table)

    if args.query:
        console.print(f"\n[dim]Query:[/dim] [italic]{args.query}[/italic]")
    if args.limit and len(rows) == args.limit:
        console.print(
            f"[dim]Showing first {args.limit} results. "
            "Use --limit N to see more.[/dim]"
        )


def cmd_approve_renames(args: argparse.Namespace) -> None:
    """
    Build an approved renames file from rename suggestions.

    The file is a human-editable JSON array where each entry has an 'approved'
    boolean field. Entries whose confidence meets --min-confidence are pre-approved;
    others are included with approved=false for reference.

    After running this command the analyst should:
      1. Open the output file and review the entries.
      2. Set approved=true/false for each entry as desired.
      3. Optionally add a custom 'comment' to be written as a Ghidra plate comment.
      4. Run ImportApprovedRenames.java inside Ghidra to apply the changes.
    """
    from src import approver, storage

    config = _load_config(args.config)
    _setup_logging(config)

    out_path = Path(args.output)

    # Load rename suggestions (RenameResult JSONL)
    try:
        suggestions = storage.load_rename_suggestions(args.input)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Failed to load suggestions:[/red] {exc}")
        sys.exit(1)

    if not suggestions:
        console.print("[yellow]No suggestions found in input file.[/yellow]")
        sys.exit(0)

    console.print(
        f"Loaded [bold]{len(suggestions)}[/bold] suggestion(s) from "
        f"[cyan]{args.input}[/cyan]"
    )

    approved_entries, skipped_entries = approver.create_approved_file(
        suggestions,
        out_path,
        min_confidence=args.min_confidence,
        add_comment=not args.no_comment,
        allow_overwrite=args.allow_overwrite,
    )

    # Summary table
    from rich.table import Table

    table = Table(title="Approved Renames Summary", show_header=True)
    table.add_column("Status", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Reason")
    table.add_row(
        "[green]Auto-approved[/green]",
        str(len(approved_entries)),
        f"confidence >= {args.min_confidence}",
    )
    table.add_row(
        "[yellow]Skipped (approved=false)[/yellow]",
        str(len(skipped_entries)),
        "low confidence or no useful name change",
    )
    console.print(table)

    console.print(
        f"\n[green]Approved file written to[/green] [cyan]{out_path}[/cyan]"
    )
    console.print(
        "\nNext steps:\n"
        "  1. Review and edit the file in any text editor.\n"
        "  2. Set [bold]approved[/bold] = true/false for each entry.\n"
        "  3. Optionally add a [bold]comment[/bold] field (plate comment in Ghidra).\n"
        "  4. Run [bold]ImportApprovedRenames.java[/bold] inside Ghidra."
        )


def cmd_reanalyze(args: argparse.Namespace) -> None:
    """Re-analyze a single function with optional analyst focus."""
    from src import db, importer, storage
    from src.analyzer import Analyzer
    from src.versions import POSTPROCESS_VERSION, prompt_version_for

    config = _load_config(args.config)
    _setup_logging(config)

    analyzer = Analyzer(config["llm"])
    if not analyzer.ping():
        console.print("[red]Cannot reach LLM backend.[/red]")
        sys.exit(1)

    functions = list(importer.load(args.source))
    target = None
    for fn in functions:
        ep = fn.get("entryPoint", fn.get("entry_point", ""))
        if ep == args.entry_point or fn.get("functionName") == args.entry_point:
            target = fn
            break
    if target is None:
        console.print(f"[red]Function not found in source:[/red] {args.entry_point}")
        sys.exit(1)

    db_path = Path(args.db or config.get("output", {}).get("db_path", "data/output/analysis.db"))
    prior = None
    run_id = args.run_id or ""
    if db_path.exists():
        db.init_db(db_path)
        if not run_id:
            run_id = db.resolve_run_id(db_path, None) or uuid.uuid4().hex
        prior_row = db.get_function(db_path, target.get("entryPoint", ""), run_id=run_id)
        if prior_row:
            from src.analyzer import AnalysisResult

            prior = AnalysisResult(
                function_name=prior_row["function_name"],
                entry_point=prior_row["entry_point"],
                summary=prior_row["summary"],
                suggested_name=prior_row["suggested_name"],
                category=prior_row["category"],
                confidence=prior_row["confidence"],
                side_effects=prior_row["side_effects"],
                uncertainties=prior_row["uncertainties"],
            )
    else:
        run_id = run_id or uuid.uuid4().hex

    if args.new_run or not db_path.exists():
        db.init_db(db_path)
        run_id = uuid.uuid4().hex
        db.create_run(
            db_path,
            run_id=run_id,
            label=f"Re-analyze {target.get('functionName', args.entry_point)}",
            model=analyzer.model,
            backend=analyzer.backend,
            prompt_version=prompt_version_for("summarize_focus.txt"),
            postprocess_version=POSTPROCESS_VERSION,
            source_input=str(args.source),
        )

    console.print(
        f"Re-analyzing [cyan]{target.get('functionName')}[/cyan] "
        f"({target.get('entryPoint')}) ..."
    )
    result = analyzer.reanalyze_function(
        target,
        focus_note=args.focus or "",
        prior_result=prior,
        run_id=run_id,
    )

    if args.output:
        out_path = Path(args.output)
        storage.init_jsonl(out_path)
        storage.append_result_jsonl(result, out_path)
        console.print(f"Wrote [cyan]{out_path}[/cyan]")

    if args.ingest or not args.output:
        db.init_db(db_path)
        if not db.get_run(db_path, run_id):
            db.create_run(
                db_path,
                run_id=run_id,
                label=f"Re-analyze {result.function_name}",
                model=analyzer.model,
                backend=analyzer.backend,
                prompt_version=result.prompt_version,
                postprocess_version=result.postprocess_version,
                source_input=str(args.source),
            )
        code = target.get("decompiledCode", "") or target.get("decompiled_code", "")
        dmap = {result.entry_point: code} if code else None
        db.ingest_results(
            [result],
            db_path,
            source_file=Path(args.source).name,
            decompiled_code_map=dmap,
            run_id=run_id,
        )
        db.complete_run(db_path, run_id, function_count=1, error_count=0)
        console.print(
            f"[green]Updated[/green] run [cyan]{run_id}[/cyan] in [cyan]{db_path}[/cyan]"
        )

    console.print(
        f"Category: [bold]{result.category}[/bold] | "
        f"Confidence: [bold]{result.confidence}[/bold]"
    )
    console.print(result.summary)


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="retool",
        description="Local LLM Reverse Engineering Toolkit",
    )
    parser.add_argument(
        "--config",
        default="config.json",
        metavar="PATH",
        help="Path to config.json (default: config.json)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ping
    p_ping = sub.add_parser("ping", help="Check local LLM backend connectivity")
    p_ping.set_defaults(func=cmd_ping)

    # analyze
    p_analyze = sub.add_parser(
        "analyze", help="Analyze decompiled functions with the local LLM"
    )
    p_analyze.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to JSON or JSONL input file",
    )
    p_analyze.add_argument(
        "--output", required=True, metavar="PATH",
        help="Path to write results (JSONL — one result per line)",
    )
    p_analyze.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="Max functions to analyze (0 = unlimited; overrides config)",
    )
    p_analyze.add_argument(
        "--error-log", metavar="PATH", default=None,
        help="Path to write per-function error records (JSONL). "
             "Defaults to <output-stem>_errors.jsonl",
    )
    p_analyze.add_argument(
        "--skip-runtime", action="store_true",
        help="Skip CRT/runtime helpers when prioritizing functions",
    )
    p_analyze.add_argument(
        "--ingest", action="store_true",
        help="After analysis, ingest results into SQLite (uses run_id in JSONL)",
    )
    p_analyze.add_argument(
        "--db", metavar="PATH", default=None,
        help="SQLite path when using --ingest (default: output.db_path from config)",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    # report
    p_report = sub.add_parser(
        "report", help="Generate a Markdown report from analysis results"
    )
    p_report.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to analysis results (.json or .jsonl)",
    )
    p_report.add_argument(
        "--out", required=True, metavar="PATH",
        help="Path to write the Markdown report",
    )
    p_report.set_defaults(func=cmd_report)

    # rename
    p_rename = sub.add_parser(
        "rename", help="Display rename suggestions from analysis results or a suggestions file"
    )
    p_rename.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to analysis results (.json or .jsonl) or rename suggestions (.jsonl)",
    )
    p_rename.add_argument(
        "--export", metavar="PATH", default=None,
        help="Optional: export rename map as JSON to this path",
    )
    p_rename.set_defaults(func=cmd_rename)

    # suggest-renames
    p_suggest = sub.add_parser(
        "suggest-renames",
        help="Generate focused rename suggestions with confidence and reasoning",
    )
    suggest_input = p_suggest.add_mutually_exclusive_group(required=True)
    suggest_input.add_argument(
        "--input", metavar="PATH",
        help="Path to function JSON/JSONL — runs dedicated rename LLM prompt",
    )
    suggest_input.add_argument(
        "--from-analysis", metavar="PATH", dest="from_analysis",
        help="Path to analysis results JSONL — derive suggestions without LLM call",
    )
    p_suggest.add_argument(
        "--output", required=True, metavar="PATH",
        help="Path to write rename suggestions JSONL",
    )
    p_suggest.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="Max functions to process (0 = unlimited)",
    )
    p_suggest.add_argument(
        "--error-log", metavar="PATH", default=None,
        help="Path for per-function error records (default: <output>_errors.jsonl)",
    )
    p_suggest.set_defaults(func=cmd_suggest_renames)

    # approve-renames
    p_approve = sub.add_parser(
        "approve-renames",
        help="Create an approved renames file from rename suggestions for Ghidra import",
    )
    p_approve.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to rename suggestions JSONL (output of suggest-renames)",
    )
    p_approve.add_argument(
        "--output", required=True, metavar="PATH",
        help="Path to write the approved renames JSON (human-editable before Ghidra import)",
    )
    p_approve.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="medium",
        metavar="LEVEL",
        dest="min_confidence",
        help="Minimum confidence level to auto-approve (default: medium)",
    )
    p_approve.add_argument(
        "--no-comment",
        action="store_true",
        help="Do not copy the suggestion reason into the Ghidra comment field",
    )
    p_approve.add_argument(
        "--allow-overwrite",
        action="store_true",
        dest="allow_overwrite",
        help="Allow renaming functions that already have a meaningful (non-auto) name in Ghidra",
    )
    p_approve.set_defaults(func=cmd_approve_renames)

    # ingest
    p_ingest = sub.add_parser(
        "ingest",
        help="Load analysis results into the SQLite search database",
    )
    p_ingest.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to analysis results (.json or .jsonl)",
    )
    p_ingest.add_argument(
        "--source-functions", metavar="PATH", default=None, dest="source_functions",
        help="Path to original function JSON/JSONL — adds decompiled code to the DB "
             "for display in the dashboard code viewer",
    )
    p_ingest.add_argument(
        "--db", metavar="PATH", default=None,
        help="Path to the SQLite database (default: output.db_path from config.json)",
    )
    p_ingest.add_argument(
        "--run-id", metavar="ID", default=None, dest="run_id",
        help="Analysis run ID (default: from JSONL provenance or new run)",
    )
    p_ingest.set_defaults(func=cmd_ingest)

    # reanalyze
    p_reanalyze = sub.add_parser(
        "reanalyze",
        help="Re-analyze one function with optional analyst focus",
    )
    p_reanalyze.add_argument(
        "--entry-point", required=True, metavar="ADDR",
        help="Function entry point address (or function name match)",
    )
    p_reanalyze.add_argument(
        "--source", required=True, metavar="PATH",
        help="Source functions JSON/JSONL (decompiled code)",
    )
    p_reanalyze.add_argument(
        "--focus", metavar="TEXT", default="",
        help="Analyst guidance for the LLM (e.g. classify as network)",
    )
    p_reanalyze.add_argument(
        "--output", metavar="PATH", default=None,
        help="Optional JSONL path to write the single result",
    )
    p_reanalyze.add_argument(
        "--db", metavar="PATH", default=None,
        help="SQLite database to update (default: output.db_path)",
    )
    p_reanalyze.add_argument(
        "--run-id", metavar="ID", default=None, dest="run_id",
        help="Run to update (default: latest run in database)",
    )
    p_reanalyze.add_argument(
        "--new-run", action="store_true",
        help="Create a new analysis run instead of updating the current one",
    )
    p_reanalyze.add_argument(
        "--ingest", action="store_true",
        help="Write result to SQLite (default when --output is omitted)",
    )
    p_reanalyze.set_defaults(func=cmd_reanalyze)

    # dashboard
    p_dash = sub.add_parser(
        "dashboard",
        help="Start the local web dashboard (http://localhost:5000 by default)",
    )
    p_dash.add_argument(
        "--host", default="127.0.0.1", metavar="HOST",
        help="Host to bind to (default: 127.0.0.1)",
    )
    p_dash.add_argument(
        "--port", type=int, default=5000, metavar="PORT",
        help="Port to listen on (default: 5000)",
    )
    p_dash.add_argument(
        "--no-browser", action="store_true",
        help="Do not open a browser window automatically",
    )
    p_dash.set_defaults(func=cmd_dashboard)

    # search
    p_search = sub.add_parser(
        "search",
        help="Search and filter analyzed functions in the database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m src.cli search --query 'file parsing'\n"
            "  python -m src.cli search --category crypto\n"
            "  python -m src.cli search --confidence low\n"
            "  python -m src.cli search --query command --confidence high\n"
            "  python -m src.cli search --stats\n"
        ),
    )
    p_search.add_argument(
        "--query", metavar="TEXT", default=None,
        help="Full-text keyword search across function names, summaries, and side effects",
    )
    p_search.add_argument(
        "--category", metavar="NAME", default=None,
        help="Filter by category (e.g. file_io, network, crypto, process, registry)",
    )
    p_search.add_argument(
        "--confidence",
        choices=["low", "medium", "high"],
        metavar="LEVEL",
        default=None,
        help="Filter by confidence level (low | medium | high)",
    )
    p_search.add_argument(
        "--limit", type=int, default=20, metavar="N",
        help="Maximum number of results to show (default: 20, 0 = unlimited)",
    )
    p_search.add_argument(
        "--stats", action="store_true",
        help="Show database statistics instead of search results",
    )
    p_search.add_argument(
        "--run-id", metavar="ID", default=None, dest="run_id",
        help="Limit search/stats to a specific analysis run",
    )
    p_search.add_argument(
        "--db", metavar="PATH", default=None,
        help="Path to the SQLite database (default: output.db_path from config.json)",
    )
    p_search.set_defaults(func=cmd_search)

    return parser


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
