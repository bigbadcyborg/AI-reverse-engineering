"""
Entry point for the reverse engineering toolkit CLI.

Usage:
    python -m src.cli <command> [options]

Commands:
    analyze   Import functions from JSON/JSONL, run LLM analysis, save results
    report    Generate a Markdown report from stored analysis results
    rename    Display rename suggestions from stored analysis results
    ping      Check connectivity to the configured local LLM backend
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
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
    from src import importer, storage
    from src.analyzer import Analyzer

    config = _load_config(args.config)
    _setup_logging(config)
    log = logging.getLogger(__name__)

    analyzer = Analyzer(config["llm"])
    out_path = Path(args.output)
    error_log_path = Path(args.error_log) if args.error_log else _default_error_log(out_path)

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

    # Apply optional --limit (0 = unlimited, overrides config)
    max_fn = args.limit if args.limit is not None else config.get("analysis", {}).get("max_functions_per_run", 0)
    if max_fn and max_fn > 0 and len(functions) > max_fn:
        console.print(
            f"[yellow]Limiting to first {max_fn} of {len(functions)} functions "
            f"(--limit / max_functions_per_run).[/yellow]"
        )
        functions = functions[:max_fn]

    total = len(functions)
    console.print(f"Loaded [bold]{total}[/bold] function(s). Writing output to [cyan]{out_path}[/cyan]\n")

    # Initialize fresh output file
    storage.init_jsonl(out_path)

    success_count = 0
    error_count = 0

    # Progress bar — works for both small and large batches
    progress_cols = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ]

    with Progress(*progress_cols, console=console, transient=False) as progress:
        task = progress.add_task("Analyzing...", total=total)

        for fn in functions:
            name = fn.get("functionName", fn.get("entryPoint", "unknown"))
            progress.update(task, description=f"[yellow]{name}[/yellow]")

            try:
                result = analyzer.analyze_function(fn)
                storage.append_result_jsonl(result, out_path)
                success_count += 1
                log.debug("OK: %s -> %s", name, result.suggested_name)
            except Exception as exc:
                error_count += 1
                ts = _utc_now()
                log.error("[%s] Failed: %s: %s", ts, name, exc)
                log.debug("Traceback:", exc_info=True)
                storage.append_error_jsonl(error_log_path, fn, exc, ts)
            finally:
                progress.advance(task)

        progress.update(task, description="Done")

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

    if success_count == 0:
        sys.exit(1)


def cmd_report(args: argparse.Namespace) -> None:
    """Generate a Markdown report from previously stored analysis results."""
    from src import reporter, storage

    config = _load_config(args.config)
    _setup_logging(config)

    results = storage.load_results(args.input)
    console.print(f"Loaded {len(results)} result(s) from [cyan]{args.input}[/cyan]")

    reporter.generate_report(results, args.out)
    console.print(f"[green]Report written to[/green] [cyan]{args.out}[/cyan]")


def cmd_rename(args: argparse.Namespace) -> None:
    """Display rename suggestions from stored analysis results."""
    from src import renamer, storage

    config = _load_config(args.config)
    _setup_logging(config)

    results = storage.load_results(args.input)
    renamer.display_suggestions(results)

    if args.export:
        renamer.export_rename_map(results, args.export)
        console.print(f"[green]Rename map exported to[/green] [cyan]{args.export}[/cyan]")


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
        "rename", help="Display rename suggestions from analysis results"
    )
    p_rename.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to analysis results (.json or .jsonl)",
    )
    p_rename.add_argument(
        "--export", metavar="PATH", default=None,
        help="Optional: export rename map as JSON to this path",
    )
    p_rename.set_defaults(func=cmd_rename)

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
