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
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console(highlight=False, legacy_windows=False)


# ------------------------------------------------------------------
# Config loading
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


# ------------------------------------------------------------------
# Command implementations
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
            "Make sure Ollama (or your LLM server) is running and the "
            "base_url in config.json is correct."
        )
        sys.exit(1)


def cmd_analyze(args: argparse.Namespace) -> None:
    """Import decompiled functions and analyze them with the local LLM."""
    from src import importer, storage
    from src.analyzer import Analyzer

    config = _load_config(args.config)
    _setup_logging(config)
    log = logging.getLogger(__name__)

    analyzer = Analyzer(config["llm"])

    # Connectivity check before spending time loading data
    console.print("Checking LLM backend connectivity …")
    if not analyzer.ping():
        console.print(
            "[red]Cannot reach LLM backend.[/red] "
            "Run [bold]python -m src.cli ping[/bold] for details."
        )
        sys.exit(1)
    console.print("[green]Backend OK.[/green]")

    # Load functions
    functions = list(importer.load(args.input))
    max_fn = config.get("analysis", {}).get("max_functions_per_run", 50)
    if len(functions) > max_fn:
        console.print(
            f"[yellow]Input contains {len(functions)} functions; "
            f"limiting to first {max_fn} per config.[/yellow]"
        )
        functions = functions[:max_fn]

    console.print(f"Loaded [bold]{len(functions)}[/bold] function(s) from [cyan]{args.input}[/cyan]")

    results = []
    for i, fn in enumerate(functions, start=1):
        name = fn.get("functionName", f"#{i}")
        console.print(f"  [{i}/{len(functions)}] Analyzing [yellow]{name}[/yellow] …")
        try:
            result = analyzer.analyze_function(fn)
            results.append(result)
            log.debug("Raw LLM response for %s:\n%s", name, result.raw_response)
        except Exception as exc:
            console.print(f"    [red]Error analyzing {name}:[/red] {exc}")
            log.debug("Exception details:", exc_info=True)

    storage.save_results(results, args.output)
    console.print(
        f"\n[green]Done.[/green] Analyzed [bold]{len(results)}[/bold] function(s). "
        f"Results saved to [cyan]{args.output}[/cyan]"
    )


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
        "analyze", help="Run LLM analysis on exported decompiled functions"
    )
    p_analyze.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to JSON or JSONL input file",
    )
    p_analyze.add_argument(
        "--output", required=True, metavar="PATH",
        help="Path to write the analysis JSON output",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    # report
    p_report = sub.add_parser(
        "report", help="Generate a Markdown report from analysis results"
    )
    p_report.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to the analysis JSON output file",
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
        help="Path to the analysis JSON output file",
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
