"""
Entry point for the reverse engineering toolkit CLI.

Usage:
    python -m src.cli <command> [options]

Commands:
    analyze   Import functions and run LLM analysis
    report    Generate a Markdown report from stored analysis
    rename    Display rename suggestions from stored analysis
    ping      Check connectivity to the local LLM backend
"""

import argparse
import sys


def cmd_analyze(args: argparse.Namespace) -> None:
    """Import decompiled functions and analyze them with the local LLM."""
    raise NotImplementedError("Iteration 1: analyze command not yet implemented.")


def cmd_report(args: argparse.Namespace) -> None:
    """Generate a Markdown report from previously stored analysis results."""
    raise NotImplementedError("Iteration 1: report command not yet implemented.")


def cmd_rename(args: argparse.Namespace) -> None:
    """Print rename suggestions from stored analysis results."""
    raise NotImplementedError("Iteration 1: rename command not yet implemented.")


def cmd_ping(args: argparse.Namespace) -> None:
    """Verify that the local LLM backend is reachable."""
    raise NotImplementedError("Iteration 1: ping command not yet implemented.")


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

    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Run LLM analysis on exported functions")
    p_analyze.add_argument("--input", required=True, metavar="PATH", help="Path to JSON/JSONL input file")
    p_analyze.add_argument("--output", required=True, metavar="PATH", help="Path to write analysis JSON output")
    p_analyze.set_defaults(func=cmd_analyze)

    # report
    p_report = subparsers.add_parser("report", help="Generate a Markdown report from analysis results")
    p_report.add_argument("--input", required=True, metavar="PATH", help="Path to analysis JSON output file")
    p_report.add_argument("--out", required=True, metavar="PATH", help="Path to write the Markdown report")
    p_report.set_defaults(func=cmd_report)

    # rename
    p_rename = subparsers.add_parser("rename", help="Show rename suggestions from analysis results")
    p_rename.add_argument("--input", required=True, metavar="PATH", help="Path to analysis JSON output file")
    p_rename.set_defaults(func=cmd_rename)

    # ping
    p_ping = subparsers.add_parser("ping", help="Check local LLM backend connectivity")
    p_ping.set_defaults(func=cmd_ping)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except NotImplementedError as exc:
        print(f"[not implemented] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
