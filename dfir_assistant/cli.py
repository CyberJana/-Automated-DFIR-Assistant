"""Command-line interface: `python -m dfir_assistant analyze <logs...> --out <dir>`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ai_assist import OllamaClient, summarize_findings
from .analyzer import analyze
from .parsers import FORMATS, UnknownFormatError
from .report import write_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfir_assistant",
        description="Parse security logs, flag suspicious activity, extract IOCs, build a timeline and report.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyse one or more log files and write the report")
    run.add_argument("logs", nargs="+", type=Path, help="log files to analyse")
    run.add_argument("--out", type=Path, required=True, help="output directory for report and exports")
    run.add_argument("--format", choices=["auto", *FORMATS], default="auto",
                     help="log format (default: auto-detect per file)")
    run.add_argument("--year", type=int, default=None,
                     help="year to assume for syslog timestamps, which have none (default: current UTC year)")
    run.add_argument("--ai-endpoint", metavar="URL",
                     help="optional LOCAL model endpoint, e.g. http://127.0.0.1:11434/api/generate (Ollama)")
    run.add_argument("--ai-model", metavar="NAME", help="model name for --ai-endpoint")
    return parser


def _analyze(args: argparse.Namespace) -> int:
    missing = [str(p) for p in args.logs if not p.is_file()]
    if missing:
        print(f"error: not a file: {', '.join(missing)}", file=sys.stderr)
        return 2

    client = None
    if args.ai_endpoint:
        if not args.ai_model:
            print("error: --ai-endpoint requires --ai-model", file=sys.stderr)
            return 2
        try:
            client = OllamaClient(args.ai_endpoint, args.ai_model)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        result = analyze(args.logs, fmt=args.format, year=args.year)
    except UnknownFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ai_summaries = None
    if client is not None:
        ai_summaries, ai_errors = summarize_findings(result.findings, client.generate)
        for message in ai_errors:
            print(f"warning: AI step skipped for {message}", file=sys.stderr)

    paths = write_outputs(result, args.out, ai_summaries)
    print(f"Events: {len(result.events)}  Findings: {len(result.findings)}  Indicators: {len(result.indicators)}")
    for path in paths:
        print(f"wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
