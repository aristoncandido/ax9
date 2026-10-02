"""Command-line entry point: wires ingest -> engine -> reporters together.

This is the only module that touches the outside world (arguments, clock,
files, terminal). Everything it calls is testable on its own.

Exit codes are a contract with whoever runs AX9 (a person, cron or CI):
    0  every in-scope asset is PASS or covered by a valid exception
    1  the run worked and found something that needs action
    2  the run itself failed (bad argument, unreadable input, cannot write output)
Keeping 1 and 2 apart lets a pipeline tell "not compliant" from "tool broken".
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, reporters
from .engine import evaluate, iso_utc
from .ingest import (
    ASSETS_FILE,
    EXCEPTIONS_FILE,
    SIEM_FILE,
    IngestError,
    load_assets,
    load_controls,
    load_exceptions,
    load_siem_sources,
    parse_timestamp,
    sha256_file,
)
from .ui import UI

EXIT_OK, EXIT_ACTION, EXIT_ERROR = 0, 1, 2
PIPELINE_STEPS = 7  # number of progress.step() calls in main(); keeps the bar ending at 100%


def build_parser() -> argparse.ArgumentParser:
    """All command-line options. `python -m ax9 --help` prints this list."""
    parser = argparse.ArgumentParser(prog="ax9", description="AX9: automated audit of log coverage, freshness and retention.")
    parser.add_argument("--data-dir", type=Path, default=Path("sample_data"),
                        help=f"folder holding {ASSETS_FILE}, {SIEM_FILE} and {EXCEPTIONS_FILE}")
    parser.add_argument("--assets", type=Path, help="inventory CSV (overrides --data-dir)")
    parser.add_argument("--siem", type=Path, help="SIEM sources CSV (overrides --data-dir)")
    parser.add_argument("--exceptions", type=Path, help="exceptions CSV (overrides --data-dir)")
    parser.add_argument("--out-dir", type=Path, default=Path("output"), help="folder for results.json/csv and report.md")
    parser.add_argument("--controls", type=Path, default=Path("controls.json"), help="controls definition file")
    parser.add_argument("--as-of", help="evaluation time, ISO 8601 UTC (default: now); fix it for reproducible runs")
    parser.add_argument("--no-banner", action="store_true", help="do not print the banner")
    parser.add_argument("--no-anim", action="store_true", help="skip the banner animation and progress bar")
    parser.add_argument("--version", action="version", version=f"ax9 {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one audit and return the exit code. `argv=None` reads sys.argv;
    tests pass an explicit list instead."""
    args = build_parser().parse_args(argv)
    ui = UI(show_banner=not args.no_banner, animate=not args.no_anim)
    ui.banner()

    # The evaluation moment. Fixed (--as-of) = reproducible; default = now.
    try:
        as_of = parse_timestamp(args.as_of) if args.as_of else datetime.now(timezone.utc).replace(microsecond=0)
    except ValueError as exc:
        ui.error(f"invalid --as-of: {exc}")
        return EXIT_ERROR

    # A specific file flag wins over the folder default.
    assets_path = args.assets or args.data_dir / ASSETS_FILE
    siem_path = args.siem or args.data_dir / SIEM_FILE
    exceptions_path = args.exceptions or args.data_dir / EXCEPTIONS_FILE

    try:
        with ui.progress(total=PIPELINE_STEPS) as progress:
            progress.step("Loading control definitions")
            controls = load_controls(args.controls)
            progress.step("Parsing asset inventory")
            assets, issues = load_assets(assets_path)
            progress.step("Parsing SIEM log sources")
            sources, siem_issues = load_siem_sources(siem_path)
            progress.step("Loading risk exceptions")
            exceptions, exc_issues = load_exceptions(exceptions_path)
            progress.step("Hashing evidence (SHA-256)")
            # controls.json is hashed too: changing a threshold must be as visible as changing data.
            hashes = {path.name: sha256_file(path) for path in (assets_path, siem_path, exceptions_path, args.controls)}
            all_issues = issues + siem_issues + exc_issues
            progress.step("Evaluating controls and exceptions")
            result = evaluate(assets, sources, exceptions, all_issues, controls, as_of, hashes, siem_path.name)
            progress.step("Writing audit reports")
            args.out_dir.mkdir(parents=True, exist_ok=True)
            reporters.write_json(result, controls, args.out_dir / "results.json")
            reporters.write_csv(result, args.out_dir / "results.csv")
            reporters.write_markdown(result, controls, args.out_dir / "report.md")
    except IngestError as exc:
        ui.error(str(exc))
        return EXIT_ERROR
    except OSError as exc:  # e.g. out-dir not writable, disk full
        ui.error(f"cannot write reports to {args.out_dir}: {exc.strerror or exc}")
        return EXIT_ERROR

    ui.success("compliance scan complete")

    # Run header: what was checked, against what, using which evidence.
    control_ids = ", ".join(c["id"] for c in controls["controls"])
    frameworks = sorted({m["framework"] for c in controls["controls"] for m in c["mappings"]})
    ui.info(f"control: {control_ids}")
    ui.info(f"frameworks: {', '.join(frameworks)}")
    ui.info(f"as-of: {iso_utc(as_of)}")
    ui.info(f"inputs: {assets_path}, {siem_path}, {exceptions_path}")
    ui.info(f"loaded {len(assets)} assets, {len(sources)} SIEM sources, {len(exceptions)} exceptions")
    if all_issues:
        ui.warning(f"{len(all_issues)} input row(s) rejected as evidence quality issues")

    reporters.write_console(result, ui)

    # One-line verdict, then where to find the full reports.
    summary = reporters.summarize(result)
    counts = ", ".join(f"{k}={v}" for k, v in summary["by_status"].items() if v)
    line = f"{summary['in_scope_assets']} in-scope assets: {counts}; compliance {summary['compliance_pct']}%"
    if summary["action_required"]:
        ui.warning(f"{line}; untracked={summary['untracked_hosts']}, expired exceptions={summary['expired_exceptions']}")
    else:
        ui.success(line)
    ui.info(f"reports: {args.out_dir / 'report.md'}, results.csv, results.json")
    return EXIT_ACTION if summary["action_required"] else EXIT_OK
