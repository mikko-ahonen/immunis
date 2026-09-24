"""The `immunis` command.

    immunis --version
    immunis scan [path] [--project NAME] [--ref SHA]
                 [--fail-on none|info|low|medium|high|critical]
                 [--report URL] [--json]

Exit codes:
    0  scanned; nothing at or above --fail-on
    1  findings at or above --fail-on
    2  the scan could not run (bad path, bad arguments, bad config)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
from pathlib import Path

from . import __version__
from .checks import run as run_checks
from .config import load as load_config
from .finding import FAIL_ON_CHOICES, gates
from .report import TOKEN_ENV, payload, send

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DEFAULT_FAIL_ON = "high"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="immunis",
        description="Find a Python repository's dependency-confusion exposure.",
    )
    parser.add_argument("--version", action="version",
                        version=f"immunis {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a checkout")
    scan.add_argument("path", nargs="?", default=".",
                      help="path to the checkout (default: working directory)")
    scan.add_argument("--project", default=None,
                      help="name to file the scan under (default: the "
                           "directory name)")
    scan.add_argument("--ref", default=None,
                      help="commit sha the scan describes")
    scan.add_argument("--fail-on", default=None, choices=FAIL_ON_CHOICES,
                      help=f"weakest severity that fails the run (default: "
                           f"{DEFAULT_FAIL_ON}, or fail_on from config; "
                           f"'none' reports without gating)")
    scan.add_argument("--report", default=None, metavar="URL",
                      help=f"base URL to POST the scan to; needs {TOKEN_ENV}")
    scan.add_argument("--json", action="store_true",
                      help="write the scan as JSON to stdout")
    return parser


def _format(findings) -> str:
    if not findings:
        return "no findings"
    lines = []
    for f in findings:
        where = f.path or "(repo)"
        if f.line:
            where = f"{where}:{f.line}"
        lines.append(f"  {f.severity.upper():8} {where}  {f.summary}  [{f.check}]")
    return "\n".join(lines)


def cmd_scan(args) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"immunis: not a directory: {root}", file=sys.stderr)
        return EXIT_ERROR

    try:
        config = load_config(root)
    except (tomllib.TOMLDecodeError, ValueError, TypeError) as exc:
        # Unreadable config is an error, not an empty config: silently scanning
        # with no policy would look exactly like scanning a clean repository.
        print(f"immunis: cannot read config: {exc}", file=sys.stderr)
        return EXIT_ERROR

    project = args.project or root.name
    fail_on = args.fail_on or config.fail_on or DEFAULT_FAIL_ON
    findings = run_checks(root, config)
    gating = gates(findings, fail_on)

    if args.json:
        json.dump(payload(project, args.ref, findings), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        where = config.source or "no config — checks needing policy are off"
        print(f"immunis {__version__} scanned {project} at {root} ({where})")
        print(_format(findings))

    if args.report:
        token = os.environ.get(TOKEN_ENV, "").strip()
        if not token:
            # Loud, but not fatal: the local gate below still holds.
            print(f"immunis: {TOKEN_ENV} is unset — not reporting",
                  file=sys.stderr)
        else:
            ok, status = send(args.report, token,
                              payload(project, args.ref, findings))
            print(f"immunis: {status}",
                  file=sys.stdout if ok else sys.stderr)

    if gating:
        print(f"\nimmunis: {len(gating)} finding(s) at or above '{fail_on}'",
              file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return EXIT_ERROR  # unreachable while subparsers are required


if __name__ == "__main__":
    raise SystemExit(main())
