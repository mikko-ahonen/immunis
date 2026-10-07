"""The `immunis` command.

    immunis --version
    immunis scan [path] [--project NAME] [--ref SHA] [--base SHA]
                 [--fail-on none|info|low|medium|high|critical]
                 [--artifact FILE | --no-artifact] [--report URL] [--json]
    immunis report FILE --report URL
    immunis gate --subject SHA --cadence NAME [--lifecycle development|production]
                 [--wait SECONDS] --report URL

`scan` does two things. It runs the checks and gates on them (the exit code),
and it writes the **fact artifact** — everything the collectors in
collectors.py saw, no judgement — to `tmp/immunis/scan.json` by default, and
POSTs it with `--report`. A consumer that evaluates its own rules over the
artifact runs the scan with `--fail-on none` and gates elsewhere. `report`
re-posts an artifact written earlier.

Exit codes:
    0  scanned; nothing at or above --fail-on
    1  findings at or above --fail-on
    2  the scan could not run (bad path, bad arguments, bad config)

`gate` asks the consumer whether a subject may ship at a cadence and exits 0
when cleared, 1 when held (the kinds not green are printed), 2 when the
answer could not be had — unknown subject, no token, consumer unreachable.
2 is also a hold: a deploy that cannot ask does not proceed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tomllib
from pathlib import Path

from . import __version__
from .checks import run as run_checks
from .collectors import scan as collect
from .config import load as load_config
from .finding import FAIL_ON_CHOICES, gates
from .report import TOKEN_ENV, ask_gate, payload, send, send_artifact

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DEFAULT_FAIL_ON = "high"
GATE_WAIT_SLICE_SECONDS = 20   # per request; the consumer caps its own wait near this
GATE_POLL_SECONDS = 5
DEFAULT_ARTIFACT = Path("tmp/immunis/scan.json")


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
    scan.add_argument("--base", default=None, metavar="SHA",
                      help="base ref of the change under review; enables the diff in the artifact")
    scan.add_argument("--artifact", default=None, metavar="FILE",
                      help=f"where to write the fact artifact (default: {DEFAULT_ARTIFACT} under the checkout)")
    scan.add_argument("--no-artifact", action="store_true",
                      help="do not write the fact artifact")
    scan.add_argument("--fail-on", default=None, choices=FAIL_ON_CHOICES,
                      help=f"weakest severity that fails the run (default: "
                           f"{DEFAULT_FAIL_ON}, or fail_on from config; "
                           f"'none' reports without gating)")
    scan.add_argument("--report", default=None, metavar="URL",
                      help=f"base URL to POST the scan to; needs {TOKEN_ENV}")
    scan.add_argument("--json", action="store_true",
                      help="write the findings as JSON to stdout")

    report = sub.add_parser("report", help="re-post an artifact written by an earlier scan")
    report.add_argument("file", help="the artifact file")
    report.add_argument("--report", required=True, metavar="URL",
                        help=f"base URL to POST the artifact to; needs {TOKEN_ENV}")

    gate = sub.add_parser("gate", help="ask the consumer whether a subject may ship at a cadence",
                          description="Exit 0 cleared, 1 held (the kinds not green are listed), "
                                      "2 unknown subject / no token / consumer unreachable — also a hold.")
    gate.add_argument("--subject", required=True, metavar="SHA", help="the commit under judgement")
    gate.add_argument("--cadence", required=True, metavar="NAME",
                      help="change, or the release cadence being cut (patch, minor, major, …)")
    gate.add_argument("--lifecycle", default="production", choices=("development", "production"),
                      help="the project's stage, from its registry (default: production)")
    gate.add_argument("--wait", type=int, default=0, metavar="SECONDS",
                      help="block until cleared or this many seconds pass (the consumer caps it)")
    gate.add_argument("--report", required=True, metavar="URL",
                      help=f"base URL of the consumer; needs {TOKEN_ENV}")
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

    artifact = collect(root, config, project=project, ref=args.ref, base=args.base, findings=findings,
                       environment=_environment())
    if not args.no_artifact:
        target = Path(args.artifact) if args.artifact else root / DEFAULT_ARTIFACT
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(artifact, indent=1) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"immunis: could not write the artifact to {target}: {exc}", file=sys.stderr)

    if args.json:
        json.dump(payload(project, args.ref, findings), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        where = config.source or "no config — checks needing policy are off"
        print(f"immunis {__version__} scanned {project} at {root} ({where})")
        print(_format(findings))
        facts = sum(len(v) for v in artifact["facts"].values())
        failed = ", ".join(f["collector"] for f in artifact["scan"]["failed"]) or "none"
        print(f"artifact: {facts} facts from {len(artifact['scan']['collectors'])} collectors (failed: {failed})")

    if args.report:
        token = os.environ.get(TOKEN_ENV, "").strip()
        if not token:
            # Loud, but not fatal: the local gate below still holds.
            print(f"immunis: {TOKEN_ENV} is unset — not reporting",
                  file=sys.stderr)
        else:
            ok, status = send_artifact(args.report, token, artifact)
            print(f"immunis: {status}",
                  file=sys.stdout if ok else sys.stderr)

    if gating:
        print(f"\nimmunis: {len(gating)} finding(s) at or above '{fail_on}'",
              file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


def _environment() -> dict:
    import platform
    env = {"python": platform.python_version(), "os": platform.system().lower()}
    for var, label in (("GITHUB_ACTIONS", "github-actions"), ("GITEA_ACTIONS", "gitea-actions"), ("CI", "ci")):
        if os.environ.get(var):
            env["ci"] = label
            break
    return env


def cmd_report(args) -> int:
    path = Path(args.file)
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"immunis: cannot read artifact {path}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(f"immunis: {TOKEN_ENV} is unset — not reporting", file=sys.stderr)
        return EXIT_ERROR
    ok, status = send_artifact(args.report, token, artifact)
    print(f"immunis: {status}", file=sys.stdout if ok else sys.stderr)
    return EXIT_OK if ok else EXIT_ERROR


def cmd_gate(args) -> int:
    """Exit 0 cleared, 1 held, 2 could not ask. 2 is the inverted rule made
    concrete: an unreachable consumer holds the deploy, nothing else."""
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(f"immunis: {TOKEN_ENV} is unset — cannot ask the gate; holding", file=sys.stderr)
        return EXIT_ERROR
    # The client paces the wait, in short server-side slices: a proxy in
    # front of the consumer times out long before a 300 s long-poll would
    # return, and "504 — holding" is the wrong reason to hold. Waiting only
    # makes sense while a verdict is still MISSING (a render in flight); a
    # verdict that failed will not change by itself, so that holds at once.
    deadline = time.monotonic() + max(0, args.wait or 0)
    while True:
        remaining = int(deadline - time.monotonic())
        slice_ = min(GATE_WAIT_SLICE_SECONDS, max(0, remaining))
        status, body, text = ask_gate(args.report, token, args.subject, args.cadence,
                                      lifecycle=args.lifecycle, wait=slice_)
        if status is None or body is None or status >= 400 or "cleared" not in body:
            detail = (body or {}).get("detail") or (body or {}).get("error") or ""
            print(f"immunis: {text}{': ' + detail if detail else ''} — holding", file=sys.stderr)
            return EXIT_ERROR
        held = [e for e in body.get("required", []) if e.get("status") != "passing"]
        still_rendering = any(e.get("status") == "missing" for e in held)
        if body["cleared"] or not still_rendering or remaining <= 0:
            break
        time.sleep(GATE_POLL_SECONDS)
    if body["cleared"]:
        note = " (override on record)" if body.get("override") else ""
        print(f"immunis: {args.subject} cleared for {args.cadence}{note}")
        return EXIT_OK
    print(f"immunis: {args.subject} held for {args.cadence} — {len(held)} kind(s) not green:", file=sys.stderr)
    for e in held:
        name = e.get("kind") or e.get("constraint")
        summary = e.get("summary") or ""
        print(f"  {name}: {e.get('status')}{' — ' + summary if summary else ''}", file=sys.stderr)
    pending = body.get("pending_override") or {}
    if pending.get("url"):
        # The way through is a human's recorded authorization in the fleet's
        # system of record — never a flag here.
        print(f"  override: a human may authorize {pending['url']}", file=sys.stderr)
    return EXIT_FINDINGS


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "report":
        return cmd_report(args)
    if args.command == "gate":
        return cmd_gate(args)
    return EXIT_ERROR  # unreachable while subparsers are required


if __name__ == "__main__":
    raise SystemExit(main())
