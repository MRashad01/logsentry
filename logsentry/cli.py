"""Command-line interface for logsentry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from logsentry import __version__
from logsentry.detect import Finding, analyze
from logsentry.parsers import parse_auth_log, parse_web_log

_SEV_ICON = {"high": "[HIGH]  ", "medium": "[MEDIUM]", "low": "[LOW]   "}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentry",
        description="Detect brute-force attempts, scanner probes, and suspicious "
                    "clients in server logs.",
    )
    p.add_argument("--auth", type=Path, help="path to an sshd auth log (auth.log / secure)")
    p.add_argument("--web", type=Path, help="path to a Combined Log Format access log")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--evidence", action="store_true",
                   help="include raw evidence lines in text output")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def render_text(findings: list[Finding], show_evidence: bool) -> str:
    if not findings:
        return "no findings — logs look clean"
    lines = [f"{len(findings)} finding(s)\n"]
    for f in findings:
        lines.append(f"{_SEV_ICON[f.severity]} {f.rule:<20} {f.ip:<16} {f.summary}")
        if show_evidence:
            lines.extend(f"    | {e}" for e in f.evidence[:5])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.auth and not args.web:
        print("error: provide --auth and/or --web log file", file=sys.stderr)
        return 2

    auth_events = web_events = None
    try:
        if args.auth:
            auth_events = list(parse_auth_log(
                args.auth.read_text(encoding="utf-8", errors="replace").splitlines()))
        if args.web:
            web_events = list(parse_web_log(
                args.web.read_text(encoding="utf-8", errors="replace").splitlines()))
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    findings = analyze(auth_events, web_events)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(render_text(findings, args.evidence))
    return 0 if not findings else 3  # non-zero when findings exist, for scripting


if __name__ == "__main__":
    raise SystemExit(main())
