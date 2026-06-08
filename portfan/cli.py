"""PORTFAN command-line interface.

Subcommands:
  triage  FILE            Summarize one nmap XML scan into prioritized findings.
  diff    OLD NEW         Diff two nmap XML scans (attack-surface change).

Exit codes:
  0  success, nothing notable (no findings / no surface change)
  1  runtime/parse error
  2  findings present (triage) or attack surface increased (diff)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import parse_nmap_xml, summarize, diff_reports


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _print_triage_table(summary: dict) -> None:
    print(f"PORTFAN triage — {summary['hosts_up']}/{summary['hosts_total']} hosts up, "
          f"{summary['open_services']} open services")
    sev = summary["severity_counts"]
    if sev:
        print("  severity: " + ", ".join(f"{k}={v}" for k, v in sorted(sev.items())))
    print(f"{'SCORE':>5}  {'SEV':<8} {'HOST':<16} {'PORT':<9} {'SERVICE':<14} REASON")
    print("-" * 78)
    for f in summary["findings"]:
        portcol = f"{f['port']}/{f['protocol']}"
        ver = " ".join(x for x in (f["product"], f["version"]) if x)
        svc = (f["service"] + (f" {ver}" if ver else ""))[:14]
        reason = f["reasons"][0] if f["reasons"] else ""
        print(f"{f['score']:>5}  {f['severity']:<8} {f['host']:<16} {portcol:<9} {svc:<14} {reason}")


def _print_diff_table(d: dict) -> None:
    print(f"PORTFAN diff — +{d['opened_count']} opened, -{d['closed_count']} closed, "
          f"~{d['changed_count']} changed")
    if d["opened"]:
        print("\nNEWLY OPEN (attack surface increase):")
        for f in d["opened"]:
            print(f"  + {f['host']}:{f['port']}/{f['protocol']} "
                  f"{f['service']} (score {f['score']}, {f['severity']})")
    if d["changed"]:
        print("\nCHANGED:")
        for c in d["changed"]:
            b, a = c["before"], c["after"]
            print(f"  ~ {c['host']}:{c['port']}/{c['protocol']} "
                  f"{b['service']} {b['version']} -> {a['service']} {a['version']}")
    if d["closed"]:
        print("\nCLOSED:")
        for f in d["closed"]:
            print(f"  - {f['host']}:{f['port']}/{f['protocol']} {f['service']}")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Summarize and diff nmap XML into prioritized triage findings "
                    "(defensive analysis only — no scanning, no network).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json"), default="table",
                   help="Output format (default: table).")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("triage", help="Summarize one nmap XML scan.")
    t.add_argument("file", help="Path to nmap -oX XML file.")

    d = sub.add_parser("diff", help="Diff two nmap XML scans.")
    d.add_argument("old", help="Path to baseline nmap XML file.")
    d.add_argument("new", help="Path to newer nmap XML file.")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.command == "triage":
            reports = parse_nmap_xml(_read(args.file))
            summary = summarize(reports)
            if args.format == "json":
                print(json.dumps(summary, indent=2))
            else:
                _print_triage_table(summary)
            return 2 if summary["open_services"] > 0 else 0

        if args.command == "diff":
            old = parse_nmap_xml(_read(args.old))
            new = parse_nmap_xml(_read(args.new))
            d = diff_reports(old, new)
            if args.format == "json":
                print(json.dumps(d, indent=2))
            else:
                _print_diff_table(d)
            return 2 if d["opened_count"] > 0 else 0

    except (OSError, ValueError) as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
