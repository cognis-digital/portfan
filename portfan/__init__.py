"""PORTFAN — turn raw nmap XML scans into a prioritized triage list.

Defensive / authorized-testing tool: it parses, summarizes, scores and diffs
nmap XML output. It performs NO scanning, NO exploitation, and makes NO network
connections — it is pure analysis of scan artifacts you already own.
"""
from .core import (
    Finding,
    HostReport,
    parse_nmap_xml,
    summarize,
    diff_reports,
    score_service,
)

TOOL_NAME = "portfan"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "HostReport",
    "parse_nmap_xml",
    "summarize",
    "diff_reports",
    "score_service",
]
