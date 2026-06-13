"""Core engine for PORTFAN.

Parses nmap XML (the `-oX` output format) and produces prioritized, defensive
triage findings. No network access — everything operates on local scan files.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Risk model
# ---------------------------------------------------------------------------
# Services that commonly warrant attention first during authorized triage.
# These are *prioritization hints*, not exploit logic.
_HIGH_RISK_SERVICES = {
    "telnet": ("Cleartext remote login", 9),
    "ftp": ("Cleartext file transfer; check for anonymous access", 7),
    "rlogin": ("Legacy cleartext r-services", 9),
    "rsh": ("Legacy cleartext r-services", 9),
    "vnc": ("Remote desktop; often weak/no auth", 8),
    "rdp": ("Remote desktop; brute-force & CVE surface", 7),
    "ms-wbt-server": ("RDP; brute-force & CVE surface", 7),
    "smb": ("File sharing; legacy SMBv1 / null sessions", 8),
    "microsoft-ds": ("SMB file sharing; legacy/null sessions", 8),
    "netbios-ssn": ("NetBIOS/SMB legacy exposure", 7),
    "mysql": ("Database exposed to network", 7),
    "ms-sql-s": ("Database exposed to network", 7),
    "postgresql": ("Database exposed to network", 7),
    "mongodb": ("Database exposed; historically unauthenticated", 8),
    "redis": ("In-memory store; often unauthenticated", 8),
    "elasticsearch": ("Search cluster; historically unauthenticated", 8),
    "memcached": ("Cache; UDP amplification & no auth", 7),
    "smtp": ("Mail relay; check open-relay", 5),
    "snmp": ("Often default community strings", 7),
    "ldap": ("Directory service; anon-bind exposure", 6),
    "http": ("Web service — enumerate app surface", 4),
    "https": ("Web service — enumerate app surface", 4),
    "ssh": ("Remote login — check version/auth policy", 3),
}

_OBSOLETE_VERSION_HINTS = (
    ("smbv1", "SMBv1 is obsolete (EternalBlue family)"),
    ("openssl/0.9", "Ancient OpenSSL"),
    # nmap XML separates product and version with a space, so the banner is
    # e.g. "apache httpd 2.2.15" — match product substring + version prefix.
    ("apache httpd 2.0", "End-of-life Apache 2.0"),
    ("apache httpd 2.2", "End-of-life Apache 2.2"),
    ("apache/2.0", "End-of-life Apache 2.0"),   # raw-banner / HTTP Server header fallback
    ("apache/2.2", "End-of-life Apache 2.2"),   # raw-banner / HTTP Server header fallback
    ("iis/6.0", "End-of-life IIS 6.0"),
    ("microsoft-iis/6.0", "End-of-life IIS 6.0"),
    ("php/5.", "End-of-life PHP 5.x"),
    ("php 5.", "End-of-life PHP 5.x"),
    ("openssh_4", "Very old OpenSSH"),
    ("openssh_5", "Old OpenSSH"),
    ("vsftpd 2.3.4", "vsftpd 2.3.4 backdoor banner"),
)


@dataclass
class Finding:
    """A single prioritized triage item for one open service."""
    host: str
    hostname: Optional[str]
    port: int
    protocol: str
    service: str
    product: str
    version: str
    state: str
    score: int
    severity: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostReport:
    host: str
    hostname: Optional[str]
    state: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "hostname": self.hostname,
            "state": self.state,
            "findings": [f.to_dict() for f in self.findings],
        }


def _severity_for(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 1:
        return "low"
    return "info"


def score_service(service: str, product: str, version: str, port: int) -> tuple[int, list[str]]:
    """Return (score, reasons) for an open service. Pure, deterministic."""
    reasons: list[str] = []
    svc = (service or "").lower()
    base = 2
    if svc in _HIGH_RISK_SERVICES:
        note, base = _HIGH_RISK_SERVICES[svc]
        reasons.append(note)
    else:
        reasons.append("Open service — review necessity")

    banner = " ".join(x for x in (product, version) if x).lower()
    for needle, note in _OBSOLETE_VERSION_HINTS:
        if needle in banner:
            base = min(10, base + 2)
            reasons.append(note)

    # Admin/management ports get a small bump when exposed.
    if port in (22, 23, 3389, 5900, 5985, 5986):
        reasons.append(f"Management port {port} exposed")
        base = min(10, base + 1)

    if not banner:
        reasons.append("No version detected — run -sV to confirm")

    return min(10, base), reasons


def parse_nmap_xml(xml_text: str) -> list[HostReport]:
    """Parse nmap -oX XML text into HostReport objects."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"Not valid nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("Root element is not <nmaprun>; not an nmap XML file")

    reports: list[HostReport] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        host_state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        addr = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                addr = addr_el.get("addr")
                break
        if addr is None:
            mac = host_el.find("address")
            addr = mac.get("addr") if mac is not None else "unknown"

        hostname = None
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name")

        report = HostReport(host=addr, hostname=hostname, state=host_state)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                if state != "open":
                    continue
                proto = port_el.get("protocol", "tcp")
                try:
                    portid = int(port_el.get("portid", "0"))
                except ValueError:
                    portid = 0
                svc_el = port_el.find("service")
                service = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""

                score, reasons = score_service(service, product, version, portid)
                report.findings.append(
                    Finding(
                        host=addr,
                        hostname=hostname,
                        port=portid,
                        protocol=proto,
                        service=service or "unknown",
                        product=product,
                        version=version,
                        state=state,
                        score=score,
                        severity=_severity_for(score),
                        reasons=reasons,
                    )
                )
        report.findings.sort(key=lambda f: (-f.score, f.port))
        reports.append(report)
    return reports


def summarize(reports: list[HostReport]) -> dict:
    """Build a prioritized triage summary across all hosts."""
    all_findings: list[Finding] = []
    for r in reports:
        all_findings.extend(r.findings)
    all_findings.sort(key=lambda f: (-f.score, f.host, f.port))

    sev_counts: dict[str, int] = {}
    for f in all_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    hosts_up = sum(1 for r in reports if r.state == "up")
    return {
        "hosts_total": len(reports),
        "hosts_up": hosts_up,
        "open_services": len(all_findings),
        "severity_counts": sev_counts,
        "findings": [f.to_dict() for f in all_findings],
    }


def _finding_key(f: Finding) -> tuple:
    return (f.host, f.protocol, f.port)


def diff_reports(old: list[HostReport], new: list[HostReport]) -> dict:
    """Diff two scans: report newly-opened, newly-closed and changed services."""
    old_map: dict[tuple, Finding] = {}
    for r in old:
        for f in r.findings:
            old_map[_finding_key(f)] = f
    new_map: dict[tuple, Finding] = {}
    for r in new:
        for f in r.findings:
            new_map[_finding_key(f)] = f

    opened = [new_map[k].to_dict() for k in sorted(new_map.keys() - old_map.keys())]
    closed = [old_map[k].to_dict() for k in sorted(old_map.keys() - new_map.keys())]
    changed = []
    for k in sorted(old_map.keys() & new_map.keys()):
        o, n = old_map[k], new_map[k]
        if (o.service, o.product, o.version) != (n.service, n.product, n.version):
            changed.append({
                "host": n.host,
                "port": n.port,
                "protocol": n.protocol,
                "before": {"service": o.service, "product": o.product, "version": o.version},
                "after": {"service": n.service, "product": n.product, "version": n.version},
            })

    # opened ports are the actionable attack-surface increase.
    opened.sort(key=lambda d: (-d["score"], d["host"], d["port"]))
    return {
        "opened": opened,
        "closed": closed,
        "changed": changed,
        "opened_count": len(opened),
        "closed_count": len(closed),
        "changed_count": len(changed),
    }
