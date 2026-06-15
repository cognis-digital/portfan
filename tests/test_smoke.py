"""Smoke tests for PORTFAN. No network access."""
import json
import os
import tempfile
import unittest

from portfan import (
    TOOL_NAME,
    TOOL_VERSION,
    parse_nmap_xml,
    summarize,
    diff_reports,
    score_service,
)
from portfan.cli import main

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")
BASELINE = os.path.join(DEMO, "baseline.xml")
FOLLOWUP = os.path.join(DEMO, "followup.xml")


class TestCore(unittest.TestCase):
    def setUp(self):
        with open(BASELINE, encoding="utf-8") as fh:
            self.reports = parse_nmap_xml(fh.read())

    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "portfan")
        self.assertTrue(TOOL_VERSION)

    def test_parse_basic(self):
        self.assertEqual(len(self.reports), 1)
        host = self.reports[0]
        self.assertEqual(host.host, "10.10.10.5")
        self.assertEqual(host.hostname, "lab-web-01.example.test")
        self.assertEqual(host.state, "up")
        self.assertEqual(len(host.findings), 3)

    def test_telnet_is_top_priority(self):
        top = self.reports[0].findings[0]
        self.assertEqual(top.service, "telnet")
        self.assertEqual(top.severity, "critical")
        self.assertGreaterEqual(top.score, 8)

    def test_eol_apache_bumps_score(self):
        score, reasons = score_service("http", "Apache httpd", "2.2.15", 80)
        self.assertTrue(any("Apache" in r for r in reasons))
        self.assertGreater(score, 4)

    def test_summarize(self):
        summary = summarize(self.reports)
        self.assertEqual(summary["hosts_up"], 1)
        self.assertEqual(summary["open_services"], 3)
        self.assertIn("critical", summary["severity_counts"])

    def test_diff_detects_changes(self):
        with open(BASELINE, encoding="utf-8") as fh:
            old = parse_nmap_xml(fh.read())
        with open(FOLLOWUP, encoding="utf-8") as fh:
            new = parse_nmap_xml(fh.read())
        d = diff_reports(old, new)
        opened_ports = {f["port"] for f in d["opened"]}
        closed_ports = {f["port"] for f in d["closed"]}
        changed_ports = {c["port"] for c in d["changed"]}
        self.assertIn(6379, opened_ports)   # redis appeared
        self.assertIn(445, opened_ports)    # smb appeared
        self.assertIn(23, closed_ports)     # telnet remediated
        self.assertIn(80, changed_ports)    # apache upgraded

    def test_bad_xml_raises(self):
        with self.assertRaises(ValueError):
            parse_nmap_xml("<notnmap></notnmap>")


class TestCli(unittest.TestCase):
    def test_triage_exit_code_on_findings(self):
        self.assertEqual(main(["--format", "json", "triage", BASELINE]), 2)

    def test_diff_exit_code_on_new_surface(self):
        self.assertEqual(main(["diff", BASELINE, FOLLOWUP]), 2)

    def test_diff_no_change_is_zero(self):
        self.assertEqual(main(["diff", BASELINE, BASELINE]), 0)

    def test_error_exit_code(self):
        self.assertEqual(main(["triage", "/nonexistent/path.xml"]), 1)

    def test_json_is_valid(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--format", "json", "triage", BASELINE])
        data = json.loads(buf.getvalue())
        self.assertIn("findings", data)


class TestHardening(unittest.TestCase):
    """Tests for the hardened input-validation and edge-case paths."""

    # --- parse_nmap_xml edge cases ---

    def test_empty_string_raises(self):
        """parse_nmap_xml('') must raise ValueError, not propagate ET internals."""
        with self.assertRaises(ValueError) as ctx:
            parse_nmap_xml("")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_whitespace_only_raises(self):
        """Whitespace-only input is not valid XML content."""
        with self.assertRaises(ValueError):
            parse_nmap_xml("   \n\t  ")

    def test_malformed_xml_raises(self):
        """Broken XML must raise ValueError with a descriptive message."""
        with self.assertRaises(ValueError) as ctx:
            parse_nmap_xml("<?xml version='1.0'?><nmaprun><host UNCLOSED")
        self.assertIn("nmap XML", str(ctx.exception))

    def test_out_of_range_ports_skipped(self):
        """Ports with portid <= 0 or > 65535 must be silently skipped."""
        xml = (
            '<nmaprun scanner="nmap">'
            '<host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/>'
            '<ports>'
            '<port protocol="tcp" portid="0"><state state="open"/>'
            '<service name="zero"/></port>'
            '<port protocol="tcp" portid="-1"><state state="open"/>'
            '<service name="neg"/></port>'
            '<port protocol="tcp" portid="99999"><state state="open"/>'
            '<service name="toobig"/></port>'
            '<port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh"/></port>'
            '</ports>'
            '</host>'
            '</nmaprun>'
        )
        reports = parse_nmap_xml(xml)
        ports = {f.port for r in reports for f in r.findings}
        # Only port 22 is within the valid 1-65535 range.
        self.assertEqual(ports, {22})

    def test_summarize_empty_reports(self):
        """summarize([]) must return a well-formed dict with zero counts."""
        s = summarize([])
        self.assertEqual(s["hosts_total"], 0)
        self.assertEqual(s["hosts_up"], 0)
        self.assertEqual(s["open_services"], 0)
        self.assertEqual(s["findings"], [])

    def test_diff_both_empty(self):
        """diff_reports([], []) must return zero counts without error."""
        d = diff_reports([], [])
        self.assertEqual(d["opened_count"], 0)
        self.assertEqual(d["closed_count"], 0)
        self.assertEqual(d["changed_count"], 0)

    # --- CLI error-path tests ---

    def test_directory_as_file_gives_exit_1(self):
        """Passing a directory path instead of a file must exit with code 1."""
        rc = main(["triage", tempfile.gettempdir()])
        self.assertEqual(rc, 1)

    def test_empty_file_gives_exit_1(self):
        """An empty XML file must produce exit code 1 (parse error), not crash."""
        with tempfile.NamedTemporaryFile(
            suffix=".xml", delete=False, mode="w", encoding="utf-8"
        ) as fh:
            fh.write("")
            tmp = fh.name
        try:
            rc = main(["triage", tmp])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(tmp)

    def test_non_utf8_file_gives_exit_1(self):
        """A binary / non-UTF-8 file must produce exit code 1, not a traceback."""
        with tempfile.NamedTemporaryFile(
            suffix=".xml", delete=False, mode="wb"
        ) as fh:
            fh.write(b"\xff\xfe<notxml>\x00\x01\x02")
            tmp = fh.name
        try:
            rc = main(["triage", tmp])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(tmp)

    def test_mcp_server_importable(self):
        """portfan.mcp_server must be importable without ImportError."""
        import importlib
        mod = importlib.import_module("portfan.mcp_server")
        self.assertTrue(callable(getattr(mod, "serve", None)))


if __name__ == "__main__":
    unittest.main()
