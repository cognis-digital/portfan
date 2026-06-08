"""Smoke tests for PORTFAN. No network access."""
import json
import os
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


if __name__ == "__main__":
    unittest.main()
