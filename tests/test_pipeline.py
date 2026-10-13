import csv
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dfir_assistant import ai_assist
from dfir_assistant.analyzer import analyze
from dfir_assistant.cli import main
from dfir_assistant.ioc import defang, extract_indicators
from dfir_assistant.models import Event, Finding
from dfir_assistant.parsers import UnknownFormatError, parse_file, parse_linux_auth, parse_web_access, parse_windows_jsonl
from dfir_assistant.report import render_report
from dfir_assistant.timeline import csv_safe

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
AUTH = SAMPLES / "linux_auth.log"
WEB = SAMPLES / "web_access.log"
WIN = SAMPLES / "windows_events.jsonl"
REF_RE = re.compile(r"E-\d{6}")


def _run_samples():
    return analyze([AUTH, WEB, WIN], year=2026)


class ParserTests(unittest.TestCase):
    def test_linux_failed_login_fields(self):
        event = parse_linux_auth(
            "Oct 10 09:01:10 web01 sshd[2140]: Failed password for root from 203.0.113.50 port 51001 ssh2",
            "x.log", 1, 2026,
        )
        self.assertEqual(event.kind, "ssh.failed_login")
        self.assertEqual((event.user, event.src_ip), ("root", "203.0.113.50"))
        self.assertEqual(event.timestamp, datetime(2026, 10, 10, 9, 1, 10, tzinfo=timezone.utc))

    def test_linux_invalid_user_prefix_is_stripped(self):
        event = parse_linux_auth(
            "Oct 10 09:01:18 web01 sshd[2141]: Failed password for invalid user admin from 203.0.113.50 port 1 ssh2",
            "x.log", 1, 2026,
        )
        self.assertEqual(event.user, "admin")

    def test_sudo_command_is_classified(self):
        event = parse_linux_auth(
            "Oct 10 09:09:05 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
            "x.log", 1, 2026,
        )
        self.assertEqual(event.kind, "sudo.command")
        self.assertEqual(event.fields["command"], "/bin/bash")
        self.assertEqual(event.fields["runas"], "root")

    def test_web_timestamp_is_converted_to_utc(self):
        event = parse_web_access(
            '203.0.113.9 - - [10/Oct/2026:11:00:00 +0200] "GET /x HTTP/1.1" 404 196 "-" "curl/8"', "x.log", 1, 2026,
        )
        self.assertEqual(event.timestamp, datetime(2026, 10, 10, 9, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(event.fields["status"], 404)

    def test_windows_fractional_seconds_and_group_member_cn(self):
        line = ('{"TimeCreated":"2026-10-10T09:43:30.1234567Z","EventID":4732,"Computer":"WIN-SRV01",'
                '"TargetUserName":"Administrators","MemberName":"CN=svc_backup,CN=Users,DC=corp,DC=local"}')
        event = parse_windows_jsonl(line, "x.jsonl", 1, 2026)
        self.assertEqual(event.kind, "win.group_member_added")
        self.assertEqual(event.user, "svc_backup")
        self.assertEqual(event.fields["group"], "Administrators")
        self.assertEqual(event.timestamp.microsecond, 123456)

    def test_unknown_format_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mystery.txt"
            path.write_text("hello world\nnothing to see here\n")
            with self.assertRaises(UnknownFormatError):
                parse_file(path)

    def test_auto_detection_on_samples(self):
        self.assertEqual(parse_file(AUTH).format, "linux_auth")
        self.assertEqual(parse_file(WEB).format, "web_access")
        self.assertEqual(parse_file(WIN).format, "windows_jsonl")


class IndicatorTests(unittest.TestCase):
    def test_defang_formats(self):
        self.assertEqual(defang("ip", "203.0.113.50"), "203[.]0[.]113[.]50")
        self.assertEqual(defang("url", "https://evil.example.com/p.ps1"), "hxxps://evil[.]example[.]com/p.ps1")
        self.assertEqual(defang("email", "bob@example.com"), "bob[@]example[.]com")

    def test_extraction_collects_evidence_refs(self):
        events = [
            Event(kind="a", source_type="t", source_file="f", line_no=1,
                  raw="fetch http://203.0.113.80/nc.exe from 203.0.113.80 hash " + "a" * 64, ref="E-000001"),
            Event(kind="a", source_type="t", source_file="f", line_no=2,
                  raw="see CVE-2024-3400 and 10.0.0.5", ref="E-000002"),
        ]
        by_key = {(i.ioc_type, i.value): i for i in extract_indicators(events)}
        self.assertEqual(by_key[("ip", "203.0.113.80")].evidence_refs, ["E-000001"])
        self.assertTrue(by_key[("ip", "10.0.0.5")].internal)
        self.assertFalse(by_key[("ip", "203.0.113.80")].internal)
        self.assertNotIn(("domain", "203.0.113.80"), by_key)  # an IP host is not a domain
        self.assertEqual(by_key[("sha256", "a" * 64)].evidence_refs, ["E-000001"])
        self.assertEqual(by_key[("cve", "CVE-2024-3400")].evidence_refs, ["E-000002"])


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = _run_samples()
        cls.rule_ids = {f.rule_id for f in cls.result.findings}

    def test_expected_rules_fire_on_samples(self):
        expected = {
            "R-SSH-001", "R-SSH-002", "R-SSH-004", "R-SUDO-001",
            "R-WEB-001", "R-WEB-002", "R-WEB-003",
            "R-WIN-001", "R-WIN-002", "R-WIN-003", "R-WIN-004", "R-WIN-005", "R-WIN-006", "R-WIN-007",
        }
        self.assertTrue(expected <= self.rule_ids, f"missing: {expected - self.rule_ids}")

    def test_success_after_failures_cites_failures_and_success(self):
        finding = next(f for f in self.result.findings if f.rule_id == "R-SSH-002")
        self.assertEqual(finding.entity, "203.0.113.50")
        kinds = [e.kind for e in finding.evidence]
        self.assertEqual(kinds[-1], "ssh.accepted_login")
        self.assertGreaterEqual(kinds.count("ssh.failed_login"), 3)

    def test_benign_activity_is_not_flagged(self):
        flagged_entities = {f.entity for f in self.result.findings}
        self.assertNotIn("198.51.100.20", flagged_entities)  # benign deploy account and browsing
        self.assertNotIn("192.168.1.25", flagged_entities)   # internal jdoe logon
        self.assertNotIn("jdoe", flagged_entities)

    def test_no_findings_without_timestamps_for_bursts(self):
        events = [Event(kind="ssh.failed_login", source_type="t", source_file="f", line_no=i,
                        raw="x", src_ip="203.0.113.9", user="root") for i in range(10)]
        from dfir_assistant.detections import run_detections
        self.assertFalse([f for f in run_detections(events) if f.rule_id == "R-SSH-001"])


class CitationIntegrityTests(unittest.TestCase):
    """Every conclusion must trace back to real evidence in the parsed logs."""

    @classmethod
    def setUpClass(cls):
        cls.result = _run_samples()
        cls.known_refs = {e.ref for e in cls.result.events}

    def test_every_finding_has_evidence_that_exists(self):
        self.assertTrue(self.result.findings)
        for finding in self.result.findings:
            self.assertTrue(finding.evidence, finding.finding_id)
            self.assertTrue(set(finding.evidence_refs) <= self.known_refs, finding.finding_id)

    def test_every_indicator_cites_existing_evidence(self):
        for ioc in self.result.indicators:
            self.assertTrue(ioc.evidence_refs, ioc.value)
            self.assertTrue(set(ioc.evidence_refs) <= self.known_refs, ioc.value)

    def test_report_cites_every_finding_and_its_sources(self):
        report = render_report(self.result)
        for finding in self.result.findings:
            self.assertIn(f"### {finding.finding_id} ·", report)
            for event in finding.evidence[:10]:
                self.assertIn(event.location, report)
                self.assertIn(f"[{event.ref}] {event.raw}", report)

    def test_findings_json_and_timeline_match_report_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(main(["analyze", str(AUTH), str(WEB), str(WIN), "--out", str(out), "--year", "2026"]), 0)
            payload = json.loads((out / "findings.json").read_text())
            self.assertEqual(len(payload["findings"]), len(self.result.findings))
            with (out / "timeline.csv").open(newline="") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), len(self.result.events))
            self.assertEqual({r["evidence_id"] for r in rows}, self.known_refs)
            linked = {r["evidence_id"] for r in rows if r["finding_ids"]}
            self.assertEqual(linked, {e.ref for f in self.result.findings for e in f.evidence})

    def test_timeline_is_sorted_by_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            main(["analyze", str(AUTH), str(WEB), str(WIN), "--out", str(out), "--year", "2026"])
            with (out / "timeline.csv").open(newline="") as fh:
                stamps = [r["timestamp_utc"] for r in csv.DictReader(fh) if r["timestamp_utc"]]
            self.assertEqual(stamps, sorted(stamps))


class TimelineSafetyTests(unittest.TestCase):
    def test_formula_prefixes_are_neutralised(self):
        self.assertEqual(csv_safe("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")")
        self.assertEqual(csv_safe("+cmd"), "'+cmd")
        self.assertEqual(csv_safe("plain"), "plain")


class AIGuardTests(unittest.TestCase):
    def _finding(self):
        event_a = Event(kind="k", source_type="t", source_file="f", line_no=1, raw="a", ref="E-000001")
        event_b = Event(kind="k", source_type="t", source_file="f", line_no=2, raw="b", ref="E-000002")
        return Finding(rule_id="R-TEST", title="t", severity="high", description="d", entity=None,
                       evidence=[event_a, event_b], finding_id="F-001")

    def test_public_endpoints_are_refused(self):
        for url in ("https://api.openai.com/v1/chat/completions", "http://10.0.0.8:11434/api/generate",
                    "https://example.com/generate", "ftp://127.0.0.1/x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                ai_assist.validate_local_endpoint(url)

    def test_loopback_endpoints_are_allowed(self):
        for url in ("http://127.0.0.1:11434/api/generate", "http://localhost:11434/api/generate"):
            self.assertEqual(ai_assist.validate_local_endpoint(url), url)

    def test_only_cited_lines_survive(self):
        text = (
            "Repeated failures precede the login [E-000001].\n"
            "This is an uncited claim.\n"
            "Cites an unknown record [E-999999].\n"
            "- Check the account for changes [E-000002]\n"
        )
        kept = ai_assist.keep_cited_lines(text, self._finding())
        self.assertEqual(kept, ["Repeated failures precede the login [E-000001].",
                                "Check the account for changes [E-000002]"])

    def test_summaries_use_injected_model_and_record_errors(self):
        finding = self._finding()

        def fake_generate(prompt):
            self.assertIn("[E-000001]", prompt)
            return "Suspicious sequence [E-000002]."

        summaries, errors = ai_assist.summarize_findings([finding], fake_generate)
        self.assertEqual(summaries["F-001"], ["Suspicious sequence [E-000002]."])
        self.assertEqual(errors, [])

        def broken(prompt):
            raise OSError("local model unreachable")

        summaries, errors = ai_assist.summarize_findings([finding], broken)
        self.assertEqual(summaries["F-001"], [])
        self.assertEqual(len(errors), 1)

    def test_cli_refuses_public_ai_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = main(["analyze", str(AUTH), "--out", tmp, "--ai-endpoint",
                         "https://api.openai.com/v1/chat", "--ai-model", "x"])
            self.assertEqual(code, 2)
            self.assertFalse((Path(tmp) / "report.md").exists())

    def test_cli_requires_model_with_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(["analyze", str(AUTH), "--out", tmp,
                                   "--ai-endpoint", "http://127.0.0.1:11434/api/generate"]), 2)


class CLITests(unittest.TestCase):
    def test_end_to_end_writes_all_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = main(["analyze", str(WEB), "--out", tmp, "--year", "2026"])
            self.assertEqual(code, 0)
            for name in ("report.md", "timeline.csv", "iocs.csv", "findings.json"):
                self.assertTrue((Path(tmp) / name).is_file(), name)
            report = (Path(tmp) / "report.md").read_text()
            self.assertIn("R-WEB-001", report)
            self.assertIn("## 4. Indicators of compromise", report)
            iocs = (Path(tmp) / "iocs.csv").read_text()
            self.assertIn("203[.]0[.]113[.]50", iocs)
            self.assertNotIn("203.0.113.50", iocs)  # IOCs are written defanged

    def test_missing_input_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(["analyze", str(ROOT / "nope.log"), "--out", tmp]), 2)


if __name__ == "__main__":
    unittest.main()
