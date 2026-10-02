"""Unit tests for AX9. Run: python -m unittest discover -s tests -v"""
from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ax9 import cli
from ax9.engine import evaluate, merge_sources, needs_action
from ax9.ingest import load_controls, load_siem_sources
from ax9.models import Asset, LogSource, RiskException, Status
from ax9.ui import UI

ROOT = Path(__file__).resolve().parent.parent
AS_OF = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
CONTROLS = load_controls(ROOT / "controls.json")


def asset(host: str = "h1", asset_id: str = "A1", pci: bool = True) -> Asset:
    return Asset(asset_id, host, "production", pci, "owner", "critical")


def source(host: str = "h1", age_hours: float = 1, retention: int = 400, hot: int = 90) -> LogSource:
    return LogSource(host, "syslog", AS_OF - timedelta(hours=age_hours), retention, hot)


def exception(asset_id: str = "A1", control: str = "LOG-01", approved_days_ago: int = 30, expires_in_days: int = 30) -> RiskException:
    return RiskException(
        asset_id, control, "test", "ciso@example.com",
        AS_OF - timedelta(days=approved_days_ago), AS_OF + timedelta(days=expires_in_days),
    )


def run(assets, sources, exceptions=(), issues=()):
    return evaluate(list(assets), list(sources), list(exceptions), list(issues), CONTROLS, AS_OF, {})


def only_finding(result):
    assert len(result.findings) == 1
    return result.findings[0]


class StatusTests(unittest.TestCase):
    """One test per status the control can produce."""

    def test_pass(self):
        finding = only_finding(run([asset()], [source()]))
        self.assertEqual(finding.status, Status.PASS)
        self.assertEqual(finding.failed_checks, ())

    def test_stale(self):
        finding = only_finding(run([asset()], [source(age_hours=30)]))
        self.assertEqual(finding.status, Status.STALE)
        self.assertEqual(finding.failed_checks, ("freshness",))

    def test_freshness_boundary_is_inclusive(self):
        finding = only_finding(run([asset()], [source(age_hours=24)]))
        self.assertEqual(finding.status, Status.PASS)

    def test_fail_retention(self):
        finding = only_finding(run([asset()], [source(retention=180)]))
        self.assertEqual(finding.status, Status.FAIL)
        self.assertEqual(finding.failed_checks, ("retention",))

    def test_fail_hot_retention(self):
        finding = only_finding(run([asset()], [source(hot=30)]))
        self.assertEqual(finding.status, Status.FAIL)
        self.assertEqual(finding.failed_checks, ("hot_retention",))

    def test_missing_marks_other_checks_not_evaluated(self):
        finding = only_finding(run([asset()], []))
        self.assertEqual(finding.status, Status.MISSING)
        self.assertEqual(finding.failed_checks, ("coverage",))
        others = {c.check_id: c.status for c in finding.checks if c.check_id != "coverage"}
        self.assertTrue(all(s is Status.NOT_EVALUATED for s in others.values()))

    def test_future_timestamp_fails_and_is_flagged(self):
        result = run([asset()], [source(age_hours=-5)])
        self.assertEqual(only_finding(result).status, Status.FAIL)
        self.assertTrue(any("future" in i.problem for i in result.data_quality))


class PrecedenceTests(unittest.TestCase):
    def test_fail_beats_stale_and_all_failures_are_listed(self):
        finding = only_finding(run([asset()], [source(age_hours=48, retention=100)]))
        self.assertEqual(finding.status, Status.FAIL)
        self.assertEqual(set(finding.failed_checks), {"freshness", "retention"})

    def test_missing_beats_everything(self):
        finding = only_finding(run([asset()], []))
        self.assertEqual(finding.status, Status.MISSING)


class ExceptionTests(unittest.TestCase):
    def test_valid_exception_keeps_original_finding(self):
        finding = only_finding(run([asset()], [], [exception()]))
        self.assertEqual(finding.status, Status.EXCEPTION)
        self.assertEqual(finding.underlying_status, Status.MISSING)
        self.assertEqual(finding.exception_state, "valid")

    def test_expired_exception_does_not_apply(self):
        finding = only_finding(run([asset()], [], [exception(approved_days_ago=200, expires_in_days=-1)]))
        self.assertEqual(finding.status, Status.MISSING)
        self.assertEqual(finding.exception_state, "expired")

    def test_future_exception_does_not_apply_yet(self):
        finding = only_finding(run([asset()], [], [exception(approved_days_ago=-1)]))
        self.assertEqual(finding.status, Status.MISSING)
        self.assertEqual(finding.exception_state, "not_yet_effective")

    def test_exception_for_another_control_is_ignored(self):
        finding = only_finding(run([asset()], [], [exception(control="IAM-07")]))
        self.assertEqual(finding.status, Status.MISSING)
        self.assertEqual(finding.exception_state, "none")

    def test_exception_on_passing_asset_stays_pass(self):
        finding = only_finding(run([asset()], [source()], [exception()]))
        self.assertEqual(finding.status, Status.PASS)


class ScopeAndInventoryTests(unittest.TestCase):
    def test_out_of_scope_asset_is_ignored(self):
        result = run([asset(pci=False)], [])
        self.assertEqual(result.findings, ())
        self.assertEqual(result.out_of_scope_count, 1)

    def test_untracked_host_is_reported(self):
        result = run([asset()], [source(), source(host="shadow-01")])
        self.assertEqual([u.hostname for u in result.untracked], ["shadow-01"])

    def test_hostname_join_ignores_case_and_spaces(self):
        finding = only_finding(run([asset(host="Pay-GW-01")], [source(host=" pay-gw-01 ")]))
        self.assertEqual(finding.status, Status.PASS)

    def test_duplicate_sources_use_conservative_view(self):
        merged = merge_sources([source(age_hours=1, retention=400), source(age_hours=50, retention=200)])
        self.assertEqual(merged.retention_days, 200)
        self.assertEqual(merged.last_event_at, AS_OF - timedelta(hours=1))


class EvidenceQualityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_malformed_row_is_rejected_and_asset_is_missing(self):
        path = self.tmp / "siem_sources.csv"
        path.write_text(
            "hostname,source_type,last_event_at,retention_days,hot_retention_days\n"
            "h1,syslog,01/10/2026 08:30,400,90\n"
            "h2,syslog,2026-10-01T08:00:00Z,,90\n",
            encoding="utf-8",
        )
        sources, issues = load_siem_sources(path)
        self.assertEqual(sources, [])
        self.assertEqual({(i.key, i.field) for i in issues}, {("h1", "last_event_at"), ("h2", "retention_days")})
        finding = only_finding(run([asset()], sources, issues=issues))
        self.assertEqual(finding.status, Status.MISSING)
        self.assertIn("rejected", finding.checks[0].reason)

    def test_evidence_records_rule_threshold_and_time(self):
        finding = only_finding(run([asset()], [source(retention=100)]))
        retention = next(c for c in finding.checks if c.check_id == "retention")
        self.assertEqual(retention.evidence.value, "100d")
        self.assertEqual(retention.evidence.threshold, ">= 365d")
        self.assertEqual(retention.evidence.evaluated_at, AS_OF)
        self.assertIn("PCI DSS v4.0.1 10.5.1", retention.requirements)


class ExitCodeTests(unittest.TestCase):
    """End-to-end through the CLI, the way CI would call it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.data = self.tmp / "data"
        self.data.mkdir()
        (self.data / "assets.csv").write_text(
            "asset_id,hostname,environment,pci_scope,owner,criticality\nA1,h1,production,yes,o,critical\n", encoding="utf-8")
        (self.data / "exceptions.csv").write_text(
            "asset_id,control_id,reason,approved_by,approved_at,expires_at\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _main(self, siem_row: str, as_of: str = "2026-10-01T09:00:00Z") -> int:
        (self.data / "siem_sources.csv").write_text(
            "hostname,source_type,last_event_at,retention_days,hot_retention_days\n" + siem_row, encoding="utf-8")
        argv = ["--data-dir", str(self.data), "--out-dir", str(self.tmp / "out"),
                "--controls", str(ROOT / "controls.json"), "--as-of", as_of, "--no-banner"]
        with contextlib.redirect_stderr(io.StringIO()):
            return cli.main(argv)

    def test_exit_0_when_compliant(self):
        self.assertEqual(self._main("h1,syslog,2026-10-01T08:00:00Z,400,90\n"), 0)
        for name in ("results.json", "results.csv", "report.md"):
            self.assertTrue((self.tmp / "out" / name).exists())

    def test_exit_1_when_action_required(self):
        self.assertEqual(self._main("h1,syslog,2026-09-20T08:00:00Z,400,90\n"), 1)

    def test_exit_2_on_bad_as_of(self):
        self.assertEqual(self._main("h1,syslog,2026-10-01T08:00:00Z,400,90\n", as_of="yesterday"), 2)

    def test_custom_siem_file_keeps_evidence_traceable(self):
        custom = self.tmp / "export_splunk_2026-10.csv"
        custom.write_text(
            "hostname,source_type,last_event_at,retention_days,hot_retention_days\n"
            "h1,syslog,01/10/2026 08:30,400,90\n", encoding="utf-8")
        argv = ["--data-dir", str(self.data), "--siem", str(custom), "--out-dir", str(self.tmp / "out"),
                "--controls", str(ROOT / "controls.json"), "--as-of", "2026-10-01T09:00:00Z", "--no-banner"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(argv), 1)
        report = json.loads((self.tmp / "out" / "results.json").read_text(encoding="utf-8"))
        coverage = report["findings"][0]["checks"][0]
        self.assertIn("rejected", coverage["reason"])
        self.assertEqual(coverage["evidence"]["source_file"], custom.name)
        self.assertIn(custom.name, report["run"]["input_sha256"])

    def test_needs_action_ignores_valid_exceptions(self):
        result = run([asset()], [], [exception()])
        self.assertFalse(needs_action(result))


class ConsoleTableTests(unittest.TestCase):
    def _render(self, rows, encoding="utf-8", tty=False):
        class Stream(io.StringIO):
            def isatty(self):
                return tty

        Stream.encoding = encoding  # type: ignore[assignment]
        stream = Stream()
        UI(stream).table("t", ["NAME", "STATUS"], rows)
        return [l for l in stream.getvalue().splitlines() if l.startswith("    ")]

    def test_rows_are_aligned_even_with_colors(self):
        lines = self._render([["a", ("FAIL", "red")], ["longer-name", ("PASS", "green")]], tty=True)
        plain = [re.sub(r"\x1b\[[0-9;]*m", "", l) for l in lines]
        self.assertEqual(len({len(l) for l in plain}), 1)
        self.assertTrue(any("\x1b[31m" in l for l in lines))

    def test_no_colors_when_not_a_tty(self):
        lines = self._render([["a", ("FAIL", "red")]])
        self.assertFalse(any("\x1b[" in l for l in lines))

    def test_ascii_fallback_when_encoding_lacks_box_chars(self):
        lines = self._render([["a", "PASS"]], encoding="ascii")
        self.assertTrue(lines[0].strip().startswith("+-"))
        "\n".join(lines).encode("ascii")


if __name__ == "__main__":
    unittest.main()
