"""
APKRadar — MailRadar is not run on a domain that does not exist.

MailRadar's own `check` command asks first whether the domain exists in DNS, and
stops if it does not. APKRadar called `analyze_domain` directly and skipped that
question, so a name with no DNS at all came back as "0/100 — CRITICAL": every
lookup answered NXDOMAIN, every check found no record, every check scored zero.
Measured on 2026-11-15 with mailradar 2026.44 on apkradar-no-such-domain.invalid.

That grade is a claim about a holder's email security, and there is no holder.
Through `send --publisher-domain`, a mistyped domain put "0/100 — CRITICAL,
indicando misure tecniche inadeguate" into a letter addressed to a DPO.

The resolver is replaced: the answer under test is NXDOMAIN, or a timeout, and a
real lookup would make the result depend on the network the suite runs on. A
timeout with no network turned "not found" into "lookup failed".
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from apkradar.cli import _check_mailradar, _mail_grade_colour, app

# dnspython is MailRadar's dependency, not APKRadar's (tests/test_declared_imports.py):
# its resolver and exceptions are reached through the module that uses them.
checker = pytest.importorskip("mailradar.checker")
dns = checker.dns

MISSING = "apkradar-no-such-domain.invalid"


def _nxdomain(*args, **kwargs):
    raise dns.resolver.NXDOMAIN


def _timeout(*args, **kwargs):
    raise dns.exception.Timeout


def test_no_score_for_a_domain_that_does_not_exist():
    with patch.object(dns.resolver, "resolve", _nxdomain), \
         patch("mailradar.checker.analyze_domain") as analyze:
        score, grade = _check_mailradar(MISSING)
    assert score is None
    assert grade != "CRITICAL"
    analyze.assert_not_called()


def test_the_reason_is_given():
    """'unavailable' alone sends the reader looking for a broken install."""
    with patch.object(dns.resolver, "resolve", _nxdomain):
        _, reason = _check_mailradar(MISSING)
    assert reason is not None
    assert "not found" in reason.lower()


def test_a_failed_lookup_is_not_read_as_a_missing_domain():
    """A timeout says nothing about the name, as in MailRadar's `check`."""
    with patch.object(dns.resolver, "resolve", _timeout), \
         patch("mailradar.checker.analyze_domain") as analyze:
        score, reason = _check_mailradar(MISSING)
    assert score is None
    assert "failed" in reason.lower()
    assert "not found" not in reason.lower()
    analyze.assert_not_called()


def test_a_report_mailradar_did_not_grade_gives_no_score():
    """MailRadar leaves total_score None when lookups got no answer: "could not
    tell" is not "bad", and it is not a number either."""
    ungraded = SimpleNamespace(total_score=None, grade="N/A")
    with patch("mailradar.checker.domain_exists", return_value=True), \
         patch("mailradar.checker.analyze_domain", return_value=ungraded):
        score, reason = _check_mailradar("example.com")
    assert score is None
    assert "not graded" in reason


def test_a_domain_that_exists_is_graded_as_mailradar_grades_it():
    graded = SimpleNamespace(total_score=78, grade="GOOD")
    with patch("mailradar.checker.domain_exists", return_value=True), \
         patch("mailradar.checker.analyze_domain", return_value=graded):
        assert _check_mailradar("example.com") == (78, "GOOD")


def test_without_mailradar_the_reason_says_so():
    """A missing install is not a missing domain, and not a failed lookup."""
    with patch.dict("sys.modules", {"mailradar.checker": None}):
        assert _check_mailradar("example.com") == (None, "MailRadar not installed")


def test_the_letter_carries_no_grade_for_a_missing_domain():
    """The reason is shown to whoever sends, and stays out of the letter."""
    from apkradar.scanner import ScanResult

    scan_result = ScanResult(apk_path="test.apk", package_name="com.example.app", app_name="Example")
    with patch("apkradar.scanner.scan", return_value=scan_result), \
         patch("apkradar.cli._check_mailradar", return_value=(None, "domain not found in DNS")), \
         patch("apkradar.cli._check_ssl", return_value=("error", None)):
        result = CliRunner().invoke(app, [
            "send", "test.apk",
            "--to", "dpo@example.com",
            "--publisher", "Example Srl",
            "--publisher-domain", MISSING,
            "--from", "test@example.com",
            "--smtp-host", "mail.example.com",
            "--smtp-user", "test@example.com",
            "--name", "Test User",
            "--dry-run",
        ])
    assert result.exit_code == 0, result.output
    head, _, letter = result.output.partition("DPO Letter Preview")
    assert "domain not found in DNS" in head
    assert "domain not found" not in letter
    assert "/100" not in letter


def test_colour_follows_mailradars_grade_not_its_own_thresholds():
    """APKRadar coloured by score (80/60), MailRadar grades at 90/75/50/25:
    a GOOD 78 came out yellow beside MailRadar's green, a MODERATE 55 red.
    MailRadar shows POOR in orange; here it is red, with CRITICAL."""
    assert _mail_grade_colour("EXCELLENT") == "green"
    assert _mail_grade_colour("GOOD") == "green"
    assert _mail_grade_colour("MODERATE") == "yellow"
    assert _mail_grade_colour("POOR") == "red"
    assert _mail_grade_colour("CRITICAL") == "red"
