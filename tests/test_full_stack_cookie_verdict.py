"""
APKRadar — `--full` must give the verdict CookieRadar gives, not a narrower one.

`_full_stack_domain` used to decide the CookieRadar verdict by itself, as the
trackers seen both before consent and after rejection (`pre & rej`). CookieRadar
decides it differently, and more strictly:

- a tracker loaded *only* after rejection is a VIOLATION ("new after rejection");
- a tracking cookie stored before any choice is a VIOLATION, whatever happens later;
- a refusal that could not be clicked is UNVERIFIED, not "none persist";
- an error page or a bot challenge is ERROR: the site was never seen.

In each of those four cases APKRadar printed a green "none persist" and reported
no consent violation to the law check. The existing tests could not see it: they
handed `_full_stack_domain` a MagicMock with two empty tracker lists, so the
result never had the shape CookieRadar actually returns.

Here the result is CookieRadar's own `ScanResult`, built with the fields its
scanner fills. Only the browser is replaced: there is no Chromium in CI for this
repository, and what is under test is what APKRadar does with the result.
"""
from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from rich.console import Console

import apkradar.cli as cli
from tests.cookie_results import cookie_result as _result


def _run(cookie_result) -> tuple[bool, str]:
    """Run `_full_stack_domain` with this CookieRadar result; (violation, output)."""
    buf = io.StringIO()

    async def fake_scan(url, *args, **kwargs):
        return cookie_result

    with patch.object(cli, "console", Console(file=buf, width=200, color_system=None)), \
         patch.object(cli, "_check_mailradar", return_value=(None, None)), \
         patch.object(cli, "_check_ssl", return_value=("error", None)), \
         patch("cookieradar.scanner.scan", fake_scan):
        violation = cli._full_stack_domain("publisher.example")
    return violation, buf.getvalue()


def test_tracker_persisting_after_rejection_is_a_violation():
    violation, out = _run(_result(pre=["doubleclick.net"], rej=["doubleclick.net"]))
    assert violation is True
    assert "VIOLATION" in out
    assert "doubleclick.net" in out


def test_tracker_new_after_rejection_is_a_violation():
    """Loaded only after the visitor refused: the worst case, and it read as green."""
    violation, out = _run(_result(pre=[], rej=["doubleclick.net"]))
    assert violation is True
    assert "VIOLATION" in out
    assert "doubleclick.net" in out
    assert "new after rejection" in out
    assert "none persist" not in out


def test_tracking_cookie_stored_before_any_choice_is_a_violation():
    cookie = {"name": "_ga", "domain": ".publisher.example", "value": "GA1.1.1.1"}
    violation, out = _run(_result(pre_cookies=[cookie]))
    assert violation is True
    assert "VIOLATION" in out
    assert "_ga" in out


def test_refusal_not_clicked_is_unverified_not_compliant():
    """No refusal was applied, so nothing is known about what a refusal does."""
    violation, out = _run(_result(pre=["doubleclick.net"], rej=[], reject_clicked=False))
    assert violation is False
    assert "UNVERIFIED" in out
    assert "none persist" not in out


@pytest.mark.parametrize("status", [403, 503])
def test_error_page_is_not_reported_as_compliant(status):
    """An edge that refused the browser: what came back is not the site."""
    violation, out = _run(_result(status=status))
    assert violation is False
    assert "ERROR" in out
    assert "none persist" not in out


def test_clean_refusal_is_ok():
    violation, out = _run(_result(pre=[], rej=[]))
    assert violation is False
    assert "OK" in out
    assert "VIOLATION" not in out


def test_an_old_cookieradar_is_named_before_the_browser_starts(monkeypatch):
    """A CookieRadar without `scanner.verdict` cannot give the verdict. Found
    out after the scan, it cost a full three-session browser run per domain to
    print "too old"; asked before, it costs nothing."""
    import cookieradar.scanner as scanner

    monkeypatch.delattr(scanner, "verdict")
    scans = []

    async def fake_scan(url, *args, **kwargs):
        scans.append(url)
        return _result()

    buf = io.StringIO()
    with (
        patch.object(cli, "console", Console(file=buf, width=200, color_system=None)),
        patch.object(cli, "_check_mailradar", return_value=(None, None)),
        patch.object(cli, "_check_ssl", return_value=("error", None)),
        patch("cookieradar.scanner.scan", fake_scan),
    ):
        violation = cli._full_stack_domain("publisher.example")
    assert violation is False
    assert "too old" in buf.getvalue()
    assert scans == []
