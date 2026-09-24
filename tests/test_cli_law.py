"""Tests for the law check that `apkradar audit` runs."""
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from apkradar import law_fetcher
from apkradar.cli import app
from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "gdpr_it_excerpt.html"
DIGITAL_CONTENT_PAGE = FIXTURES / "dir2019_770_it_excerpt.html"
CDC_49_PAGE = FIXTURES / "normattiva_cdc_art49.html"
runner = CliRunner()


def _result(trackers=True, transfers=False, sensitive=False):
    return ScanResult(
        apk_path="app.apk",
        package_name="com.example.app",
        sha256="a" * 64,
        trackers=[TrackerFound(package="com.appsflyer", name="AppsFlyer")] if trackers else [],
        extra_eu_transfers=[TransferFound("com.appsflyer", "AppsFlyer Ltd. (USA/Israel)")] if transfers else [],
        sensitive_permissions=[
            PermissionFound("android.permission.ACCESS_FINE_LOCATION", "precise GPS location")
        ] if sensitive else [],
    )


def _page_for(url):
    if "normattiva.it" in url:
        return FIXTURES / f"normattiva_cdc_art{url.split('~art')[1].split('!')[0]}.html"
    if "32019L0770" in url:
        return DIGITAL_CONTENT_PAGE
    return FIXTURE


def _sha(ref, page=FIXTURE):
    text = law_fetcher.parse_articles(page.read_text(encoding="utf-8"), (ref.split("(")[0],))[ref]
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture
def eurlex(monkeypatch):
    """EUR-Lex answering with the real page excerpt."""
    calls = []

    def fake_fetch_html(url, **kwargs):
        calls.append(url)
        return _page_for(url).read_text(encoding="utf-8")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    return calls


def _audit(result, *args):
    with patch("apkradar.scanner.scan", return_value=result):
        return runner.invoke(app, ["audit", "app.apk", *args])


def test_audit_cites_the_articles_for_trackers(eurlex):
    out = _audit(_result())

    assert out.exit_code == 0, out.output
    assert "Provision applied: GDPR art. 5(1)(a)" in out.output
    assert f"SHA256: {_sha('5(1)(a)')}" in out.output
    assert "Provision applied: GDPR art. 6" in out.output
    assert f"SHA256: {_sha('6')}" in out.output
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    assert f"Version of: {today}" in out.output
    assert "EUR-Lex" in out.output


def test_trackers_cite_directive_2019_770_to_be_checked(eurlex):
    out = _audit(_result())

    assert "To be checked against the app's privacy notice" in out.output
    assert "Provision applied: Contenuti digitali dir. 2019/770 art. 8(1)(b)" in out.output
    assert f"SHA256: {_sha('8(1)(b)', DIGITAL_CONTENT_PAGE)}" in out.output


def test_sensitive_permissions_cite_consumer_code_49(eurlex):
    out = _audit(_result(trackers=False, sensitive=True))

    assert "Provision applied: Codice del Consumo D.Lgs. 206/2005 art. 49\n" in out.output
    assert f"SHA256: {_sha('49', CDC_49_PAGE)}" in out.output
    assert "verified against Normattiva" in out.output
    assert eurlex[-1] == (
        "https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:decreto.legislativo:2005-09-06;206~art49!vig="
    )


def test_audit_cites_46_and_9(eurlex):
    out = _audit(_result(trackers=False, transfers=True, sensitive=True))

    assert "Provision applied: GDPR art. 46" in out.output
    assert "Provision applied: GDPR art. 9" in out.output
    assert "art. 5(1)(a)" not in out.output


def test_audit_without_findings_downloads_nothing(eurlex):
    out = _audit(_result(trackers=False))

    assert out.exit_code == 0
    assert "Norma applicata" not in out.output
    assert eurlex == []


def test_audit_writes_the_cache(eurlex, tmp_path):
    _audit(_result())
    assert (tmp_path / "apkradar-home" / "law_cache.json").is_file()


def test_second_audit_offline_uses_cache(eurlex, monkeypatch):
    first = _audit(_result())
    day = first.output.split("Version of: ")[1][:10]

    def offline(url, **kwargs):
        raise law_fetcher.LawFetchError("offline")

    monkeypatch.setattr(law_fetcher, "fetch_html", offline)
    out = _audit(_result())

    assert out.exit_code == 0
    assert "cache" in out.output
    assert f"SHA256: {_sha('5(1)(a)')}" in out.output
    assert f"Version of: {day}" in out.output


def test_audit_offline_without_cache():
    # conftest makes every download fail
    out = _audit(_result())

    assert out.exit_code == 0
    assert "Provision applied: GDPR art. 5(1)(a)" in out.output
    assert "SHA256: not available" in out.output


def test_audit_reports_changed_text(eurlex, monkeypatch):
    _audit(_result())
    page = FIXTURE.read_text(encoding="utf-8").replace(
        "trattati in modo lecito, corretto e trasparente",
        "trattati in modo lecito, corretto e sempre trasparente",
    )
    monkeypatch.setattr(law_fetcher, "fetch_html", lambda url, **kw: page)

    out = _audit(_result())

    assert out.exit_code == 0
    assert "cambiato" in out.output
    assert _sha("5(1)(a)") in out.output  # the previous hash is shown


def test_law_check_failure_does_not_fail_audit(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("apkradar.law_checker.check", boom)
    out = _audit(_result())

    assert out.exit_code == 0
    assert "unexpected" in out.output


def test_failed_scan_skips_law_check(eurlex):
    out = _audit(ScanResult(apk_path="app.apk", error="File not found: app.apk"))

    assert out.exit_code == 1
    assert "Norma applicata" not in out.output
    assert eurlex == []


@patch("apkradar.cli._check_ssl", return_value=("valid", "01/01/2027"))
@patch("apkradar.cli._check_mailradar", return_value=(90, "A"))
def test_full_cookie_violation_cites_article_7(mock_mail, mock_ssl, eurlex):
    tracker = MagicMock(domain="tracker.example")
    cookies = MagicMock()
    cookies.pre_consent.trackers = [tracker]
    cookies.post_reject.trackers = [tracker]

    with patch("asyncio.run", return_value=cookies):
        out = _audit(_result(), "--full")

    assert out.exit_code == 0, out.output
    assert "VIOLATION" in out.output
    assert "Provision applied: GDPR art. 7" in out.output
    assert f"SHA256: {_sha('7')}" in out.output


@patch("apkradar.cli._check_ssl", return_value=("valid", "01/01/2027"))
@patch("apkradar.cli._check_mailradar", return_value=(90, "A"))
def test_full_without_cookie_violation_does_not_cite_article_7(mock_mail, mock_ssl, eurlex):
    cookies = MagicMock()
    cookies.pre_consent.trackers = [MagicMock(domain="tracker.example")]
    cookies.post_reject.trackers = []

    with patch("asyncio.run", return_value=cookies):
        out = _audit(_result(), "--full")

    assert "art. 7" not in out.output
