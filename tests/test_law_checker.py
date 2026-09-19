"""Tests for mapping APKRadar findings to GDPR provisions."""
from datetime import datetime, timezone

import pytest

from apkradar import law_fetcher
from apkradar.law_cache import LawCache
from apkradar.law_checker import (
    FINDING_ARTICLES,
    Citation,
    check,
    findings_of,
    format_citation,
)
from apkradar.law_fetcher import LawFetchError, Provision
from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound

DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)


def _result(trackers=False, transfers=False, sensitive=False):
    return ScanResult(
        apk_path="app.apk",
        package_name="com.example.app",
        trackers=[TrackerFound(package="com.appsflyer", name="AppsFlyer")] if trackers else [],
        extra_eu_transfers=[TransferFound("com.appsflyer", "AppsFlyer Ltd. (USA/Israel)")] if transfers else [],
        sensitive_permissions=[
            PermissionFound("android.permission.ACCESS_FINE_LOCATION", "precise GPS location")
        ] if sensitive else [],
    )


def _provisions(fetched_at, suffix=""):
    """What fetch_provisions returns: every article the checker can cite."""
    stamp = fetched_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    refs = {ref for refs in FINDING_ARTICLES.values() for ref in refs}
    return {ref: Provision.from_text(ref, f"testo di {ref}{suffix}", stamp) for ref in refs}


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law_cache.json")


@pytest.fixture
def online(monkeypatch):
    calls = []

    def fake(now=None, **kwargs):
        calls.append(now)
        return _provisions(now)

    monkeypatch.setattr(law_fetcher, "fetch_provisions", fake)
    return calls


# ─── mapping ──────────────────────────────────────────────────────────────────

def test_mapping():
    assert FINDING_ARTICLES == {
        "tracker": ("5(1)(a)", "6"),
        "extra_eu": ("46",),
        "consent": ("7",),
        "sensitive": ("9",),
    }


def test_findings_of_clean_app():
    assert findings_of(_result()) == []


def test_findings_of_all():
    result = _result(trackers=True, transfers=True, sensitive=True)
    assert findings_of(result, consent_violation=True) == [
        "tracker", "extra_eu", "consent", "sensitive",
    ]


def test_findings_of_single():
    assert findings_of(_result(sensitive=True)) == ["sensitive"]
    assert findings_of(_result(transfers=True)) == ["extra_eu"]


# ─── check ────────────────────────────────────────────────────────────────────

def test_no_findings_no_download(cache, online):
    law = check(_result(), cache=cache, now=DAY1)
    assert law.citations == []
    assert law.source == "none"
    assert online == []
    assert not cache.path.exists()


def test_tracker_cites_5_1_a_and_6(cache, online):
    law = check(_result(trackers=True), cache=cache, now=DAY1)

    assert law.source == "eur-lex"
    assert [(c.finding, c.article) for c in law.citations] == [
        ("tracker", "5(1)(a)"),
        ("tracker", "6"),
    ]
    expected = _provisions(DAY1)["5(1)(a)"].sha256
    assert law.citations[0].sha256 == expected
    assert law.citations[0].version_date == "2026-09-19"


def test_each_finding_cites_its_article(cache, online):
    law = check(
        _result(trackers=True, transfers=True, sensitive=True),
        consent_violation=True, cache=cache, now=DAY1,
    )
    assert [c.article for c in law.citations] == ["5(1)(a)", "6", "46", "7", "9"]


def test_first_audit_fills_the_cache(cache, online):
    check(_result(trackers=True), cache=cache, now=DAY1)
    assert cache.load()["6"].sha256 == _provisions(DAY1)["6"].sha256


def test_second_audit_same_text_keeps_version_date(cache, online):
    check(_result(trackers=True), cache=cache, now=DAY1)
    law = check(_result(trackers=True), cache=cache, now=DAY2)

    assert law.source == "eur-lex"
    assert law.changed == {}
    assert law.citations[0].version_date == "2026-09-19"


def test_second_audit_changed_text_updates_cache(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", lambda now=None, **kw: _provisions(now))
    check(_result(trackers=True), cache=cache, now=DAY1)
    old = cache.load()["6"].sha256

    monkeypatch.setattr(
        law_fetcher, "fetch_provisions", lambda now=None, **kw: _provisions(now, " (rettificato)")
    )
    law = check(_result(trackers=True), cache=cache, now=DAY2)

    new = _provisions(DAY2, " (rettificato)")["6"].sha256
    assert law.changed == {"5(1)(a)": _provisions(DAY1)["5(1)(a)"].sha256, "6": old}
    assert law.citations[1].sha256 == new
    assert law.citations[1].version_date == "2026-10-01"
    assert cache.load()["6"].sha256 == new


def test_changed_only_reports_cited_articles(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", lambda now=None, **kw: _provisions(now))
    check(_result(trackers=True), cache=cache, now=DAY1)
    monkeypatch.setattr(
        law_fetcher, "fetch_provisions", lambda now=None, **kw: _provisions(now, " (rettificato)")
    )
    law = check(_result(sensitive=True), cache=cache, now=DAY2)
    assert set(law.changed) <= {"9"}


def test_offline_uses_cache(cache, online, monkeypatch):
    check(_result(trackers=True), cache=cache, now=DAY1)

    def offline(**kwargs):
        raise LawFetchError("offline")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", offline)
    law = check(_result(trackers=True), cache=cache, now=DAY2)

    assert law.source == "cache"
    assert law.error == "offline"
    assert law.citations[0].sha256 == _provisions(DAY1)["5(1)(a)"].sha256
    assert law.citations[0].version_date == "2026-09-19"


def test_offline_without_cache(cache):
    # conftest makes every download fail
    law = check(_result(trackers=True), cache=cache, now=DAY1)

    assert law.source == "unavailable"
    assert [c.article for c in law.citations] == ["5(1)(a)", "6"]
    assert all(c.sha256 is None and c.version_date is None for c in law.citations)


def test_cache_write_failure_still_cites_fresh_text(cache, online, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(LawCache, "update", fail)
    law = check(_result(trackers=True), cache=cache, now=DAY1)

    assert law.source == "eur-lex"
    assert law.citations[0].sha256 == _provisions(DAY1)["5(1)(a)"].sha256


def test_default_cache_location(tmp_path, online):
    # conftest points APKRADAR_HOME at a temporary folder
    check(_result(trackers=True), now=DAY1)
    assert (tmp_path / "apkradar-home" / "law_cache.json").is_file()


# ─── format ───────────────────────────────────────────────────────────────────

def test_format_citation():
    c = Citation(finding="tracker", article="5(1)(a)", sha256="ab" * 32, version_date="2026-09-19")
    assert format_citation(c) == (
        "Norma applicata: GDPR art. 5(1)(a)\n"
        f"SHA256: {'ab' * 32}\n"
        "Versione del: 2026-09-19"
    )


def test_format_citation_without_text():
    c = Citation(finding="tracker", article="6", sha256=None, version_date=None)
    assert format_citation(c) == (
        "Norma applicata: GDPR art. 6\n"
        "SHA256: non disponibile\n"
        "Versione del: non disponibile"
    )
