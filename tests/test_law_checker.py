"""Tests for mapping APKRadar findings to GDPR, directive 2019/770 and Consumer Code provisions."""
import json
from datetime import UTC, datetime

import pytest

from apkradar import law_fetcher
from apkradar.law_cache import LawCache
from apkradar.law_checker import (
    ALSO_FETCH,
    FINDING_ARTICLES,
    FINDING_TITLES,
    Citation,
    check,
    findings_of,
    format_citation,
    notes_of,
)
from apkradar.law_fetcher import CONSUMER_CODE, DIGITAL_CONTENT, GDPR, LawFetchError, Provision
from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound

DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


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


def _fake_fetch(suffix=""):
    """fetch_provisions returning every cited reference of the requested articles."""
    calls = []

    def fake(act, articles, now=None, **kwargs):
        calls.append((act, articles))
        stamp = law_fetcher.utc_stamp(now)
        refs = {ref for pairs in FINDING_ARTICLES.values() for a, ref in pairs if a == act}
        refs |= set(articles)
        return {
            ref: Provision.from_text(ref, f"{act.name} {ref}{suffix}", stamp, act.celex)
            for ref in refs if ref.split("(")[0] in articles
        }

    fake.calls = calls
    return fake


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law_cache.json")


@pytest.fixture
def online(monkeypatch):
    fake = _fake_fetch()
    monkeypatch.setattr(law_fetcher, "fetch_provisions", fake)
    return fake.calls


# ─── mapping ──────────────────────────────────────────────────────────────────

def test_mapping():
    assert FINDING_ARTICLES == {
        "tracker": ((GDPR, "5(1)(a)"), (GDPR, "6")),
        "tracker_undisclosed": ((DIGITAL_CONTENT, "8(1)(b)"),),
        "extra_eu": ((GDPR, "46"),),
        "consent": ((GDPR, "7"),),
        "sensitive": ((GDPR, "9"),),
        "permissions_undisclosed": ((CONSUMER_CODE, "49"),),
    }
    assert set(FINDING_TITLES) == set(FINDING_ARTICLES)


def test_undisclosed_titles_say_it_must_be_checked():
    # APKRadar cannot read the app's privacy policy or the store's data safety section
    assert "to be checked" in FINDING_TITLES["tracker_undisclosed"].lower()
    assert "to be checked" in FINDING_TITLES["permissions_undisclosed"].lower()


def test_gdpr_articles_explaining_the_others_are_downloaded_too():
    assert ALSO_FETCH == {GDPR: ("4", "5", "6", "7", "9", "13", "28", "46")}


def test_findings_of_clean_app():
    assert findings_of(_result()) == {}
    assert notes_of(_result()) == []


def test_trackers():
    assert findings_of(_result(trackers=True)) == {
        "tracker": ["AppsFlyer"],
        "tracker_undisclosed": ["AppsFlyer"],
    }


def test_sensitive_permissions():
    assert findings_of(_result(sensitive=True)) == {
        "sensitive": ["ACCESS_FINE_LOCATION (precise GPS location)"],
        "permissions_undisclosed": ["ACCESS_FINE_LOCATION (precise GPS location)"],
    }


def test_findings_of_all_in_report_order():
    result = _result(trackers=True, transfers=True, sensitive=True)
    assert list(findings_of(result, consent_violation=True)) == [
        "tracker", "tracker_undisclosed", "extra_eu", "consent", "sensitive", "permissions_undisclosed",
    ]


# ─── check ────────────────────────────────────────────────────────────────────

def test_no_findings_no_download(cache, online):
    law = check(_result(), cache=cache, now=DAY1)
    assert law.citations == []
    assert online == []
    assert not cache.path.exists()


def test_tracker_citations(cache, online):
    law = check(_result(trackers=True), cache=cache, now=DAY1)

    assert [(c.finding, c.law, c.article) for c in law.citations] == [
        ("tracker", "GDPR", "5(1)(a)"),
        ("tracker", "GDPR", "6"),
        ("tracker_undisclosed", "Contenuti digitali dir. 2019/770", "8(1)(b)"),
    ]
    assert [s.source for s in law.acts] == ["verified", "verified"]
    assert law.citations[0].version_date == "2026-09-19"


def test_downloads_cited_and_explanatory_articles(cache, online):
    check(_result(trackers=True, sensitive=True), cache=cache, now=DAY1)
    assert online == [
        (GDPR, ("5", "6", "9", "4", "7", "13", "28", "46")),
        (DIGITAL_CONTENT, ("8",)),
        (CONSUMER_CODE, ("49",)),
    ]
    assert (GDPR.celex, "28") in cache.load()


def test_each_finding_cites_its_article(cache, online):
    law = check(
        _result(trackers=True, transfers=True, sensitive=True),
        consent_violation=True, cache=cache, now=DAY1,
    )
    assert [c.article for c in law.citations] == ["5(1)(a)", "6", "8(1)(b)", "46", "7", "9", "49"]
    assert law.citations[-1].law == "Codice del Consumo D.Lgs. 206/2005"


def test_second_audit_same_text_keeps_version_date(cache, online):
    check(_result(trackers=True), cache=cache, now=DAY1)
    law = check(_result(trackers=True), cache=cache, now=DAY2)

    assert law.changed == {}
    assert law.citations[0].version_date == "2026-09-19"


def test_second_audit_changed_text_updates_cache(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch())
    first = check(_result(trackers=True), cache=cache, now=DAY1)

    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch(" (rettificato)"))
    law = check(_result(trackers=True), cache=cache, now=DAY2)

    assert law.changed["GDPR art. 6"] == first.citations[1].sha256
    assert law.citations[1].version_date == "2026-10-01"
    assert cache.load()[(GDPR.celex, "6")].sha256 == law.citations[1].sha256


def test_offline_uses_cache(cache, online, monkeypatch):
    first = check(_result(trackers=True), cache=cache, now=DAY1)

    def offline(*args, **kwargs):
        raise LawFetchError("offline")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", offline)
    law = check(_result(trackers=True), cache=cache, now=DAY2)

    assert [(s.source, s.error) for s in law.acts] == [("cache", "offline"), ("cache", "offline")]
    assert law.citations[0].sha256 == first.citations[0].sha256
    assert law.citations[0].version_date == "2026-09-19"


def test_offline_without_cache(cache):
    # conftest makes every download fail
    law = check(_result(trackers=True), cache=cache, now=DAY1)

    assert [s.source for s in law.acts] == ["unavailable", "unavailable"]
    assert all(c.sha256 is None and c.version_date is None for c in law.citations)


def test_cache_write_failure_still_cites_fresh_text(cache, online, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(LawCache, "update", fail)
    law = check(_result(trackers=True), cache=cache, now=DAY1)

    assert [s.source for s in law.acts] == ["verified", "verified"]
    assert law.citations[0].sha256 is not None


def test_default_cache_location(tmp_path, online):
    # conftest points APKRADAR_HOME at a temporary folder
    check(_result(trackers=True), now=DAY1)
    assert (tmp_path / "apkradar-home" / "law_cache.json").is_file()


def test_cache_written_by_the_previous_version_is_still_read(cache):
    # Before 2026-09-19's generalisation entries were keyed by article only;
    # the file format itself is the same
    old = Provision.from_text("6", "testo", "2026-09-19T14:00:00Z", GDPR.celex)
    cache.path.parent.mkdir(parents=True, exist_ok=True)
    cache.path.write_text(
        json.dumps({"checked_at": "2026-09-19T14:00:00Z", "entries": [old.to_dict()]}),
        encoding="utf-8",
    )
    assert cache.load() == {(GDPR.celex, "6"): old}


# ─── format ───────────────────────────────────────────────────────────────────

def test_format_citation():
    c = Citation("tracker", "GDPR", "5(1)(a)", "ab" * 32, "2026-09-19")
    assert format_citation(c) == (
        "Provision applied: GDPR art. 5(1)(a)\n"
        f"SHA256: {'ab' * 32}\n"
        "Version of: 2026-09-19"
    )


def test_format_citation_without_text():
    c = Citation("tracker", "GDPR", "6", None, None)
    assert format_citation(c) == (
        "Provision applied: GDPR art. 6\n"
        "SHA256: not available\n"
        "Version of: not available"
    )
