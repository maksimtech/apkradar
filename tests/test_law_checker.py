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
    special_category_reason,
)
from apkradar.law_fetcher import CONSUMER_CODE, DIGITAL_CONTENT, GDPR, LawFetchError, Provision
from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound

DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


LOCATION = PermissionFound("android.permission.ACCESS_FINE_LOCATION", "precise GPS location")
BODY_SENSORS = PermissionFound("android.permission.BODY_SENSORS", "vital signs (heart rate)")
FINGERPRINT = PermissionFound("android.permission.USE_FINGERPRINT", "fingerprint")


def _result(trackers=False, transfers=False, sensitive=False, permission=LOCATION):
    return ScanResult(
        apk_path="app.apk",
        package_name="com.example.app",
        trackers=[TrackerFound(package="com.appsflyer", name="AppsFlyer")] if trackers else [],
        extra_eu_transfers=[TransferFound("com.appsflyer", "AppsFlyer Ltd. (USA/Israel)")] if transfers else [],
        sensitive_permissions=[permission] if sensitive else [],
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
        "sensitive": ((GDPR, "5(1)(c)"), (GDPR, "6")),
        "special_category": ((GDPR, "9"),),
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


# ─── art. 9: the permissions it can apply to, and the many it cannot ──────────
#
# Until 2026-09-30 every sensitive permission was cited under art. 9, in a letter
# addressed to a data protection officer. Twenty-eight permissions were, including
# storage read and the advertising identifier. A DPO can dismiss that in one line,
# and the findings underneath it — trackers, extra-EU transfers, undisclosed
# permissions — are the ones that hold.


def test_a_location_permission_does_not_reach_a_special_category():
    """Art. 9(1) is an exhaustive list, and location is not on it.

    It can *reveal* a special category by inference — a weekly visit to a clinic
    or a place of worship — but that is a property of a purpose and a pattern,
    not of the permission, and this audit reads a manifest.
    """
    assert "special_category" not in findings_of(_result(sensitive=True))
    assert special_category_reason("android.permission.ACCESS_FINE_LOCATION") is None


def test_a_body_sensor_permission_does_reach_one_and_says_which():
    found = findings_of(_result(sensitive=True, permission=BODY_SENSORS))

    assert found["special_category"] == [
        "BODY_SENSORS (vital signs (heart rate)): heart rate and comparable vital signs, "
        "which are data concerning health"
    ]
    # and it is still a sensitive permission like any other
    assert found["sensitive"] == ["BODY_SENSORS (vital signs (heart rate))"]


def test_an_on_device_fingerprint_unlock_is_not_a_special_category():
    """The one that looks most like art. 9 and is furthest from it.

    USE_FINGERPRINT and USE_BIOMETRIC ask Android to authenticate the user. The
    matching happens in the operating system, against a template that never
    leaves the secure hardware, and the app receives a boolean. Art. 9 covers
    biometric data processed *for the purpose of uniquely identifying* a person,
    and an app that receives no biometric data processes none.
    """
    assert "special_category" not in findings_of(_result(sensitive=True, permission=FINGERPRINT))
    assert special_category_reason("android.permission.USE_BIOMETRIC") is None


def test_health_connect_records_are_matched_by_their_prefix():
    """Health Connect has a permission per record type, some fifty of them.

    None are in scanner.SENSITIVE_PERMISSIONS yet. The prefix is matched so that
    the day one is added it arrives cited correctly, instead of joining the art. 9
    claim by default the way everything else used to.
    """
    reason = special_category_reason("android.permission.health.READ_HEART_RATE")

    assert reason is not None
    assert "health" in reason


def test_only_the_health_permissions_of_the_table_can_cite_art_9():
    """A reading of the whole table, so the answer is measured and not assumed.

    If a permission is added to scanner.SENSITIVE_PERMISSIONS and belongs here,
    this is where it has to be said out loud.
    """
    from apkradar.scanner import SENSITIVE_PERMISSIONS

    special = {p for p in SENSITIVE_PERMISSIONS if special_category_reason(p)}

    assert special == {
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
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
    """Art. 9 is still downloaded although this app does not cite it.

    It moved from the cited articles to the explanatory ones when the location
    permission stopped claiming it, and it has to keep arriving: the next audit
    of an app with a body sensor permission cites it, and an article that is only
    fetched when already cited would be fetched too late.
    """
    check(_result(trackers=True, sensitive=True), cache=cache, now=DAY1)
    assert online == [
        (GDPR, ("5", "6", "4", "7", "9", "13", "28", "46")),
        (DIGITAL_CONTENT, ("8",)),
        (CONSUMER_CODE, ("49",)),
    ]
    assert (GDPR.celex, "28") in cache.load()


def test_each_finding_cites_its_article(cache, online):
    law = check(
        _result(trackers=True, transfers=True, sensitive=True),
        consent_violation=True, cache=cache, now=DAY1,
    )
    assert [c.article for c in law.citations] == [
        "5(1)(a)", "6", "8(1)(b)", "46", "7", "5(1)(c)", "6", "49",
    ]
    assert law.citations[-1].law == "Codice del Consumo D.Lgs. 206/2005"


def test_a_special_category_permission_adds_art_9_and_nothing_else_does(cache, online):
    """The same app with a body sensor permission, which is the art. 9 case.

    Art. 6 appears twice on purpose: the trackers need a lawful basis and so does
    every permission. Each finding lists its own provisions.
    """
    law = check(
        _result(trackers=True, transfers=True, sensitive=True, permission=BODY_SENSORS),
        consent_violation=True, cache=cache, now=DAY1,
    )
    assert [c.article for c in law.citations] == [
        "5(1)(a)", "6", "8(1)(b)", "46", "7", "5(1)(c)", "6", "9", "49",
    ]


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
