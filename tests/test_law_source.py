"""A verified text names the source that answered, not the act's publisher.

EU acts are downloaded from Cellar (publications.europa.eu), with EUR-Lex only as the fallback, but the report said
"verified against EUR-Lex" whichever answered (open item of the 2026-10-17 audit). Here the source travels with
the download: fetch_provisions_from returns it and the law check's status carries it.

Answers come from pages already recorded for the other law tests (gdpr_it_excerpt.html, normattiva_cdc_art49.html),
served by httpx.MockTransport at the HTTP boundary, as CLAUDE.md allows: nothing reaches the network, and every
request is seen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from apkradar import law_checker, law_fetcher
from apkradar.law_cache import LawCache
from apkradar.scanner import ScanResult, TrackerFound

FIXTURES = Path(__file__).parent / "fixtures"
GDPR_PAGE = (FIXTURES / "gdpr_it_excerpt.html").read_text(encoding="utf-8")
CDC_49_PAGE = (FIXTURES / "normattiva_cdc_art49.html").read_text(encoding="utf-8")
GDPR_CELLAR_URL = "https://publications.europa.eu/resource/celex/32016R0679"
GDPR_EURLEX_URL = "https://eur-lex.europa.eu/legal-content/IT/TXT/HTML/?uri=CELEX:32016R0679"
CDC_49_URL = law_fetcher.NORMATTIVA_URL.format(urn=law_fetcher.CONSUMER_CODE.celex, article="49")
NOW = datetime(2026, 10, 23, 16, 0, tzinfo=UTC)
REAL_FETCH_HTML = law_fetcher.fetch_html


@pytest.fixture
def real_fetch(monkeypatch):
    """conftest disables fetch_html so that no test reaches the network; the clients below answer only from the
    recordings, so the real function goes back."""
    monkeypatch.setattr(law_fetcher, "fetch_html", REAL_FETCH_HTML)


def recorded(pages: dict[str, str], seen: list[str]) -> httpx.Client:
    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) in pages:
            return httpx.Response(200, text=pages[str(request.url)])
        return httpx.Response(503)

    return httpx.Client(transport=httpx.MockTransport(answer))


def test_cellar_is_named_when_cellar_answered(real_fetch):
    seen: list[str] = []
    provisions, source = law_fetcher.fetch_provisions_from(
        law_fetcher.GDPR, ("6",), now=NOW, client=recorded({GDPR_CELLAR_URL: GDPR_PAGE}, seen))
    assert source == "Cellar"
    assert "6" in provisions
    assert seen == [GDPR_CELLAR_URL]


def test_eur_lex_is_named_when_only_the_fallback_answered(real_fetch):
    seen: list[str] = []
    _, source = law_fetcher.fetch_provisions_from(
        law_fetcher.GDPR, ("6",), now=NOW, client=recorded({GDPR_EURLEX_URL: GDPR_PAGE}, seen))
    assert source == "EUR-Lex"
    assert seen == [GDPR_CELLAR_URL, GDPR_EURLEX_URL]


def test_normattiva_is_named_for_an_italian_act(real_fetch):
    seen: list[str] = []
    _, source = law_fetcher.fetch_provisions_from(
        law_fetcher.CONSUMER_CODE, ("49",), now=NOW, client=recorded({CDC_49_URL: CDC_49_PAGE}, seen))
    assert source == "Normattiva"
    assert seen == [CDC_49_URL]


def test_the_law_check_status_carries_the_source(real_fetch, tmp_path):
    seen: list[str] = []
    result = ScanResult(apk_path="app.apk", package_name="com.example.app",
                        trackers=[TrackerFound(package="com.appsflyer", name="AppsFlyer")])
    law = law_checker.check(result, cache=LawCache(tmp_path / "law_cache.json"), now=NOW,
                            client=recorded({GDPR_CELLAR_URL: GDPR_PAGE}, seen))
    gdpr = next(status for status in law.acts if status.act == law_fetcher.GDPR)
    assert (gdpr.source, gdpr.origin) == ("verified", "Cellar")


def test_a_text_from_the_cache_names_no_source(real_fetch, tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    result = ScanResult(apk_path="app.apk", package_name="com.example.app",
                        trackers=[TrackerFound(package="com.appsflyer", name="AppsFlyer")])
    law_checker.check(result, cache=cache, now=NOW, client=recorded({GDPR_CELLAR_URL: GDPR_PAGE}, []))
    law = law_checker.check(result, cache=cache, now=NOW, client=recorded({}, []))
    gdpr = next(status for status in law.acts if status.act == law_fetcher.GDPR)
    assert (gdpr.source, gdpr.origin) == ("cache", None)


# ─── verified means every reference cited, from the host asked ────────────────
# Ported from MailRadar's replayed tests (#103), on the same recorded GDPR page.

TRACKER = ScanResult(apk_path="app.apk", package_name="com.example.app",
                     trackers=[TrackerFound(package="com.appsflyer", name="AppsFlyer")])


def _point_a_untabled(page: str) -> str:
    """The GDPR page with the label of 5(1)(a) gone, as when Cellar lays the
    point out as a paragraph: article 5 still parses, point a) does not."""
    label = '<p class="oj-normal">a)</p>'
    at = page.index(label, page.index('<div id="005.001">'))
    return page[:at] + '<p class="oj-normal"></p>' + page[at + len(label):]


def test_a_point_missing_from_the_fresh_text_is_not_verified(real_fetch, tmp_path):
    """Cellar answered and article 5 parsed, but point a) was not in it: GDPR was
    "verified against Cellar" beside "SHA256: not available"."""
    page = _point_a_untabled(GDPR_PAGE)
    law = law_checker.check(TRACKER, cache=LawCache(tmp_path / "law_cache.json"), now=NOW,
                            client=recorded({GDPR_CELLAR_URL: page}, []))

    gdpr = next(status for status in law.acts if status.act == law_fetcher.GDPR)
    assert (gdpr.source, gdpr.tried, gdpr.failure) == ("unavailable", "Cellar", "not_in_text")
    assert gdpr.reason == "Cellar answered without the text cited"
    assert law.citations[0].article == "5(1)(a)"
    assert law.citations[0].sha256 is None


def test_a_text_from_another_host_is_not_verified_against_cellar(real_fetch, tmp_path):
    """Cellar's 303 pointing elsewhere: the page that host serves is not Cellar's."""
    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "publications.europa.eu":
            return httpx.Response(303, headers={"Location": "https://example.org/DOC_1"})
        if request.url.host == "example.org":
            return httpx.Response(200, text=GDPR_PAGE)
        return httpx.Response(202, text="challenge")   # EUR-Lex's WAF

    law = law_checker.check(TRACKER, cache=LawCache(tmp_path / "law_cache.json"), now=NOW,
                            client=httpx.Client(transport=httpx.MockTransport(answer)))

    gdpr = next(status for status in law.acts if status.act == law_fetcher.GDPR)
    assert (gdpr.source, gdpr.origin) == ("unavailable", None)
    assert gdpr.reason == "Cellar and EUR-Lex unreachable"
    assert not any(httpx.URL(url).host == "example.org" for url in seen), seen


def test_a_redirect_httpx_cannot_follow_falls_back_to_eur_lex(real_fetch, tmp_path):
    """http://xn--/DOC_1 made httpx raise idna.core.IDNAError, which went past
    both fallbacks and out of the law check."""
    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.host == "publications.europa.eu":
            return httpx.Response(303, headers={"Location": "http://xn--/DOC_1"})
        if str(request.url) == GDPR_EURLEX_URL:
            return httpx.Response(200, text=GDPR_PAGE)
        return httpx.Response(503)

    law = law_checker.check(TRACKER, cache=LawCache(tmp_path / "law_cache.json"), now=NOW,
                            client=httpx.Client(transport=httpx.MockTransport(answer)))

    gdpr = next(status for status in law.acts if status.act == law_fetcher.GDPR)
    assert (gdpr.source, gdpr.origin) == ("verified", "EUR-Lex")
