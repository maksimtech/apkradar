"""Tests for the EUR-Lex GDPR fetcher."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from apkradar import law_fetcher
from apkradar.law_fetcher import (
    ARTICLES,
    CELEX,
    LawFetchError,
    Provision,
    fetch_html as real_fetch_html,
    fetch_provisions,
    parse_articles,
)

FIXTURE = Path(__file__).parent / "fixtures" / "gdpr_it_excerpt.html"
NOW = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def page():
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def texts(page):
    return parse_articles(page)


# ─── parse_articles ───────────────────────────────────────────────────────────

def test_articles_cover_the_checker_mapping():
    # law_checker cites art. 7 and 46 as well as the articles to explain
    for article in ("4", "5", "6", "7", "9", "13", "28", "46"):
        assert article in ARTICLES


def test_extracts_articles_paragraphs_and_points(texts):
    for ref in (
        "4", "4(1)", "4(26)",
        "5", "5(1)", "5(1)(a)", "5(1)(f)", "5(2)",
        "6", "6(1)(a)", "6(1)(f)", "6(4)(e)",
        "7", "7(1)", "7(4)",
        "9", "9(1)", "9(2)(a)", "9(2)(j)",
        "13(1)(a)", "13(2)(f)",
        "28(3)(h)", "28(10)",
        "46", "46(2)(a)", "46(3)(b)",
    ):
        assert ref in texts, ref


def test_point_text(texts):
    assert texts["5(1)(a)"] == (
        "a) trattati in modo lecito, corretto e trasparente nei confronti "
        "dell'interessato («liceità, correttezza e trasparenza»);"
    )


def test_paragraph_text(texts):
    assert texts["7(1)"] == (
        "1. Qualora il trattamento sia basato sul consenso, il titolare del trattamento "
        "deve essere in grado di dimostrare che l'interessato ha prestato il proprio "
        "consenso al trattamento dei propri dati personali."
    )


def test_paragraph_includes_its_points(texts):
    paragraph = texts["5(1)"]
    assert paragraph.startswith("1. I dati personali sono:")
    assert texts["5(1)(a)"] in paragraph
    assert texts["5(1)(f)"] in paragraph


def test_article_is_its_paragraphs_one_per_line(texts):
    assert texts["7"] == "\n".join(texts[f"7({n})"] for n in range(1, 5))


def test_article_text_leaves_out_number_and_title(texts):
    assert "Articolo 7" not in texts["7"]
    assert "Condizioni per il consenso" not in texts["7"]


def test_definitions_of_article_4_are_numbered_points(texts):
    assert texts["4(1)"].startswith(
        "1) «dato personale»: qualsiasi informazione riguardante una persona fisica"
    )
    assert texts["4"].startswith("Ai fini del presente regolamento s'intende per:")


def test_footnote_references_are_dropped(texts):
    assert texts["4(25)"].endswith("del Parlamento europeo e del Consiglio;")
    assert "(19)" not in texts["4"]


def test_following_chapter_heading_is_not_part_of_article_4(texts):
    assert "CAPO II" not in texts["4"]
    assert texts["4"].endswith("sulla base di un accordo tra due o più Stati.")


def test_whitespace_is_normalized(texts):
    for text in texts.values():
        assert "\xa0" not in text
        assert "  " not in text
        assert text == text.strip()


def test_only_requested_articles(page):
    texts = parse_articles(page, articles=("7",))
    assert set(texts) == {"7", "7(1)", "7(2)", "7(3)", "7(4)"}


def test_missing_article_raises(page):
    with pytest.raises(LawFetchError, match="99"):
        parse_articles(page, articles=("5", "99"))


def test_page_without_articles_raises():
    # EUR-Lex answers some automated requests with a JavaScript challenge page
    with pytest.raises(LawFetchError):
        parse_articles("<html><body><script>challenge()</script></body></html>")


# ─── fetch_html ───────────────────────────────────────────────────────────────

def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_html_returns_page():
    client = _client(lambda request: httpx.Response(200, text="<html>ok</html>"))
    assert real_fetch_html("https://eur-lex.europa.eu/x", client=client) == "<html>ok</html>"


@pytest.mark.parametrize("status", [202, 404, 503])
def test_fetch_html_rejects_non_200(status):
    client = _client(lambda request: httpx.Response(status, text="challenge"))
    with pytest.raises(LawFetchError, match=str(status)):
        real_fetch_html("https://eur-lex.europa.eu/x", client=client)


def test_fetch_html_network_error():
    def handler(request):
        raise httpx.ConnectError("offline", request=request)

    with pytest.raises(LawFetchError, match="offline"):
        real_fetch_html("https://eur-lex.europa.eu/x", client=_client(handler))


def test_fetch_html_sends_user_agent():
    seen = {}

    def handler(request):
        seen["ua"] = request.headers["user-agent"]
        return httpx.Response(200, text="ok")

    real_fetch_html("https://eur-lex.europa.eu/x", client=_client(handler))
    assert seen["ua"].startswith("APKRadar/")


# ─── fetch_provisions ─────────────────────────────────────────────────────────

def test_fetch_provisions(page, monkeypatch):
    urls = []

    def fake_fetch_html(url, **kwargs):
        urls.append(url)
        return page

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    provisions = fetch_provisions(now=NOW)

    assert urls == [
        "https://eur-lex.europa.eu/legal-content/IT/TXT/HTML/?uri=CELEX:32016R0679"
    ]
    p = provisions["5(1)(a)"]
    assert isinstance(p, Provision)
    assert p.article == "5(1)(a)"
    assert p.text.startswith("a) trattati in modo lecito")
    assert p.sha256 == hashlib.sha256(p.text.encode("utf-8")).hexdigest()
    assert p.fetched_at == "2026-09-19T14:00:00Z"
    assert p.celex == CELEX == "32016R0679"


def test_provision_dict_round_trip():
    p = Provision.from_text("5(1)(a)", "a) testo;", "2026-09-19T14:00:00Z")
    assert p.to_dict() == {
        "article": "5(1)(a)",
        "text": "a) testo;",
        "sha256": hashlib.sha256("a) testo;".encode("utf-8")).hexdigest(),
        "fetched_at": "2026-09-19T14:00:00Z",
        "celex": "32016R0679",
    }
    assert Provision.from_dict(p.to_dict()) == p
