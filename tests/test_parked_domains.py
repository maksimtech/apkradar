"""A domain that is for sale cannot be audited: it belongs to nobody yet.

`com.gameitech.preschool.abc123.tracing.learning` reverses to `gameitech.com`.
Measured on 2026-09-25, that domain redirects to

    https://forsale.godaddy.com/forsale/gameitech.com?utm_source=TDFS&…

with nameservers ns75/ns76.domaincontrol.com — GoDaddy's parking. Its MailRadar
score is 0/100, and that zero is the mail posture of a for-sale landing page. The
publisher's own domain, gameitech.in, scores 14/100.

Auditing it is worse than useless, and not only because the number is wrong. A
for-sale domain has no holder to answer for it, anyone can buy it — including
after the report is written and before it is read — and a finding against it would
be a finding against whoever happens to own it next. A report that contains such a
row invalidates itself, and the person who signed it looks like they did not check.

So a candidate that answers with a for-sale page is not analysed, does not reach
MailRadar, SSL or CookieRadar, does not enter the letter, and is not printed: the
report says a domain was set aside for being on sale, without naming it. Naming it
would put it back in the document.

The check is an HTTP request, so it cannot live in `resolve()`, which is pure.
`looks_parked` does the asking and takes its fetcher as an argument, which is how
these tests avoid the network.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from apkradar import publisher
from apkradar.cli import app
from apkradar.scanner import ScanResult

runner = CliRunner()

ABC123 = "com.gameitech.preschool.abc123.tracing.learning"

# The redirect chain measured on the real domain, verbatim.
GAMEITECH_FINAL = (
    "https://forsale.godaddy.com/forsale/gameitech.com?utm_source=TDFS"
    "&utm_medium=sn_affiliate_click&utm_campaign=TDFS_GoDaddy_DLS"
    "&traffic_type=TDFS&traffic_id=GoDaddy_DLS"
)


def fetcher(final_url: str, body: str = ""):
    """Stands in for the HTTP request: what the browser would end up at."""
    def fetch(domain: str) -> tuple[str, str]:
        return final_url, body
    return fetch


# ── recognising a for-sale page ─────────────────────────────────────────────


def test_the_real_gameitech_chain_is_recognised():
    assert publisher.looks_parked("gameitech.com", fetch=fetcher(GAMEITECH_FINAL)) is True


@pytest.mark.parametrize(
    "final",
    [
        "https://forsale.godaddy.com/forsale/example.com",
        "https://www.sedo.com/search/details.php?domain=example.com",
        "https://sedoparking.com/example.com",
        "https://www.afternic.com/domain/example.com",
        "https://dan.com/buy-domain/example.com",
        "https://www.hugedomains.com/domain_profile.cfm?d=example.com",
        "https://www.buydomains.com/lander/example.com",
        "https://parkingcrew.net/example.com",
        "https://bodis.com/example.com",
    ],
)
def test_the_known_marketplaces(final):
    assert publisher.looks_parked("example.com", fetch=fetcher(final)) is True


def test_a_landing_page_served_without_a_redirect():
    """Some parkings answer on the domain itself, so the words count too."""
    body = "<html><title>example.com</title><body>This domain is for sale.</body></html>"

    assert publisher.looks_parked("example.com", fetch=fetcher("https://example.com", body)) is True


@pytest.mark.parametrize(
    "phrase",
    ["this domain is for sale", "buy this domain", "the domain example.com is for sale"],
)
def test_the_phrases_that_count(phrase):
    assert publisher.looks_parked("example.com", fetch=fetcher("https://example.com", phrase)) is True


# ── and not mistaking a real site for one ───────────────────────────────────


def test_a_publishers_own_site_is_not_parked():
    body = "<html><title>Gameitech</title><body>Kids education games</body></html>"

    assert publisher.looks_parked("gameitech.in", fetch=fetcher("https://gameitech.in/", body)) is False


def test_a_redirect_within_the_same_site_is_not_a_sale():
    assert publisher.looks_parked(
        "example.com", fetch=fetcher("https://www.example.com/en/")
    ) is False


def test_a_shop_that_sells_things_other_than_itself():
    """"buy" alone is half the web; the phrase has to be about the domain."""
    body = "Buy this hoodie. Free shipping. Buy now."

    assert publisher.looks_parked("shop.example", fetch=fetcher("https://shop.example", body)) is False


def test_a_domain_that_cannot_be_reached_is_not_declared_parked():
    """Could not tell is not the same as for sale, and dropping a real domain on
    a timeout would hide the publisher."""
    def fails(domain):
        raise OSError("connection refused")

    assert publisher.looks_parked("example.com", fetch=fails) is False


def test_an_empty_answer_is_not_parked():
    assert publisher.looks_parked("example.com", fetch=fetcher("", "")) is False


# ── dropping it from the candidates ─────────────────────────────────────────


def test_the_parked_candidate_is_removed():
    pub = publisher.resolve(ABC123)                     # no Play data: the guess
    assert pub.best == "gameitech.com"

    clean = publisher.without_parked(pub, check=lambda d: d == "gameitech.com")

    assert clean.candidates == []
    assert clean.best is None


def test_it_is_recorded_so_the_report_can_explain_itself():
    pub = publisher.without_parked(
        publisher.resolve(ABC123), check=lambda d: d == "gameitech.com"
    )

    assert pub.parked == ("gameitech.com",)


def test_the_note_says_it_without_naming_it():
    pub = publisher.without_parked(
        publisher.resolve(ABC123), check=lambda d: d == "gameitech.com"
    )

    assert "gameitech.com" not in pub.note
    assert "sale" in pub.note.lower()


def test_a_clean_domain_passes_through_untouched():
    pub = publisher.resolve(ABC123, "http://gameitech.in")
    clean = publisher.without_parked(pub, check=lambda d: False)

    assert clean.best == "gameitech.in"
    assert clean.parked == ()


def test_only_the_publisher_candidate_is_ever_checked():
    """One request, for one domain. The SDK domains are not publisher candidates
    and an audit should not be probing every one of them for a sale."""
    asked: list[str] = []
    publisher.without_parked(publisher.resolve(ABC123), check=asked.append)

    assert asked == ["gameitech.com"]


def test_a_domain_the_sender_stated_is_checked_too():
    """If the sender names a domain that is on sale, the letter must not cite it
    — they will want to know, and an art. 32 claim against a parked domain is the
    worst version of this defect."""
    pub = publisher.resolve(ABC123, stated="gameitech.com")
    assert pub.verified is True

    clean = publisher.without_parked(pub, check=lambda d: d == "gameitech.com")

    assert clean.best is None
    assert clean.verified is False


# ── through the commands ────────────────────────────────────────────────────


def _result(package=ABC123, site=""):
    return ScanResult(
        apk_path="abc123.xapk",
        package_name=package,
        app_name="abc 123 Tracing for Toddlers",
        sha256="06703ff9" * 8,
        developer_site=site,
    )


@pytest.fixture
def audited(monkeypatch):
    def run(result, extra=(), parked=("gameitech.com",)):
        import apkradar.scanner as scanner

        monkeypatch.setattr(scanner, "scan", lambda path, **kw: result)
        monkeypatch.setattr(publisher, "looks_parked", lambda d, **kw: d in parked)

        checked: list[str] = []

        def mail(domain):
            checked.append(domain)
            return 0, "CRITICAL"

        def no_browser(coro):
            if hasattr(coro, "close"):
                coro.close()
            raise RuntimeError("no browser")

        with patch("apkradar.cli._check_mailradar", side_effect=mail), \
             patch("apkradar.cli._check_ssl", return_value=("valid", "30/01/2027")), \
             patch("asyncio.run", side_effect=no_browser):
            outcome = runner.invoke(app, ["audit", "abc123.xapk", "--full", *extra])
        return outcome, checked
    return run


def test_the_parked_domain_reaches_no_radar(audited):
    outcome, checked = audited(_result())

    assert "gameitech.com" not in checked, checked
    assert outcome.exit_code == 0, outcome.output


def test_it_is_not_printed_either(audited):
    outcome, _ = audited(_result())

    assert "gameitech.com" not in outcome.output


def test_the_report_says_a_domain_was_set_aside_for_being_on_sale(audited):
    outcome, _ = audited(_result())

    assert "sale" in outcome.output.lower()


def test_the_publishers_real_domain_is_still_analysed(audited):
    """With the listing present, gameitech.in is the candidate and it is clean."""
    outcome, checked = audited(_result(site="http://gameitech.in"))

    assert "gameitech.in" in checked
    assert "gameitech.com" not in outcome.output


def test_offline_does_not_switch_the_check_off(audited):
    """--offline means "do not ask Google Play". The rest of `--full` is network
    work by definition, and this check is part of the analysis."""
    outcome, checked = audited(_result(), extra=["--offline"])

    assert "gameitech.com" not in checked


@pytest.fixture
def sending(monkeypatch):
    def run(result, parked=("gameitech.com",)):
        import apkradar.scanner as scanner

        monkeypatch.setattr(scanner, "scan", lambda path, **kw: result)
        monkeypatch.setattr(publisher, "looks_parked", lambda d, **kw: d in parked)
        with patch("apkradar.cli._check_mailradar", return_value=(0, "CRITICAL")), \
             patch("apkradar.cli._check_ssl", return_value=("valid", None)):
            return runner.invoke(app, [
                "send", "abc123.xapk",
                "--to", "dpo@example.com", "--publisher", "Gameitech",
                "--from", "t@example.com", "--smtp-host", "smtp.example.com",
                "--smtp-user", "t@example.com", "--name", "T", "--dry-run",
            ])
    return run


def test_the_letter_cites_no_parked_domain(sending):
    outcome = sending(_result())

    assert "gameitech.com" not in outcome.output
    assert "misure tecniche inadeguate" not in outcome.output


def test_send_tells_the_operator_why(sending):
    outcome = sending(_result())

    assert "sale" in outcome.output.lower()
