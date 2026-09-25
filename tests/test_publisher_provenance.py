"""The publisher domain is a guess, and it was being asserted as a fact.

`package_to_domain` reverses the Android package name. A package name is the
reverse-DNS of whoever *built* the app, which in public-sector work is almost
always the supplier and not the controller. The guessed domain was then handed to
MailRadar, the SSL check and CookieRadar, printed under the heading "Publisher",
and written into a GDPR letter as the basis of an art. 32 allegation.

Four apps, measured on 2026-09-25:

| package                        | package_to_domain      | Play developerWebsite   | right   |
|--------------------------------|------------------------|-------------------------|---------|
| com.moonactive.coinmaster      | moonactive.com ✅      | moonactive.zendesk.com ❌ | package |
| com.gameitech.…abc123…         | gameitech.com ❌ (for sale) | gameitech.in ✅      | Play    |
| it.Beta80Group.whereareu       | Beta80Group.it ❌ (supplier) | where.areu.lombardia.it ✅ | Play |
| com.x8bit.bitwarden            | x8bit.com ❌ (unrelated firm) | bitwarden.com ✅   | Play    |

Play wins 3–1, so the obvious remedy — switch source — is wrong: `developerWebsite`
is free text and here it is a Zendesk helpdesk tenant, whose mail posture is
largely Zendesk's configuration. Neither source is authoritative alone.

So these tests do not pin a better guess. They pin the distinction between
knowing and guessing: consult both sources, filter the SaaS tenants out, label
the provenance wherever a domain is printed, and never accuse a named legal
entity under art. 32 over a domain nobody established it owns. It is the same
line exeradar draws between `unsigned` and `unknown`.

Where it ended up: the listing does win over the package name, because the one
case where it loses — the Zendesk tenant above — is removed by the platform
filter first. What was wrong was switching source *without* that filter and
without saying which source answered. The guess is then set aside rather than
reported beside it; test_guess_set_aside.py carries that step, and
test_parked_domains.py the one after it.
"""

from __future__ import annotations

import pytest

from apkradar import publisher
from apkradar.scanner import ScanResult
from apkradar.utils import package_to_domain

# The real values, from the four APKs examined.
COINMASTER = "com.moonactive.coinmaster"
ABC123 = "com.gameitech.preschool.abc123.tracing.learning"
WHEREAREU = "it.Beta80Group.whereareu"
BITWARDEN = "com.x8bit.bitwarden"


# ── the domain has to be one string, not two ─────────────────────────────────


def test_the_guess_is_lowercased():
    """`Beta80Group.it` and `beta80group.it` were counted as two domains.

    The main branch returned f"{sld}.{tld}" while only the generic-segment
    branch called .lower(), and get_all_domains collects into a set — so the
    capitals bought a second round of MailRadar, SSL and CookieRadar on the same
    host, and printed it twice.
    """
    assert package_to_domain(WHEREAREU) == "beta80group.it"


def test_the_generic_segment_branch_stays_lowercased():
    assert package_to_domain("com.Game.Asteroids_Revenge") == "asteroids-revenge.com"


@pytest.mark.parametrize(
    ("package", "domain"),
    [
        ("org.wikipedia", "wikipedia.org"),
        ("com.nextcloud.client", "nextcloud.com"),
        ("org.telegram.messenger.web", "telegram.org"),
        ("app.organicmaps", "organicmaps.app"),
        ("org.fdroid.fdroid", "fdroid.org"),
        (COINMASTER, "moonactive.com"),
    ],
)
def test_the_cases_the_heuristic_gets_right_are_unchanged(package, domain):
    """The heuristic is not the defect and is not being replaced."""
    assert package_to_domain(package) == domain


# ── a site field is free text, so it has to be normalised ───────────────────


@pytest.mark.parametrize(
    ("value", "host"),
    [
        ("https://gameitech.in/", "gameitech.in"),
        ("http://where.areu.lombardia.it/privacy", "where.areu.lombardia.it"),
        ("https://www.nextcloud.com", "nextcloud.com"),
        ("bitwarden.com", "bitwarden.com"),
        ("https://Example.COM:8443/x?y=1", "example.com"),
        ("https://example.com.", "example.com"),
    ],
)
def test_a_declared_site_becomes_a_bare_host(value, host):
    assert publisher.normalise_site(value) == host


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "gameitech",              # no dot: not a host
        "not a url at all",
        "mailto:dpo@example.com",
        "192.168.1.1",            # an address is not a publisher domain
    ],
)
def test_what_is_not_a_host_yields_nothing(value):
    """Rather than a string that later gets printed as "the publisher domain"."""
    assert publisher.normalise_site(value) is None


# ── SaaS, hosting and social hosts are not the publisher's domain ───────────


@pytest.mark.parametrize(
    "host",
    [
        "moonactive.zendesk.com",
        "acme.freshdesk.com",
        "gameitech.wixsite.com",
        "someone.github.io",
        "someone.blogspot.com",
        "someone.blogspot.it",
        "someone.wordpress.com",
        "sites.google.com",
        "play.google.com",
        "facebook.com",
        "myapp.web.app",
        "myapp.firebaseapp.com",
        "forsale.godaddy.com",
    ],
)
def test_a_platform_host_is_not_a_publisher_domain(host):
    """Measuring it measures the platform's configuration, not the publisher's.

    MailRadar on Coin Master's three candidates: moonactive.com 40/100,
    moonactive.zendesk.com 42/100, zendesk.com 56/100. The middle number is
    mostly Zendesk's doing.
    """
    assert publisher.is_platform_host(host) is True


@pytest.mark.parametrize(
    "host",
    ["moonactive.com", "gameitech.in", "where.areu.lombardia.it", "bitwarden.com", "google.com"],
)
def test_a_real_publisher_host_is_not_filtered(host):
    """google.com included deliberately: it is a platform *and* a publisher."""
    assert publisher.is_platform_host(host) is False


# ── the four real cases ─────────────────────────────────────────────────────


def test_coinmaster_keeps_the_package_guess_and_drops_the_helpdesk():
    """The case that reverses the obvious fix.

    Play declares a Zendesk tenant; the package name happens to be right. So the
    Play value is discarded as a platform host and the guess survives — still
    labelled a guess, because nothing verified it.
    """
    pub = publisher.resolve(COINMASTER, "https://moonactive.zendesk.com")

    assert pub.best == "moonactive.com"
    assert pub.provenance == "package_name"
    assert pub.verified is False
    assert pub.rejected_play == "moonactive.zendesk.com"


@pytest.mark.parametrize(
    ("package", "play_site", "guessed"),
    [
        (ABC123, "https://gameitech.in/", "gameitech.com"),
        (WHEREAREU, "https://where.areu.lombardia.it/", "beta80group.it"),
        (BITWARDEN, "https://bitwarden.com", "x8bit.com"),
    ],
)
def test_when_the_two_sources_differ_the_listing_wins_alone(package, play_site, guessed):
    """The reverse-DNS guess is set aside, not weighed against the listing.

    This asserted that both were reported and neither chosen, which was the
    previous rule. What it was guarding — no source is silently preferred — still
    holds in the sense that matters: the guess is not preferred, it is not used
    at all, and the one domain that remains is labelled unverified. Each of these
    three guesses is somebody else's company: the app's software house, a parked
    domain, and an unrelated Spanish firm.
    """
    pub = publisher.resolve(package, play_site)

    assert [d for d, _ in pub.candidates] == [publisher.normalise_site(play_site)]
    assert pub.overridden_by_play == guessed
    assert pub.verified is False


def test_the_controller_domain_is_among_the_candidates():
    """The complaint was that where.areu.lombardia.it was never checked at all.

    Seven domains were analysed for 112 Where ARE U and the controller's was not
    one of them — while the supplier's was, under the "Publisher" heading.
    """
    pub = publisher.resolve(WHEREAREU, "https://where.areu.lombardia.it/")

    assert "where.areu.lombardia.it" in {d for d, _ in pub.candidates}


def test_agreement_is_the_only_thing_that_verifies_a_domain():
    pub = publisher.resolve("com.nextcloud.client", "https://www.nextcloud.com/")

    assert pub.best == "nextcloud.com"
    assert pub.provenance == "agreed"
    assert pub.verified is True


def test_agreement_survives_a_platform_host():
    """Zendesk's own app, hypothetically: both sources say zendesk.com.

    The filter exists to catch a tenant named after someone else, not to argue
    with two independent sources that say the same thing.
    """
    pub = publisher.resolve("com.zendesk.android", "https://www.zendesk.com")

    assert pub.best == "zendesk.com"
    assert pub.verified is True


def test_a_package_under_a_hosting_domain_is_not_a_publisher_domain():
    """io.github.* is an ordinary Android package prefix, and github.io is not
    the publisher's domain — App Manager is a real app with this shape."""
    pub = publisher.resolve("io.github.muntashirakon.AppManager")

    assert pub.best is None
    assert pub.rejected_package == "github.io"


def test_offline_leaves_the_guess_as_a_guess():
    """No Play lookup is not a reason to promote the guess to a fact."""
    pub = publisher.resolve(ABC123)

    assert pub.best == "gameitech.com"
    assert pub.provenance == "package_name"
    assert pub.verified is False


def test_no_package_name_claims_nothing():
    pub = publisher.resolve("")

    assert pub.best is None
    assert pub.candidates == []
    assert pub.verified is False


def test_a_domain_stated_by_the_sender_is_taken_as_established():
    """--publisher-domain is a human taking responsibility, like --publisher.

    `send` already requires the addressee and the publisher name to be typed in;
    a domain asserted the same way is not a guess by this tool.
    """
    pub = publisher.resolve(WHEREAREU, stated="where.areu.lombardia.it")

    assert pub.best == "where.areu.lombardia.it"
    assert pub.provenance == "stated"
    assert pub.verified is True


# ── provenance has to travel with the domain ────────────────────────────────


def test_a_guess_says_so_where_it_is_printed():
    pub = publisher.resolve(ABC123)
    text = pub.describe("gameitech.com")

    assert "gameitech.com" in text
    assert "package name" in text
    assert "unverified" in text


def test_a_play_value_names_its_source():
    pub = publisher.resolve(WHEREAREU, "https://where.areu.lombardia.it/")

    assert "Google Play" in pub.describe("where.areu.lombardia.it")


def test_agreement_is_described_as_agreement():
    pub = publisher.resolve("com.nextcloud.client", "https://nextcloud.com")

    assert "unverified" not in pub.describe("nextcloud.com")


def test_no_domain_is_ever_described_without_a_provenance():
    """Every candidate carries a label; that is the whole point."""
    for pub in (
        publisher.resolve(COINMASTER, "https://moonactive.zendesk.com"),
        publisher.resolve(ABC123, "https://gameitech.in/"),
        publisher.resolve("com.nextcloud.client", "https://nextcloud.com"),
    ):
        for domain, _ in pub.candidates:
            assert pub.describe(domain) != domain
            assert "(" in pub.describe(domain)


# ── the scan carries the Play data, and stays offline unless asked ──────────


def _result(package=ABC123, site=""):
    return ScanResult(apk_path="x.apk", package_name=package, developer_site=site)


def test_scan_result_holds_what_play_says():
    result = _result(site="https://gameitech.in/")

    assert result.developer_site == "https://gameitech.in/"
    assert hasattr(result, "developer")


def test_a_result_resolves_through_the_same_rules():
    """A ScanResult goes through resolve(), so it inherits the same rule."""
    pub = publisher.from_result(_result(site="https://gameitech.in/"))

    assert pub.best == "gameitech.in"
    assert [d for d, _ in pub.candidates] == ["gameitech.in"]


def test_the_scan_does_no_lookup_unless_asked(tmp_path, monkeypatch):
    """scan() is a static analysis and a library call; it does not dial out."""
    from apkradar import search_cmd

    called: list[str] = []
    monkeypatch.setattr(search_cmd, "lookup", lambda pkg: called.append(pkg))

    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK\x03\x04")
    from apkradar.scanner import scan

    scan(str(apk))
    assert called == []


def test_the_lookup_failing_does_not_fail_the_scan(tmp_path, monkeypatch):
    """Offline, or Play refusing: the APK findings are still valid."""
    from apkradar import search_cmd
    from apkradar.scanner import scan

    def boom(pkg):
        raise RuntimeError("no network")

    monkeypatch.setattr(search_cmd, "lookup", boom)

    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK\x03\x04")
    result = scan(str(apk), lookup_publisher=True)

    assert "no network" not in (result.error or "")


# ── the dead branch: the manifest domains never reached the analysis ────────


def test_manifest_domains_are_analysed():
    """get_all_domains(result, apk=None) could read them and was never given an
    apk, so extract_domains_from_apk was unreachable from `audit --full`."""
    from apkradar.utils import get_all_domains

    result = _result()
    result.manifest_domains = ["deep.example.com"]

    assert "deep.example.com" in get_all_domains(result)


def test_the_store_deep_link_is_not_audited():
    """Waking the manifest branch must not add a check on Google's store page.

    112 Where ARE U declares two hosts in its manifest, `play.google.com` and
    `schemas.android.com`, and nearly every app declares the first. A deep link
    to a platform is not a statement about the publisher.
    """
    from apkradar.utils import get_all_domains

    result = _result()
    result.manifest_domains = ["play.google.com", "where.areu.lombardia.it"]
    domains = get_all_domains(result)

    assert "play.google.com" not in domains
    assert "where.areu.lombardia.it" in domains


def test_an_sdk_domain_is_not_filtered_as_a_platform():
    """facebook.com is exactly what to check when the Facebook SDK is embedded.

    The platform filter answers "is this the publisher's domain", not "is this
    worth checking", so it does not touch the SDK list.
    """
    from apkradar.scanner import TrackerFound
    from apkradar.utils import get_all_domains

    result = _result()
    result.trackers = [TrackerFound(package="com.facebook.appevents", name="Facebook")]

    assert "facebook.com" in get_all_domains(result)


def test_only_the_listings_domain_is_analysed():
    """It used to send both downstream. `gameitech.com` is for sale — see
    test_parked_domains.py — and it was getting three network checks and a row in
    the report under the publisher's name."""
    from apkradar.utils import get_all_domains

    domains = get_all_domains(_result(site="https://gameitech.in/"))

    assert "gameitech.in" in domains
    assert "gameitech.com" not in domains


def test_a_rejected_platform_host_is_not_analysed():
    from apkradar.utils import get_all_domains

    domains = get_all_domains(_result(COINMASTER, "https://moonactive.zendesk.com"))

    assert "moonactive.zendesk.com" not in domains
    assert "moonactive.com" in domains


# ── what Google Play actually returns ───────────────────────────────────────
#
# Fetched live on 2026-09-25 with google_play_scraper, from the three listings:
#
#   it.Beta80Group.whereareu   developer "AREU"
#                              developerWebsite "https://where.areu.lombardia.it"
#   com.moonactive.coinmaster  developer "Moon Active"
#                              developerWebsite "http://moonactive.zendesk.com"
#   com.gameitech.…abc123…     developer "Gameitech - Kids Education Games"
#                              developerWebsite "http://gameitech.in"
#
# Verbatim, because the shapes matter: two of the three are http, none has a
# trailing slash, and the issue's table was written with https and slashes. The
# normaliser has to accept what the field really holds, not a tidied version.

LIVE_PLAY_SITES = {
    WHEREAREU: "https://where.areu.lombardia.it",
    COINMASTER: "http://moonactive.zendesk.com",
    ABC123: "http://gameitech.in",
}


@pytest.mark.parametrize(
    ("package", "expected"),
    [
        (WHEREAREU, "where.areu.lombardia.it"),
        (COINMASTER, None),                      # a Zendesk tenant, dropped
        (ABC123, "gameitech.in"),
    ],
)
def test_the_real_play_field_normalises(package, expected):
    pub = publisher.resolve(package, LIVE_PLAY_SITES[package])

    assert pub.from_play == expected


def test_the_real_coinmaster_field_is_recognised_as_a_helpdesk():
    """http, no path, no slash — and still a tenant."""
    pub = publisher.resolve(COINMASTER, LIVE_PLAY_SITES[COINMASTER])

    assert pub.rejected_play == "moonactive.zendesk.com"
    assert pub.best == "moonactive.com"
    assert pub.verified is False


@pytest.mark.parametrize("package", [WHEREAREU, ABC123])
def test_the_real_listings_win_over_the_real_guesses(package):
    """The two live cases where Play is right and the package name is not.

    The domain is used and still not verified: a field one developer typed in is
    not two sources agreeing, so the letter's art. 32 section stays silent unless
    the sender states the domain.
    """
    pub = publisher.resolve(package, LIVE_PLAY_SITES[package])

    assert pub.best == publisher.normalise_site(LIVE_PLAY_SITES[package])
    assert pub.overridden_by_play
    assert pub.verified is False
    assert len(pub.candidates) == 1


def test_no_live_listing_makes_a_domain_verified():
    """Not one of the three agrees with its package name — which is why the
    letter's art. 32 section needs the sender to state the domain."""
    for package, site in LIVE_PLAY_SITES.items():
        assert publisher.resolve(package, site).verified is False, package
