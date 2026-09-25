"""The app itself says where its privacy policy lives. That is a third witness.

Two sources decide the publisher's domain today and neither is independent of the
developer: the package name is their reverse-DNS, and the Play listing is a field
they typed. So nothing is ever "established" without the sender saying so, and the
DPO letter cannot state an art. 32 finding on its own.

There is a third thing to ask, and it is the artifact. Measured on the real
112 Where ARE U package (SHA-256 af0db3dc…b751) on 2026-09-25:

    where.areu.lombardia.it      9 occurrences in the base APK
      …including /privacy, /credits, /Disclaimer, /coverage
    beta80group.it               0 occurrences

The app points at its controller's site, repeatedly, and at the software house
that built it not once. Google Play names the same domain. Two parties that did
not copy from each other agree, and that is what "established" has meant here all
along.

Three rules keep this from becoming a way to accuse someone new.

**It can only corroborate, never propose.** The check asks "does this APK mention
*this* domain", one candidate at a time. It cannot return a domain, so it cannot
introduce a target to audit.

**It corroborates the Play listing only.** The package name and the contents of
the APK are both the builder's work: an `© Beta 80 Group — beta80group.it` in a
credits screen would otherwise promote the supplier's domain to established and
put the art. 32 finding back on the wrong company, which is the defect this whole
line of work removed.

**A mention has to look deliberate.** A policy or terms URL, or several mentions
— not one string that happens to contain the name.

Where it does nothing: abc 123 Tracing mentions neither gameitech.in nor
gameitech.com anywhere in its APK, so that case stays unverified and the letter
stays silent, exactly as before.
"""

from __future__ import annotations

import pytest

from apkradar import publisher
from apkradar.content import Mention, mentions_of
from apkradar.scanner import ScanResult

WHEREAREU = "it.Beta80Group.whereareu"
ABC123 = "com.gameitech.preschool.abc123.tracing.learning"
AREU_SITE = "https://where.areu.lombardia.it"

# What the real APK holds, in the shape the extractor sees it.
AREU_CONTENT = (
    b"\x00\x01binary junk\x00"
    b"https://where.areu.lombardia.it/\x00"
    b"https://where.areu.lombardia.it/privacy\x00"
    b"https://where.areu.lombardia.it/credits\x00"
    b"https://where.areu.lombardia.it/Disclaimer\x00"
    b"schemas.android.com\x00play.google.com\x00"
)


@pytest.fixture
def apk(tmp_path):
    def write(content: bytes = AREU_CONTENT) -> str:
        target = tmp_path / "app.apk"
        target.write_bytes(content)
        return str(target)
    return write


# ── counting what the file says ─────────────────────────────────────────────


def test_a_domain_the_app_names_is_counted(apk):
    found = mentions_of("where.areu.lombardia.it", apk())

    assert found.count == 4
    assert found.policy_url == "https://where.areu.lombardia.it/privacy"


def test_a_domain_the_app_never_names_is_absent(apk):
    found = mentions_of("beta80group.it", apk())

    assert found.count == 0
    assert found.policy_url is None
    assert found.deliberate is False


def test_the_match_does_not_run_past_the_name(apk):
    """`gameitech.in` must not be found inside `gameitech.info`. A label that
    continues is a different domain, and counting it would corroborate the wrong
    one."""
    found = mentions_of("gameitech.in", apk(b"visit https://gameitech.info/ today"))

    assert found.count == 0


def test_a_subdomain_is_not_the_domain(apk):
    """`areu.lombardia.it` is not `where.areu.lombardia.it`: the question is
    about one host, asked one host at a time."""
    found = mentions_of("areu.lombardia.it", apk())

    assert found.count == 0


def test_case_does_not_matter(apk):
    found = mentions_of("where.areu.lombardia.it", apk(b"HTTPS://WHERE.AREU.LOMBARDIA.IT/PRIVACY"))

    assert found.count == 1
    assert found.policy_url


@pytest.mark.parametrize("path", ["/privacy", "/informativa", "/terms", "/legal", "/privacy-policy"])
def test_the_pages_that_count_as_deliberate(apk, path):
    found = mentions_of("example.com", apk(f"https://example.com{path} ".encode()))

    assert found.deliberate is True
    assert found.policy_url


def test_one_bare_mention_is_not_deliberate(apk):
    """A single appearance with no policy page is a coincidence until proven
    otherwise — a string in a resource, a comment, a changelog."""
    found = mentions_of("example.com", apk(b"built by example.com"))

    assert found.count == 1
    assert found.deliberate is False


def test_several_mentions_are_deliberate(apk):
    found = mentions_of("example.com", apk(b"example.com x example.com y example.com"))

    assert found.count == 3
    assert found.deliberate is True


def test_a_file_that_cannot_be_read_says_nothing(tmp_path):
    """Not zero mentions — nothing. A missing file is not evidence of absence."""
    found = mentions_of("example.com", str(tmp_path / "gone.apk"))

    assert found.readable is False
    assert found.deliberate is False


def test_an_empty_domain_is_not_asked_about(apk):
    assert mentions_of("", apk()).count == 0


# ── promoting a candidate, and refusing to ──────────────────────────────────


def _result(package=WHEREAREU, site=AREU_SITE, mention: Mention | None = None):
    result = ScanResult(apk_path="whereareu.xapk", package_name=package, developer_site=site)
    if mention is not None:
        result.site_mention = mention
    return result


def test_the_listing_the_app_confirms_is_established():
    """Play says where.areu.lombardia.it, the app says it four times including
    its privacy policy. Two parties, no copying, same answer."""
    pub = publisher.from_result(
        _result(mention=Mention(count=4, policy_url=f"{AREU_SITE}/privacy", readable=True))
    )

    assert pub.best == "where.areu.lombardia.it"
    assert pub.verified is True
    assert pub.provenance == "corroborated"


def test_the_label_says_what_confirmed_it():
    pub = publisher.from_result(
        _result(mention=Mention(count=4, policy_url=f"{AREU_SITE}/privacy", readable=True))
    )

    assert "app" in pub.describe().lower()
    assert "unverified" not in pub.describe()


def test_a_listing_the_app_never_mentions_stays_unverified():
    """abc 123 Tracing: neither of its candidate domains appears in the APK."""
    pub = publisher.from_result(
        ScanResult(
            apk_path="abc123.xapk",
            package_name=ABC123,
            developer_site="http://gameitech.in",
            site_mention=Mention(count=0, policy_url=None, readable=True),
        )
    )

    assert pub.best == "gameitech.in"
    assert pub.verified is False


def test_a_mention_that_is_not_deliberate_does_not_establish_anything():
    pub = publisher.from_result(
        _result(mention=Mention(count=1, policy_url=None, readable=True))
    )

    assert pub.verified is False


def test_an_unreadable_apk_establishes_nothing():
    pub = publisher.from_result(
        _result(mention=Mention(count=0, policy_url=None, readable=False))
    )

    assert pub.verified is False


def test_the_package_name_guess_is_never_promoted_this_way():
    """The rule that keeps this safe. The package name and the APK's contents are
    both the builder's work, so one confirming the other is one party speaking
    twice — and it would put the finding back on the software house."""
    pub = publisher.from_result(
        ScanResult(
            apk_path="whereareu.xapk",
            package_name=WHEREAREU,
            developer_site="",          # no listing: the guess is the candidate
            site_mention=Mention(count=9, policy_url="https://beta80group.it/privacy", readable=True),
        )
    )

    assert pub.best == "beta80group.it"
    assert pub.verified is False, "the builder cannot corroborate the builder"


def test_agreement_between_the_first_two_still_verifies():
    pub = publisher.resolve("com.nextcloud.client", "https://nextcloud.com")

    assert pub.verified is True
    assert pub.provenance == "agreed"


def test_a_stated_domain_still_wins():
    pub = publisher.from_result(
        _result(mention=Mention(count=4, policy_url=f"{AREU_SITE}/privacy", readable=True)),
        stated="areu.lombardia.it",
    )

    assert pub.best == "areu.lombardia.it"
    assert pub.provenance == "stated"


def test_a_result_with_no_mention_at_all_behaves_as_before():
    """Every caller that never asks the question gets the previous behaviour."""
    pub = publisher.from_result(_result())

    assert pub.best == "where.areu.lombardia.it"
    assert pub.verified is False
