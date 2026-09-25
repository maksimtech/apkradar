"""When Google Play names the publisher's site, the package name is not consulted.

Reporting both was the previous step: the guess was labelled, the disagreement was
stated, and nothing was presented as established. It is still not good enough,
because `beta80group.it` is Beta 80 Group's domain and Beta 80 Group is not the
addressee of anything. The app is published by AREU, a regional health agency;
Beta 80 Group wrote it. Under GDPR that is the processor (art. 28) and not the
controller (art. 24), and an audit that runs MailRadar, SSL and CookieRadar over
the processor's corporate site and prints the results in a report about the
controller's app is pointing at the wrong legal person — however carefully the
row is labelled.

So the rule is no longer "report both". When the Play listing gives a domain that
survives the platform filter, that is the publisher's domain as far as this tool
goes, and the reverse-DNS of the package name is set aside: not analysed, not
printed, not sent downstream. It stays in the data model, because a JSON consumer
may want to know a guess existed, and `--verbose` will show it to whoever asks.

The Coin Master case is what keeps this honest: there the Play field is a Zendesk
helpdesk tenant, the platform filter removes it, and the package-name guess is all
there is. It is still used, and still labelled unverified.

Measured live on 2026-09-25 against the three real listings.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from apkradar import publisher
from apkradar.cli import app
from apkradar.scanner import ScanResult

runner = CliRunner()

WHEREAREU = "it.Beta80Group.whereareu"
ABC123 = "com.gameitech.preschool.abc123.tracing.learning"
COINMASTER = "com.moonactive.coinmaster"

AREU_SITE = "https://where.areu.lombardia.it"
GAMEITECH_SITE = "http://gameitech.in"
ZENDESK_SITE = "http://moonactive.zendesk.com"


# ── the guess is set aside ──────────────────────────────────────────────────


def test_the_play_domain_is_the_only_candidate():
    pub = publisher.resolve(WHEREAREU, AREU_SITE)

    assert [d for d, _ in pub.candidates] == ["where.areu.lombardia.it"]


def test_the_suppliers_domain_is_not_among_them():
    pub = publisher.resolve(WHEREAREU, AREU_SITE)

    assert "beta80group.it" not in [d for d, _ in pub.candidates]
    assert pub.from_package is None


def test_the_guess_is_recorded_rather_than_forgotten():
    """Kept as data: the report does not print it, and a consumer can ask."""
    pub = publisher.resolve(WHEREAREU, AREU_SITE)

    assert pub.overridden_by_play == "beta80group.it"


def test_the_play_domain_is_used_but_not_verified():
    """A free-text field one developer filled in is not two sources agreeing."""
    pub = publisher.resolve(WHEREAREU, AREU_SITE)

    assert pub.best == "where.areu.lombardia.it"
    assert pub.provenance == "play_listing"
    assert pub.verified is False


def test_there_is_no_disagreement_left_to_report():
    """Nothing competes: one source answered and the other was not consulted.

    `disagree` is gone with the rule it described — a property that could only
    ever be False is the same defect as an option that does nothing. That the
    two sources differed is still recorded, as `overridden_by_play`.
    """
    pub = publisher.resolve(WHEREAREU, AREU_SITE)

    assert not hasattr(pub, "disagree")
    assert len(pub.candidates) == 1


def test_the_note_explains_without_naming_the_third_party():
    """Whoever reads the note learns that a guess was dropped. They do not learn
    a domain to go and audit."""
    note = publisher.resolve(WHEREAREU, AREU_SITE).note

    assert "beta80group.it" not in note
    assert "package name" in note


def test_the_same_holds_for_gameitech():
    pub = publisher.resolve(ABC123, GAMEITECH_SITE)

    assert [d for d, _ in pub.candidates] == ["gameitech.in"]
    assert pub.overridden_by_play == "gameitech.com"


# ── what the rule must not break ────────────────────────────────────────────


def test_coinmaster_still_falls_back_to_the_package_name():
    """Play names a Zendesk tenant, the filter removes it, and the guess is the
    only thing left. The counter-example that shaped all of this."""
    pub = publisher.resolve(COINMASTER, ZENDESK_SITE)

    assert [d for d, _ in pub.candidates] == ["moonactive.com"]
    assert pub.provenance == "package_name"
    assert pub.overridden_by_play is None


def test_with_no_play_data_the_guess_is_still_used():
    pub = publisher.resolve(ABC123)

    assert [d for d, _ in pub.candidates] == ["gameitech.com"]
    assert pub.overridden_by_play is None


def test_agreement_is_still_agreement():
    pub = publisher.resolve("com.nextcloud.client", "https://nextcloud.com")

    assert pub.verified is True
    assert pub.overridden_by_play is None


def test_a_domain_stated_by_the_sender_still_wins():
    pub = publisher.resolve(WHEREAREU, AREU_SITE, stated="areu.lombardia.it")

    assert pub.best == "areu.lombardia.it"
    assert pub.verified is True


# ── and it must not reach the downstream radars ─────────────────────────────


def test_the_supplier_domain_is_not_analysed():
    from apkradar.utils import get_all_domains

    result = ScanResult(
        apk_path="whereareu.xapk", package_name=WHEREAREU, developer_site=AREU_SITE
    )

    domains = get_all_domains(result)
    assert "beta80group.it" not in domains
    assert "where.areu.lombardia.it" in domains


def _result(package=WHEREAREU, site=AREU_SITE):
    return ScanResult(
        apk_path="whereareu.xapk",
        package_name=package,
        app_name="112 Where ARE U",
        sha256="af0db3dc" * 8,
        developer_site=site,
    )


@pytest.fixture
def audited(monkeypatch):
    def run(result, extra=()):
        import apkradar.scanner as scanner

        monkeypatch.setattr(scanner, "scan", lambda path, **kw: result)

        def no_browser(coro):
            if hasattr(coro, "close"):
                coro.close()
            raise RuntimeError("no browser")

        with patch("apkradar.cli._check_mailradar", return_value=(44, "POOR")), \
             patch("apkradar.cli._check_ssl", return_value=("valid", "01/12/2026")), \
             patch("asyncio.run", side_effect=no_browser):
            return runner.invoke(app, ["audit", "whereareu.xapk", "--full", *extra])
    return run


def test_the_full_analysis_never_prints_it(audited):
    """The domain, not the string: `it.Beta80Group.whereareu` is the app's own
    package name and belongs in the report — it is the identity of the artifact
    being audited. What must not appear is `beta80group.it`."""
    outcome = audited(_result())

    assert "beta80group.it" not in outcome.output.lower()
    assert "where.areu.lombardia.it" in outcome.output


def test_the_full_analysis_says_a_guess_was_set_aside(audited):
    """Silence would leave the reader wondering whether the package name was
    even looked at."""
    outcome = audited(_result())

    assert "package name" in outcome.output


def test_verbose_shows_it_to_whoever_asks(audited):
    """The one place it may appear: the flag whose purpose is detail."""
    outcome = audited(_result(), extra=["--verbose"])

    assert "beta80group.it" in outcome.output


@pytest.fixture
def sending(monkeypatch):
    def run(result, extra=()):
        import apkradar.scanner as scanner

        monkeypatch.setattr(scanner, "scan", lambda path, **kw: result)
        with patch("apkradar.cli._check_mailradar", return_value=(44, "POOR")), \
             patch("apkradar.cli._check_ssl", return_value=("valid", None)):
            return runner.invoke(app, [
                "send", "whereareu.xapk",
                "--to", "dpo@example.com", "--publisher", "AREU",
                "--from", "t@example.com", "--smtp-host", "smtp.example.com",
                "--smtp-user", "t@example.com", "--name", "T", "--dry-run", *extra,
            ])
    return run


def test_send_never_mentions_the_supplier(sending):
    """Not in the letter, which was already true, and now not on the console
    either. The package name, which contains the company's name, is a fact about
    the app and stays."""
    outcome = sending(_result())

    assert "beta80group.it" not in outcome.output.lower()


def test_send_checks_the_publishers_own_domain(sending):
    """The checks run on AREU's domain rather than on nobody's."""
    checked: list[str] = []
    import apkradar.scanner as scanner

    with patch("apkradar.cli._check_mailradar",
               side_effect=lambda d: (checked.append(d), (44, "POOR"))[1]), \
         patch("apkradar.cli._check_ssl", return_value=("valid", None)), \
         patch.object(scanner, "scan", lambda path, **kw: _result()):
        runner.invoke(app, [
            "send", "whereareu.xapk",
            "--to", "dpo@example.com", "--publisher", "AREU",
            "--from", "t@example.com", "--smtp-host", "smtp.example.com",
            "--smtp-user", "t@example.com", "--name", "T", "--dry-run",
        ])

    assert checked == ["where.areu.lombardia.it"]
