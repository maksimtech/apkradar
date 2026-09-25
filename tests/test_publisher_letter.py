"""An art. 32 allegation needs a domain whose owner is known.

`apkradar send --dry-run` on 112 Where ARE U produced a letter addressed
"Spettabile AREU" containing:

    4. MISURE TECNICHE — art. 32 GDPR

    L'analisi della sicurezza email del dominio publisher (Beta80Group.it) ha
    prodotto un punteggio di 44/100 — POOR, indicando misure tecniche inadeguate
    per la protezione delle comunicazioni.

A formal allegation against AREU, resting on the DNS records of a domain owned by
Beta 80 Group — the supplier — and the template asserts the ownership by calling
it "il dominio publisher". The SSL variants at lines 51–55 are blunter still:
"in violazione del principio di sicurezza del trattamento ex art. 32 GDPR".

Beta 80 Group's 44/100 is real, and so is the tracker surviving consent rejection
on their site. That is what makes it a problem rather than a rounding error: the
finding is true about someone who is not the addressee.

These tests draw the line where the data supports it. The letter may state a
technical finding about a domain the sender has established — because they typed
it in, or because both independent sources agree — and otherwise says plainly
that it established nothing, which is not the same as finding nothing.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.scanner import ScanResult, TrackerFound
from apkradar.sender import render_letter

runner = CliRunner()

WHEREAREU = "it.Beta80Group.whereareu"
AREU_SITE = "https://where.areu.lombardia.it/"

SEND_ARGS = [
    "--to", "dpo@areu.lombardia.it",
    "--publisher", "AREU",
    "--from", "test@example.com",
    "--smtp-host", "smtp.example.com",
    "--smtp-user", "test@example.com",
    "--name", "Test User",
    "--dry-run",
]

INADEQUATE = "misure tecniche inadeguate"
NO_ISSUES = "Non sono state rilevate criticità"


def _result(package=WHEREAREU, site="", trackers=()):
    result = ScanResult(
        apk_path="whereareu.xapk",
        package_name=package,
        app_name="112 Where ARE U",
        version_name="3.10.0.0",
        sha256="af0db3dc" * 8,
        developer_site=site,
    )
    result.trackers = [TrackerFound(package=p, name=n) for p, n in trackers]
    return result


def _letter(**kwargs):
    kwargs.setdefault("result", _result())
    kwargs.setdefault("publisher", "AREU")
    kwargs.setdefault("sender_name", "Test User")
    kwargs.setdefault("sender_org", "")
    kwargs.setdefault("sender_email", "test@example.com")
    return render_letter(**kwargs)


# ── the letter ──────────────────────────────────────────────────────────────


def test_an_unestablished_domain_supports_no_allegation():
    """The reproduction from the issue, as an assertion."""
    letter = _letter(publisher_domain="beta80group.it", mail_score=44, mail_grade="POOR")

    assert INADEQUATE not in letter
    assert "beta80group.it" not in letter


def test_and_it_does_not_claim_the_opposite_either():
    """"No issues found" would be a second false statement, not a fix."""
    letter = _letter(publisher_domain="beta80group.it", mail_score=44, mail_grade="POOR")

    assert NO_ISSUES not in letter


def test_section_four_says_what_it_could_not_establish():
    """A heading with nothing under it invites the reader to fill the gap."""
    letter = _letter(publisher_domain="beta80group.it", mail_score=44, mail_grade="POOR")
    section = letter.split("4. MISURE TECNICHE")[1].split("5.")[0]

    assert section.strip(), "section 4 left empty"
    assert "art. 32" in section
    assert "package" in section.lower() or "titolarità" in section.lower()


def test_the_unsafe_default_is_the_safe_one():
    """A caller that says nothing about provenance gets no allegation.

    render_letter is called from `send` and from anything embedding this package;
    the parameter defaults to unverified so that forgetting it cannot produce a
    claim.
    """
    letter = _letter(publisher_domain="beta80group.it", ssl_status="expired")

    assert "scaduto" not in letter


@pytest.mark.parametrize(
    ("ssl_status", "word"),
    [("expired", "scaduto"), ("self_signed", "autofirmato"), ("unknown_ca", "non riconosciuta")],
)
def test_no_ssl_allegation_over_an_unestablished_domain(ssl_status, word):
    letter = _letter(publisher_domain="beta80group.it", ssl_status=ssl_status)

    assert word not in letter


def test_a_domain_the_sender_stated_supports_the_finding():
    """This is the path a real complaint takes: the sender names the domain."""
    letter = _letter(
        publisher_domain="where.areu.lombardia.it",
        publisher_domain_verified=True,
        mail_score=44,
        mail_grade="POOR",
    )

    assert INADEQUATE in letter
    assert "where.areu.lombardia.it" in letter
    assert "44/100" in letter


def test_a_verified_domain_with_nothing_wrong_says_so():
    letter = _letter(
        publisher_domain="where.areu.lombardia.it",
        publisher_domain_verified=True,
        mail_score=95,
        mail_grade="A",
    )

    assert NO_ISSUES in letter
    assert INADEQUATE not in letter


# ── `send` ──────────────────────────────────────────────────────────────────


@pytest.fixture
def sending(monkeypatch):
    """Run `send --dry-run` with the network stubbed out."""
    def run(result, extra=(), mail=(44, "POOR"), ssl=("valid", "01/12/2026")):
        import apkradar.scanner as scanner

        monkeypatch.setattr(scanner, "scan", lambda path, **kw: result)
        with patch("apkradar.cli._check_mailradar", return_value=mail), \
             patch("apkradar.cli._check_ssl", return_value=ssl):
            return runner.invoke(app, ["send", "whereareu.xapk", *SEND_ARGS, *extra])
    return run


def test_send_does_not_accuse_over_a_guessed_domain(sending):
    outcome = sending(_result())

    assert outcome.exit_code == 0, outcome.output
    assert INADEQUATE not in outcome.output


def test_send_explains_why_the_section_is_empty(sending):
    """Silence would look like a bug; the user needs to know what to do."""
    outcome = sending(_result())

    assert "--publisher-domain" in outcome.output


def test_send_accepts_the_domain_from_the_sender(sending):
    outcome = sending(_result(), extra=["--publisher-domain", "where.areu.lombardia.it"])

    assert INADEQUATE in outcome.output
    assert "where.areu.lombardia.it" in outcome.output


def test_send_checks_the_domain_the_sender_gave(sending):
    """Not the guessed one: the mail score in the letter has to be that host's."""
    import apkradar.scanner as scanner

    checked: list[str] = []
    with patch("apkradar.cli._check_mailradar", side_effect=lambda d: (checked.append(d), (44, "POOR"))[1]), \
         patch("apkradar.cli._check_ssl", return_value=("valid", None)), \
         patch.object(scanner, "scan", lambda path, **kw: _result()):
        runner.invoke(
            app,
            ["send", "whereareu.xapk", *SEND_ARGS,
             "--publisher-domain", "where.areu.lombardia.it"],
        )

    assert checked == ["where.areu.lombardia.it"]


def test_send_reports_the_listings_domain_and_not_the_guess(sending):
    """It used to print both. The second was Beta 80 Group's corporate domain,
    and `send` builds a letter addressed to AREU — see test_guess_set_aside.py."""
    outcome = sending(_result(site=AREU_SITE))

    assert "where.areu.lombardia.it" in outcome.output
    assert "beta80group.it" not in outcome.output.lower()
    assert INADEQUATE not in outcome.output


def test_send_uses_agreement_without_being_told(sending):
    """Both sources saying nextcloud.com is evidence the sender did not invent."""
    outcome = sending(
        _result(package="com.nextcloud.client", site="https://nextcloud.com"),
        mail=(44, "POOR"),
    )

    assert INADEQUATE in outcome.output


def test_send_skips_the_play_lookup_when_offline(sending):
    from apkradar import search_cmd

    calls: list[str] = []
    with patch.object(search_cmd, "lookup", side_effect=lambda pkg: calls.append(pkg)):
        sending(_result(), extra=["--offline"])

    assert calls == []


# ── `audit --full` ──────────────────────────────────────────────────────────


@pytest.fixture
def auditing(monkeypatch):
    def run(result, extra=()):
        import apkradar.scanner as scanner

        monkeypatch.setattr(scanner, "scan", lambda path, **kw: result)
        cookies = MagicMock()
        cookies.pre_consent.trackers = []
        cookies.post_reject.trackers = []
        def run(coro):
            if hasattr(coro, "close"):
                coro.close()
            return cookies

        with patch("apkradar.cli._check_mailradar", return_value=(44, "POOR")), \
             patch("apkradar.cli._check_ssl", return_value=("valid", "01/12/2026")), \
             patch("asyncio.run", side_effect=run):
            return runner.invoke(app, ["audit", "whereareu.xapk", "--full", *extra])
    return run


def test_full_labels_the_guessed_publisher_domain(auditing):
    """Seven domains were printed identically under one heading; the reader had
    no way to tell the guess from the SDK domains taken out of the file."""
    outcome = auditing(_result())
    line = next(ln for ln in outcome.output.splitlines() if "beta80group.it" in ln)

    assert "package name" in line
    assert "unverified" in line


def test_full_does_not_label_an_sdk_domain_a_publisher(auditing):
    outcome = auditing(
        _result(trackers=[("com.google.android.gms.ads", "Google Ads")])
    )
    line = next(ln for ln in outcome.output.splitlines() if "doubleclick.net" in ln)

    assert "package name" not in line
    assert "SDK" in line


def test_full_analyses_the_controller_domain_too(auditing):
    outcome = auditing(_result(site=AREU_SITE))

    assert "where.areu.lombardia.it" in outcome.output


def test_full_says_a_guess_was_set_aside(auditing):
    """It used to announce a disagreement and analyse both. Now it says the
    domain comes from the listing and that a guess was dropped, without naming
    the guess."""
    outcome = auditing(_result(site=AREU_SITE))

    assert "package name" in outcome.output
    assert "beta80group.it" not in outcome.output.lower()


def test_full_does_not_analyse_a_helpdesk_tenant(auditing):
    """It may be named once, as skipped, with the reason — that is the report
    explaining itself. What it may not have is a block of MailRadar, SSL and
    CookieRadar findings, which would be Zendesk's configuration filed under
    Moon Active."""
    outcome = auditing(
        _result(package="com.moonactive.coinmaster", site="https://moonactive.zendesk.com")
    )
    analysed = [ln for ln in outcome.output.splitlines() if ln.startswith("🔗 ")]

    assert not any("moonactive.zendesk.com" in ln for ln in analysed), analysed
    assert any("moonactive.com" in ln for ln in analysed), analysed


def test_full_asks_play_unless_told_not_to(auditing):
    """The lookup is what makes the comparison possible, and --full is already
    a networked command."""
    import apkradar.scanner as scanner

    asked: list[bool] = []

    def recording_scan(path, **kw):
        asked.append(kw.get("lookup_publisher", False))
        return _result()

    with patch.object(scanner, "scan", recording_scan), \
         patch("apkradar.cli._check_mailradar", return_value=(None, None)), \
         patch("apkradar.cli._check_ssl", return_value=("error", None)), \
         patch("asyncio.run", side_effect=Exception("no browser")):
        runner.invoke(app, ["audit", "whereareu.xapk", "--full"])
        runner.invoke(app, ["audit", "whereareu.xapk", "--full", "--offline"])

    assert asked == [True, False]


def test_plain_audit_stays_offline(auditing):
    """Without --full nothing about the publisher is printed, so nothing is
    looked up: an audit of a file on disk should not need the network."""
    import apkradar.scanner as scanner

    asked: list[bool] = []

    def recording_scan(path, **kw):
        asked.append(kw.get("lookup_publisher", False))
        return _result()

    with patch.object(scanner, "scan", recording_scan):
        runner.invoke(app, ["audit", "whereareu.xapk"])

    assert asked == [False]
