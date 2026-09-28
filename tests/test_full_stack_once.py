"""
APKRadar — each domain is analysed once.

In `audit --full` the loop over the publisher candidates appears twice: once
before the `if domains:` block and once identically inside it. When a candidate
exists — that is, nearly always — the publisher's domain receives **two**
complete analyses: two DNS interrogations with MailRadar, two TLS handshakes and
two browser sessions with cookie rejection through CookieRadar.

It is not only wasted work. It is double traffic against a third party's
infrastructure, from a tool that names that third party in an allegation under
named articles, and it is two identical panels in the report: a reader cannot
tell whether the second is a second measurement or the same one printed twice.

The test counts the calls per domain, which is the thing that matters: asserting
on how many lines the report prints would let through a fix that hides the second
pass without stopping it.
"""
from __future__ import annotations

import collections
from unittest.mock import patch

from typer.testing import CliRunner

import apkradar.cli as cli
from apkradar.cli import app
from apkradar.scanner import ScanResult

runner = CliRunner()


class _Publisher:
    """Quel poco di PublisherDomain che il blocco --full consulta."""

    overridden_by_play = None
    parked = ()
    rejected_play = None
    rejected_package = None
    set_aside = frozenset()


def _scanned() -> ScanResult:
    return ScanResult(
        apk_path="demo.apk",
        package_name="com.example.demo",
        app_name="Demo",
        version_name="1.0",
        sha256="a" * 64,
    )


def test_each_domain_is_analysed_once():
    calls: collections.Counter = collections.Counter()

    def counting_stack(domain, **kwargs):
        calls[domain] += 1
        return False

    with patch("apkradar.scanner.scan", return_value=_scanned()), \
         patch.object(cli, "_domains_to_analyse",
                      lambda result: (_Publisher(),
                                      [("editore.example", "package_name")],
                                      ["sdk-uno.example", "sdk-due.example"])), \
         patch.object(cli, "_full_stack_domain", counting_stack), \
         patch.object(cli, "_law_check", lambda *a, **k: None):
        outcome = runner.invoke(app, ["audit", "demo.apk", "--full"])

    assert outcome.exit_code == 0, outcome.output
    doubled = {domain: n for domain, n in calls.items() if n > 1}
    assert not doubled, f"analizzati piu' di una volta: {doubled}"
    assert set(calls) == {"editore.example", "sdk-uno.example", "sdk-due.example"}


def test_the_publisher_domain_is_still_analysed():
    """La correzione ovvia — togliere un ciclo — deve togliere quello giusto:
    il dominio dell'editore e' il soggetto del referto, non un accessorio."""
    seen = []

    with patch("apkradar.scanner.scan", return_value=_scanned()), \
         patch.object(cli, "_domains_to_analyse",
                      lambda result: (_Publisher(),
                                      [("editore.example", "package_name")], [])), \
         patch.object(cli, "_full_stack_domain",
                      lambda domain, **kw: seen.append(domain) or False), \
         patch.object(cli, "_law_check", lambda *a, **k: None):
        outcome = runner.invoke(app, ["audit", "demo.apk", "--full"])

    assert outcome.exit_code == 0, outcome.output
    assert seen == ["editore.example"]
