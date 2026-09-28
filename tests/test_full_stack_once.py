"""
APKRadar — ogni dominio si analizza una volta sola.

In `audit --full` il ciclo sui candidati editore compare due volte: una prima
del blocco `if domains:` e una identica dentro. Quando un candidato c'è — cioè
quasi sempre — il dominio dell'editore riceve **due** analisi complete: due
interrogazioni DNS con MailRadar, due handshake TLS e due sessioni di browser
con rifiuto dei cookie tramite CookieRadar.

Non è solo lavoro sprecato. È traffico doppio contro l'infrastruttura di un
terzo, da uno strumento che quel terzo lo nomina in una contestazione per
articoli, e sono due blocchi identici nel referto: chi legge non sa se il
secondo sia una seconda misura o la stessa stampata due volte.

Il test conta le chiamate per dominio, che è la cosa che conta: asserire su
quante righe stampa il referto lascerebbe passare una correzione che nasconde
il secondo giro senza smettere di farlo.
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
