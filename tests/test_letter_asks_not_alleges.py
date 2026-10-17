"""The letter asks what static analysis cannot establish (audit F02, 2026-10-17).

`apkradar send … --dry-run` on abc 123 Tracing 1.8 wrote, to the publisher's DPO:

    La presenza di questi SDK comporta la trasmissione di dati personali a soggetti terzi.
    …
    Sono stati rilevati trasferimenti di dati verso i seguenti soggetti extra-UE:
      → Google LLC (USA)

What was detected is code: classes of an SDK in the DEX, and a component of a
US vendor. The README says so itself — a detected SDK "does not show whether
the SDK is active, what data it sends", an extra-EU vendor "does not show that
data leaves the EU" — and art. 44 GDPR is about a transfer of personal data to
a third country, which nothing in an APK establishes. A DPO who reads that a
transfer was "detected" and knows none happened can set the whole letter aside.

So the two sections now say what was found, say what it does not show, and
ask — the way the art. 9 section of the same letter already does.

The scan result is a real scan of an APK built by tests/android_files.py from
the app's AdMob classes (see tests/test_measurement_api_is_not_analytics.py).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apkradar.scanner import scan
from apkradar.sender import render_letter
from tests.android_files import dex_blob, manifest, write_apk

PACKAGE = "com.gameitech.preschool.abc123.tracing.learning"
MAIN = f"{PACKAGE}.MainActivity"


@pytest.fixture
def letter(tmp_path: Path) -> str:
    apk = write_apk(tmp_path / "app.apk", manifest(PACKAGE, activities=(MAIN,)),
                    dex=dex_blob([MAIN, "com.google.android.gms.ads.AdView"]))
    result = scan(apk)
    assert result.trackers and result.extra_eu_transfers, "the scan must find something to write about"
    text = render_letter(result=result, publisher="Gameitech", publisher_domain="", sender_name="Mario Rossi",
                         sender_org="", sender_email="mario@example.org")
    return " ".join(text.split())


def test_the_letter_does_not_state_that_data_is_transmitted(letter):
    assert "comporta la trasmissione" not in letter


def test_the_letter_asks_what_the_sdks_transmit_and_on_what_basis(letter):
    assert "non dimostra" in letter
    assert "Si chiede di indicare, per ciascuno, quali dati personali trasmetta" in letter


def test_the_letter_does_not_say_a_transfer_was_detected(letter):
    assert "Sono stati rilevati trasferimenti" not in letter


def test_the_letter_names_the_vendors_as_code_and_asks_about_transfers(letter):
    assert "L'APK contiene codice dei seguenti fornitori con sede fuori dall'Unione europea" in letter
    assert "Google LLC (USA)" in letter
    assert "Si chiede di indicare se dati personali degli utenti vengano trasferiti a tali soggetti" in letter
    assert "art. 46 GDPR" in letter


def test_with_nothing_found_the_letter_says_no_vendor_code_rather_than_no_transfer(tmp_path):
    apk = write_apk(tmp_path / "clean.apk", manifest("org.example.clean"), dex=dex_blob(["org.example.clean.Main"]))
    text = " ".join(render_letter(result=scan(apk), publisher="Example", publisher_domain="", sender_name="M",
                                  sender_org="", sender_email="m@example.org").split())

    assert "Non è stato rilevato codice di fornitori extra-UE noti" in text
    assert "trasferimenti di dati extra-UE" not in text
