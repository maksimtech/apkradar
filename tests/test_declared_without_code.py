"""A manifest component whose class is not in the DEX is a declaration, not an SDK.

Measured on Fennec 157.0.0 as F-Droid builds it (org.mozilla.fennec_fdroid,
version code 1570020, SHA-256
04a5f4d3e49fc36a67ff4b530910c994e4ff81d6f6649cf3f75e48ddb49247a9) on 2026-10-09.
Its manifest declares

    <receiver android:name="com.adjust.sdk.AdjustPreinstallReferrerReceiver"
              android:exported="true"/>

and none of its three DEX files holds a single descriptor under `Lcom/adjust/`:
the F-Droid build is made without the Adjust SDK, and the manifest keeps the
receiver. APKRadar reported the tracker "Adjust" and a transfer to "Adjust GmbH
(Germany) → USA", and the DPO letter would have put both in front of Mozilla —
an allegation about code that is not in the file, which is the kind a DPO can
dismiss without reading the rest.

The fixture is that manifest excerpt, compiled by tests/android_files.py, with a
DEX that holds the app's own classes and none of Adjust's. The same APK with the
receiver's class present is the control: a declaration backed by code is still
the SDK. And an APK with no DEX at all is read on the manifest's word, as before,
because "no code to check against" is not "confirmed absent".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkradar.scanner import scan
from tests.android_files import dex_blob, manifest, write_apk

PACKAGE = "org.mozilla.fennec_fdroid"
MAIN = "org.mozilla.fenix.HomeActivity"
RECEIVER = "com.adjust.sdk.AdjustPreinstallReferrerReceiver"


def _apk(tmp_path: Path, dex: bytes | None) -> str:
    return write_apk(
        tmp_path / "fennec.apk",
        manifest(PACKAGE, activities=(MAIN,), receivers=(RECEIVER,)),
        dex=dex,
    )


@pytest.fixture
def declared_without_code(tmp_path):
    return scan(_apk(tmp_path, dex_blob([MAIN, "org.mozilla.fenix.FenixApplication"])))


@pytest.fixture
def declared_with_code(tmp_path):
    return scan(_apk(tmp_path, dex_blob([MAIN, RECEIVER, "com.adjust.sdk.Adjust"])))


@pytest.fixture
def no_dex_at_all(tmp_path):
    return scan(_apk(tmp_path, None))


def test_the_fixture_is_a_scan_that_succeeded(declared_without_code):
    assert declared_without_code.error is None
    assert declared_without_code.package_name == PACKAGE


def test_a_declared_component_with_no_class_in_the_dex_is_not_a_tracker(declared_without_code):
    assert [t.name for t in declared_without_code.trackers] == []


def test_nor_is_it_a_transfer(declared_without_code):
    assert [t.entity for t in declared_without_code.extra_eu_transfers] == []


def test_the_same_declaration_backed_by_code_is_the_sdk(declared_with_code):
    assert [t.name for t in declared_with_code.trackers] == ["Adjust"]
    assert [t.entity for t in declared_with_code.extra_eu_transfers] == ["Adjust GmbH (Germany) → USA"]


def test_without_any_dex_the_manifest_is_taken_at_its_word(no_dex_at_all):
    """No code to check against is not evidence of absence."""
    assert [t.name for t in no_dex_at_all.trackers] == ["Adjust"]
