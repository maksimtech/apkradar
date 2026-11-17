"""In an XAPK or APKM, the base APK is the app; a split is not.

The extractor took the first member that was neither `split_*.apk` nor
`config.*.apk`, preferring one whose name held the package. A feature split
named otherwise (`feature_ads.apk`, as dynamic-feature splits are) listed before
the base in the archive was scanned in its place: no code, no permissions, no
trackers, and the report said 100/100 — GOOD about an app with Google Ads in it.
Found by the bug hunt of 2026-11-17 on a bundle built from the abc 123 Tracing
APKs pulled from a test phone (`_hunt/synth/feature_first.xapk`), whose
manifest.json says which member is the base:

    "split_apks": [{"file": "base.apk", "id": "base"},
                   {"file": "feature_ads.apk", "id": "feature_ads"}]

APKMirror's .apkm names its base `base.apk`. And whatever is picked, an APK whose
<manifest> carries a `split=` attribute is a split by its own declaration: it is
never reported as the app.

The APKs are written here by tests/android_files.py and read by the real
androguard: a base that asks for the camera, a feature split that asks for
nothing.
"""

from __future__ import annotations

import json
import zipfile

import pytest

from apkradar.extractor import cleanup_temp, extract_main_apk
from apkradar.scanner import scan
from tests.android_files import ANDROID_NS, manifest, write_apk

PACKAGE = "com.gameitech.preschool.abc123.tracing.learning"
CAMERA = "android.permission.CAMERA"


def _split_manifest(split: str) -> str:
    return (
        f'<manifest xmlns:android="{ANDROID_NS}" package="{PACKAGE}" split="{split}"'
        ' android:isFeatureSplit="true">'
        '<application android:hasCode="false"/>'
        "</manifest>"
    )


@pytest.fixture
def base_apk(tmp_path):
    return write_apk(tmp_path / "base-src.apk", manifest(PACKAGE, permissions=(CAMERA,)))


@pytest.fixture
def feature_apk(tmp_path):
    return write_apk(tmp_path / "feature-src.apk", _split_manifest("feature_ads"))


def _bundle(path, members, meta):
    """`members` in archive order: (name in the bundle, source file)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        z.writestr("manifest.json", json.dumps(meta))
        for name, source in members:
            z.write(source, name)
    return str(path)


def test_xapk_base_declared_in_manifest_is_the_one_scanned(tmp_path, base_apk, feature_apk):
    bundle = _bundle(
        tmp_path / "app.xapk",
        [("feature_ads.apk", feature_apk), ("base.apk", base_apk)],
        {
            "xapk_version": 2,
            "package_name": PACKAGE,
            "split_apks": [{"file": "base.apk", "id": "base"}, {"file": "feature_ads.apk", "id": "feature_ads"}],
        },
    )

    result = scan(bundle)

    assert result.error is None, result.error
    assert [p.permission for p in result.sensitive_permissions] == [CAMERA], f"scored {result.score}"


def test_apkm_base_apk_is_the_one_extracted(tmp_path, base_apk, feature_apk):
    bundle = _bundle(
        tmp_path / "app.apkm",
        [("feature_ads.apk", feature_apk), ("base.apk", base_apk)],
        {"pname": PACKAGE},
    )

    apk, tmp_dir = extract_main_apk(bundle)
    try:
        assert apk is not None and apk.endswith("base.apk"), apk
    finally:
        cleanup_temp(tmp_dir)


def test_a_base_named_in_the_manifest_but_missing_is_not_replaced_by_a_guess(tmp_path, feature_apk):
    """The manifest says which member is the app; if it is not there, the
    bundle is incomplete, and the feature split is still not the app."""
    bundle = _bundle(
        tmp_path / "app.xapk",
        [("feature_ads.apk", feature_apk)],
        {"xapk_version": 2, "package_name": PACKAGE, "split_apks": [{"file": "base.apk", "id": "base"}]},
    )

    result = scan(bundle)

    assert result.error is not None
    assert result.score is None


def test_a_split_is_never_reported_as_the_app(tmp_path, feature_apk):
    """No manifest.json to say which member is the base, and only a feature split
    to pick: it is a split by its own manifest, and the scan says so instead of
    scoring it."""
    bundle = _bundle(tmp_path / "app.xapk", [("feature_ads.apk", feature_apk)], {"xapk_version": 2})

    result = scan(bundle)

    assert result.score is None
    assert result.score_label == "N/A"
    assert "split" in (result.error or "")
    assert "feature_ads" in (result.error or "")


def test_a_split_given_as_an_apk_is_not_scored_either(feature_apk):
    result = scan(feature_apk)

    assert result.score is None
    assert "split" in (result.error or "")
