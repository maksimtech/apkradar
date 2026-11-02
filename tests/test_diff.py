"""`apkradar diff`: what changed between two releases of the same app.

Every APK here is a real file, written by tests/android_files.py and opened by the
real androguard through scanner.scan(). Nothing about the scan is replaced: the
comparison is only worth what the two scans it compares are worth.

The case that asked for the command: Adobe Acrobat Reader stops at 24.8.1 on a
Galaxy Tab A SM-T515, whose Android runs 32-bit on a 64-bit CPU. The later
releases ship native code for arm64-v8a only, so the store no longer offers them
to a device that runs armeabi-v7a only. Nothing in the release notes says so; the
ABIs the two files ship do.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.diff import diff
from apkradar.scanner import scan
from tests.android_files import dex_blob, manifest, write_apk, write_bundle

PKG = "org.example.reader"
LOCATION = "android.permission.ACCESS_FINE_LOCATION"
INTERNET = "android.permission.INTERNET"
CAMERA = "android.permission.CAMERA"


# ─── Which ABIs a file ships ──────────────────────────────────────────────────


def test_an_apk_ships_the_abis_its_lib_directory_names(tmp_path):
    path = write_apk(tmp_path / "app.apk", manifest(PKG), native=("armeabi-v7a", "arm64-v8a"))
    assert scan(path).native_abis == ["arm64-v8a", "armeabi-v7a"]


def test_an_apk_without_native_code_ships_no_abi(tmp_path):
    path = write_apk(tmp_path / "app.apk", manifest(PKG))
    assert scan(path).native_abis == []


def test_an_apkm_ships_the_abis_of_its_splits(tmp_path):
    """APKMirror's bundles carry native code in split_config.<abi>.apk, not in the
    base APK. A density split is not an ABI."""
    base = write_apk(tmp_path / "base.apk", manifest(PKG))
    bundle = write_bundle(
        tmp_path / "app.apkm", base, ("arm64_v8a", "armeabi_v7a", "xxhdpi", "it"), package=PKG
    )
    assert scan(bundle).native_abis == ["arm64-v8a", "armeabi-v7a"]


def test_an_xapk_ships_the_abis_of_its_splits(tmp_path):
    base = write_apk(tmp_path / "base.apk", manifest(PKG))
    bundle = write_bundle(tmp_path / "app.xapk", base, ("x86_64", "xhdpi"), package=PKG, kind="xapk")
    assert scan(bundle).native_abis == ["x86_64"]


def test_a_bundle_adds_the_abis_its_base_apk_ships(tmp_path):
    base = write_apk(tmp_path / "base.apk", manifest(PKG), native=("x86",))
    bundle = write_bundle(tmp_path / "app.apkm", base, ("arm64_v8a",), package=PKG)
    assert scan(bundle).native_abis == ["arm64-v8a", "x86"]


def test_only_the_abi_directories_android_installs_from_count(tmp_path):
    """lib/ can hold anything a build put there; the package manager loads native
    code from the ABI directories only."""
    path = write_apk(tmp_path / "app.apk", manifest(PKG), native=("arm64-v8a", "notanabi"))
    assert scan(path).native_abis == ["arm64-v8a"]


# ─── The comparison ───────────────────────────────────────────────────────────


def _pair(tmp_path, old: dict, new: dict, *, old_dex=None, new_dex=None, old_abi=(), new_abi=()):
    old_path = write_apk(tmp_path / "old.apk", manifest(PKG, **old), dex=old_dex, native=old_abi)
    new_path = write_apk(tmp_path / "new.apk", manifest(PKG, **new), dex=new_dex, native=new_abi)
    return scan(old_path), scan(new_path)


def test_the_version_and_the_sdk_levels_are_compared(tmp_path):
    old, new = _pair(
        tmp_path,
        {"version_code": 100, "version_name": "24.8.1", "min_sdk": 24, "target_sdk": 34},
        {"version_code": 200, "version_name": "24.9.0", "min_sdk": 28, "target_sdk": 35},
    )
    d = diff(old, new)
    assert d.same_package
    assert (d.version_name, d.version_code) == (("24.8.1", "24.9.0"), ("100", "200"))
    assert d.min_sdk == ("24", "28")
    assert d.target_sdk == ("34", "35")


def test_permissions_added_and_removed_keep_their_sensitivity(tmp_path):
    old, new = _pair(
        tmp_path,
        {"permissions": (INTERNET, CAMERA)},
        {"permissions": (INTERNET, LOCATION)},
    )
    d = diff(old, new)
    assert [(p.permission, p.gdpr_relevant) for p in d.permissions_added] == [(LOCATION, True)]
    assert [p.permission for p in d.permissions_removed] == [CAMERA]


def test_a_tracker_that_appears_is_reported_with_its_transfer(tmp_path):
    old, new = _pair(
        tmp_path, {}, {},
        old_dex=dex_blob(classes=[f"{PKG}.Main"]),
        new_dex=dex_blob(classes=[f"{PKG}.Main", "com.appsflyer.AppsFlyerLib"]),
    )
    d = diff(old, new)
    assert d.trackers_added == ["AppsFlyer"]
    assert d.trackers_removed == []
    assert d.transfers_added == ["AppsFlyer Ltd. (USA/Israel)"]
    assert d.score[0] is not None and d.score[1] is not None
    assert d.score[1] < d.score[0]


def test_an_abi_that_disappears_is_a_device_the_new_release_leaves_behind(tmp_path):
    """The Acrobat case: arm64-v8a stays, armeabi-v7a goes."""
    old, new = _pair(tmp_path, {}, {}, old_abi=("armeabi-v7a", "arm64-v8a"), new_abi=("arm64-v8a",))
    d = diff(old, new)
    assert d.abis_removed == ["armeabi-v7a"]
    assert d.abis_added == []
    assert d.abis_left_behind == ["armeabi-v7a"]


def test_dropping_all_native_code_leaves_no_device_behind(tmp_path):
    """Without native code the app runs on any ABI: the ABIs are gone, no device is."""
    old, new = _pair(tmp_path, {}, {}, old_abi=("armeabi-v7a", "arm64-v8a"), new_abi=())
    d = diff(old, new)
    assert d.abis_removed == ["arm64-v8a", "armeabi-v7a"]
    assert d.abis_left_behind == []


def test_hosts_in_the_manifest_and_in_the_code_are_compared(tmp_path):
    old, new = _pair(
        tmp_path,
        {"hosts": ("old.example.org",)},
        {"hosts": ("new.example.org",)},
        # Real vendor hosts: reserved names (example.org) are references to the
        # scanner, not servers. Neither is contacted: the DEX is only read.
        old_dex=dex_blob(urls=["https://app-measurement.com/a"]),
        new_dex=dex_blob(urls=["https://app-measurement.com/a", "https://googleads.g.doubleclick.net/mads/gma"]),
    )
    d = diff(old, new)
    assert d.domains_added == ["new.example.org"]
    assert d.domains_removed == ["old.example.org"]
    assert d.hosts_added == ["googleads.g.doubleclick.net"]
    assert d.hosts_removed == []


def test_two_different_apps_are_not_two_releases(tmp_path):
    old = scan(write_apk(tmp_path / "a.apk", manifest("org.example.one")))
    new = scan(write_apk(tmp_path / "b.apk", manifest("org.example.two")))
    assert not diff(old, new).same_package


def test_two_identical_releases_differ_in_nothing(tmp_path):
    old, new = _pair(tmp_path, {"permissions": (INTERNET,)}, {"permissions": (INTERNET,)})
    assert not diff(old, new).has_changes


def test_the_json_form_holds_every_finding(tmp_path):
    old, new = _pair(
        tmp_path,
        {"version_name": "1.0", "permissions": (CAMERA,)},
        {"version_name": "2.0", "permissions": (LOCATION,)},
        old_abi=("armeabi-v7a", "arm64-v8a"),
        new_abi=("arm64-v8a",),
    )
    data = diff(old, new).to_dict()
    assert data["package"] == PKG
    assert data["version_name"] == {"old": "1.0", "new": "2.0"}
    assert data["permissions"]["added"] == [{"permission": LOCATION, "sensitive": True}]
    assert data["permissions"]["removed"] == [{"permission": CAMERA, "sensitive": True}]
    assert data["native_abis"] == {
        "old": ["arm64-v8a", "armeabi-v7a"],
        "new": ["arm64-v8a"],
        "added": [],
        "removed": ["armeabi-v7a"],
        "left_behind": ["armeabi-v7a"],
    }
    json.dumps(data)  # serialisable as it stands


# ─── The command ──────────────────────────────────────────────────────────────


@pytest.fixture
def acrobat_like(tmp_path):
    old = write_apk(
        tmp_path / "old.apk",
        manifest(PKG, version_name="24.8.1", permissions=(INTERNET,)),
        native=("armeabi-v7a", "arm64-v8a"),
    )
    new = write_apk(
        tmp_path / "new.apk",
        manifest(PKG, version_name="24.9.0", min_sdk=28, permissions=(INTERNET, LOCATION)),
        native=("arm64-v8a",),
    )
    return old, new


def test_the_command_prints_what_changed(acrobat_like):
    old, new = acrobat_like
    result = CliRunner().invoke(app, ["diff", old, new])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "24.8.1 → 24.9.0" in out
    assert "24 → 28" in out
    assert LOCATION in out
    assert "armeabi-v7a" in out
    assert "no longer offered" in out


def test_the_command_prints_json_alone_with_json(acrobat_like):
    old, new = acrobat_like
    result = CliRunner().invoke(app, ["diff", old, new, "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["native_abis"]["left_behind"] == ["armeabi-v7a"]


def test_the_command_fails_when_a_file_cannot_be_read(tmp_path, acrobat_like):
    old, _ = acrobat_like
    result = CliRunner().invoke(app, ["diff", old, str(tmp_path / "missing.apk")])
    assert result.exit_code == 1


def test_the_command_warns_when_the_packages_differ(tmp_path):
    a = write_apk(tmp_path / "a.apk", manifest("org.example.one"))
    b = write_apk(tmp_path / "b.apk", manifest("org.example.two"))
    result = CliRunner().invoke(app, ["diff", a, b])
    assert result.exit_code == 0, result.output
    assert "different packages" in result.output
