"""The advertising identifier is the one permission this tool cannot afford to miss.

SENSITIVE_PERMISSIONS held 23 entries, every one of them prefixed
`android.permission.`, and the match was exact string membership. Google Play
services permissions live under `com.google.android.gms.permission.*`, so they
could not match under any circumstances — not as an oversight about one
permission, but as a whole namespace that was invisible.

Found on 2026-09-25 against `com.gameitech.preschool.abc123.tracing.learning`
("abc 123 Tracing for Toddlers", PEGI 3, Educational, 100,000+ downloads). Its
manifest declares eight permissions, four of them advertising identifiers, and
the report said:

    Score: 75/100 — MODERATE
    No sensitive permissions

The advertising ID is an online identifier under GDPR art. 4(1) and recital 30 —
it is the mechanism by which a user is profiled on Android — and
ACCESS_ADSERVICES_TOPICS exists for interest-based advertising by name. For a
tool whose stated purpose is surfacing profiling, "no sensitive permissions" on
that manifest misses the target it set for itself.

The manifest is reproduced verbatim from the APK examined
(SHA-256 06703ff9b879c8c9886ff92c6cbd43f8a0d7471f989620e5d730d33f852b058a,
from APKPure rather than Play).
"""

from __future__ import annotations

import pytest

from apkradar.scanner import SENSITIVE_PERMISSIONS, scan

# Exactly what abc 123 Tracing v1.8 declares.
ABC123_PERMISSIONS = [
    "com.google.android.gms.permission.AD_ID",
    "android.permission.ACCESS_ADSERVICES_AD_ID",
    "android.permission.ACCESS_ADSERVICES_TOPICS",
    "android.permission.ACCESS_ADSERVICES_ATTRIBUTION",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.INTERNET",
    "android.permission.WAKE_LOCK",
]

ADVERTISING = ABC123_PERMISSIONS[:4]


class _StubAPK:
    """Stands in for androguard's APK: the scanner imports it inside scan()."""

    def __init__(self, path, permissions=None):
        self._permissions = list(permissions if permissions is not None else ABC123_PERMISSIONS)

    def get_package(self):
        return "com.gameitech.preschool.abc123.tracing.learning"

    def get_app_name(self):
        return "abc 123 Tracing for Toddlers"

    def get_androidversion_name(self):
        return "1.8"

    def get_androidversion_code(self):
        return 18

    def get_min_sdk_version(self):
        return 21

    def get_target_sdk_version(self):
        return 34

    def get_permissions(self):
        return list(self._permissions)

    # Everything the rest of the scan touches, answering "nothing here".
    def get_files(self):
        return []

    def get_dex_names(self):
        return []

    def get_all_dex(self):
        return []

    def get_activities(self):
        return []

    def get_services(self):
        return []

    def get_receivers(self):
        return []

    def get_providers(self):
        return []

    def get_signature_names(self):
        return []

    def get_certificates(self):
        return []

    def is_signed(self):
        return False

    def get_androidversion_code_int(self):
        return 18

    def get_elements(self, *args, **kwargs):
        return []

    def get_element(self, *args, **kwargs):
        return None

    def get_main_activity(self):
        return None


@pytest.fixture
def scanned(tmp_path, monkeypatch):
    """Run a real scan with androguard replaced, so no APK file is needed."""
    def run(permissions=None):
        apk = tmp_path / "abc123.apk"
        apk.write_bytes(b"PK\x03\x04not-a-real-archive")

        import androguard.core.apk as ag
        monkeypatch.setattr(
            ag, "APK", lambda path: _StubAPK(path, permissions), raising=True
        )
        return scan(str(apk))
    return run


# ── the table ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("permission", ADVERTISING)
def test_each_advertising_permission_is_recognised(permission):
    assert permission in SENSITIVE_PERMISSIONS, permission


def test_the_table_no_longer_assumes_the_android_permission_prefix():
    """A whole namespace was unreachable, not one permission.

    Play services permissions are `com.google.android.gms.permission.*`, and a
    table where every key begins `android.permission.` cannot match any of them.
    """
    assert any(
        not name.startswith("android.permission.")
        for name in SENSITIVE_PERMISSIONS
    ), "every key still carries the android.permission. prefix"


@pytest.mark.parametrize("permission", ADVERTISING)
def test_each_description_says_what_it_is_for(permission):
    """The report prints the description; "AD_ID" alone explains nothing."""
    description = SENSITIVE_PERMISSIONS[permission].lower()
    assert any(word in description for word in ("advertis", "topics", "attribution")), description


# ── the scan ────────────────────────────────────────────────────────────────


def test_the_toddler_app_no_longer_reports_no_sensitive_permissions(scanned):
    result = scanned()

    assert result.sensitive_permission_count == 4, [
        p.permission for p in result.sensitive_permissions
    ]
    found = {p.permission for p in result.sensitive_permissions}
    assert found == set(ADVERTISING)


def test_the_four_harmless_permissions_are_not_counted(scanned):
    """INTERNET and WAKE_LOCK are not sensitive; the count must not inflate."""
    result = scanned()

    assert "android.permission.INTERNET" not in {
        p.permission for p in result.sensitive_permissions
    }
    assert len(result.permissions) == len(ABC123_PERMISSIONS)


def test_the_score_falls_by_five_for_each(scanned):
    """Documented formula: 100 − 10×trackers − 5×permissions − 5×transfers.

    With no trackers and no transfers in this stub, four permissions cost 20.
    """
    with_ads = scanned()
    without = scanned(permissions=ABC123_PERMISSIONS[4:])

    assert without.score - with_ads.score == 20, (without.score, with_ads.score)


def test_an_app_that_asks_for_nothing_sensitive_still_says_so(scanned):
    """The fix must not turn every permission into a finding."""
    result = scanned(permissions=["android.permission.INTERNET"])

    assert result.sensitive_permission_count == 0


# ── a second real manifest ──────────────────────────────────────────────────
#
# Coin Master, com.moonactive.coinmaster, XAPK 3.5.2720 (versionCode 3415933)
# from APKPure, SHA-256 f13a6ebc08817a6544ad08cef02aa34fd59b6f35349157f1935c35cb525f6a73.
# All 23 permissions it declares, verbatim.
#
# The point of a second file: abc123 is a 100,000-download educational app and
# Coin Master is a 100-million-download game, and the same four advertising
# identifiers were invisible in both. Before the table was fixed this manifest
# yielded three sensitive permissions out of twenty-three.

COINMASTER_PERMISSIONS = [
    "android.permission.ACCESS_ADSERVICES_AD_ID",
    "android.permission.ACCESS_ADSERVICES_ATTRIBUTION",
    "android.permission.ACCESS_ADSERVICES_TOPICS",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.INTERNET",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "com.android.vending.BILLING",
    "com.applovin.array.apphub.permission.BIND_APPHUB_SERVICE",
    "com.google.android.c2dm.permission.RECEIVE",
    "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
    "com.google.android.gms.permission.AD_ID",
    "com.huawei.appmarket.service.commondata.permission.GET_COMMON_DATA",
    "com.moonactive.coinmaster.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
    "com.moonactive.coinmaster.permission.C2D_MESSAGE",
    "com.samsung.android.mapsagent.permission.READ_APP_INFO",
]


def test_the_coinmaster_manifest_is_the_whole_of_it():
    """A guard on the fixture itself: 23 is the number the report cites."""
    assert len(COINMASTER_PERMISSIONS) == 23


def test_every_advertising_permission_is_found_in_the_second_file(scanned):
    result = scanned(COINMASTER_PERMISSIONS)
    found = {p.permission for p in result.sensitive_permissions}

    assert set(ADVERTISING) <= found, sorted(found)


def test_the_count_for_coinmaster(scanned):
    """Three before — storage read, storage write, contacts — and seven now."""
    result = scanned(COINMASTER_PERMISSIONS)

    assert result.sensitive_permission_count == 7


def test_the_third_party_bind_permissions_are_not_claimed_as_sensitive(scanned):
    """AppLovin, Finsky, Huawei and Samsung service bindings are declared by
    this app and are not in the table. Left alone deliberately: a permission to
    talk to a store service is not an identifier, and stretching the table to
    cover them would be a judgement nobody measured."""
    result = scanned(COINMASTER_PERMISSIONS)
    found = {p.permission for p in result.sensitive_permissions}

    assert not any("BIND_" in permission for permission in found)


def test_the_clamp_is_what_a_real_game_reaches(scanned):
    """16 trackers, 7 permissions and 4 transfers come to −115. The stub has no
    trackers, so only the permission half is exercised here — the arithmetic
    itself is tested in test_score_arithmetic.py."""
    result = scanned(COINMASTER_PERMISSIONS)

    assert result.score == 100 - 7 * 5
