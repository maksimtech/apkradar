"""
Tests for DEX-based SDK detection.

Fixtures in tests/fixtures/sdk_fixtures.json were generated from the official
SDK artifacts (see the _source field there): manifest component names come from
each AAR's AndroidManifest.xml, class names from its classes.jar. Several SDKs
declare no manifest component at all, so they can only be found in the DEX.
"""
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from apkradar.scanner import _packages_in_dex, scan

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "sdk_fixtures.json").read_text(encoding="utf-8"))["sdks"]


def _dex_blob(classes, padding=0):
    """A fake .dex holding class descriptors the way a real DEX stores them."""
    body = b"".join(b"L" + c.replace(".", "/").encode() + b";\x00" for c in classes)
    return b"dex\n035\x00" + b"\x00" * padding + body


def _make_apk(dex_files=None):
    """Write a temp .apk (zip) containing the given {name: dex bytes}."""
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fd:
        path = fd.name
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fake binary manifest")
        for name, blob in (dex_files or {}).items():
            z.writestr(name, blob)
    return path


def _scan(path, components=()):
    """Run scan() with androguard mocked to return the given components."""
    apk = MagicMock()
    apk.get_package.return_value = "com.example.app"
    apk.get_app_name.return_value = "Example"
    apk.get_androidversion_name.return_value = "1.0"
    apk.get_androidversion_code.return_value = "1"
    apk.get_min_sdk_version.return_value = "24"
    apk.get_target_sdk_version.return_value = "34"
    apk.get_permissions.return_value = []
    apk.get_providers.return_value = [c for c in components if "Provider" in c]
    apk.get_services.return_value = [c for c in components if "Service" in c]
    apk.get_receivers.return_value = [c for c in components if "Receiver" in c]
    apk.get_activities.return_value = [
        c for c in components if not any(k in c for k in ("Provider", "Service", "Receiver"))
    ]
    with patch("androguard.core.apk.APK", return_value=apk):
        return scan(path)


class DexScanTestCase(unittest.TestCase):

    def scan_app(self, components=(), dex_classes=(), extra_dex=None, padding=0):
        files = {}
        if dex_classes:
            files["classes.dex"] = _dex_blob(dex_classes, padding=padding)
        if extra_dex:
            files["classes2.dex"] = _dex_blob(extra_dex)
        path = _make_apk(files)
        self.addCleanup(os.unlink, path)
        result = _scan(path, components)
        self.assertIsNone(result.error)
        return result

    @staticmethod
    def names(result):
        return [t.name for t in result.trackers]


class TestSdkWithoutManifestComponents(DexScanTestCase):
    """SDKs that declare no component can only be detected in the DEX."""

    def test_appsflyer_declares_no_components(self):
        """Guard: the fixture must keep matching the real AppsFlyer artifact."""
        self.assertEqual(FIXTURES["appsflyer"]["manifest_components"], [])

    def test_appsflyer_detected_from_dex(self):
        result = self.scan_app(dex_classes=FIXTURES["appsflyer"]["classes"])
        self.assertIn("AppsFlyer", self.names(result))

    def test_appsflyer_not_detected_without_dex(self):
        """Control: same app, no DEX → nothing to match."""
        result = self.scan_app()
        self.assertEqual(self.names(result), [])

    def test_firebase_analytics_detected_from_dex(self):
        result = self.scan_app(
            components=FIXTURES["firebase_common"]["manifest_components"],
            dex_classes=FIXTURES["firebase_analytics"]["classes"],
        )
        self.assertIn("Firebase Analytics", self.names(result))

    def test_facebook_app_events_detected_from_dex(self):
        result = self.scan_app(
            components=FIXTURES["facebook_appevents"]["manifest_components"],
            dex_classes=FIXTURES["facebook_appevents"]["classes"],
        )
        self.assertIn("Facebook App Events", self.names(result))


class TestMeasurementSignature(DexScanTestCase):
    """com.google.android.gms.measurement is what Firebase Analytics declares."""

    def test_detected_from_manifest_components_only(self):
        result = self.scan_app(components=FIXTURES["firebase_measurement"]["manifest_components"])
        self.assertIn("Firebase Analytics", self.names(result))

    def test_detected_from_dex_only(self):
        result = self.scan_app(dex_classes=FIXTURES["firebase_measurement"]["classes"])
        self.assertIn("Firebase Analytics", self.names(result))

    def test_reported_once_when_found_twice(self):
        """measurement + firebase.analytics are the same SDK → one entry."""
        result = self.scan_app(
            components=FIXTURES["firebase_measurement"]["manifest_components"],
            dex_classes=FIXTURES["firebase_analytics"]["classes"]
            + FIXTURES["firebase_measurement"]["classes"],
        )
        self.assertEqual(self.names(result).count("Firebase Analytics"), 1)


class TestFirebaseCrashlytics(DexScanTestCase):
    """Firebase Crashlytics lives under com.google.firebase.crashlytics."""

    def test_detected_from_dex(self):
        result = self.scan_app(
            components=FIXTURES["crashlytics"]["manifest_components"],
            dex_classes=FIXTURES["crashlytics"]["classes"],
        )
        self.assertIn("Crashlytics", self.names(result))

    def test_not_detected_from_shared_firebase_component(self):
        """Control: ComponentDiscoveryService ships with every Firebase library."""
        result = self.scan_app(components=FIXTURES["crashlytics"]["manifest_components"])
        self.assertNotIn("Crashlytics", self.names(result))

    def test_reported_once_with_legacy_fabric_package(self):
        """com.crashlytics (Fabric) + com.google.firebase.crashlytics → one entry."""
        result = self.scan_app(
            dex_classes=FIXTURES["crashlytics"]["classes"]
            + ["com.crashlytics.android.Crashlytics"],
        )
        self.assertEqual(self.names(result).count("Crashlytics"), 1)
        self.assertEqual(result.score, 100 - 10 - 5)  # one tracker, Google transfer

    def test_google_transfer_from_crashlytics(self):
        result = self.scan_app(dex_classes=FIXTURES["crashlytics"]["classes"])
        self.assertIn("Google LLC (USA)", [t.entity for t in result.extra_eu_transfers])


class TestDexFalsePositives(DexScanTestCase):

    def test_unrelated_google_libraries_are_not_trackers(self):
        """Material, Gson and AndroidX are Google code but not tracking SDKs."""
        result = self.scan_app(dex_classes=[
            "com.google.android.material.button.MaterialButton",
            "com.google.gson.Gson",
            "com.google.common.collect.ImmutableList",
            "androidx.appcompat.app.AppCompatActivity",
            "kotlin.jvm.internal.Intrinsics",
        ])
        self.assertEqual(self.names(result), [])
        self.assertEqual(result.extra_eu_transfers, [])

    def test_similar_prefix_not_matched(self):
        result = self.scan_app(dex_classes=[
            "com.nielsenhomes.app.MainActivity",
            "com.adjustable.widget.Slider",
            "com.appsflyerish.Fake",
        ])
        self.assertEqual(self.names(result), [])

    def test_admob_still_detected_from_manifest(self):
        """Regression guard for the manifest path."""
        result = self.scan_app(components=FIXTURES["admob"]["manifest_components"])
        self.assertIn("Google Ads", self.names(result))


class TestDexTransfers(DexScanTestCase):

    def test_transfer_derived_from_dex_tracker(self):
        result = self.scan_app(dex_classes=FIXTURES["appsflyer"]["classes"])
        self.assertIn("AppsFlyer Ltd. (USA/Israel)", [t.entity for t in result.extra_eu_transfers])

    def test_google_transfer_from_firebase_analytics(self):
        result = self.scan_app(dex_classes=FIXTURES["firebase_analytics"]["classes"])
        self.assertIn("Google LLC (USA)", [t.entity for t in result.extra_eu_transfers])

    def test_transfer_listed_once(self):
        result = self.scan_app(
            components=FIXTURES["firebase_measurement"]["manifest_components"],
            dex_classes=FIXTURES["firebase_analytics"]["classes"],
        )
        entities = [t.entity for t in result.extra_eu_transfers]
        self.assertEqual(entities.count("Google LLC (USA)"), 1)


class TestDexScanRobustness(DexScanTestCase):

    def test_multiple_dex_files_all_scanned(self):
        result = self.scan_app(
            dex_classes=FIXTURES["appsflyer"]["classes"],
            extra_dex=FIXTURES["facebook_appevents"]["classes"],
        )
        self.assertIn("AppsFlyer", self.names(result))
        self.assertIn("Facebook App Events", self.names(result))

    def test_match_across_chunk_boundary(self):
        """A large DEX is read in chunks; a match on a boundary must be found."""
        result = self.scan_app(dex_classes=FIXTURES["appsflyer"]["classes"], padding=4 * 1024 * 1024 - 12)
        self.assertIn("AppsFlyer", self.names(result))

    def test_apk_that_is_not_a_zip_does_not_break_scan(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"not a zip at all")
            path = f.name
        self.addCleanup(os.unlink, path)
        result = _scan(path, components=FIXTURES["admob"]["manifest_components"])
        self.assertIsNone(result.error)
        self.assertIn("Google Ads", self.names(result))

    def test_apk_without_dex(self):
        result = self.scan_app(components=FIXTURES["admob"]["manifest_components"])
        self.assertEqual(self.names(result), ["Google Ads"])


class TestPackagesInDexHelper(unittest.TestCase):
    """The DEX search should not do more work than needed."""

    def test_nothing_to_look_for_reads_nothing(self):
        """With no packages left to find, the APK is never opened."""
        self.assertEqual(_packages_in_dex("/nonexistent/app.apk", set()), set())

    def test_stops_reading_once_everything_is_found(self):
        path = _make_apk({
            "classes.dex": _dex_blob(FIXTURES["appsflyer"]["classes"]),
            "classes2.dex": _dex_blob(FIXTURES["facebook_appevents"]["classes"]),
        })
        self.addCleanup(os.unlink, path)

        opened = []
        real_open = zipfile.ZipFile.open

        def spy(self, name, *args, **kwargs):
            opened.append(name)
            return real_open(self, name, *args, **kwargs)

        with patch.object(zipfile.ZipFile, "open", spy):
            found = _packages_in_dex(path, {"com.appsflyer"})

        self.assertEqual(found, {"com.appsflyer"})
        self.assertEqual(opened, ["classes.dex"], "classes2.dex should not be read")


if __name__ == "__main__":
    unittest.main()
