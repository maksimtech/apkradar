"""Tests for APKRadar scanner module."""
import unittest

from apkradar.scanner import (
    EXTRA_EU_TRANSFERS,
    SENSITIVE_PERMISSIONS,
    TRACKER_SIGNATURES,
    PermissionFound,
    ScanResult,
    TrackerFound,
    scan,
)


class TestScanResult(unittest.TestCase):
    """Tests for ScanResult dataclass."""

    def test_default_values(self):
        result = ScanResult(apk_path="test.apk")
        self.assertEqual(result.apk_path, "test.apk")
        self.assertEqual(result.trackers, [])
        self.assertEqual(result.permissions, [])
        self.assertEqual(result.sensitive_permissions, [])
        self.assertEqual(result.extra_eu_transfers, [])
        self.assertIsNone(result.error)

    def test_score_perfect(self):
        result = ScanResult(apk_path="test.apk")
        self.assertEqual(result.score, 100)
        self.assertEqual(result.score_label, "GOOD")

    def test_score_with_trackers(self):
        result = ScanResult(apk_path="test.apk")
        result.trackers = [
            TrackerFound(package="com.google.firebase.analytics", name="Firebase Analytics"),
            TrackerFound(package="com.facebook.appevents", name="Facebook App Events"),
        ]
        self.assertEqual(result.score, 80)
        self.assertEqual(result.score_label, "GOOD")

    def test_score_critical(self):
        result = ScanResult(apk_path="test.apk")
        result.trackers = [
            TrackerFound(package=f"com.tracker{i}", name=f"Tracker {i}")
            for i in range(10)
        ]
        self.assertEqual(result.score, 0)
        self.assertEqual(result.score_label, "CRITICAL")

    def test_score_moderate(self):
        result = ScanResult(apk_path="test.apk")
        result.trackers = [
            TrackerFound(package=f"com.tracker{i}", name=f"Tracker {i}")
            for i in range(4)
        ]
        self.assertEqual(result.score, 60)
        self.assertEqual(result.score_label, "MODERATE")

    def test_score_poor(self):
        result = ScanResult(apk_path="test.apk")
        result.trackers = [
            TrackerFound(package=f"com.tracker{i}", name=f"Tracker {i}")
            for i in range(6)
        ]
        self.assertEqual(result.score, 40)
        self.assertEqual(result.score_label, "POOR")

    def test_tracker_count(self):
        result = ScanResult(apk_path="test.apk")
        result.trackers = [
            TrackerFound(package="com.google.firebase.analytics", name="Firebase"),
            TrackerFound(package="com.facebook.appevents", name="Facebook"),
        ]
        self.assertEqual(result.tracker_count, 2)

    def test_sensitive_permission_count(self):
        result = ScanResult(apk_path="test.apk")
        result.sensitive_permissions = [
            PermissionFound(
                permission="android.permission.ACCESS_FINE_LOCATION",
                description="precise GPS location",
            )
        ]
        self.assertEqual(result.sensitive_permission_count, 1)


class TestTrackerSignatures(unittest.TestCase):
    """Tests for tracker signatures database."""

    def test_not_empty(self):
        self.assertGreater(len(TRACKER_SIGNATURES), 0)

    def test_google_analytics_present(self):
        self.assertIn("com.google.android.gms.analytics", TRACKER_SIGNATURES)

    def test_facebook_present(self):
        self.assertIn("com.facebook.appevents", TRACKER_SIGNATURES)

    def test_firebase_present(self):
        self.assertIn("com.google.firebase.analytics", TRACKER_SIGNATURES)

    def test_values_are_strings(self):
        for key, value in TRACKER_SIGNATURES.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, str)


class TestSensitivePermissions(unittest.TestCase):
    """Tests for sensitive permissions database."""

    def test_not_empty(self):
        self.assertGreater(len(SENSITIVE_PERMISSIONS), 0)

    def test_location_present(self):
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", SENSITIVE_PERMISSIONS)

    def test_camera_present(self):
        self.assertIn("android.permission.CAMERA", SENSITIVE_PERMISSIONS)

    def test_microphone_present(self):
        self.assertIn("android.permission.RECORD_AUDIO", SENSITIVE_PERMISSIONS)

    def test_contacts_present(self):
        self.assertIn("android.permission.READ_CONTACTS", SENSITIVE_PERMISSIONS)


class TestExtraEUTransfers(unittest.TestCase):
    """Tests for extra-EU transfers database."""

    def test_not_empty(self):
        self.assertGreater(len(EXTRA_EU_TRANSFERS), 0)

    def test_google_present(self):
        self.assertIn("com.google", EXTRA_EU_TRANSFERS)

    def test_facebook_present(self):
        self.assertIn("com.facebook", EXTRA_EU_TRANSFERS)

    def test_tiktok_present(self):
        self.assertIn("com.tiktok", EXTRA_EU_TRANSFERS)

    def test_chinese_companies_present(self):
        self.assertIn("com.huawei", EXTRA_EU_TRANSFERS)
        self.assertIn("com.xiaomi", EXTRA_EU_TRANSFERS)
        self.assertIn("com.baidu", EXTRA_EU_TRANSFERS)


def _scan_with_components(components):
    """Run scan() on a fake .apk whose manifest declares the given components."""
    import os
    import tempfile
    from unittest.mock import MagicMock, patch

    apk = MagicMock()
    apk.get_package.return_value = "com.example.app"
    apk.get_app_name.return_value = "Example"
    apk.get_androidversion_name.return_value = "1.0"
    apk.get_androidversion_code.return_value = "1"
    apk.get_min_sdk_version.return_value = "21"
    apk.get_target_sdk_version.return_value = "34"
    apk.get_permissions.return_value = []
    apk.get_providers.return_value = []
    apk.get_services.return_value = []
    apk.get_receivers.return_value = []
    apk.get_activities.return_value = list(components)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        f.write(b"fake")
        tmp = f.name
    try:
        with patch("androguard.core.apk.APK", return_value=apk):
            return scan(tmp)
    finally:
        os.unlink(tmp)


class TestTrackerMatching(unittest.TestCase):
    """Tests for tracker/transfer matching against declared components."""

    def _tracker_names(self, components):
        result = _scan_with_components(components)
        self.assertIsNone(result.error)
        return {t.name for t in result.trackers}

    def test_real_tracker_detected(self):
        names = self._tracker_names(["com.appsflyer.SingleInstallBroadcastReceiver"])
        self.assertEqual(names, {"AppsFlyer"})

    def test_long_signature_detected(self):
        """Signatures longer than 4 segments must still match."""
        names = self._tracker_names(["com.google.android.gms.analytics.AnalyticsService"])
        self.assertEqual(names, {"Google Analytics"})

    def test_similar_prefix_not_matched(self):
        """com.nielsenhomes must not match Nielsen."""
        names = self._tracker_names(["com.nielsenhomes.app.MainActivity"])
        self.assertNotIn("Nielsen", names)

    def test_short_component_not_matched(self):
        """com.a must not match AppsFlyer/AppLovin/Adjust/Amplitude/AdColony."""
        names = self._tracker_names(["com.a"])
        self.assertEqual(names, set())

    def test_google_play_services_not_analytics_or_ads(self):
        """GoogleApiActivity is not Google Analytics nor Google Ads."""
        names = self._tracker_names(["com.google.android.gms.common.api.GoogleApiActivity"])
        self.assertEqual(names, set())

    def test_firebase_messaging_not_analytics(self):
        names = self._tracker_names(["com.google.firebase.messaging.FirebaseMessagingService"])
        self.assertNotIn("Firebase Analytics", names)

    def test_transfer_similar_prefix_not_matched(self):
        """com.adjustable must not match Adjust transfer."""
        result = _scan_with_components(["com.adjustable.x.Main"])
        self.assertEqual(result.extra_eu_transfers, [])

    def test_transfer_detected(self):
        result = _scan_with_components(["com.facebook.ads.AudienceNetworkActivity"])
        self.assertEqual(
            [t.entity for t in result.extra_eu_transfers],
            ["Meta Platforms Inc. (USA)"],
        )


class TestScanFileNotFound(unittest.TestCase):
    """Tests for scan() with missing file."""

    def test_scan_missing_file_returns_error(self):
        result = scan("/nonexistent/app.apk")
        self.assertIsNotNone(result.error)

    def test_scan_missing_file_has_path(self):
        result = scan("/nonexistent/app.apk")
        self.assertEqual(result.apk_path, "/nonexistent/app.apk")

    def test_scan_missing_file_has_no_score(self):
        """A file that is not there was not measured, so it has no score.

        This asserted 0/CRITICAL. The intent — never look compliant — is kept
        below; what changed is that 0 is a measurement and this is not one.
        """
        result = scan("/nonexistent/app.apk")
        self.assertIsNone(result.score)
        self.assertEqual(result.score_label, "N/A")
        self.assertNotIn(result.score_label, ("GOOD", "MODERATE"))


class TestSkippedResult(unittest.TestCase):
    """A row that was never audited is neither compliant nor critical."""

    def test_skipped_label(self):
        result = ScanResult(apk_path="com.example.app", skipped=True)
        self.assertEqual(result.score_label, "SKIPPED")

    def test_skipped_is_not_good(self):
        """Without a scan there are no findings, so the raw score would be 100."""
        result = ScanResult(apk_path="com.example.app", skipped=True)
        self.assertNotEqual(result.score_label, "GOOD")

    def test_skipped_is_not_critical(self):
        result = ScanResult(apk_path="com.example.app", skipped=True)
        self.assertNotEqual(result.score_label, "CRITICAL")

    def test_an_error_is_still_not_a_skip(self):
        """Regression guard, restated: the two must stay distinguishable.

        It used to enforce that with CRITICAL against SKIPPED. Both now decline
        to give a number, so the guard is on the labels — which still differ —
        rather than on one of them being a verdict.
        """
        errored = ScanResult(apk_path="a.apk", error="boom")
        skipped = ScanResult(apk_path="a.apk", skipped=True)

        self.assertFalse(errored.skipped)
        self.assertEqual(errored.score_label, "N/A")
        self.assertEqual(skipped.score_label, "SKIPPED")
        self.assertNotEqual(errored.score_label, skipped.score_label)


class TestFailedScanScore(unittest.TestCase):
    """A failed scan must never look compliant — nor measured.

    The first half is the original requirement and still holds: no GOOD, no
    MODERATE, nothing that reads as a pass. The second is what these tests were
    missing: 0/100 is the score of the worst possible app, and a file that could
    not be opened has not earned even that. Both are asserted below.
    """

    def test_unknown_format_has_no_score(self):
        result = scan("notes.txt")
        self.assertIsNotNone(result.error)
        self.assertIsNone(result.score)
        self.assertEqual(result.score_label, "N/A")
        self.assertNotIn(result.score_label, ("GOOD", "MODERATE"))

    def test_missing_bundle_has_no_score(self):
        result = scan("/nonexistent/app.xapk")
        self.assertIsNotNone(result.error)
        self.assertIsNone(result.score)
        self.assertEqual(result.score_label, "N/A")
        self.assertNotIn(result.score_label, ("GOOD", "MODERATE"))

    def test_corrupted_apk_score_0_critical(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK\x05\x06" + b"\x00" * 18)  # empty zip, no manifest
            tmp = f.name
        try:
            result = scan(tmp)
        finally:
            os.unlink(tmp)
        self.assertIsNotNone(result.error)
        self.assertIsNone(result.score)
        self.assertEqual(result.score_label, "N/A")

    def test_an_error_overrides_findings(self):
        """An error wins over whatever was collected before it.

        Half-collected findings are not a result, so the score stays absent
        rather than being computed from them.
        """
        result = ScanResult(apk_path="test.apk", error="boom")
        self.assertIsNone(result.score)
        self.assertEqual(result.score_label, "N/A")


if __name__ == "__main__":
    unittest.main()
