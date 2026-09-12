"""Tests for APKRadar scanner module."""
import unittest
from apkradar.scanner import (
    ScanResult,
    TrackerFound,
    PermissionFound,
    TransferFound,
    TRACKER_SIGNATURES,
    SENSITIVE_PERMISSIONS,
    EXTRA_EU_TRANSFERS,
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


class TestScanFileNotFound(unittest.TestCase):
    """Tests for scan() with missing file."""

    def test_scan_missing_file_returns_error(self):
        result = scan("/nonexistent/app.apk")
        self.assertIsNotNone(result.error)

    def test_scan_missing_file_has_path(self):
        result = scan("/nonexistent/app.apk")
        self.assertEqual(result.apk_path, "/nonexistent/app.apk")

    def test_scan_missing_file_score_100(self):
        result = scan("/nonexistent/app.apk")
        self.assertEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
