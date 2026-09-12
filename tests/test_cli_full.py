"""Tests for APKRadar CLI --full flag with mocked dependencies."""
import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from apkradar.cli import app
from apkradar.scanner import ScanResult


def _make_scan_result(package_name="com.example.app"):
    """Create a minimal ScanResult with package name."""
    return ScanResult(
        apk_path="test.apk",
        package_name=package_name,
        app_name="Test App",
        version_name="1.0",
        version_code="1",
        min_sdk="24",
        target_sdk="35",
        sha256="abc123" * 11,
    )


def _make_cookie_result(pre_trackers=None, post_trackers=None):
    """Create a mock CookieRadar result."""
    mock = MagicMock()
    mock.pre_consent.trackers = pre_trackers or []
    mock.post_reject.trackers = post_trackers or []
    return mock


class TestAuditFullFlag(unittest.TestCase):
    """Tests for --full flag edge cases."""

    def setUp(self):
        self.runner = CliRunner()

    @patch("apkradar.scanner.scan")
    def test_full_no_package_name(self, mock_scan):
        """--full should skip publisher analysis when package_name is empty."""
        mock_scan.return_value = ScanResult(apk_path="test.apk", package_name="")
        result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("Full stack analysis", result.output)

    @patch("apkradar.scanner.scan")
    def test_full_shows_publisher_domain(self, mock_scan):
        """--full should display the publisher domain."""
        mock_scan.return_value = _make_scan_result("com.scopely.monopolygo")
        with patch("apkradar.cli.asyncio.run", side_effect=Exception("no browser")):
            result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("scopely.com", result.output)

    @patch("apkradar.scanner.scan")
    def test_full_mailradar_exception(self, mock_scan):
        """--full should handle MailRadar exceptions gracefully."""
        mock_scan.return_value = _make_scan_result("com.example.app")
        with patch("apkradar.cli.asyncio.run", side_effect=Exception("error")):
            result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
            self.assertEqual(result.exit_code, 0)

    @patch("apkradar.scanner.scan")
    def test_full_cookieradar_no_violation(self, mock_scan):
        """--full should show no violation when no persistent trackers."""
        mock_scan.return_value = _make_scan_result("com.example.app")
        with patch("apkradar.cli.asyncio.run", return_value=_make_cookie_result()):
            result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
            self.assertEqual(result.exit_code, 0)

    @patch("apkradar.scanner.scan")
    def test_full_cookieradar_exception(self, mock_scan):
        """--full should handle CookieRadar exceptions gracefully."""
        mock_scan.return_value = _make_scan_result("com.example.app")
        with patch("apkradar.cli.asyncio.run", side_effect=Exception("Connection error")):
            result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
            self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
