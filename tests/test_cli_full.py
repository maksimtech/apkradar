"""Tests for APKRadar CLI --full flag with mocked dependencies."""
import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from apkradar.cli import app
from apkradar.scanner import ScanResult


def _make_scan_result(package_name="com.example.app"):
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


def _make_cookie_result():
    mock = MagicMock()
    mock.pre_consent.trackers = []
    mock.post_reject.trackers = []
    return mock


class TestAuditFullFlag(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    @patch("apkradar.scanner.scan")
    def test_full_no_package_name(self, mock_scan):
        mock_scan.return_value = ScanResult(apk_path="test.apk", package_name="")
        result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("Full stack analysis", result.output)

    @patch("asyncio.run", side_effect=Exception("no browser"))
    @patch("apkradar.cli._check_ssl", return_value=("error", None))
    @patch("apkradar.cli._check_mailradar", return_value=(None, None))
    @patch("apkradar.scanner.scan")
    def test_full_shows_publisher_domain(self, mock_scan, mock_mail, mock_ssl, mock_run):
        mock_scan.return_value = _make_scan_result("com.scopely.monopolygo")
        result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("scopely.com", result.output)

    @patch("asyncio.run", side_effect=Exception("error"))
    @patch("apkradar.cli._check_ssl", return_value=("error", None))
    @patch("apkradar.cli._check_mailradar", return_value=(None, None))
    @patch("apkradar.scanner.scan")
    def test_full_no_network(self, mock_scan, mock_mail, mock_ssl, mock_run):
        mock_scan.return_value = _make_scan_result("com.example.app")
        result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
        self.assertEqual(result.exit_code, 0)

    @patch("asyncio.run")
    @patch("apkradar.cli._check_ssl", return_value=("error", None))
    @patch("apkradar.cli._check_mailradar", return_value=(None, None))
    @patch("apkradar.scanner.scan")
    def test_full_cookieradar_no_violation(self, mock_scan, mock_mail, mock_ssl, mock_run):
        mock_scan.return_value = _make_scan_result("com.example.app")
        mock_run.return_value = _make_cookie_result()
        result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
        self.assertEqual(result.exit_code, 0)

    @patch("asyncio.run", side_effect=Exception("no browser"))
    @patch("apkradar.cli._check_ssl", return_value=("expired", None))
    @patch("apkradar.cli._check_mailradar", return_value=(20, "CRITICAL"))
    @patch("apkradar.scanner.scan")
    def test_full_ssl_expired(self, mock_scan, mock_mail, mock_ssl, mock_run):
        mock_scan.return_value = _make_scan_result("com.example.app")
        result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("EXPIRED", result.output)


if __name__ == "__main__":
    unittest.main()
