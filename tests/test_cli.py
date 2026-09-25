"""Tests for APKRadar CLI."""
import os
import tempfile
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_help(self):
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("APK compliance auditor", result.output)

    def test_audit_help(self):
        result = self.runner.invoke(app, ["audit", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_batch_help(self):
        result = self.runner.invoke(app, ["batch", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_send_help(self):
        result = self.runner.invoke(app, ["send", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_audit_missing_apk(self):
        """Exit 1, and a label that is neither a pass nor a number.

        It asserted CRITICAL. The part worth keeping is the second line — the
        output must not read as compliant — and that is now checked without
        requiring a verdict the tool never reached.
        """
        result = self.runner.invoke(app, ["audit", "nonexistent.apk"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("N/A", result.output)
        self.assertNotIn("GOOD", result.output)
        self.assertNotIn("0/100", result.output)

    def test_audit_unknown_format_exit_1(self):
        result = self.runner.invoke(app, ["audit", "notes.txt"])
        self.assertEqual(result.exit_code, 1)

    def test_audit_success_exit_0(self):
        ok = ScanResult(apk_path="test.apk", package_name="com.example.app", sha256="a" * 64)
        with patch("apkradar.scanner.scan", return_value=ok):
            result = self.runner.invoke(app, ["audit", "test.apk"])
        self.assertEqual(result.exit_code, 0)

    def test_batch_continues_after_failure_then_exit_1(self):
        ok = ScanResult(apk_path="good.apk", package_name="com.example.app")
        bad = ScanResult(apk_path="bad.apk", error="File not found: bad.apk")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("bad.apk\ngood.apk\n")
            tmp = f.name
        try:
            with patch("apkradar.scanner.scan", side_effect=[bad, ok]) as mock_scan:
                result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(mock_scan.call_count, 2)
            self.assertEqual(result.exit_code, 1)
            # Was "🔴 CRITICAL — 0/100": a file that was never opened is
            # reported as not analysed, without counters it never measured.
            # Asserted on that line alone: "0/100" is a substring of the
            # "100/100" the other APK in this same run prints.
            failed_line = next(
                line for line in result.output.splitlines() if "not analysed" in line
            )
            self.assertNotIn("/100", failed_line)
            self.assertNotIn("trackers", failed_line)
        finally:
            os.unlink(tmp)

    def test_batch_all_ok_exit_0(self):
        ok = ScanResult(apk_path="good.apk", package_name="com.example.app")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("good.apk\n")
            tmp = f.name
        try:
            with patch("apkradar.scanner.scan", return_value=ok):
                result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 0)
        finally:
            os.unlink(tmp)

    def test_batch_missing_file(self):
        result = self.runner.invoke(app, ["batch", "nonexistent.txt"])
        self.assertNotEqual(result.exit_code, 0)

    def test_batch_with_empty_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 0)
        finally:
            os.unlink(tmp)

    def test_batch_with_comments_only(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# comment\n# another comment\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 0)
        finally:
            os.unlink(tmp)

    def test_batch_with_nonexistent_apk(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("/nonexistent/app.apk\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 1)
        finally:
            os.unlink(tmp)

    def test_batch_shows_error_for_bad_apk(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("/nonexistent/bad.apk\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 1)
            self.assertIn("❌", result.output)
        finally:
            os.unlink(tmp)


class TestInit(unittest.TestCase):

    def test_version_exists(self):
        import apkradar
        self.assertTrue(hasattr(apkradar, "__version__"))
        self.assertIsInstance(apkradar.__version__, str)

    def test_version_format(self):
        import apkradar
        parts = apkradar.__version__.split(".")
        self.assertEqual(len(parts), 3)


class TestPrintResult(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_print_result_with_error(self):
        from apkradar.cli import _print_result
        result = ScanResult(apk_path="test.apk", error="Test error")
        _print_result(result)

    def test_print_result_clean(self):
        from apkradar.cli import _print_result
        result = ScanResult(
            apk_path="test.apk",
            package_name="com.example.app",
            app_name="Test App",
            version_name="1.0",
            version_code="1",
            sha256="abc123" * 11,
        )
        _print_result(result)

    def test_print_result_with_trackers(self):
        from apkradar.cli import _print_result
        result = ScanResult(apk_path="test.apk")
        result.trackers = [TrackerFound(package="com.google.firebase", name="Firebase")]
        _print_result(result)

    def test_print_result_with_sensitive_permissions(self):
        from apkradar.cli import _print_result
        result = ScanResult(apk_path="test.apk")
        result.sensitive_permissions = [
            PermissionFound(
                permission="android.permission.ACCESS_FINE_LOCATION",
                description="precise GPS location",
            )
        ]
        _print_result(result)

    def test_print_result_with_extra_eu(self):
        from apkradar.cli import _print_result
        result = ScanResult(apk_path="test.apk")
        result.extra_eu_transfers = [
            TransferFound(package_prefix="com.google", entity="Google LLC (USA)")
        ]
        _print_result(result)


class TestBatchErrorPath(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_batch_shows_error_for_bad_apk(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("/nonexistent/bad.apk\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 1)
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
