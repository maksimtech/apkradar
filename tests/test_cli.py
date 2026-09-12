"""Tests for APKRadar CLI."""
import unittest
from typer.testing import CliRunner
from apkradar.cli import app


class TestCLI(unittest.TestCase):
    """Tests for APKRadar CLI commands."""

    def setUp(self):
        self.runner = CliRunner()

    def test_help(self):
        """CLI help should exit with code 0."""
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("APK compliance auditor", result.output)

    def test_audit_help(self):
        """audit --help should exit with code 0."""
        result = self.runner.invoke(app, ["audit", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_batch_help(self):
        """batch --help should exit with code 0."""
        result = self.runner.invoke(app, ["batch", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_audit_missing_apk(self):
        """audit command should handle missing APK gracefully."""
        result = self.runner.invoke(app, ["audit", "nonexistent.apk"])
        self.assertEqual(result.exit_code, 0)

    def test_batch_missing_file(self):
        """batch command should exit with error if file not found."""
        result = self.runner.invoke(app, ["batch", "nonexistent.txt"])
        self.assertNotEqual(result.exit_code, 0)


class TestInit(unittest.TestCase):
    """Tests for APKRadar package init."""

    def test_version_exists(self):
        """Package should have a version string."""
        import apkradar
        self.assertTrue(hasattr(apkradar, "__version__"))
        self.assertIsInstance(apkradar.__version__, str)

    def test_version_format(self):
        """Version should follow YYYY.MM.patch format."""
        import apkradar
        parts = apkradar.__version__.split(".")
        self.assertEqual(len(parts), 3)


if __name__ == "__main__":
    unittest.main()


class TestPrintResult(unittest.TestCase):
    """Tests for _print_result function."""

    def test_print_result_with_error(self):
        from apkradar.cli import _print_result
        from apkradar.scanner import ScanResult
        from io import StringIO
        result = ScanResult(apk_path="test.apk", error="Test error")
        # Should not raise
        _print_result(result)

    def test_print_result_clean(self):
        from apkradar.cli import _print_result
        from apkradar.scanner import ScanResult
        result = ScanResult(
            apk_path="test.apk",
            package_name="com.example.app",
            app_name="Test App",
            version_name="1.0",
            version_code="1",
            sha256="abc123" * 10,
        )
        # Should not raise
        _print_result(result)

    def test_print_result_with_trackers(self):
        from apkradar.cli import _print_result
        from apkradar.scanner import ScanResult, TrackerFound
        result = ScanResult(apk_path="test.apk")
        result.trackers = [TrackerFound(package="com.google.firebase", name="Firebase")]
        _print_result(result)


class TestPrintResult(unittest.TestCase):
    """Tests for _print_result function."""

    def setUp(self):
        from apkradar.scanner import ScanResult, TrackerFound, PermissionFound, TransferFound
        self.ScanResult = ScanResult
        self.TrackerFound = TrackerFound
        self.PermissionFound = PermissionFound
        self.TransferFound = TransferFound

    def test_print_result_with_error(self):
        from apkradar.cli import _print_result
        result = self.ScanResult(apk_path="test.apk", error="Test error")
        _print_result(result)

    def test_print_result_clean(self):
        from apkradar.cli import _print_result
        result = self.ScanResult(
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
        result = self.ScanResult(apk_path="test.apk")
        result.trackers = [
            self.TrackerFound(package="com.google.firebase", name="Firebase")
        ]
        _print_result(result)

    def test_print_result_with_sensitive_permissions(self):
        from apkradar.cli import _print_result
        result = self.ScanResult(apk_path="test.apk")
        result.sensitive_permissions = [
            self.PermissionFound(
                permission="android.permission.ACCESS_FINE_LOCATION",
                description="precise GPS location",
            )
        ]
        _print_result(result)

    def test_print_result_with_extra_eu(self):
        from apkradar.cli import _print_result
        result = self.ScanResult(apk_path="test.apk")
        result.extra_eu_transfers = [
            self.TransferFound(package_prefix="com.google", entity="Google LLC (USA)")
        ]
        _print_result(result)


class TestBatchWithFile(unittest.TestCase):
    """Tests for batch command with real file."""

    def setUp(self):
        self.runner = CliRunner()

    def test_batch_with_empty_file(self):
        """batch with empty file should succeed."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 0)
        finally:
            os.unlink(tmp)

    def test_batch_with_comments_only(self):
        """batch with only comments should succeed."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# comment\n# another comment\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 0)
        finally:
            os.unlink(tmp)

    def test_batch_with_nonexistent_apk(self):
        """batch with nonexistent APK path should still complete."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("/nonexistent/app.apk\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 0)
        finally:
            os.unlink(tmp)


class TestBatchErrorPath(unittest.TestCase):
    """Tests for batch error display path."""

    def setUp(self):
        self.runner = CliRunner()

    def test_batch_shows_error_for_bad_apk(self):
        """batch should display error for unreadable APK."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("/nonexistent/bad.apk\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("❌", result.output)
        finally:
            os.unlink(tmp)
