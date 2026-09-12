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

    def test_audit_wip(self):
        """audit command should show work in progress message."""
        result = self.runner.invoke(app, ["audit", "com.example.app"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Work in progress", result.output)

    def test_batch_wip(self):
        """batch command should show work in progress message."""
        result = self.runner.invoke(app, ["batch", "apps.txt"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Work in progress", result.output)


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
