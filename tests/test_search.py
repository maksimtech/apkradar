"""Tests for APKRadar search command."""
import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from apkradar.cli import app
from apkradar.search_cmd import AppInfo


def _make_app_info(available=True):
    return AppInfo(
        package_name="com.moonactive.coinmaster",
        title="Coin Master",
        developer="Moon Active",
        score=4.5,
        installs="100.000.000+",
        category="Games",
        description="Spin the slot machine",
        available=available,
        removal_reason=None if available else "Removed for policy violation",
    )


class TestSearchCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_search_help(self):
        result = self.runner.invoke(app, ["search", "--help"])
        self.assertEqual(result.exit_code, 0)

    @patch("apkradar.search_cmd.lookup")
    def test_search_package_found(self, mock_lookup):
        mock_lookup.return_value = _make_app_info(available=True)
        result = self.runner.invoke(app, ["search", "com.moonactive.coinmaster"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Coin Master", result.output)

    @patch("apkradar.search_cmd.lookup")
    def test_search_package_not_found(self, mock_lookup):
        mock_lookup.return_value = _make_app_info(available=False)
        result = self.runner.invoke(app, ["search", "com.removed.app"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("not found", result.output.lower())

    def test_search_by_name_shows_hint(self):
        result = self.runner.invoke(app, ["search", "Coin Master"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("play.google.com", result.output)


class TestLookup(unittest.TestCase):

    def test_lookup_available(self):
        from apkradar.search_cmd import lookup
        with patch("google_play_scraper.app") as mock_app:
            mock_app.return_value = {
                "title": "Coin Master",
                "developer": "Moon Active",
                "score": 4.5,
                "installs": "100.000.000+",
                "genre": "Games",
                "description": "Spin the slot machine",
            }
            result = lookup("com.moonactive.coinmaster")
            self.assertTrue(result.available)
            self.assertEqual(result.title, "Coin Master")

    def test_lookup_not_found(self):
        from apkradar.search_cmd import lookup
        with patch("google_play_scraper.app", side_effect=Exception("Not found")):
            with patch("apkradar.search_cmd._search_removal_reason", return_value=None):
                result = lookup("com.nonexistent.app")
                self.assertFalse(result.available)

    def test_search_removal_reason_exception(self):
        from apkradar.search_cmd import _search_removal_reason
        with patch("httpx.get", side_effect=Exception("timeout")):
            result = _search_removal_reason("com.removed.app")
            self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
