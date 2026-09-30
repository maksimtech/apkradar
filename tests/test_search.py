"""Tests for APKRadar search command.

The lookup used to answer three different questions with one sentence, "App not
found on Google Play": the store has no such listing, the store did not answer,
and google-play-scraper is not installed. Then it fetched a web abstract and
printed it as the reason — for whichever of the three had happened.

The store asked was never named either. `google_play_scraper.app` defaults to
`country="us"`, so an app published for Europe only was reported as not found
from a shop it had never been in.
"""
import unittest
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.search_cmd import LISTED, NOT_LISTED, UNKNOWN, AppInfo


def _make_app_info(status=LISTED, **extra):
    return AppInfo(
        package_name="com.moonactive.coinmaster",
        title="Coin Master",
        developer="Moon Active",
        score=4.5,
        installs="100.000.000+",
        category="Games",
        description="Spin the slot machine",
        status=status,
        **extra,
    )


class TestSearchCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_search_help(self):
        result = self.runner.invoke(app, ["search", "--help"])
        self.assertEqual(result.exit_code, 0)

    @patch("apkradar.search_cmd.lookup")
    def test_search_package_found(self, mock_lookup):
        mock_lookup.return_value = _make_app_info()
        result = self.runner.invoke(app, ["search", "com.moonactive.coinmaster"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Coin Master", result.output)

    @patch("apkradar.search_cmd.lookup")
    def test_a_store_with_no_listing_says_which_store(self, mock_lookup):
        mock_lookup.return_value = _make_app_info(
            NOT_LISTED, country="us", removal_hint="Removed for policy violation"
        )
        result = self.runner.invoke(app, ["search", "com.removed.app"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("not listed", result.output.lower())
        self.assertIn("us", result.output.lower())
        self.assertIn("unverified", result.output.lower())
        self.assertIn("Removed for policy violation", result.output)

    @patch("apkradar.search_cmd.lookup")
    def test_a_store_that_did_not_answer_is_not_an_app_that_is_gone(self, mock_lookup):
        """The distinction the command exists to keep.

        A timeout is not a removal, and the output must not read like one.
        """
        mock_lookup.return_value = _make_app_info(UNKNOWN, error="ReadTimeout: too slow")
        result = self.runner.invoke(app, ["search", "com.working.app"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("could not tell", result.output.lower())
        self.assertIn("ReadTimeout: too slow", result.output)
        self.assertNotIn("not listed", result.output.lower())
        self.assertNotIn("removed", result.output.lower())

    @patch("apkradar.search_cmd.lookup")
    def test_the_country_asked_for_is_the_country_used(self, mock_lookup):
        mock_lookup.return_value = _make_app_info(NOT_LISTED, country="it", lang="it")
        result = self.runner.invoke(app, ["search", "com.x.y", "--country", "it", "--lang", "it"])

        self.assertEqual(mock_lookup.call_args.kwargs, {"lang": "it", "country": "it"})
        self.assertIn("it", result.output.lower())

    def test_search_by_name_shows_hint(self):
        result = self.runner.invoke(app, ["search", "Coin Master"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("play.google.com", result.output)


class TestLookup(unittest.TestCase):

    def test_a_listing_is_a_listing(self):
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
        self.assertEqual(result.status, LISTED)
        self.assertEqual(result.title, "Coin Master")

    def test_the_locale_is_passed_on_and_recorded(self):
        """Which store answered is part of the answer, and it used to be
        neither asked for nor written down."""
        from apkradar.search_cmd import lookup
        with patch("google_play_scraper.app") as mock_app:
            mock_app.return_value = {"title": "T"}
            result = lookup("com.x.y", lang="it", country="it")

        self.assertEqual(mock_app.call_args.kwargs, {"lang": "it", "country": "it"})
        self.assertEqual((result.lang, result.country), ("it", "it"))

    def test_the_store_saying_no_is_not_listed(self):
        from google_play_scraper.exceptions import NotFoundError

        from apkradar.search_cmd import lookup
        with (
            patch("google_play_scraper.app", side_effect=NotFoundError("App not found(404).")),
            patch("apkradar.search_cmd._web_abstract", return_value=None) as abstract,
        ):
            result = lookup("com.nonexistent.app")

        self.assertEqual(result.status, NOT_LISTED)
        self.assertFalse(result.available)
        self.assertTrue(result.not_listed)
        abstract.assert_called_once()

    def test_a_network_failure_is_not_a_missing_app(self):
        """The defect, pinned. This returned `available=False` with a "removal
        reason" attached, and the app was on sale the whole time."""
        from apkradar.search_cmd import lookup
        with (
            patch("google_play_scraper.app", side_effect=TimeoutError("timed out")),
            patch("apkradar.search_cmd._web_abstract") as abstract,
        ):
            result = lookup("com.working.app")

        self.assertEqual(result.status, UNKNOWN)
        self.assertTrue(result.undetermined)
        self.assertFalse(result.not_listed)
        self.assertIn("TimeoutError", result.error)
        self.assertIsNone(result.removal_hint)
        abstract.assert_not_called()      # no hint about a state nobody established

    def test_a_missing_scraper_is_not_a_missing_app(self):
        from apkradar.search_cmd import lookup
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

        def no_scraper(name, *args, **kwargs):
            if name.startswith("google_play_scraper"):
                raise ImportError("No module named 'google_play_scraper'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_scraper):
            result = lookup("com.any.app")

        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("google-play-scraper unavailable", result.error)


class TestWebAbstract(unittest.TestCase):
    """What DuckDuckGo says about a package name, which is not a cause.

    The query is "<package> removed banned Google Play Store", so the answer is
    about that query: a namesake, the vendor, Play policy in general. It is
    printed as an unverified hint for exactly that reason.
    """

    def test_an_abstract_comes_back_as_a_hint(self):
        from apkradar.search_cmd import _web_abstract
        mock_response = MagicMock()
        mock_response.json.return_value = {"AbstractText": "App was removed for violating policies."}
        with patch("httpx.get", return_value=mock_response):
            result = _web_abstract("com.removed.app")

        self.assertIsNotNone(result)
        self.assertIn("removed", result.lower())

    def test_no_abstract_is_no_hint(self):
        from apkradar.search_cmd import _web_abstract
        mock_response = MagicMock()
        mock_response.json.return_value = {"AbstractText": ""}
        with patch("httpx.get", return_value=mock_response):
            self.assertIsNone(_web_abstract("com.removed.app"))

    def test_a_failed_search_is_no_hint(self):
        from apkradar.search_cmd import _web_abstract
        with patch("httpx.get", side_effect=Exception("timeout")):
            self.assertIsNone(_web_abstract("com.removed.app"))


if __name__ == "__main__":
    unittest.main()
