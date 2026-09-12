"""Tests for APKRadar utils module."""
import unittest
from apkradar.utils import package_to_domain, domain_to_url, GENERIC_SEGMENTS


class TestPackageToDomain(unittest.TestCase):

    def test_standard_com(self):
        self.assertEqual(package_to_domain("com.scopely.monopolygo"), "scopely.com")

    def test_google(self):
        self.assertEqual(package_to_domain("com.google.android.gms"), "google.com")

    def test_io_tld(self):
        self.assertEqual(package_to_domain("io.branch.referral"), "branch.io")

    def test_me_tld(self):
        self.assertEqual(package_to_domain("me.bitwarden.vault"), "bitwarden.me")

    def test_two_parts(self):
        self.assertEqual(package_to_domain("com.example"), "example.com")

    def test_empty_string(self):
        self.assertIsNone(package_to_domain(""))

    def test_none_like(self):
        self.assertIsNone(package_to_domain("singlepart"))

    def test_facebook(self):
        self.assertEqual(package_to_domain("com.facebook.katana"), "facebook.com")

    def test_generic_game_segment(self):
        """com.game.asteroids_revenge → asteroids-revenge.com"""
        result = package_to_domain("com.game.asteroids_revenge")
        self.assertEqual(result, "asteroids-revenge.com")

    def test_generic_app_segment(self):
        """com.app.mycompany → mycompany.com"""
        result = package_to_domain("com.app.mycompany")
        self.assertEqual(result, "mycompany.com")

    def test_generic_mobile_segment(self):
        """com.mobile.mycompany → mycompany.com"""
        result = package_to_domain("com.mobile.mycompany")
        self.assertEqual(result, "mycompany.com")

    def test_generic_segment_only_two_parts(self):
        """com.game → game.com (no third part available)"""
        result = package_to_domain("com.game")
        self.assertEqual(result, "game.com")

    def test_underscore_replaced(self):
        """Underscores in app name replaced with hyphens."""
        result = package_to_domain("com.game.my_app")
        self.assertEqual(result, "my-app.com")


class TestDomainToUrl(unittest.TestCase):

    def test_plain_domain(self):
        self.assertEqual(domain_to_url("scopely.com"), "https://scopely.com")

    def test_already_https(self):
        self.assertEqual(domain_to_url("https://scopely.com"), "https://scopely.com")

    def test_already_http(self):
        self.assertEqual(domain_to_url("http://scopely.com"), "http://scopely.com")


class TestGenericSegments(unittest.TestCase):

    def test_game_is_generic(self):
        self.assertIn("game", GENERIC_SEGMENTS)

    def test_app_is_generic(self):
        self.assertIn("app", GENERIC_SEGMENTS)

    def test_google_not_generic(self):
        self.assertNotIn("google", GENERIC_SEGMENTS)

    def test_facebook_not_generic(self):
        self.assertNotIn("facebook", GENERIC_SEGMENTS)


if __name__ == "__main__":
    unittest.main()
