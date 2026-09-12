"""Tests for APKRadar utils module."""
import unittest
from apkradar.utils import package_to_domain, domain_to_url


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


class TestDomainToUrl(unittest.TestCase):

    def test_plain_domain(self):
        self.assertEqual(domain_to_url("scopely.com"), "https://scopely.com")

    def test_already_https(self):
        self.assertEqual(domain_to_url("https://scopely.com"), "https://scopely.com")

    def test_already_http(self):
        self.assertEqual(domain_to_url("http://scopely.com"), "http://scopely.com")


if __name__ == "__main__":
    unittest.main()
