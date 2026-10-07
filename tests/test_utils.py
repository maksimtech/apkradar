"""Tests for APKRadar utils module."""
import unittest

import pytest

from apkradar.utils import GENERIC_SEGMENTS, domain_to_url, package_to_domain


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

    def test_package_to_domain_never_returns_an_underscore_hostname(self):
        """The generic branch turned `_` into `-` and the main one did not:
        com.my_company.app gave my_company.com, which is not a hostname and
        still went on to MailRadar, the certificate check and CookieRadar."""
        self.assertEqual(package_to_domain("com.my_company.app"), "my-company.com")


class TestDomainToUrl(unittest.TestCase):

    def test_plain_domain(self):
        self.assertEqual(domain_to_url("scopely.com"), "https://scopely.com")

    def test_already_https(self):
        self.assertEqual(domain_to_url("https://scopely.com"), "https://scopely.com")

    def test_already_http(self):
        self.assertEqual(domain_to_url("http://scopely.com"), "http://scopely.com")

    def test_domain_to_url_adds_the_scheme_to_hosts_starting_with_http(self):
        """`startswith("http")` took a domain such as httpbin.org for a URL."""
        self.assertEqual(domain_to_url("httpbin.org"), "https://httpbin.org")


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


class TestExtractDomainsFromApk(unittest.TestCase):
    """Tests for extract_domains_from_apk function."""

    def test_extract_domains_exception_returns_empty(self):
        """Should return empty list on any exception."""
        from apkradar.utils import extract_domains_from_apk
        mock_apk = None  # will raise AttributeError
        result = extract_domains_from_apk(mock_apk)
        self.assertEqual(result, [])

    def test_extract_domains_from_a_real_manifest(self):
        """Should extract domains from manifest XML."""
        from apkradar.utils import extract_domains_from_apk

        result = extract_domains_from_apk(_real_apk(
            "www.example.com", "api.example.com", "localhost", "*.wildcard.com",
        ))
        self.assertIn("www.example.com", result)
        self.assertIn("api.example.com", result)
        self.assertNotIn("localhost", result)
        self.assertNotIn("*.wildcard.com", result)

    def test_extract_domains_skips_ip(self):
        """Should skip IP addresses."""
        from apkradar.utils import extract_domains_from_apk

        result = extract_domains_from_apk(_real_apk("192.168.1.1", "127.0.0.1"))
        self.assertEqual(result, [])

    def test_extract_domains_skips_placeholders(self):
        """Should skip template placeholders."""
        from apkradar.utils import extract_domains_from_apk

        result = extract_domains_from_apk(_real_apk("{dynamic_host}"))
        self.assertEqual(result, [])


def _real_apk(*hosts: str):
    """androguard's APK, opened on a real APK whose manifest declares `hosts`.

    Built by tests/android_files.py: a binary manifest inside a ZIP, read by the
    real parser, so get_xml() returns what androguard 4 returns — bytes. The
    str these tests used to be handed by a mock hid that the function raised,
    and returned nothing, on every real APK.
    """
    import tempfile
    from pathlib import Path

    from androguard.core.apk import APK

    from tests.android_files import manifest, write_apk

    with tempfile.TemporaryDirectory() as root:
        return APK(write_apk(Path(root) / "app.apk", manifest("com.example.app", hosts=hosts)))


def test_extract_domains_reads_the_bytes_androguard_actually_returns():
    """androguard 4's AXMLPrinter.get_xml() returns bytes. The str pattern
    raised TypeError, the exception was swallowed, and the deep links of a
    real APK were NEVER collected: manifest_domains was always empty."""
    from apkradar.utils import extract_domains_from_apk

    apk = _real_apk("where.areu.lombardia.it")
    assert isinstance(apk.get_android_manifest_axml().get_xml(), bytes)

    assert extract_domains_from_apk(apk) == ["where.areu.lombardia.it"]


@pytest.mark.parametrize("host", ["10.0.2.2", "172.16.0.1", "evil.com\r\nX-Injected: 1", "a b.example"])
def test_extract_domains_rejects_values_that_are_not_hostnames(host):
    """Only 127.0.0.1 and 192.* were refused: private addresses (10.0.2.2 is
    the emulator's host) and values with a space or a CR/LF in them joined the
    domains to analyse — MailRadar, the certificate check, the CONNECT line
    sent to a proxy."""
    from apkradar.utils import extract_domains_from_apk

    assert extract_domains_from_apk(_real_apk(host)) == []


class TestExtractSdkDomains(unittest.TestCase):
    """Tests for extract_sdk_domains function."""

    def test_firebase_domains(self):
        from apkradar.scanner import TrackerFound
        from apkradar.utils import extract_sdk_domains
        trackers = [TrackerFound(package="com.google.firebase.analytics", name="Firebase")]
        domains = extract_sdk_domains(trackers)
        self.assertIn("firebase.google.com", domains)

    def test_facebook_domains(self):
        from apkradar.scanner import TrackerFound
        from apkradar.utils import extract_sdk_domains
        trackers = [TrackerFound(package="com.facebook.ads", name="Facebook")]
        domains = extract_sdk_domains(trackers)
        self.assertIn("facebook.com", domains)

    def test_empty_trackers(self):
        from apkradar.utils import extract_sdk_domains
        domains = extract_sdk_domains([])
        self.assertEqual(domains, [])

    def test_multiple_trackers(self):
        from apkradar.scanner import TrackerFound
        from apkradar.utils import extract_sdk_domains
        trackers = [
            TrackerFound(package="com.appsflyer", name="AppsFlyer"),
            TrackerFound(package="com.applovin", name="AppLovin"),
        ]
        domains = extract_sdk_domains(trackers)
        self.assertIn("appsflyer.com", domains)
        self.assertIn("applovin.com", domains)


class TestGetAllDomains(unittest.TestCase):
    """Tests for get_all_domains function."""

    def test_publisher_domain_included(self):
        from apkradar.scanner import ScanResult
        from apkradar.utils import get_all_domains
        result = ScanResult(apk_path="test.apk", package_name="com.scopely.monopolygo")
        domains = get_all_domains(result)
        self.assertIn("scopely.com", domains)

    def test_sdk_domains_included(self):
        from apkradar.scanner import ScanResult, TrackerFound
        from apkradar.utils import get_all_domains
        result = ScanResult(apk_path="test.apk", package_name="com.example.app")
        result.trackers = [TrackerFound(package="com.appsflyer", name="AppsFlyer")]
        domains = get_all_domains(result)
        self.assertIn("appsflyer.com", domains)

    def test_empty_package_name(self):
        from apkradar.scanner import ScanResult
        from apkradar.utils import get_all_domains
        result = ScanResult(apk_path="test.apk", package_name="")
        domains = get_all_domains(result)
        self.assertIsInstance(domains, list)


class TestGetAllDomainsWithApk(unittest.TestCase):

    def test_get_all_domains_with_manifest_apk(self):
        from unittest.mock import MagicMock

        from apkradar.scanner import ScanResult
        from apkradar.utils import get_all_domains
        result = ScanResult(apk_path="test.apk", package_name="com.example.app")
        mock_apk = MagicMock()
        mock_apk.get_android_manifest_axml.return_value.get_xml.return_value = (
            '<data android:host="api.example.com"/>'
        )
        domains = get_all_domains(result, apk=mock_apk)
        self.assertIn("example.com", domains)
        self.assertIn("api.example.com", domains)
