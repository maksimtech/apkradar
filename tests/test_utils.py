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


class TestExtractDomainsFromApk(unittest.TestCase):
    """Tests for extract_domains_from_apk function."""

    def test_extract_domains_exception_returns_empty(self):
        """Should return empty list on any exception."""
        from apkradar.utils import extract_domains_from_apk
        mock_apk = None  # will raise AttributeError
        result = extract_domains_from_apk(mock_apk)
        self.assertEqual(result, [])

    def test_extract_domains_with_mock(self):
        """Should extract domains from manifest XML."""
        from unittest.mock import MagicMock
        from apkradar.utils import extract_domains_from_apk

        mock_apk = MagicMock()
        mock_apk.get_android_manifest_axml.return_value.get_xml.return_value = (
            '<manifest>'
            '<data android:scheme="https" android:host="www.example.com"/>'
            '<data android:scheme="https" android:host="api.example.com"/>'
            '<data android:scheme="https" android:host="localhost"/>'
            '<data android:scheme="https" android:host="*.wildcard.com"/>'
            '</manifest>'
        )
        result = extract_domains_from_apk(mock_apk)
        self.assertIn("www.example.com", result)
        self.assertIn("api.example.com", result)
        self.assertNotIn("localhost", result)
        self.assertNotIn("*.wildcard.com", result)

    def test_extract_domains_skips_ip(self):
        """Should skip IP addresses."""
        from unittest.mock import MagicMock
        from apkradar.utils import extract_domains_from_apk

        mock_apk = MagicMock()
        mock_apk.get_android_manifest_axml.return_value.get_xml.return_value = (
            '<data android:host="192.168.1.1"/>'
            '<data android:host="127.0.0.1"/>'
        )
        result = extract_domains_from_apk(mock_apk)
        self.assertEqual(result, [])

    def test_extract_domains_skips_placeholders(self):
        """Should skip template placeholders."""
        from unittest.mock import MagicMock
        from apkradar.utils import extract_domains_from_apk

        mock_apk = MagicMock()
        mock_apk.get_android_manifest_axml.return_value.get_xml.return_value = (
            '<data android:host="{dynamic_host}"/>'
        )
        result = extract_domains_from_apk(mock_apk)
        self.assertEqual(result, [])


class TestExtractSdkDomains(unittest.TestCase):
    """Tests for extract_sdk_domains function."""

    def test_firebase_domains(self):
        from apkradar.utils import extract_sdk_domains
        from apkradar.scanner import TrackerFound
        trackers = [TrackerFound(package="com.google.firebase.analytics", name="Firebase")]
        domains = extract_sdk_domains(trackers)
        self.assertIn("firebase.google.com", domains)

    def test_facebook_domains(self):
        from apkradar.utils import extract_sdk_domains
        from apkradar.scanner import TrackerFound
        trackers = [TrackerFound(package="com.facebook.ads", name="Facebook")]
        domains = extract_sdk_domains(trackers)
        self.assertIn("facebook.com", domains)

    def test_empty_trackers(self):
        from apkradar.utils import extract_sdk_domains
        domains = extract_sdk_domains([])
        self.assertEqual(domains, [])

    def test_multiple_trackers(self):
        from apkradar.utils import extract_sdk_domains
        from apkradar.scanner import TrackerFound
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
        from apkradar.utils import get_all_domains
        from apkradar.scanner import ScanResult
        result = ScanResult(apk_path="test.apk", package_name="com.scopely.monopolygo")
        domains = get_all_domains(result)
        self.assertIn("scopely.com", domains)

    def test_sdk_domains_included(self):
        from apkradar.utils import get_all_domains
        from apkradar.scanner import ScanResult, TrackerFound
        result = ScanResult(apk_path="test.apk", package_name="com.example.app")
        result.trackers = [TrackerFound(package="com.appsflyer", name="AppsFlyer")]
        domains = get_all_domains(result)
        self.assertIn("appsflyer.com", domains)

    def test_empty_package_name(self):
        from apkradar.utils import get_all_domains
        from apkradar.scanner import ScanResult
        result = ScanResult(apk_path="test.apk", package_name="")
        domains = get_all_domains(result)
        self.assertIsInstance(domains, list)


class TestGetAllDomainsWithApk(unittest.TestCase):

    def test_get_all_domains_with_manifest_apk(self):
        from apkradar.utils import get_all_domains
        from apkradar.scanner import ScanResult
        from unittest.mock import MagicMock
        result = ScanResult(apk_path="test.apk", package_name="com.example.app")
        mock_apk = MagicMock()
        mock_apk.get_android_manifest_axml.return_value.get_xml.return_value = (
            '<data android:host="api.example.com"/>'
        )
        domains = get_all_domains(result, apk=mock_apk)
        self.assertIn("example.com", domains)
        self.assertIn("api.example.com", domains)
