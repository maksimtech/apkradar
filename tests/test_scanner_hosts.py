"""
Tests for the hosts an APK carries in its DEX string literals.

The feature exists because of a measurement: auditing Breezy Weather 6.2.2 on
2026-10-02, the manifest declared one deep link and the package name guessed one
domain, while the DEX held 161 hosts — AccuWeather, NOAA, JMA, Baidu, Xiaomi
among them. The same report said "no extra-EU transfers", correctly, because that
check reads SDK packages and those providers ship no SDK.

Two things are therefore asserted harder than the extraction itself. That a host
in the code is reported as carried and not as contacted, and that it changes no
score — an app offering fifty weather providers carries fifty endpoints and talks
to the one configured, so scoring them would penalise choice. And that a URL cut
by a chunk boundary is never reported as its own prefix: `api.exam` out of
`api.example.com` passes every hostname rule there is, and a false endpoint in
this list ends up in a letter to a DPO.
"""
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from apkradar import hosts as hosts_mod
from apkradar.hosts import MAX_HOSTS, hosts_in_dex, is_reference, vendor_of
from apkradar.scanner import scan


def _dex_blob(urls=(), padding=0, filler=b"\x00"):
    """A fake .dex holding URL strings the way a DEX stores string data."""
    body = b"".join(b"\x00" + u.encode() + b"\x00" for u in urls)
    return b"dex\n035\x00" + filler * padding + body


def _make_apk(dex_files=None, extra=None):
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fd:
        path = fd.name
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fake binary manifest")
        for name, blob in (dex_files or {}).items():
            z.writestr(name, blob)
        for name, blob in (extra or {}).items():
            z.writestr(name, blob)
    return path


def _scan(path):
    """Run scan() with androguard mocked: the DEX is what matters here."""
    apk = MagicMock()
    apk.get_package.return_value = "com.example.app"
    apk.get_app_name.return_value = "Example"
    apk.get_androidversion_name.return_value = "1.0"
    apk.get_androidversion_code.return_value = "1"
    apk.get_min_sdk_version.return_value = "24"
    apk.get_target_sdk_version.return_value = "34"
    apk.get_permissions.return_value = []
    apk.get_providers.return_value = []
    apk.get_services.return_value = []
    apk.get_receivers.return_value = []
    apk.get_activities.return_value = []
    with patch("androguard.core.apk.APK", return_value=apk):
        return scan(path)


class HostExtractionTestCase(unittest.TestCase):

    def _hosts(self, urls, **kw):
        path = _make_apk({"classes.dex": _dex_blob(urls, **kw)})
        try:
            return hosts_in_dex(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_https_and_http_both_count(self):
        found, _ = self._hosts(["https://api.example.com/v1", "http://plain.example.org/x"])
        self.assertEqual(found, ["api.example.com", "plain.example.org"])

    def test_the_path_and_query_are_not_part_of_the_host(self):
        found, _ = self._hosts(["https://api.example.com/v1/forecast?lat=1&lon=2"])
        self.assertEqual(found, ["api.example.com"])

    def test_a_port_is_not_part_of_the_host(self):
        found, _ = self._hosts(["https://api.example.com:8443/v1"])
        self.assertEqual(found, ["api.example.com"])

    def test_the_result_is_sorted_and_deduplicated(self):
        found, _ = self._hosts([
            "https://z.example.com/", "https://a.example.com/", "https://z.example.com/other",
        ])
        self.assertEqual(found, ["a.example.com", "z.example.com"])

    def test_a_host_is_lowercased(self):
        """Two spellings of one host would otherwise be two findings."""
        found, _ = self._hosts(["https://API.Example.COM/v1", "https://api.example.com/v2"])
        self.assertEqual(found, ["api.example.com"])

    def test_trailing_punctuation_is_stripped(self):
        found, _ = self._hosts(["https://api.example.com."])
        self.assertEqual(found, ["api.example.com"])


class NotAHostTestCase(unittest.TestCase):
    """A DEX is full of URL-shaped strings that are not URLs."""

    def _hosts(self, urls):
        path = _make_apk({"classes.dex": _dex_blob(urls)})
        try:
            return hosts_in_dex(path)[0]
        finally:
            Path(path).unlink(missing_ok=True)

    def test_a_format_string_is_not_a_host(self):
        self.assertEqual(self._hosts(["https://%s/api/v1", "https://%1$s.example/x"]), [])

    def test_a_template_placeholder_is_not_a_host(self):
        self.assertEqual(self._hosts(["https://{host}/api", "https://${BASE}/x"]), [])

    def test_a_single_label_is_not_a_host(self):
        """`https://localhost/` and `https://api/` name nothing auditable."""
        self.assertEqual(self._hosts(["https://localhost/x", "https://api/v1"]), [])

    def test_a_numeric_tld_is_refused(self):
        """Which is how an IPv4 literal is excluded — see `_valid_host`."""
        self.assertEqual(self._hosts(["https://192.168.1.1/x", "https://10.0.0.1/"]), [])

    def test_a_label_may_not_begin_or_end_with_a_hyphen(self):
        self.assertEqual(self._hosts(["https://-bad.example.com/", "https://bad-.example.com/"]), [])

    def test_a_label_longer_than_sixty_three_characters_is_refused(self):
        self.assertEqual(self._hosts([f"https://{'a' * 64}.example.com/"]), [])

    def test_a_label_of_exactly_sixty_three_characters_is_accepted(self):
        self.assertEqual(self._hosts([f"https://{'a' * 63}.example.com/"]), [f"{'a' * 63}.example.com"])

    def test_a_host_longer_than_the_dns_limit_is_refused(self):
        long_host = ".".join(["abcdefghij"] * 25) + ".com"   # 279 characters
        self.assertGreater(len(long_host), 253)
        self.assertEqual(self._hosts([f"https://{long_host}/"]), [])

    def test_a_scheme_other_than_http_is_ignored(self):
        """`content://`, `file://` and `jdbc:` are not endpoints."""
        self.assertEqual(self._hosts(["content://com.example.provider/items", "file://etc/hosts"]), [])


class ChunkBoundaryTestCase(unittest.TestCase):
    """The failure mode that would put invented hostnames in a report.

    `DEX_CHUNK_SIZE` is patched small rather than building a 4 MB fixture: the
    rule under test is about a match touching the end of a buffer, and which
    buffer that is makes no difference to it.
    """

    def _hosts(self, blob, chunk):
        path = _make_apk({"classes.dex": blob})
        try:
            with patch.object(hosts_mod, "DEX_CHUNK_SIZE", chunk):
                return hosts_in_dex(path)[0]
        finally:
            Path(path).unlink(missing_ok=True)

    def test_a_url_split_across_chunks_is_read_whole(self):
        blob = _dex_blob(["https://api.example.com/v1"], padding=100, filler=b"x")
        # A chunk boundary inside "example": the first buffer ends mid-host.
        found = self._hosts(blob, 120)
        self.assertEqual(found, ["api.example.com"])

    def test_the_prefix_of_a_split_url_is_not_reported(self):
        """`api.exam` is a valid hostname by every rule, and never existed."""
        blob = _dex_blob(["https://api.example.com/v1"], padding=100, filler=b"x")
        for chunk in range(100, 135):
            with self.subTest(chunk=chunk):
                found = self._hosts(blob, chunk)
                self.assertEqual(found, ["api.example.com"])

    def test_a_url_at_the_very_end_of_a_dex_is_not_lost(self):
        """The last buffer has no successor to defer to, so it must be read."""
        blob = b"dex\n035\x00" + b"x" * 50 + b"https://tail.example.com"
        for chunk in (16, 32, 64, 4096):
            with self.subTest(chunk=chunk):
                self.assertEqual(self._hosts(blob, chunk), ["tail.example.com"])


class SeveralDexFilesTestCase(unittest.TestCase):

    def test_every_dex_is_read(self):
        path = _make_apk({
            "classes.dex": _dex_blob(["https://one.example.com/"]),
            "classes2.dex": _dex_blob(["https://two.example.com/"]),
            "classes3.dex": _dex_blob(["https://three.example.com/"]),
        })
        try:
            found, _ = hosts_in_dex(path)
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertEqual(found, ["one.example.com", "three.example.com", "two.example.com"])

    def test_a_non_dex_entry_is_not_read(self):
        """Resources and assets hold URLs too, and this finding is about code."""
        path = _make_apk(
            {"classes.dex": _dex_blob(["https://code.example.com/"])},
            extra={"assets/config.json": b'{"url": "https://asset.example.com/"}'},
        )
        try:
            found, _ = hosts_in_dex(path)
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertEqual(found, ["code.example.com"])


class BoundsTestCase(unittest.TestCase):

    def test_the_list_is_capped_and_says_so(self):
        urls = [f"https://h{n:05d}.example.com/" for n in range(MAX_HOSTS + 50)]
        path = _make_apk({"classes.dex": _dex_blob(urls)})
        try:
            with patch.object(hosts_mod, "DEX_CHUNK_SIZE", 1024):
                found, truncated = hosts_in_dex(path)
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertTrue(truncated)
        self.assertLessEqual(len(found), MAX_HOSTS)

    def test_nothing_is_truncated_when_the_list_fits(self):
        path = _make_apk({"classes.dex": _dex_blob(["https://one.example.com/"])})
        try:
            found, truncated = hosts_in_dex(path)
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertFalse(truncated)
        self.assertEqual(found, ["one.example.com"])


class UnreadableTestCase(unittest.TestCase):
    """A host list is an addition to a report; no scan fails over it."""

    def test_a_missing_file_yields_nothing(self):
        self.assertEqual(hosts_in_dex("does-not-exist.apk"), ([], False))

    def test_a_file_that_is_not_a_zip_yields_nothing(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fd:
            fd.write(b"not a zip at all")
            path = fd.name
        try:
            self.assertEqual(hosts_in_dex(path), ([], False))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_an_apk_without_dex_yields_nothing(self):
        path = _make_apk()
        try:
            self.assertEqual(hosts_in_dex(path), ([], False))
        finally:
            Path(path).unlink(missing_ok=True)


class ClassificationTestCase(unittest.TestCase):

    def test_a_specification_host_is_a_reference(self):
        for host in ("www.w3.org", "www.opengis.net", "schemas.android.com", "creativecommons.org"):
            with self.subTest(host=host):
                self.assertTrue(is_reference(host))

    def test_an_endpoint_is_not_a_reference(self):
        for host in ("api.met.no", "api.github.com", "dataservice.accuweather.com"):
            with self.subTest(host=host):
                self.assertFalse(is_reference(host))

    def test_a_lookalike_domain_is_not_a_reference(self):
        """Suffix matching has to be segment-aware, or `notw3.org` passes."""
        self.assertFalse(is_reference("notw3.org"))
        self.assertFalse(is_reference("w3.org.example.com"))

    def test_a_known_vendor_is_named(self):
        self.assertEqual(vendor_of("weatherapi.intl.xiaomi.com"), "Xiaomi Corporation (China)")
        self.assertEqual(vendor_of("api.map.baidu.com"), "Baidu Inc. (China)")
        self.assertEqual(vendor_of("googleapis.com"), "Google LLC (USA)")

    def test_an_unknown_host_has_no_vendor(self):
        self.assertIsNone(vendor_of("api.met.no"))

    def test_a_lookalike_vendor_domain_is_not_matched(self):
        self.assertIsNone(vendor_of("notbaidu.com"))
        self.assertIsNone(vendor_of("baidu.com.evil.example"))


class ScanIntegrationTestCase(unittest.TestCase):

    def setUp(self):
        self.path = _make_apk({"classes.dex": _dex_blob([
            "https://api.met.no/weatherapi",
            "https://weatherapi.intl.xiaomi.com/wtr-v3",
            "https://www.w3.org/2001/XMLSchema",
        ])})
        self.result = _scan(self.path)

    def tearDown(self):
        Path(self.path).unlink(missing_ok=True)

    def test_the_scan_collects_the_hosts(self):
        self.assertEqual(
            self.result.dex_hosts,
            ["api.met.no", "weatherapi.intl.xiaomi.com", "www.w3.org"],
        )

    def test_endpoints_exclude_the_references(self):
        self.assertEqual(
            [f.host for f in self.result.dex_endpoints],
            ["api.met.no", "weatherapi.intl.xiaomi.com"],
        )
        self.assertEqual(self.result.dex_references, ["www.w3.org"])

    def test_a_vendor_host_is_singled_out(self):
        [found] = self.result.dex_vendor_hosts
        self.assertEqual(found.host, "weatherapi.intl.xiaomi.com")
        self.assertEqual(found.entity, "Xiaomi Corporation (China)")

    def test_an_endpoint_with_no_known_vendor_carries_no_entity(self):
        [met] = [f for f in self.result.dex_endpoints if f.host == "api.met.no"]
        self.assertEqual(met.entity, "")

    def test_the_hosts_do_not_change_the_score(self):
        """The contract that keeps this finding honest.

        Three endpoints, one of them Xiaomi's, and no tracker or permission: a
        host the code can reach is not a transfer, and only a runtime observation
        could make it one. 100 with nothing deducted, as before the feature.
        """
        self.assertEqual(self.result.score, 100)
        self.assertEqual(self.result.score_deductions, [])
        self.assertEqual(self.result.extra_eu_transfers, [])

    def test_the_hosts_are_not_added_to_the_audited_domains(self):
        """`--full` runs MailRadar and CookieRadar on every domain it is given.

        157 endpoints would be 157 of each, about servers the app may never
        contact. The host list is reported, not audited — and if that ever
        changes it must be a decision, not a drift.
        """
        from apkradar.utils import get_all_domains

        audited = get_all_domains(self.result)
        self.assertNotIn("api.met.no", audited)
        self.assertNotIn("weatherapi.intl.xiaomi.com", audited)


if __name__ == "__main__":
    unittest.main()
