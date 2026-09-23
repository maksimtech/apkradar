"""Tests for APKRadar extractor module."""
import os
import tempfile
import unittest
import zipfile
import json
from apkradar.extractor import detect_format, extract_main_apk, cleanup_temp


def _make_zip(path: str, files: dict) -> None:
    """Create a ZIP file with given files dict {name: content}."""
    with zipfile.ZipFile(path, 'w') as z:
        for name, content in files.items():
            if isinstance(content, str):
                content = content.encode()
            z.writestr(name, content)


class TestDetectFormat(unittest.TestCase):
    """Tests for detect_format function."""

    def test_apk_extension(self):
        self.assertEqual(detect_format("app.apk"), "apk")

    def test_xapk_extension(self):
        self.assertEqual(detect_format("app.xapk"), "xapk")

    def test_apkm_extension(self):
        self.assertEqual(detect_format("app.apkm"), "apkm")

    def test_uppercase_extension(self):
        self.assertEqual(detect_format("app.APK"), "apk")

    def test_unknown_extension(self):
        self.assertEqual(detect_format("app.ipa"), "unknown")

    def test_xapk_by_content(self):
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            tmp = f.name
        try:
            _make_zip(tmp, {
                "manifest.json": json.dumps({"xapk_version": 2}),
                "com.example.app.apk": b"PK\x03\x04",
            })
            self.assertEqual(detect_format(tmp), "xapk")
        finally:
            os.unlink(tmp)

    def test_apk_by_content(self):
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            tmp = f.name
        try:
            _make_zip(tmp, {
                "AndroidManifest.xml": b"<manifest/>",
            })
            self.assertEqual(detect_format(tmp), "apk")
        finally:
            os.unlink(tmp)


class TestExtractMainApk(unittest.TestCase):
    """Tests for extract_main_apk function."""

    def test_apk_returns_same_path(self):
        apk_path, tmp_dir = extract_main_apk("app.apk")
        self.assertEqual(apk_path, "app.apk")
        self.assertIsNone(tmp_dir)

    def test_unknown_format_returns_none(self):
        apk_path, tmp_dir = extract_main_apk("app.ipa")
        self.assertIsNone(apk_path)
        self.assertIsNone(tmp_dir)

    def test_xapk_extracts_main_apk(self):
        with tempfile.NamedTemporaryFile(suffix='.xapk', delete=False) as f:
            tmp_xapk = f.name
        try:
            _make_zip(tmp_xapk, {
                "manifest.json": json.dumps({
                    "xapk_version": 2,
                    "package_name": "com.example.app",
                }),
                "com.example.app.apk": b"PK\x03\x04",
                "split_config.arm64_v8a.apk": b"PK\x03\x04",
            })
            apk_path, tmp_dir = extract_main_apk(tmp_xapk)
            self.assertIsNotNone(apk_path)
            self.assertIsNotNone(tmp_dir)
            self.assertTrue(apk_path.endswith(".apk"))
            cleanup_temp(tmp_dir)
        finally:
            os.unlink(tmp_xapk)

    def test_empty_xapk_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix='.xapk', delete=False) as f:
            tmp_xapk = f.name
        try:
            _make_zip(tmp_xapk, {
                "manifest.json": json.dumps({"xapk_version": 2}),
            })
            apk_path, tmp_dir = extract_main_apk(tmp_xapk)
            self.assertIsNone(apk_path)
            self.assertIsNone(tmp_dir)
        finally:
            os.unlink(tmp_xapk)


class TestCleanupTemp(unittest.TestCase):
    """Tests for cleanup_temp function."""

    def test_cleanup_removes_dir(self):
        tmp = tempfile.mkdtemp()
        self.assertTrue(os.path.exists(tmp))
        cleanup_temp(tmp)
        self.assertFalse(os.path.exists(tmp))

    def test_cleanup_none_does_not_raise(self):
        cleanup_temp(None)

    def test_cleanup_nonexistent_does_not_raise(self):
        cleanup_temp("/nonexistent/path/that/does/not/exist")


if __name__ == "__main__":
    unittest.main()


class TestDetectFormatApkm(unittest.TestCase):
    """Tests for APKM detection by content."""

    def test_apkm_by_content(self):
        """ZIP with manifest.json without xapk_version → apkm."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            tmp = f.name
        try:
            _make_zip(tmp, {
                "manifest.json": json.dumps({"pname": "com.example.app"}),
                "com.example.app.apk": b"PK\x03\x04",
            })
            self.assertEqual(detect_format(tmp), "apkm")
        finally:
            os.unlink(tmp)

    def test_detect_format_invalid_zip_returns_unknown(self):
        """Non-ZIP file with no extension match → unknown."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b"not a zip file")
            tmp = f.name
        try:
            self.assertEqual(detect_format(tmp), "unknown")
        finally:
            os.unlink(tmp)


class TestExtractMainApkEdgeCases(unittest.TestCase):
    """Edge case tests for extract_main_apk."""

    def test_xapk_with_config_apk_skipped(self):
        """config.* APKs should be skipped."""
        with tempfile.NamedTemporaryFile(suffix='.xapk', delete=False) as f:
            tmp_xapk = f.name
        try:
            _make_zip(tmp_xapk, {
                "manifest.json": json.dumps({
                    "xapk_version": 2,
                    "package_name": "com.example.app",
                }),
                "com.example.app.apk": b"PK\x03\x04",
                "config.arm64_v8a.apk": b"PK\x03\x04",
            })
            apk_path, tmp_dir = extract_main_apk(tmp_xapk)
            self.assertIsNotNone(apk_path)
            self.assertNotIn("config", apk_path)
            cleanup_temp(tmp_dir)
        finally:
            os.unlink(tmp_xapk)

    def test_xapk_invalid_manifest_json(self):
        """Invalid manifest JSON should not crash."""
        with tempfile.NamedTemporaryFile(suffix='.xapk', delete=False) as f:
            tmp_xapk = f.name
        try:
            _make_zip(tmp_xapk, {
                "manifest.json": b"not valid json{{{",
                "com.example.app.apk": b"PK\x03\x04",
            })
            apk_path, tmp_dir = extract_main_apk(tmp_xapk)
            self.assertIsNotNone(apk_path)
            cleanup_temp(tmp_dir)
        finally:
            os.unlink(tmp_xapk)

    def test_xapk_package_name_matches_apk(self):
        """APK matching package_name should be preferred."""
        with tempfile.NamedTemporaryFile(suffix='.xapk', delete=False) as f:
            tmp_xapk = f.name
        try:
            _make_zip(tmp_xapk, {
                "manifest.json": json.dumps({
                    "xapk_version": 2,
                    "package_name": "com.scopely.monopolygo",
                }),
                "com.scopely.monopolygo.apk": b"PK\x03\x04",
                "base.apk": b"PK\x03\x04",
            })
            apk_path, tmp_dir = extract_main_apk(tmp_xapk)
            self.assertIsNotNone(apk_path)
            self.assertIn("monopolygo", apk_path)
            cleanup_temp(tmp_dir)
        finally:
            os.unlink(tmp_xapk)

    def test_extract_invalid_zip_returns_none(self):
        """Invalid ZIP file should return (None, None)."""
        with tempfile.NamedTemporaryFile(suffix='.xapk', delete=False) as f:
            f.write(b"not a zip file")
            tmp = f.name
        try:
            apk_path, tmp_dir = extract_main_apk(tmp)
            self.assertIsNone(apk_path)
            self.assertIsNone(tmp_dir)
        finally:
            os.unlink(tmp)


class TestExtractHostileNames(unittest.TestCase):
    """The path returned must be the file that was actually written.

    Snyk Code flags the extraction as "Arbitrary File Write via Archive
    Extraction". That title is wrong: ZipFile.extract() sanitises the member
    name itself and never writes outside the directory it is given — verified
    against both cases below.

    The line after it did not. It rebuilt the path with os.path.join() from the
    raw name out of the archive, so for a hostile name it pointed somewhere
    else entirely, outside the temporary directory. The risk is not writing but
    reading: a crafted XAPK could make APKRadar open and report on an unrelated
    file chosen by whoever built the archive.
    """

    def _extract_named(self, member: str):
        with tempfile.NamedTemporaryFile(suffix='.xapk', delete=False) as f:
            archive = f.name
        _make_zip(archive, {
            "manifest.json": json.dumps({"package_name": "com.example.app"}),
            member: b"PK\x03\x04fake-apk",
        })
        try:
            return extract_main_apk(archive)
        finally:
            os.unlink(archive)

    def _assert_path_is_real(self, apk_path, tmp_dir, member):
        self.assertIsNotNone(apk_path, f"no path returned for {member!r}")
        self.assertIsNotNone(tmp_dir)
        try:
            real = os.path.realpath(apk_path)
            root = os.path.realpath(tmp_dir)
            self.assertTrue(
                os.path.exists(apk_path),
                f"returned path does not exist for {member!r}: {apk_path}",
            )
            self.assertEqual(
                os.path.commonpath([real, root]), root,
                f"returned path escapes the temp directory for {member!r}: {apk_path}",
            )
        finally:
            cleanup_temp(tmp_dir)

    def test_parent_directory_traversal_in_member_name(self):
        """../../escaped.apk — extract() keeps it in; the returned path must too."""
        member = "../../escaped.apk"
        apk_path, tmp_dir = self._extract_named(member)
        self._assert_path_is_real(apk_path, tmp_dir, member)

    def test_absolute_member_name(self):
        """/abs/rooted.apk — os.path.join would discard tmp_dir entirely."""
        member = "/abs/rooted.apk"
        apk_path, tmp_dir = self._extract_named(member)
        self._assert_path_is_real(apk_path, tmp_dir, member)

    def test_an_ordinary_name_still_works(self):
        """The guard must not cost the normal case."""
        member = "com.example.app.apk"
        apk_path, tmp_dir = self._extract_named(member)
        self._assert_path_is_real(apk_path, tmp_dir, member)
        self.assertTrue(apk_path.endswith("com.example.app.apk"))
