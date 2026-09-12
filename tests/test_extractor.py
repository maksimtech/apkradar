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
