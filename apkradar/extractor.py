"""
APKRadar — APK extractor.
Handles .apk, .xapk (APKPure) and .apkm (APKMirror) formats.
"""
from __future__ import annotations

import json
import os
import tempfile
import zipfile
from pathlib import Path

# The extension is only a hint: a file that lies about it falls through to the
# content check below, which is why this is a lookup and not a validation.
_FORMAT_BY_EXTENSION = {".apk": "apk", ".xapk": "xapk", ".apkm": "apkm"}


def detect_format(path: str) -> str:
    """
    Detect APK file format.

    Returns:
        'apk', 'xapk', 'apkm' or 'unknown'
    """
    ext = Path(path).suffix.lower()
    if ext in _FORMAT_BY_EXTENSION:
        return _FORMAT_BY_EXTENSION[ext]

    # Try to detect by content
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if "manifest.json" in names:
                data = json.loads(z.read("manifest.json"))
                if "xapk_version" in data:
                    return "xapk"
                return "apkm"
            if "AndroidManifest.xml" in names:
                return "apk"
    except Exception:
        pass

    return "unknown"


def extract_main_apk(path: str) -> tuple[str | None, str | None]:
    """
    Extract the main APK from a bundle format.

    Args:
        path: Path to .xapk or .apkm file

    Returns:
        Tuple of (apk_path, temp_dir) — caller must clean up temp_dir
        Returns (None, None) on failure
    """
    fmt = detect_format(path)

    if fmt == "apk":
        return path, None

    if fmt not in ("xapk", "apkm"):
        return None, None

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            apk_files = []

            # Try to get package name from manifest
            package_name = None
            if "manifest.json" in names:
                try:
                    data = json.loads(z.read("manifest.json"))
                    package_name = data.get("package_name") or data.get("pname")
                except Exception:
                    pass

            # Find main APK — not a split
            for name in names:
                if not name.endswith(".apk"):
                    continue
                basename = os.path.basename(name)
                if basename.startswith("split_"):
                    continue
                if basename.startswith("config."):
                    continue
                apk_files.append(name)

            # If package name known, prefer matching APK
            main_apk = None
            if package_name and apk_files:
                for f in apk_files:
                    if package_name in f:
                        main_apk = f
                        break

            if not main_apk and apk_files:
                main_apk = apk_files[0]

            if not main_apk:
                return None, None

            # Extract to temp dir.
            #
            # extract() returns where it actually wrote, and that is the only
            # path worth trusting: it sanitises the member name itself, so an
            # entry called "../../x.apk" or "/abs/x.apk" lands inside tmp_dir
            # all the same. Rebuilding the path with os.path.join() from the
            # raw name, as this did, produced a different path outside tmp_dir
            # — and APKRadar would then open whatever happened to be there,
            # reporting on a file the archive's author chose.
            tmp_dir = tempfile.mkdtemp(prefix="apkradar_")
            apk_path = z.extract(main_apk, tmp_dir)
            return apk_path, tmp_dir

    except Exception:
        return None, None


def cleanup_temp(tmp_dir: str | None) -> None:
    """Remove temporary directory created during extraction."""
    if tmp_dir and os.path.exists(tmp_dir):
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
