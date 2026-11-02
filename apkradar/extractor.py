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
            try:
                apk_path = z.extract(main_apk, tmp_dir)
            except Exception:
                # A bad CRC or a full disk: the caller gets no tmp_dir to clean
                # up, so the directory and the half-written APK go here.
                cleanup_temp(tmp_dir)
                raise
            return apk_path, tmp_dir

    except Exception:
        return None, None


# The ABI directories Android installs native code from (lib/<abi>/ in an APK).
# Anything else under lib/ is not native code the package manager would load.
KNOWN_ABIS = ("armeabi", "armeabi-v7a", "arm64-v8a", "x86", "x86_64", "mips", "mips64", "riscv64")

# A configuration split is named after its qualifier, and a split name cannot hold
# a hyphen: the split for arm64-v8a is split_config.arm64_v8a.apk (APKMirror) or
# config.arm64_v8a.apk (APKPure).
_ABI_BY_SPLIT_QUALIFIER = {abi.replace("-", "_"): abi for abi in KNOWN_ABIS}
_SPLIT_PREFIXES = ("split_config.", "config.")


def abis_in_apk(path: str) -> set[str]:
    """The ABIs an APK ships native code for: the names of its lib/<abi>/ directories.

    Read from the zip directory alone, no library is opened. An APK with no
    native code ships none, and runs on any ABI. A file that is not a zip has no
    directory to read: that is for the APK parser to report, not this.
    """
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return set()
    return {
        parts[1]
        for parts in (name.split("/") for name in names)
        if len(parts) >= 3 and parts[0] == "lib" and parts[1] in KNOWN_ABIS and parts[-1]
    }


def abis_in_splits(path: str) -> set[str]:
    """The ABIs a bundle's configuration splits are for.

    A bundle ships native code in one split per ABI, so the split names say which
    ABIs it covers; density and language splits are not ABIs and are skipped.
    """
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return set()
    found = set()
    for name in names:
        base = os.path.basename(name)
        if not base.endswith(".apk"):
            continue
        for prefix in _SPLIT_PREFIXES:
            if base.startswith(prefix):
                qualifier = base[len(prefix):-len(".apk")]
                if qualifier in _ABI_BY_SPLIT_QUALIFIER:
                    found.add(_ABI_BY_SPLIT_QUALIFIER[qualifier])
                break
    return found


def cleanup_temp(tmp_dir: str | None) -> None:
    """Remove temporary directory created during extraction."""
    if tmp_dir and os.path.exists(tmp_dir):
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
