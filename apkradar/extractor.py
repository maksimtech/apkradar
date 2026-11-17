"""
APKRadar — APK extractor.
Handles .apk, .xapk (APKPure) and .apkm (APKMirror) formats.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import zipfile
from pathlib import Path

# What the base APK of a bundle may unpack to. The largest seen is Outlook's base,
# 175 MB; the real ones measured (Outlook, Candy Crush, Fitbit, at deflate level 9)
# compress at most about 4:1, being zips themselves. A member past either limit is a
# zip bomb, not an APK: 1 MiB of zeros deflated unpacks to 1 GiB. The ratio counts
# only past MIN_RATIO_CHECKED, so a tiny member that compresses well is left alone.
MAX_MEMBER_BYTES = 1 << 30
MAX_RATIO = 100
MIN_RATIO_CHECKED = 1 << 20
_COPY_CHUNK = 1 << 20

# The name the extracted APK takes in the temporary folder: the member's own, when
# it is a plain file name, so no path or device name out of the archive reaches open().
_PLAIN_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")


class BundleMemberRefused(ValueError):
    """The base APK of a bundle would unpack to more than any real APK does."""


def _check_member(info: zipfile.ZipInfo) -> None:
    size, packed = info.file_size, info.compress_size
    if size > MAX_MEMBER_BYTES:
        raise BundleMemberRefused(
            f"refused to extract {info.filename!r} from the bundle: it unpacks to {size} bytes, "
            f"over the {MAX_MEMBER_BYTES}-byte limit"
        )
    if size > MIN_RATIO_CHECKED and size > MAX_RATIO * packed:
        raise BundleMemberRefused(
            f"refused to extract {info.filename!r} from the bundle: it unpacks to {size} bytes from "
            f"{packed}, more than {MAX_RATIO} times its size (a zip bomb, not an APK)"
        )


def _extract_bounded(z: zipfile.ZipFile, info: zipfile.ZipInfo, directory: str) -> str:
    """Write `info` into `directory`, never more bytes than it declares nor than the limit."""
    base = os.path.basename(info.filename.replace("\\", "/"))
    target = os.path.join(directory, base if _PLAIN_NAME.fullmatch(base) else "base.apk")
    limit = min(info.file_size, MAX_MEMBER_BYTES)
    written = 0
    with z.open(info) as source, open(target, "wb") as out:
        while chunk := source.read(_COPY_CHUNK):
            written += len(chunk)
            if written > limit:
                raise BundleMemberRefused(
                    f"refused to extract {info.filename!r} from the bundle: it unpacks to more than "
                    f"the {limit} bytes it declares"
                )
            out.write(chunk)
    return target


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


def _declared_base(data: object) -> str | None:
    """The member an XAPK's manifest.json names as the base APK, if it names one.

    APKPure lists every APK of the bundle under `split_apks`, the base with
    `"id": "base"`: `[{"file": "com.example.apk", "id": "base"},
    {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"}]`.
    """
    splits = data.get("split_apks") if isinstance(data, dict) else None
    if not isinstance(splits, list):
        return None
    for entry in splits:
        if isinstance(entry, dict) and entry.get("id") == "base" and isinstance(entry.get("file"), str):
            return entry["file"]
    return None


def _choose_base(names: list[str], data: object) -> str | None:
    """Which member of a bundle is the base APK, the one that is the app.

    In order: the one manifest.json names; `<package>.apk` (APKPure's name for
    it) and `base.apk` (APKMirror's); then a guess among the members that are
    not named as splits, preferring one whose name holds the package. A feature
    split is named freely (`feature_ads.apk`), so the guess can still land on
    one: the scanner refuses an APK that declares itself a split.

    A base named in manifest.json but not in the archive is not replaced by a
    guess: the bundle is incomplete, and the guess would be a split.
    """
    declared = _declared_base(data)
    if declared is not None:
        return declared if declared in names else None

    apk_files = []
    for name in names:
        if not name.endswith(".apk"):
            continue
        basename = os.path.basename(name)
        if basename.startswith("split_"):
            continue
        if basename.startswith("config."):
            continue
        apk_files.append(name)

    package_name = (data.get("package_name") or data.get("pname")) if isinstance(data, dict) else None
    named = {os.path.basename(name): name for name in apk_files}
    for base in (f"{package_name}.apk" if isinstance(package_name, str) else None, "base.apk"):
        if base in named:
            return named[base]
    if isinstance(package_name, str) and package_name:
        for name in apk_files:
            if package_name in name:
                return name

    return apk_files[0] if apk_files else None


def extract_main_apk(path: str) -> tuple[str | None, str | None]:
    """
    Extract the main APK from a bundle format.

    Args:
        path: Path to .xapk or .apkm file

    Returns:
        Tuple of (apk_path, temp_dir) — caller must clean up temp_dir
        Returns (None, None) on failure

    Raises:
        BundleMemberRefused: the base APK would unpack past MAX_MEMBER_BYTES
            or MAX_RATIO; the message says which, for the report.
    """
    fmt = detect_format(path)

    if fmt == "apk":
        return path, None

    if fmt not in ("xapk", "apkm"):
        return None, None

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()

            data = None
            if "manifest.json" in names:
                try:
                    data = json.loads(z.read("manifest.json"))
                except Exception:
                    data = None   # an unreadable manifest.json names no base

            main_apk = _choose_base(names, data)
            if not main_apk:
                return None, None

            # Checked before anything is written: what the member declares
            # it unpacks to, against MAX_MEMBER_BYTES and MAX_RATIO.
            info = z.getinfo(main_apk)
            _check_member(info)

            # Extract to temp dir.
            #
            # The path returned is where the APK was actually written, and that
            # is the only path worth trusting: it is built from the member's
            # plain file name alone, so an entry called "../../x.apk" or
            # "/abs/x.apk" lands inside tmp_dir all the same. Rebuilding the
            # path with os.path.join() from the raw name, as this once did,
            # produced a different path outside tmp_dir — and APKRadar would
            # then open whatever happened to be there, reporting on a file the
            # archive's author chose.
            tmp_dir = tempfile.mkdtemp(prefix="apkradar_")
            try:
                apk_path = _extract_bounded(z, info, tmp_dir)
            except Exception:
                # A bad CRC, a full disk or a member that unpacks past what it
                # declares: the caller gets no tmp_dir to clean up, so the
                # directory and the half-written APK go here.
                cleanup_temp(tmp_dir)
                raise
            return apk_path, tmp_dir

    except BundleMemberRefused:
        raise
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
