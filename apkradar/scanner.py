"""
APKRadar — Androguard scanner.
Analyzes APK files for trackers, permissions and GDPR compliance.
Supports .apk, .xapk (APKPure) and .apkm (APKMirror) formats.
"""
from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─── Tracker database ────────────────────────────────────────────────────────

TRACKER_SIGNATURES = {
    "com.google.android.gms.analytics": "Google Analytics",
    "com.google.firebase.analytics": "Firebase Analytics",
    "com.google.android.gms.measurement": "Firebase Analytics",
    "com.google.android.gms.ads": "Google Ads",
    "com.facebook.appevents": "Facebook App Events",
    "com.facebook.ads": "Facebook Audience Network",
    "com.appsflyer": "AppsFlyer",
    "com.adjust.sdk": "Adjust",
    "com.amplitude.api": "Amplitude",
    "io.branch.referral": "Branch",
    "com.mixpanel.android": "Mixpanel",
    "com.segment.analytics": "Segment",
    "com.onesignal": "OneSignal",
    "com.chartboost": "Chartboost",
    "com.ironsource.mediationsdk": "IronSource",
    "com.applovin": "AppLovin",
    "com.unity3d.ads": "Unity Ads",
    "com.vungle": "Vungle",
    "com.mopub": "MoPub",
    "com.flurry.android": "Flurry",
    "com.comscore": "Comscore",
    "com.nielsen": "Nielsen",
    "com.criteo": "Criteo",
    "com.tradedoubler": "TradeDoubler",
    "com.snap.adkit": "Snap Ads",
    "com.tiktok.sdk": "TikTok SDK",
    "com.twitter.sdk.android.mopub": "Twitter MoPub",
    "com.inmobi": "InMobi",
    "com.tapjoy": "Tapjoy",
    "com.startapp": "StartApp",
    "com.adcolony": "AdColony",
    "com.fyber": "Fyber",
    "com.smaato": "Smaato",
    "com.yandex.metrica": "Yandex Metrica",
    "com.newrelic.agent.android": "New Relic",
    "com.instabug": "Instabug",
    "com.bugsnag.android": "Bugsnag",
    "com.crashlytics": "Crashlytics",
    "com.datadog": "Datadog",
    "io.sentry": "Sentry",
    "com.microsoft.appcenter": "App Center",
    "com.huawei.hms.analytics": "Huawei Analytics",
    "com.xiaomi.mipush": "Xiaomi Push",
    "com.baidu.mobads": "Baidu Ads",
}

SENSITIVE_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION": "precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "approximate location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "background location",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.WRITE_CONTACTS": "contacts write",
    "android.permission.READ_CALL_LOG": "call log",
    "android.permission.WRITE_CALL_LOG": "call log write",
    "android.permission.READ_SMS": "SMS messages",
    "android.permission.RECEIVE_SMS": "SMS receive",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.CAMERA": "camera",
    "android.permission.READ_EXTERNAL_STORAGE": "storage read",
    "android.permission.WRITE_EXTERNAL_STORAGE": "storage write",
    "android.permission.READ_PHONE_STATE": "device ID/IMEI",
    "android.permission.READ_PHONE_NUMBERS": "phone numbers",
    "android.permission.PROCESS_OUTGOING_CALLS": "outgoing calls",
    "android.permission.BODY_SENSORS": "biometric sensors",
    "android.permission.ACTIVITY_RECOGNITION": "physical activity",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.WRITE_CALENDAR": "calendar write",
    "android.permission.GET_ACCOUNTS": "device accounts",
    "android.permission.USE_BIOMETRIC": "biometrics",
    "android.permission.USE_FINGERPRINT": "fingerprint",
}

EXTRA_EU_TRANSFERS = {
    "com.google": "Google LLC (USA)",
    "com.facebook": "Meta Platforms Inc. (USA)",
    "com.amazon": "Amazon Web Services (USA)",
    "com.microsoft": "Microsoft Corporation (USA)",
    "com.appsflyer": "AppsFlyer Ltd. (USA/Israel)",
    "com.adjust": "Adjust GmbH (Germany) → USA",
    "com.amplitude": "Amplitude Inc. (USA)",
    "com.mixpanel": "Mixpanel Inc. (USA)",
    "com.tiktok": "ByteDance Ltd. (China/USA)",
    "com.yandex": "Yandex LLC (Russia)",
    "com.huawei": "Huawei Technologies (China)",
    "com.xiaomi": "Xiaomi Corporation (China)",
    "com.baidu": "Baidu Inc. (China)",
}


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class TrackerFound:
    package: str
    name: str
    category: str = "advertising"


@dataclass
class PermissionFound:
    permission: str
    description: str
    gdpr_relevant: bool = True


@dataclass
class TransferFound:
    package_prefix: str
    entity: str


@dataclass
class ScanResult:
    apk_path: str
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    sha256: str = ""
    apk_format: str = "apk"
    trackers: list[TrackerFound] = field(default_factory=list)
    permissions: list[PermissionFound] = field(default_factory=list)
    sensitive_permissions: list[PermissionFound] = field(default_factory=list)
    extra_eu_transfers: list[TransferFound] = field(default_factory=list)
    error: Optional[str] = None
    skipped: bool = False

    @property
    def tracker_count(self) -> int:
        return len(self.trackers)

    @property
    def sensitive_permission_count(self) -> int:
        return len(self.sensitive_permissions)

    @property
    def score(self) -> int:
        """Compliance score 0-100. Higher is better. A failed scan scores 0."""
        if self.error or self.skipped:
            return 0
        score = 100
        score -= self.tracker_count * 10
        score -= self.sensitive_permission_count * 5
        score -= len(self.extra_eu_transfers) * 5
        return max(0, score)

    @property
    def score_label(self) -> str:
        if self.skipped:
            return "SKIPPED"
        if self.score >= 80:
            return "GOOD"
        elif self.score >= 60:
            return "MODERATE"
        elif self.score >= 40:
            return "POOR"
        else:
            return "CRITICAL"


# ─── Scanner ──────────────────────────────────────────────────────────────────

def _in_package(name: str, package: str) -> bool:
    """True if name is package itself or lives under it (segment-aware prefix)."""
    return name == package or name.startswith(package + ".")


# Read DEX files in chunks so a large one never lands in memory in full
DEX_CHUNK_SIZE = 4 * 1024 * 1024


def _packages_in_dex(apk_path: str, packages: set[str]) -> set[str]:
    """
    Find which of the given packages have classes in the APK's DEX files.

    Many SDKs (Firebase Analytics, AppsFlyer, Facebook App Events) declare no
    manifest component at all, so the manifest alone cannot detect them. DEX
    files store class names as descriptors like `Lcom/appsflyer/AFLogger;`,
    which is what this searches for. Matching the trailing slash keeps
    `com.appsflyerish` from matching `com.appsflyer`.

    Returns:
        The subset of packages found. Unreadable APKs yield whatever was
        matched so far — a scan is never failed because of this.
    """
    patterns = {p: b"L" + p.replace(".", "/").encode() + b"/" for p in packages}
    if not patterns:
        return set()

    overlap = max(len(pat) for pat in patterns.values()) - 1
    found: set[str] = set()

    try:
        with zipfile.ZipFile(apk_path) as z:
            dex_names = [n for n in z.namelist() if n.endswith(".dex")]
            for name in dex_names:
                if not patterns:
                    break
                with z.open(name) as fh:
                    tail = b""
                    while patterns:
                        chunk = fh.read(DEX_CHUNK_SIZE)
                        if not chunk:
                            break
                        buf = tail + chunk
                        for pkg in [p for p, pat in patterns.items() if pat in buf]:
                            found.add(pkg)
                            del patterns[pkg]
                        tail = buf[-overlap:] if overlap else b""
    except Exception:
        pass

    return found


def scan(apk_path: str) -> ScanResult:
    """
    Scan an APK file for GDPR compliance issues.
    Supports .apk, .xapk (APKPure) and .apkm (APKMirror) formats.

    Args:
        apk_path: Path to the APK/XAPK/APKM file

    Returns:
        ScanResult with all findings
    """
    from apkradar.extractor import extract_main_apk, cleanup_temp, detect_format

    result = ScanResult(apk_path=apk_path)
    tmp_dir = None

    try:
        fmt = detect_format(apk_path)
        result.apk_format = fmt

        if fmt == "unknown":
            result.error = f"Unknown format: {apk_path}"
            return result

        # Extract main APK if bundle format
        if fmt in ("xapk", "apkm"):
            actual_path, tmp_dir = extract_main_apk(apk_path)
            if not actual_path:
                result.error = f"Could not extract APK from {fmt.upper()} bundle"
                return result
        else:
            actual_path = apk_path

        path = Path(actual_path)
        if not path.exists():
            result.error = f"File not found: {apk_path}"
            return result

        # SHA256 hash of original file
        result.sha256 = hashlib.sha256(Path(apk_path).read_bytes()).hexdigest()

        # Parse APK with androguard
        from androguard.core.apk import APK
        apk = APK(str(path))

        # Metadata
        result.package_name = apk.get_package() or ""
        result.app_name = apk.get_app_name() or ""
        result.version_name = apk.get_androidversion_name() or ""
        result.version_code = str(apk.get_androidversion_code() or "")
        result.min_sdk = str(apk.get_min_sdk_version() or "")
        result.target_sdk = str(apk.get_target_sdk_version() or "")

        # Scan permissions
        permissions = apk.get_permissions() or []
        for perm in permissions:
            if perm in SENSITIVE_PERMISSIONS:
                pf = PermissionFound(
                    permission=perm,
                    description=SENSITIVE_PERMISSIONS[perm],
                    gdpr_relevant=True,
                )
                result.permissions.append(pf)
                result.sensitive_permissions.append(pf)
            else:
                result.permissions.append(
                    PermissionFound(
                        permission=perm,
                        description=perm.split(".")[-1].lower(),
                        gdpr_relevant=False,
                    )
                )

        # Scan declared components for trackers
        components = {
            item
            for item in (
                apk.get_providers()
                + apk.get_services()
                + apk.get_receivers()
                + apk.get_activities()
            )
            if item
        }

        # Match against tracker signatures, in the manifest first
        matched = {
            sig for sig in TRACKER_SIGNATURES
            if any(_in_package(c, sig) for c in components)
        }

        # Then in the DEX, for the SDKs the manifest did not reveal
        matched |= _packages_in_dex(str(path), set(TRACKER_SIGNATURES) - matched)

        # One entry per SDK: several signatures can name the same one
        seen_trackers = set()
        for sig, name in TRACKER_SIGNATURES.items():
            if sig in matched and name not in seen_trackers:
                seen_trackers.add(name)
                result.trackers.append(TrackerFound(package=sig, name=name))

        # Check extra-EU transfers: declared components, or the vendor of a
        # detected SDK (DEX-detected SDKs have no component to match against)
        for prefix, entity in EXTRA_EU_TRANSFERS.items():
            if any(_in_package(c, prefix) for c in components) or any(
                _in_package(sig, prefix) for sig in matched
            ):
                result.extra_eu_transfers.append(
                    TransferFound(package_prefix=prefix, entity=entity)
                )

    except Exception as e:
        result.error = str(e)

    finally:
        cleanup_temp(tmp_dir)

    return result
