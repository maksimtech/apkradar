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

from apkradar.content import Mention, mentions_of


def set_library_logging(enabled: bool) -> None:
    """Let androguard's own log through, or keep it out of the report.

    androguard 4.1.4 logs through loguru, whose default handler writes DEBUG to
    stderr. Measured on six real APKs on 2026-09-25, that log was between 98.7%
    and 99.5% of everything `apkradar audit` produced — 8,201 lines against 42
    of report on one of them. `--verbose` exists to ask for this level of
    detail, so without it the library stays quiet.

    Disabled by prefix, so this package's own logging is untouched. loguru is a
    dependency of androguard rather than of this package, so its absence is not
    an error: nothing to silence means nothing to do.
    """
    try:
        from loguru import logger
    except ImportError:
        return
    if enabled:
        logger.enable("androguard")
    else:
        logger.disable("androguard")


# Quiet by default, from the moment the module is imported: a caller should not
# have to remember to ask, and the scan is a library call as often as a command.
set_library_logging(False)

# ─── Tracker database ────────────────────────────────────────────────────────

TRACKER_SIGNATURES = {
    "com.google.android.gms.analytics": "Google Analytics",
    "com.google.firebase.analytics": "Firebase Analytics",
    "com.google.android.gms.measurement": "Firebase Analytics",
    "com.google.android.gms.ads": "Google Ads",
    # Reading the advertising ID is not serving advertising, and until 2026-09-30
    # this tool could not tell the two apart: see SIGNATURE_EXCEPTIONS below.
    "com.google.android.gms.ads.identifier": "Google advertising ID (AdvertisingIdClient)",
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
    "com.google.firebase.crashlytics": "Crashlytics",
    "com.crashlytics": "Crashlytics",
    "com.datadog": "Datadog",
    "io.sentry": "Sentry",
    "com.microsoft.appcenter": "App Center",
    "com.huawei.hms.analytics": "Huawei Analytics",
    "com.xiaomi.mipush": "Xiaomi Push",
    "com.baidu.mobads": "Baidu Ads",
}

# Sub-packages that do not count as the signature they sit under.
#
# `com.google.android.gms.ads.identifier` is AdvertisingIdClient: the call that
# reads the advertising ID. It ships in play-services-ads-identifier, which
# arrives with measurement, analytics, basement and a long list of libraries that
# have nothing to do with advertising — so a DEX search for
# `Lcom/google/android/gms/ads/` finds it in applications that have never
# displayed an advertisement.
#
# Reported as "Google Ads", it also put googleadservices.com and doubleclick.net
# into the audited domain list (utils.SDK_DOMAINS), and from there into the letter
# sent to the publisher. That is an allegation that the application talks to
# DoubleClick, made from evidence that it can read an identifier. The finding is
# real — the identifier is what profiling on Android is built on, and the AD_ID
# permission is in SENSITIVE_PERMISSIONS for that reason — but it is a different
# finding, and it is reported under its own name.
#
# AdMob is still detected: it has hundreds of classes under `ads/` that are not
# under `ads/identifier/`, and one is enough.
SIGNATURE_EXCEPTIONS = {
    "com.google.android.gms.ads": ("com.google.android.gms.ads.identifier",),
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
    # "biometric sensors" until 2026-09-30, which is what BODY_SENSORS reads
    # like and not what it gives: heart rate and comparable vital signs, i.e.
    # health data. The old wording is half of why art. 9 was cited for every
    # permission in this table — biometric data under art. 9 means a template
    # processed to identify somebody, which this is not.
    "android.permission.BODY_SENSORS": "vital signs (heart rate)",
    # The same data read with the app in the background. law_checker had its
    # art. 9 reason all along; missing from here, no app could ever reach it.
    "android.permission.BODY_SENSORS_BACKGROUND": "vital signs (heart rate) in background",
    "android.permission.ACTIVITY_RECOGNITION": "physical activity",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.WRITE_CALENDAR": "calendar write",
    "android.permission.GET_ACCOUNTS": "device accounts",
    "android.permission.USE_BIOMETRIC": "biometrics",
    "android.permission.USE_FINGERPRINT": "fingerprint",
    # Play services permissions live outside the android.permission.* namespace,
    # and the table used to contain nothing but that prefix — so the advertising
    # identifier, which is the mechanism by which a user is profiled on Android,
    # could not be matched at all. GDPR art. 4(1) and recital 30 make it an
    # online identifier; ACCESS_ADSERVICES_TOPICS names interest-based
    # advertising in the permission itself.
    #
    # Found on an app for toddlers that reported "No sensitive permissions"
    # while requesting all four (2026-09-25).
    "com.google.android.gms.permission.AD_ID": "advertising ID",
    "android.permission.ACCESS_ADSERVICES_AD_ID": "advertising ID (Privacy Sandbox)",
    "android.permission.ACCESS_ADSERVICES_TOPICS": "interest-based advertising (Topics API)",
    "android.permission.ACCESS_ADSERVICES_ATTRIBUTION": "ad attribution (Privacy Sandbox)",
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
class HostFound:
    """A host carried in the DEX, and the vendor behind it when it is a known one."""
    host: str
    entity: str = ""


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
    # From the Play listing, and only when the caller asked for the lookup.
    # The package name alone cannot establish who publishes an app — see
    # apkradar.publisher for what the two sources are worth against each other.
    developer: str = ""
    developer_site: str = ""
    # What the package itself says about the domain Play declared: the third
    # witness, and the only one that is not the developer's own word. Filled by
    # the scan when the Play lookup ran; None means nobody asked.
    site_mention: Mention | None = None
    # Deep-link hosts declared in the manifest. Collected here because the one
    # caller of get_all_domains never had an APK object to pass it.
    manifest_domains: list[str] = field(default_factory=list)
    # Hosts the DEX string literals carry — see apkradar.hosts for why these are
    # not the same thing as the domains above, and why none of them is scored:
    # the code *can* reach them, which is not evidence that it does.
    dex_hosts: list[str] = field(default_factory=list)
    dex_hosts_truncated: bool = False
    error: str | None = None
    skipped: bool = False

    @property
    def dex_endpoints(self) -> list[HostFound]:
        """The DEX hosts that are servers, each with its vendor when known."""
        from apkradar.hosts import is_reference, vendor_of

        return [
            HostFound(host=host, entity=vendor_of(host) or "")
            for host in self.dex_hosts
            if not is_reference(host)
        ]

    @property
    def dex_references(self) -> list[str]:
        """The DEX hosts that are specifications, schemas or licences."""
        from apkradar.hosts import is_reference

        return [host for host in self.dex_hosts if is_reference(host)]

    @property
    def dex_vendor_hosts(self) -> list[HostFound]:
        """DEX endpoints belonging to the vendors EXTRA_EU_TRANSFERS names.

        The overlap between the two findings, and the reason this extraction
        exists: an app can carry AccuWeather, Baidu and Xiaomi endpoints while
        shipping none of their SDKs, which is what the transfer check reads.
        """
        return [found for found in self.dex_endpoints if found.entity]

    @property
    def tracker_count(self) -> int:
        return len(self.trackers)

    @property
    def sensitive_permission_count(self) -> int:
        return len(self.sensitive_permissions)

    @property
    def score_deductions(self) -> list[tuple[str, int]]:
        """What was subtracted from 100, as (what was found, points).

        Only findings that exist are listed: a `0 (0 trackers)` term would read
        as a measurement of zero rather than as nothing found. Empty when there
        is no score to explain.
        """
        if self.score is None:
            return []

        counted = (
            (self.tracker_count, 10, "tracker", "trackers"),
            (self.sensitive_permission_count, 5, "sensitive permission",
             "sensitive permissions"),
            # Short on purpose: the Extra-EU Transfers table is printed a few
            # lines below, and the full term pushed this line past 80 columns.
            (len(self.extra_eu_transfers), 5, "transfer", "transfers"),
        )
        return [
            (f"{count} {one if count == 1 else many}", count * weight)
            for count, weight, one, many in counted
            if count
        ]

    @property
    def score_arithmetic(self) -> str | None:
        """The score as a sum a reader can check, or None if there is no score.

        A clamp is stated rather than hidden: 16 trackers, 3 permissions and 4
        transfers come to −95, and printing 0 without saying so implies the app
        was measured at the bottom of the scale instead of below it.
        """
        if self.score is None:
            return None

        deductions = self.score_deductions
        if not deductions:
            return "100, nothing deducted"

        raw = 100 - sum(points for _, points in deductions)
        terms = " ".join(f"− {points} ({what})" for what, points in deductions)
        if raw < 0:
            return f"100 {terms} = −{abs(raw)}, clamped to 0"
        return f"100 {terms} = {raw}"

    @property
    def score(self) -> int | None:
        """Compliance score 0-100, higher being better, or None.

        None when the APK could not be parsed or was skipped. It used to be 0,
        which is the score of the worst possible app rather than the absence of
        one — and the counters printed beside it were the initial values of
        counters, not measurements. The distinction is the one exeradar draws
        between `unsigned` and `unknown`: "bad" and "could not tell" are
        different answers.
        """
        if self.error or self.skipped:
            return None
        score = 100
        score -= self.tracker_count * 10
        score -= self.sensitive_permission_count * 5
        score -= len(self.extra_eu_transfers) * 5
        return max(0, score)

    @property
    def score_label(self) -> str:
        if self.skipped:
            return "SKIPPED"
        score = self.score
        if score is None:
            # No verdict was reached, so none is reported. CRITICAL is a verdict.
            return "N/A"
        if score >= 80:
            return "GOOD"
        elif score >= 60:
            return "MODERATE"
        elif score >= 40:
            return "POOR"
        else:
            return "CRITICAL"


# ─── Scanner ──────────────────────────────────────────────────────────────────

def _in_package(name: str, package: str) -> bool:
    """True if name is package itself or lives under it (segment-aware prefix)."""
    return name == package or name.startswith(package + ".")


# Read DEX files in chunks so a large one never lands in memory in full
DEX_CHUNK_SIZE = 4 * 1024 * 1024


def _descriptor(package: str) -> bytes:
    """A package as DEX writes it: `com.appsflyer` → `Lcom/appsflyer/`."""
    return b"L" + package.replace(".", "/").encode() + b"/"


def _hit(buf: bytes, pattern: bytes, excluded: tuple[bytes, ...]) -> bool:
    """True if `pattern` occurs in `buf` other than as one of `excluded`.

    Without `excluded` this is `pattern in buf`. With it, every occurrence is
    read a little further: `Lcom/google/android/gms/ads/identifier/` is not
    `Lcom/google/android/gms/ads/` for the purposes of finding AdMob, and the
    difference is the word after the last slash.

    An occurrence whose remainder is a truncated beginning of an exception is
    left undecided rather than counted: the caller keeps an overlapping tail, so
    it comes back with the rest of the bytes instead of being judged on the half
    that is present. `Lcom/google/android/gms/ads/AdView;` is decided at the "A",
    though — it is not the start of "identifier/", and waiting for more bytes to
    say so would be waiting for nothing.
    """
    if not excluded:
        return pattern in buf
    start = buf.find(pattern)
    while start != -1:
        rest = buf[start + len(pattern):]
        if not rest.startswith(excluded) and not any(exc.startswith(rest) for exc in excluded):
            return True
        start = buf.find(pattern, start + 1)
    return False


def _packages_in_dex(apk_path: str, packages: set[str]) -> set[str]:
    """
    Find which of the given packages have classes in the APK's DEX files.

    Many SDKs (Firebase Analytics, AppsFlyer, Facebook App Events) declare no
    manifest component at all, so the manifest alone cannot detect them. DEX
    files store class names as descriptors like `Lcom/appsflyer/AFLogger;`,
    which is what this searches for. Matching the trailing slash keeps
    `com.appsflyerish` from matching `com.appsflyer`.

    SIGNATURE_EXCEPTIONS narrows a signature that would otherwise swallow a
    sub-package meaning something else — `com.google.android.gms.ads` against the
    advertising-ID reader living under it.

    Returns:
        The subset of packages found. Unreadable APKs yield whatever was
        matched so far — a scan is never failed because of this.
    """
    patterns = {
        p: (
            _descriptor(p),
            tuple(
                _descriptor(exc)[len(_descriptor(p)):]
                for exc in SIGNATURE_EXCEPTIONS.get(p, ())
            ),
        )
        for p in packages
    }
    if not patterns:
        return set()

    # Room for the longest descriptor and for the longest exception under it, so
    # an occurrence split across two chunks is judged on the whole thing.
    overlap = max(
        len(pat) + max((len(exc) for exc in excluded), default=0)
        for pat, excluded in patterns.values()
    ) - 1
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
                        for pkg in [
                            p for p, (pat, excluded) in patterns.items() if _hit(buf, pat, excluded)
                        ]:
                            found.add(pkg)
                            del patterns[pkg]
                        tail = buf[-overlap:] if overlap else b""
    except Exception:
        pass

    return found


def _classes_in_dex(apk_path: str, classes: set[str]) -> set[str]:
    """Which of `classes` the APK's DEX files define, as `Lcom/example/Main;`.

    A manifest can declare a component whose class is not in the file. Fennec
    157.0.0 as F-Droid builds it declares
    `com.adjust.sdk.AdjustPreinstallReferrerReceiver` and ships no class under
    `com.adjust` at all: the build is made without the Adjust SDK and the manifest
    keeps the receiver. Read on the manifest alone, that was "Adjust" in the
    tracker table and "Adjust GmbH (Germany) → USA" in the transfers — in a letter
    to Mozilla, about code that is not in the file.

    The whole descriptor, terminated by `;`: `Lcom/adjust/sdk/Adjust;` is not
    `Lcom/adjust/sdk/AdjustPreinstallReferrerReceiver;`, and the question is
    whether this component exists, not whether something under its package does.

    Same reading as `_packages_in_dex`: chunked, never raising, returning what
    was found so far on an APK it cannot read.
    """
    patterns = {c: b"L" + c.replace(".", "/").encode() + b";" for c in classes}
    if not patterns:
        return set()
    overlap = max(len(p) for p in patterns.values()) - 1
    found: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path) as z:
            for name in [n for n in z.namelist() if n.endswith(".dex")]:
                if not patterns:
                    break
                with z.open(name) as fh:
                    tail = b""
                    while patterns:
                        chunk = fh.read(DEX_CHUNK_SIZE)
                        if not chunk:
                            break
                        buf = tail + chunk
                        for cls in [c for c, pat in patterns.items() if pat in buf]:
                            found.add(cls)
                            del patterns[cls]
                        tail = buf[-overlap:] if overlap else b""
    except Exception:
        pass
    return found


def _components_with_code(apk_path: str, declared: set[str]) -> set[str]:
    """The declared components the code defines — or all of them, if nothing is.

    An APK with no readable DEX cannot confirm anything, and "no code to check
    against" is not "confirmed absent": the manifest is then taken at its word,
    which is what every scan did before this check existed. An APK whose code
    defines none of its own components is read the same way, because that is
    what an unreadable DEX looks like from here, not what an app looks like.
    """
    if not declared:
        return declared
    return _classes_in_dex(apk_path, declared) or declared


def _fill_publisher(result: ScanResult, apk_path: str | None = None) -> None:
    """Add what Google Play says about the publisher, if it will say anything.

    Never fatal: an app that is no longer listed, or no network at all, leaves
    the APK findings exactly as valid as they were. The Play data only ever adds
    a second opinion on the publisher's domain.

    And then asks the package about that same domain, which is the one question
    whose answer does not come from the developer's own typing.
    """
    try:
        from apkradar.search_cmd import lookup

        info = lookup(result.package_name)
        result.developer = info.developer or ""
        result.developer_site = info.developer_website or ""
    except Exception:
        return

    if not (result.developer_site and apk_path):
        return
    try:
        from apkradar.publisher import normalise_site

        host = normalise_site(result.developer_site)
        if host:
            result.site_mention = mentions_of(host, apk_path)
    except Exception:  # noqa: BLE001 - corroboration is a bonus, never a failure
        pass


def scan(apk_path: str, lookup_publisher: bool = False) -> ScanResult:
    """
    Scan an APK file for GDPR compliance issues.
    Supports .apk, .xapk (APKPure) and .apkm (APKMirror) formats.

    Args:
        apk_path: Path to the APK/XAPK/APKM file
        lookup_publisher: Ask Google Play who publishes the app and what site
            they declare. Off by default: this is a static analysis of a file on
            disk, and a library call should not dial out unless asked.

    Returns:
        ScanResult with all findings
    """
    from apkradar.extractor import cleanup_temp, detect_format, extract_main_apk

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

        # Deep-link hosts, read while the manifest is open
        from apkradar.utils import extract_domains_from_apk
        result.manifest_domains = extract_domains_from_apk(apk)

        if lookup_publisher and result.package_name:
            # The extracted base APK for a bundle, the file itself otherwise:
            # the strings live in the APK, not in the XAPK wrapper.
            _fill_publisher(result, str(path))

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

        # Scan declared components for trackers — the ones the code defines. A
        # declaration the DEX does not back is a leftover of a build that removed
        # the SDK, not the SDK: see _classes_in_dex.
        declared = {
            item
            for item in (
                apk.get_providers()
                + apk.get_services()
                + apk.get_receivers()
                + apk.get_activities()
            )
            if item
        }
        components = _components_with_code(str(path), declared)

        # Match against tracker signatures, in the manifest first. A component
        # under an excepted sub-package does not count as the signature above it,
        # the same way it does not in the DEX.
        matched = {
            sig for sig in TRACKER_SIGNATURES
            if any(
                _in_package(c, sig)
                and not any(_in_package(c, exc) for exc in SIGNATURE_EXCEPTIONS.get(sig, ()))
                for c in components
            )
        }

        # Then in the DEX, for the SDKs the manifest did not reveal
        matched |= _packages_in_dex(str(path), set(TRACKER_SIGNATURES) - matched)

        # The same files, read for the hosts their string literals hold. A second
        # pass rather than one combined with the search above: that one stops as
        # soon as every signature is decided, which is the right thing for it and
        # would leave this one reading half a DEX.
        from apkradar.hosts import hosts_in_dex
        result.dex_hosts, result.dex_hosts_truncated = hosts_in_dex(str(path))

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
