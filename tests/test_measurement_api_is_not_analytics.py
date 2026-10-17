"""AdMob's measurement API is not Firebase Analytics (audit F01, 2026-10-17).

abc 123 Tracing 1.8 (com.gameitech.preschool.abc123.tracing.learning, base.apk
SHA-256 4bba01000efbffd0…) holds, under `com.google.android.gms.measurement`,
14 classes and no others, all in its classes2.dex:

    measurement/api/AppMeasurementSdk (+ $ConditionalUserProperty, $EventInterceptor, $OnEventListener)
    measurement/internal/zzga zzhe zzhf zzhg zzhh zzhi zzhj zzio zzit
    measurement/sdk/api/R                ← the R class carries the artefact's name

That is `play-services-measurement-sdk-api`: the interface through which Google
Ads would talk to Analytics *if* Analytics were there, and it arrives as a
dependency of play-services-ads. No `AppMeasurement` class, none of the
`AppMeasurement{Service,Receiver,JobService}` components the real SDK's
manifest always merges in, no `com.google.firebase.analytics`, and in 1,038
flows captured from the app on an emulator, no traffic to app-measurement.com.

APKRadar reported "Firebase Analytics (com.google.android.gms.measurement)",
took 10 points for it, and put it in section 1 of the letter: an allegation
against every app that shows AdMob ads. The classes directly in the
`measurement` package — the AppMeasurement entry point and its components —
are the SDK; the api, sdk and internal sub-packages the interface also ships
are not evidence of it.

The APKs are built by tests/android_files.py from that class list (derived:
the real descriptors, in a DEX the scanner reads the way it reads any other).
"""
from __future__ import annotations

from pathlib import Path

from apkradar.scanner import scan
from tests.android_files import dex_blob, manifest, write_apk

PACKAGE = "com.gameitech.preschool.abc123.tracing.learning"
MAIN = "com.gameitech.preschool.abc123.tracing.learning.MainActivity"

SDK_API = [
    "com.google.android.gms.measurement.api.AppMeasurementSdk",
    "com.google.android.gms.measurement.api.AppMeasurementSdk$ConditionalUserProperty",
    "com.google.android.gms.measurement.api.AppMeasurementSdk$EventInterceptor",
    "com.google.android.gms.measurement.api.AppMeasurementSdk$OnEventListener",
    *(f"com.google.android.gms.measurement.internal.{name}"
      for name in ("zzga", "zzhe", "zzhf", "zzhg", "zzhh", "zzhi", "zzhj", "zzio", "zzit")),
    "com.google.android.gms.measurement.sdk.api.R",
]
ADMOB = ["com.google.android.gms.ads.AdView"]


def _trackers(tmp_path: Path, classes, receivers=()) -> set[str]:
    apk = write_apk(tmp_path / "app.apk", manifest(PACKAGE, activities=(MAIN,), receivers=receivers),
                    dex=dex_blob([MAIN, *classes]))
    return {t.name for t in scan(apk).trackers}


def test_admob_s_measurement_api_alone_is_not_firebase_analytics(tmp_path):
    trackers = _trackers(tmp_path, SDK_API + ADMOB)

    assert "Firebase Analytics" not in trackers
    assert "Google Ads" in trackers


def test_the_appmeasurement_entry_point_is_firebase_analytics(tmp_path):
    """The other side, so the fix cannot become a false negative: the real SDK
    has `AppMeasurement` directly in the package."""
    trackers = _trackers(tmp_path, SDK_API + ADMOB + ["com.google.android.gms.measurement.AppMeasurement"])

    assert "Firebase Analytics" in trackers


def test_a_declared_appmeasurement_service_backed_by_code_is_firebase_analytics(tmp_path):
    service = "com.google.android.gms.measurement.AppMeasurementReceiver"

    assert "Firebase Analytics" in _trackers(tmp_path, SDK_API + [service], receivers=(service,))


def test_firebase_s_own_analytics_package_is_still_firebase_analytics(tmp_path):
    assert "Firebase Analytics" in _trackers(tmp_path, ["com.google.firebase.analytics.FirebaseAnalytics"])
