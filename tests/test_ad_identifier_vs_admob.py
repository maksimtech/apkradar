"""Reading the advertising ID is not serving advertising.

`com.google.android.gms.ads.identifier.AdvertisingIdClient` is the call that
reads the advertising ID. It ships in play-services-ads-identifier, which arrives
with play-services-measurement, analytics, basement and a long list of libraries
that have nothing to do with advertising, so a DEX search for
`Lcom/google/android/gms/ads/` finds it in applications that have never displayed
an advertisement.

The signature table held one entry for that whole prefix, named "Google Ads", and
`utils.SDK_DOMAINS` hung googleadservices.com and doubleclick.net on it. So the
identifier alone produced:

    Trackers: Google Ads (com.google.android.gms.ads)
    Domains audited: googleadservices.com, doubleclick.net

and those domains went into the letter sent to the publisher — an allegation that
the application talks to DoubleClick, drawn from evidence that it can read an
identifier. The finding underneath is real, and it already has its own place: the
AD_ID permission is in SENSITIVE_PERMISSIONS, and an online identifier is what
GDPR art. 4(1) and recital 30 are about. It is a different finding, and it is now
reported under its own name.

The direction of the error is what makes it worth a file of its own. Missing a
tracker understates a report; naming a domain an app never contacts puts a false
statement in a letter to a company, over a signature.
"""

from __future__ import annotations

import zipfile

import pytest

from apkradar import utils
from apkradar.scanner import (
    SIGNATURE_EXCEPTIONS,
    TRACKER_SIGNATURES,
    TrackerFound,
    _packages_in_dex,
    scan,
)

ADS = "com.google.android.gms.ads"
IDENTIFIER = "com.google.android.gms.ads.identifier"
GMS = "com.google.android.gms"

# What the two look like inside a DEX file.
IDENTIFIER_CLASS = b"Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;"
ADMOB_CLASS = b"Lcom/google/android/gms/ads/AdView;"
ADMOB_INTERNAL_CLASS = b"Lcom/google/android/gms/ads/internal/client/zzbu;"


def dex_with(*classes: bytes, filler: bytes = b"") -> bytes:
    """Bytes that look enough like a DEX for a descriptor search.

    Nothing here parses DEX: the scan looks for class descriptors in the raw
    bytes, so this is what it is looking at.
    """
    return b"dex\n035\x00" + filler + b"".join(c + b"\x00" for c in classes)


@pytest.fixture
def apk(tmp_path):
    def build(*classes: bytes, filler: bytes = b"", name="app.apk"):
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("classes.dex", dex_with(*classes, filler=filler))
        return path

    return build


# ── the DEX search ──────────────────────────────────────────────────────────


def test_the_identifier_alone_is_not_admob(apk):
    found = _packages_in_dex(str(apk(IDENTIFIER_CLASS)), {ADS, IDENTIFIER, GMS})

    assert IDENTIFIER in found
    assert ADS not in found, "AdvertisingIdClient was read as AdMob"
    assert GMS in found            # it is Play services, and that much is true


def test_an_admob_class_is_admob(apk):
    found = _packages_in_dex(str(apk(ADMOB_CLASS)), {ADS, IDENTIFIER, GMS})

    assert ADS in found
    assert IDENTIFIER not in found


def test_admob_is_still_found_when_the_identifier_is_there_too(apk):
    """The ordinary case for an app that does serve ads: both are present, and
    the exception must not hide the one it is not about."""
    found = _packages_in_dex(str(apk(IDENTIFIER_CLASS, ADMOB_INTERNAL_CLASS)), {ADS, IDENTIFIER})

    assert found == {ADS, IDENTIFIER}


def test_the_verdict_does_not_depend_on_where_the_chunks_fall(apk, monkeypatch):
    """The descriptor and the word after it can land in two different reads.

    The search walks a DEX in chunks and keeps an overlapping tail. If the tail
    were shorter than the descriptor plus the excepted sub-package, an occurrence
    split across the boundary would be judged on half of itself — and the half
    that is missing is exactly the part that says "identifier".
    """
    monkeypatch.setattr("apkradar.scanner.DEX_CHUNK_SIZE", 8)

    for offset in range(0, 48):
        found = _packages_in_dex(
            str(apk(IDENTIFIER_CLASS, filler=b"x" * offset, name=f"a{offset}.apk")),
            {ADS, IDENTIFIER},
        )
        assert ADS not in found, f"read as AdMob with the class starting at offset {offset}"
        assert IDENTIFIER in found, f"not found at all with offset {offset}"


# ── the domains, which is where the accusation was ──────────────────────────


def test_the_identifier_does_not_pull_in_doubleclick():
    domains = utils.extract_sdk_domains([
        TrackerFound(package=IDENTIFIER, name=TRACKER_SIGNATURES[IDENTIFIER]),
    ])

    # Set operations rather than `in`: CodeQL reads a host literal on the left of
    # `in` as a URL being checked by substring (py/incomplete-url-substring-
    # sanitization) and cannot see that the right side is a list of hosts, where
    # membership is equality. The rule is worth keeping sharp elsewhere, and this
    # says the same thing without tripping it.
    assert {"doubleclick.net", "googleadservices.com"}.isdisjoint(domains)
    # what is true stays: this is a Play services call
    assert set(domains) == {"google.com", "googleapis.com"}


def test_admob_does_pull_them_in():
    domains = utils.extract_sdk_domains([
        TrackerFound(package=ADS, name=TRACKER_SIGNATURES[ADS]),
    ])

    assert {"doubleclick.net", "googleadservices.com"} <= set(domains)


def test_the_match_is_segment_aware_and_not_a_substring_search():
    """`prefix in package` was the old test, and a substring of a package name is
    not a package. Nothing about `com.appsflyerish` is AppsFlyer."""
    domains = utils.extract_sdk_domains([
        TrackerFound(package="com.appsflyerish.sdk", name="not appsflyer"),
    ])

    assert domains == []


# ── the whole scan, on a file ───────────────────────────────────────────────


class _StubAPK:
    """androguard's APK, answering "nothing here" to everything but the basics.

    The DEX step reads the file from disk as a zip, so the classes above are what
    this scan actually sees.
    """

    def __init__(self, path):
        self.path = path

    def get_package(self):
        return "com.example.reader"

    def get_app_name(self):
        return "Reader"

    def get_androidversion_name(self):
        return "1.0"

    def get_androidversion_code(self):
        return 1

    def get_min_sdk_version(self):
        return 21

    def get_target_sdk_version(self):
        return 34

    def get_permissions(self):
        return ["com.google.android.gms.permission.AD_ID"]

    def get_files(self):
        return []

    def get_dex_names(self):
        return []

    def get_all_dex(self):
        return []

    def get_activities(self):
        return []

    def get_services(self):
        return []

    def get_receivers(self):
        return []

    def get_providers(self):
        return []

    def get_signature_names(self):
        return []

    def get_certificates(self):
        return []

    def is_signed(self):
        return False

    def get_androidversion_code_int(self):
        return 1

    def get_elements(self, *args, **kwargs):
        return []

    def get_element(self, *args, **kwargs):
        return None

    def get_main_activity(self):
        return None


@pytest.fixture
def scanned(apk, monkeypatch):
    def run(*classes: bytes):
        path = apk(*classes)
        import androguard.core.apk as ag

        monkeypatch.setattr(ag, "APK", lambda p: _StubAPK(p), raising=True)
        return scan(str(path))

    return run


def test_an_app_that_only_reads_the_identifier_is_reported_as_that(scanned):
    result = scanned(IDENTIFIER_CLASS)

    names = {tracker.name for tracker in result.trackers}
    assert "Google advertising ID (AdvertisingIdClient)" in names
    assert "Google Ads" not in names

    domains = utils.get_all_domains(result)
    assert {"doubleclick.net", "googleadservices.com"}.isdisjoint(domains)

    # and the permission it does declare is still a finding
    assert [p.permission for p in result.sensitive_permissions] == [
        "com.google.android.gms.permission.AD_ID"
    ]


def test_an_app_with_admob_is_still_reported_as_that(scanned):
    result = scanned(ADMOB_CLASS)

    assert "Google Ads" in {tracker.name for tracker in result.trackers}
    assert {"doubleclick.net"} <= set(utils.get_all_domains(result))


def test_the_exception_is_declared_where_a_reader_will_look():
    """A rule this specific has to be findable from the table it narrows."""
    assert SIGNATURE_EXCEPTIONS[ADS] == (IDENTIFIER,)
    assert IDENTIFIER in TRACKER_SIGNATURES
    assert "advertising ID" in TRACKER_SIGNATURES[IDENTIFIER]
