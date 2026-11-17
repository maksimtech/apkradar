"""Health Connect permissions are sensitive, and they reach art. 9.

Health Connect gives each kind of health record its own permission, under
`android.permission.health.`: READ_HEART_RATE, READ_SEXUAL_ACTIVITY,
READ_MENSTRUATION, READ_MEDICAL_DATA_VACCINES, and some eighty more, each with
its WRITE_ counterpart. law_checker has matched that prefix as data concerning
health since 2026-09-30, but the scanner reported a permission as sensitive only
if it was in SENSITIVE_PERMISSIONS, where none of them is: the art. 9 branch for
Health Connect could not be reached.

Measured by the bug hunt of 2026-11-17 on Fitbit's app as installed on a test
phone (com.fitbit.FitbitMobile, version code 1104134720): it declares about
eighty `android.permission.health.*` permissions, sexual activity, menstruation
and medical records among them, and the report listed none of them.

The APKs here are written by tests/android_files.py with the permissions named
in the manifest and nothing else, and opened by the real androguard.
"""

from __future__ import annotations

import pytest

from apkradar.law_checker import findings_of
from apkradar.scanner import scan
from tests.android_files import manifest, write_apk

HEALTH = (
    "android.permission.health.READ_HEART_RATE",
    "android.permission.health.WRITE_HEART_RATE",
    "android.permission.health.READ_SEXUAL_ACTIVITY",
    "android.permission.health.WRITE_MENSTRUATION",
    "android.permission.health.READ_MEDICAL_DATA_VACCINES",
    "android.permission.health.READ_HEALTH_DATA_IN_BACKGROUND",
)


@pytest.fixture
def health_app(tmp_path):
    permissions = ("android.permission.INTERNET", *HEALTH)
    return scan(write_apk(tmp_path / "health.apk", manifest("com.example.health", permissions=permissions)))


def test_health_connect_permissions_are_reported(health_app):
    assert health_app.error is None, health_app.error
    reported = [p.permission for p in health_app.sensitive_permissions]

    assert sorted(reported) == sorted(HEALTH)
    assert "android.permission.INTERNET" not in reported


def test_each_says_which_record_it_reaches(health_app):
    described = {p.permission: p.description for p in health_app.sensitive_permissions}

    assert described["android.permission.health.READ_SEXUAL_ACTIVITY"] == "Health Connect: sexual activity (read)"
    assert described["android.permission.health.WRITE_MENSTRUATION"] == "Health Connect: menstruation (write)"
    assert described["android.permission.health.READ_MEDICAL_DATA_VACCINES"] == (
        "Health Connect: medical data vaccines (read)"
    )
    assert all(p.gdpr_relevant for p in health_app.sensitive_permissions)


def test_the_art_9_branch_for_health_connect_is_reached(health_app):
    special = findings_of(health_app)["special_category"]

    assert len(special) == len(HEALTH)
    assert (
        "READ_HEART_RATE (Health Connect: heart rate (read)): "
        "a Health Connect record, which is data concerning health"
    ) in special


def test_a_name_outside_the_prefix_is_not_taken_for_one(tmp_path):
    """The prefix is matched with its final dot: a permission an app defines for
    itself under a name that merely starts the same way is not Health Connect."""
    lookalike = "android.permission.healthy.READ_STEPS"
    result = scan(write_apk(tmp_path / "x.apk", manifest("com.example.x", permissions=(lookalike,))))

    assert result.sensitive_permissions == []
