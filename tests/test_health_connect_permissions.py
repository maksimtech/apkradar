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

import re

import pytest
from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.diff import diff
from apkradar.law_checker import findings_of
from apkradar.scanner import PermissionFound, ScanResult, scan
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


# ─── the score: Health Connect counts once ────────────────────────────────────
# Owner's decision, 2026-11-17: the Health Connect permissions are one group in
# the score. Each kind of record has its own permission, so a fitness app asks
# for dozens where another app asks for one "body sensors" permission; at 5
# points each, Fitbit's eighty would cost 400 points for one capability. They
# cost what one sensitive permission costs, however many there are, and every
# one of them is still listed and still cited under art. 9.

LOCATION = PermissionFound("android.permission.ACCESS_FINE_LOCATION", "precise GPS location")


def _health(n):
    return [
        PermissionFound(f"android.permission.health.READ_RECORD_{i}", f"Health Connect: record {i} (read)")
        for i in range(n)
    ]


def _result(permissions):
    found = ScanResult(apk_path="app.apk", package_name="com.example.app")
    found.sensitive_permissions = list(permissions)
    return found


def test_health_connect_costs_one_sensitive_permission_however_many():
    found = _result([LOCATION, *_health(80)])

    assert found.score == 100 - 5 - 5
    assert found.sensitive_permission_count == 81   # all still listed
    assert found.score_deductions == [
        ("1 sensitive permission", 5),
        ("Health Connect (80 permissions, counted once)", 5),
    ]
    assert found.score_arithmetic == (
        "100 − 5 (1 sensitive permission) − 5 (Health Connect (80 permissions, counted once)) = 90"
    )


def test_a_single_health_connect_permission_is_named_as_one():
    found = _result(_health(1))

    assert found.score == 95
    assert found.score_deductions == [("Health Connect (1 permission, counted once)", 5)]


@pytest.mark.parametrize("health", [0, 1, 6, 80])
@pytest.mark.parametrize("others", [0, 1, 9])
def test_the_printed_sum_is_still_the_score(health, others):
    found = _result([LOCATION] * others + _health(health))

    assert found.score == max(0, 100 - sum(points for _, points in found.score_deductions))


def test_the_scanned_app_counts_its_health_connect_permissions_once(health_app):
    """Six of them in the manifest, and INTERNET, which is not sensitive."""
    assert len(health_app.sensitive_permissions) == len(HEALTH)
    assert health_app.score == 95
    assert health_app.score_arithmetic == "100 − 5 (Health Connect (6 permissions, counted once)) = 95"


def test_two_releases_differing_only_in_health_connect_score_the_same(tmp_path):
    """diff reads the same score: adding records to the group costs nothing more."""
    old = scan(write_apk(tmp_path / "old.apk", manifest("com.example.health", permissions=HEALTH[:2])))
    new = scan(write_apk(tmp_path / "new.apk", manifest("com.example.health", permissions=HEALTH)))
    d = diff(old, new)

    assert d.score == (95, 95)
    assert d.to_dict()["score"] == {"old": 95, "new": 95}
    assert len(d.permissions_added) == len(HEALTH) - 2


def test_the_audit_lists_every_permission_and_explains_the_group(tmp_path):
    apk = write_apk(tmp_path / "health.apk", manifest("com.example.health", permissions=HEALTH))
    out = CliRunner().invoke(app, ["audit", apk, "--offline"])
    flat = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", out.output).split())

    assert "Score: 95/100" in flat
    assert "Health Connect (6 permissions, counted once)" in flat
    for permission in HEALTH:
        assert permission.rsplit(".", 1)[-1] in flat
