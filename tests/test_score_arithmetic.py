"""The score is a number with no working shown, and at the bottom it lies flat.

`score = 100 − 10×trackers − 5×permissions − 5×transfers`, clamped at 0. The
formula is documented in the README and it reproduces exactly on every app
measured, so the model does what it says. Two things it does not say out loud:

**Where the points went.** Nextcloud 35.0.0 scores 55 POOR with no trackers and
no extra-EU transfers — nine declared permissions, because a cloud client needs
contacts, calendar and camera. Bitwarden scores 70 with one tracker and one
transfer to Google. A reader comparing 55 to 70 has no way to see that the two
numbers are made of different things unless they open the source.

**That 0 is a floor.** Coin Master, with 16 real tracking SDKs, computes to −95
and prints 0/100. So does an app with 20 trackers, and so did a truncated file
that could not be opened at all until that was fixed separately. Below zero the
number stops discriminating, and nothing in the report admits it.

Neither is fixed by changing the weights — whether permission count should cost
what it costs is a design question, not a defect, and it is not decided here.
What is fixed is that the arithmetic is now printed, so the number can be audited
without reading the code and a clamp announces itself.
"""

from __future__ import annotations

import pytest

from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound


def result(trackers=0, permissions=0, transfers=0, **kwargs) -> ScanResult:
    found = ScanResult(apk_path="app.apk", package_name="com.example.app", **kwargs)
    found.trackers = [
        TrackerFound(package=f"com.tracker{n}", name=f"Tracker {n}") for n in range(trackers)
    ]
    found.sensitive_permissions = [
        PermissionFound(permission=f"android.permission.P{n}", description="x")
        for n in range(permissions)
    ]
    found.extra_eu_transfers = [
        TransferFound(package_prefix=f"com.vendor{n}", entity=f"Vendor {n} (USA)")
        for n in range(transfers)
    ]
    return found


# ── the working ─────────────────────────────────────────────────────────────


def test_a_clean_app_says_nothing_was_deducted():
    assert result().score_arithmetic == "100, nothing deducted"


def test_bitwarden():
    """The README example: 100 − 10 − 15 − 5 = 70."""
    found = result(trackers=1, permissions=3, transfers=1)

    assert found.score == 70
    assert found.score_arithmetic == (
        "100 − 10 (1 tracker) − 15 (3 sensitive permissions) "
        "− 5 (1 transfer) = 70"
    )


def test_nextcloud():
    """The case that reads wrong: every point lost to declared functionality."""
    found = result(permissions=9)

    assert found.score == 55
    assert found.score_arithmetic == "100 − 45 (9 sensitive permissions) = 55"


def test_coinmaster_shows_the_clamp():
    """16 trackers, 3 permissions, 4 transfers: 100 − 160 − 15 − 20 = −95."""
    found = result(trackers=16, permissions=3, transfers=4)

    assert found.score == 0
    assert "−95" in found.score_arithmetic
    assert "clamped to 0" in found.score_arithmetic


def test_the_clamp_is_not_announced_when_it_did_not_happen():
    found = result(trackers=10)

    assert found.score == 0
    assert "clamped" not in found.score_arithmetic, "exactly 0 was not clamped"


@pytest.mark.parametrize(
    ("kwargs", "singular"),
    [
        ({"trackers": 1}, "1 tracker)"),
        ({"permissions": 1}, "1 sensitive permission)"),
        ({"transfers": 1}, "1 transfer)"),
    ],
)
def test_one_of_something_is_not_plural(kwargs, singular):
    assert singular in result(**kwargs).score_arithmetic


@pytest.mark.parametrize(
    ("kwargs", "plural"),
    [
        ({"trackers": 2}, "2 trackers)"),
        ({"permissions": 2}, "2 sensitive permissions)"),
        ({"transfers": 2}, "2 transfers)"),
    ],
)
def test_more_than_one_is(kwargs, plural):
    assert plural in result(**kwargs).score_arithmetic


def test_only_what_was_found_is_listed():
    """A zero term would be noise, and would suggest something was looked for
    and measured at zero rather than not found."""
    text = result(trackers=1).score_arithmetic

    assert "permission" not in text
    assert "transfer" not in text


# ── it has to agree with the score ──────────────────────────────────────────


@pytest.mark.parametrize("trackers", [0, 1, 3])
@pytest.mark.parametrize("permissions", [0, 2, 9])
@pytest.mark.parametrize("transfers", [0, 1, 4])
def test_the_deductions_account_for_the_score(trackers, permissions, transfers):
    """Whatever the weights are, the printed sum has to be the printed score."""
    found = result(trackers=trackers, permissions=permissions, transfers=transfers)
    deducted = sum(points for _, points in found.score_deductions)

    assert max(0, 100 - deducted) == found.score


def test_no_arithmetic_for_a_scan_that_produced_none():
    """A failed scan has no score, so there is nothing to show working for."""
    failed = ScanResult(apk_path="broken.apk", error="EOCD signature not found")
    skipped = ScanResult(apk_path="app.apk", skipped=True)

    assert failed.score_arithmetic is None
    assert skipped.score_arithmetic is None
    assert failed.score_deductions == []


# ── and it has to be visible ────────────────────────────────────────────────


def test_the_report_shows_the_working():
    from unittest.mock import patch

    from typer.testing import CliRunner

    import apkradar.scanner as scanner
    from apkradar.cli import app

    found = result(trackers=1, permissions=3, transfers=1)
    with patch.object(scanner, "scan", lambda path, **kw: found):
        outcome = CliRunner().invoke(app, ["audit", "app.apk"])

    assert "100 − 10 (1 tracker)" in outcome.output


def test_a_failed_scan_prints_no_working():
    from unittest.mock import patch

    from typer.testing import CliRunner

    import apkradar.scanner as scanner
    from apkradar.cli import app

    failed = ScanResult(apk_path="broken.apk", error="EOCD signature not found")
    with patch.object(scanner, "scan", lambda path, **kw: failed):
        outcome = CliRunner().invoke(app, ["audit", "broken.apk"])

    assert "100 −" not in outcome.output
    assert "nothing deducted" not in outcome.output
