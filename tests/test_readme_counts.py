"""The numbers the README states for the signature lists are the code's numbers.

On 2026-10-09 the README said APKRadar "recognises 43 SDKs", "flags 24 Android
permissions", and, in Known limitations, that "only the 43 trackers, 23
permissions and 13 vendors" are recognised. The code had 44 distinct SDK names
over 46 signatures and 28 permissions, and the permissions table left out the
five most recently added: BODY_SENSORS_BACKGROUND and the four advertising
identifiers. Three different counts for one table is how a reader learns the
document was not re-read when the code moved — and the permissions table is the
one a team checks its own app's manifest against.

Read from the README rather than typed here, so the next addition to a table
fails this test instead of ageing the document again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from apkradar.scanner import EXTRA_EU_TRANSFERS, SENSITIVE_PERMISSIONS, TRACKER_SIGNATURES

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")


def _number(pattern: str) -> int:
    match = re.search(pattern, README)
    assert match, pattern
    return int(match.group(1))


def test_the_number_of_sdks_recognised():
    assert _number(r"recognises (\d+) SDKs") == len(set(TRACKER_SIGNATURES.values()))


def test_the_number_of_permissions_flagged():
    assert _number(r"flags (\d+) Android permissions") == len(SENSITIVE_PERMISSIONS)


def test_the_known_limitations_say_the_same():
    trackers, permissions, vendors = (
        int(n) for n in re.search(r"Only the (\d+) trackers, (\d+) permissions and (\d+)\s+vendors", README).groups()
    )
    assert (trackers, permissions, vendors) == (
        len(set(TRACKER_SIGNATURES.values())), len(SENSITIVE_PERMISSIONS), len(EXTRA_EU_TRANSFERS),
    )


@pytest.mark.parametrize("permission", sorted(SENSITIVE_PERMISSIONS))
def test_every_flagged_permission_is_in_the_readme_table(permission):
    assert f"`{permission.rsplit('.', 1)[-1]}`" in README, permission
