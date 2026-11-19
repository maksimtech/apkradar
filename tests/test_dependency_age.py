"""A release is taken at least 14 days after it is out, and uv enforces it.

On 2026-11-19 Renovate opened #81 for pytest-asyncio 1.4.1.post1 and the lock it
wrote held 1.5.0, published seven days earlier: Renovate updates the lock with
`uv lock --upgrade-package`, and uv takes the newest version the range allows,
whatever Renovate's minimumReleaseAge says. Renovate flagged it
(`renovate/artifacts` failed), but that status is not a required check and
GitHub's auto-merge merged it. The age rule now lives in uv itself, so every
lock, Renovate's and ours, is written under it.

Two packages are exempt: mailradar and cookieradar, the Radars apkradar builds
on. Their releases ship in the same monthly cycle (a fix in cookieradar has to
reach apkradar's release of the same second Tuesday), and the wait exists for
third-party releases, not for ours. Renovate gets the same exemption, or it
would hold them back where uv does not.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWN_RADARS = {"mailradar", "cookieradar"}


def uv_settings() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8")).get("tool", {}).get("uv", {})


def lock_options() -> dict:
    return tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8")).get("options", {})


def renovate_rules() -> list[dict]:
    config = json.loads((ROOT / ".github" / "renovate.json").read_text(encoding="utf-8"))
    return config.get("packageRules", [])


def test_uv_takes_nothing_newer_than_fourteen_days():
    age = uv_settings().get("exclude-newer")
    assert age, "pyproject.toml has no [tool.uv] exclude-newer"
    match = re.fullmatch(r"(\d+) days?", age)
    assert match, f"exclude-newer {age!r} is not a span in days"
    assert int(match.group(1)) >= 14


def test_only_our_own_radars_are_exempt_in_uv():
    exempt = uv_settings().get("exclude-newer-package", {})
    assert exempt == dict.fromkeys(OWN_RADARS, False), exempt


def test_the_lock_was_written_under_the_rule():
    """A lock written before the setting, or by hand, says nothing about age."""
    options = lock_options()
    assert options.get("exclude-newer-span") == "P14D", options
    assert options.get("exclude-newer-package") == dict.fromkeys(OWN_RADARS, False), options


def test_renovate_does_not_hold_back_our_own_radars():
    exempt = [r for r in renovate_rules() if set(r.get("matchPackageNames", [])) == OWN_RADARS]
    assert len(exempt) == 1, "one rule has to name exactly mailradar and cookieradar"
    assert "minimumReleaseAge" in exempt[0] and exempt[0]["minimumReleaseAge"] is None, exempt[0]
