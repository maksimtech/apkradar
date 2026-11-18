"""Renovate proposes what may be merged, and merges on its own only what nobody
needs to read.

Until 2026-11-18 Dependabot did this (`.github/dependabot.yml`, whose rules
tests/test_dependabot_config.py held). Two of them stay:

- a release is taken at least 14 days after it is out, unless a known
  vulnerability makes the older version the risk. Without the wait, on
  2026-10-29 and 2026-11-02, twelve pull requests across the Radar asked for
  releases two to thirteen days old;
- Actions updates arrive as one pull request a week, not one per action.

What Renovate adds:

- one batch a week, on Thursday, the day before the Friday release;
- minor, patch and digest updates merge on their own once the required checks
  pass; a major waits for a person;
- the lower bounds in pyproject.toml are raised by hand, when the code needs
  them, and Renovate only moves uv.lock within them. A bound raised by a bot is a
  bound no test asked for, and the other way round is how 2026-11-15 went wrong:
  code written against mailradar's main while the bound still said 2026.44;
- the Python the image and the matrix run is a decision with its own tests
  (tests/test_docker_python.py, tests/test_ci_dependencies.py): no bot moves it;
- Actions are pinned to a commit digest, not to a tag that can be moved.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".github" / "renovate.json"


def config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def rules() -> list[dict]:
    return config().get("packageRules", [])


def _days(age: str) -> int:
    match = re.fullmatch(r"(\d+) days?", age)
    assert match, f"minimumReleaseAge {age!r} is not written in days"
    return int(match.group(1))


def test_dependabot_no_longer_asks_for_version_updates():
    """Two bots on one stream open every pull request twice."""
    assert not (ROOT / ".github" / "dependabot.yml").exists()


def test_every_release_waits_fourteen_days():
    assert _days(config()["minimumReleaseAge"]) >= 14


def test_a_known_vulnerability_does_not_wait():
    alerts = config()["vulnerabilityAlerts"]
    assert alerts.get("enabled", True) is True
    assert alerts["minimumReleaseAge"] is None
    assert alerts["schedule"] == ["at any time"]


def test_one_weekly_batch_the_day_before_the_release():
    assert config()["schedule"] == ["before 6am on thursday"]
    assert config()["timezone"] == "Europe/Rome"


def test_actions_updates_arrive_as_one_pull_request():
    actions = [r for r in rules() if r.get("matchManagers") == ["github-actions"]]
    assert len(actions) == 1 and actions[0].get("groupName"), actions


def test_actions_are_pinned_to_a_commit():
    assert "helpers:pinGitHubActionDigests" in config()["extends"]


def test_lower_bounds_are_raised_by_hand():
    python = [r for r in rules() if r.get("matchManagers") == ["pep621"]]
    assert python and all(r.get("rangeStrategy") == "update-lockfile" for r in python), python


def test_a_major_waits_for_a_person():
    for rule in rules():
        if rule.get("automerge"):
            types = rule.get("matchUpdateTypes")
            assert types, f"an automerge rule with no update types takes majors too: {rule}"
            assert "major" not in types, rule


def test_no_bot_moves_the_python_we_run():
    frozen = [
        r for r in rules()
        if r.get("matchDepNames") == ["python"] and r.get("enabled") is False
    ]
    assert frozen, "a rule has to keep Renovate off the Python version"
    assert set(frozen[0]["matchUpdateTypes"]) >= {"major", "minor"}
