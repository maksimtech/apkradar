"""Every action every workflow uses is pinned to a commit, with its full version beside it.

apkradar pinned its actions before the other Radars, but checked the rule only
in the NIS2 evidence job (tests/test_nis2_evidence.py) and for scout-action
(tests/test_scout_binary.py). On 2026-11-24 one pin was left that did not say
which release it is: `pypa/gh-action-pypi-publish`, in the job that holds the
PyPI OIDC token, commented `# release/v1`, a branch. Its commit is v1.14.3, and
the comment now says so.

A full commit hash cannot be moved. The `# vX.Y.Z` after it says which release
it is, for a reader and for the dependency updater, which updates both together.
This file is mailradar's, the one the other five Radars share (alignment to
apkradar, step 3).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.y*ml"))
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", re.M)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
# Major, minor and patch: `# v7` and `# v7.1` name lines of releases, not the one pinned
VERSION = re.compile(r"#\s*v?\d+\.\d+\.\d+\b")


def _uses(path: Path) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in USES.finditer(path.read_text(encoding="utf-8"))]


def test_there_are_workflows_to_check():
    assert len(WORKFLOWS) >= 10


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path):
    loose = [ref for ref, _ in _uses(path) if not ref.startswith(("./", "docker://")) and not PINNED.match(ref)]
    assert loose == [], f"{path.name}: not pinned to a full commit: {loose}"


@pytest.mark.parametrize("comment,says_the_release", [
    ("# v7.0.1", True),
    ("# v1.14.3", True),
    ("# 2.1.0", True),
    ("# v7", False),          # a major is a moving tag, not a release
    ("# v7.1", False),        # nor is a minor: which patch?
    ("# release/v1", False),  # a branch
    ("", False),
])
def test_the_version_comment_names_a_full_release(comment, says_the_release):
    """The rule the Radars share is a commit plus its full version (alignment to
    apkradar, step 3): `vX.Y` names a line of releases, not the one pinned."""
    assert bool(VERSION.search(comment)) is says_the_release


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_pin_says_which_release_it_is(path):
    bare = [ref for ref, rest in _uses(path) if PINNED.match(ref) and not VERSION.search(rest)]
    assert bare == [], f"{path.name}: pinned without a '# vX.Y.Z' comment: {bare}"
