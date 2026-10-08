"""Every workflow that runs pytest installs the dependencies the project declares.

The rule exists because breaking it is invisible until a dependency is added.
sonarcloud.yml installed `pip install -e .` plus a hand-written list of pytest
plugins rather than the declared extra, so it had a different set of packages
from tests.yml — and on 2026-09-24, adding hypothesis broke the SonarCloud run
with `ModuleNotFoundError: No module named 'hypothesis'` while the test workflow
stayed green.

A list written by hand cannot stay in step with pyproject.toml. The extra can.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# How this project declares its test dependencies.
DECLARED_INSTALL = 'pip install -e ".[dev]"'

# Plugins that belong to one workflow and are not project dependencies.
WORKFLOW_ONLY = {"pytest-codspeed"}

# pip flags whose next token is a value rather than a package.
FLAGS_TAKING_A_VALUE = {
    "--only-binary", "--no-binary", "--index-url", "--extra-index-url",
    "--find-links", "--constraint", "-c", "--requirement", "-r", "--target", "-t",
}


def _run_scripts(path: pathlib.Path) -> list[str]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    scripts = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps", []):
            if isinstance(step.get("run"), str):
                scripts.append(step["run"])
    return scripts


def _workflows_running_pytest() -> list[pathlib.Path]:
    return [
        path for path in sorted(WORKFLOWS.glob("*.yml"))
        if any(re.search(r"\bpytest\b", script) for script in _run_scripts(path))
    ]


def _named_packages(line: str) -> set[str]:
    """The distributions a pip line installs by name.

    Three things are not names, and all three were mistaken for one on the first
    attempt: the editable target itself (`-e ".[dev]"`, whose quoting hides the
    dot), the value of a flag such as `--only-binary :all:`, and any flag.
    """
    line = line.split("#", 1)[0].strip()
    if not line.startswith("pip install"):
        return set()

    names: set[str] = set()
    skip_next = False
    for token in line.removeprefix("pip install").split():
        if skip_next:
            skip_next = False
            continue
        if token in ("-e", "--editable"):
            skip_next = True                      # the target, not a package
            continue
        if token.startswith("-"):
            skip_next = token in FLAGS_TAKING_A_VALUE
            continue
        name = re.split(r"[<>=!~\[]", token.strip("\"'"), maxsplit=1)[0]
        if name and name not in WORKFLOW_ONLY:
            names.add(name)
    return names


@pytest.mark.parametrize("path", _workflows_running_pytest(), ids=lambda p: p.name)
def test_a_workflow_that_runs_pytest_installs_the_declared_extra(path):
    scripts = "\n".join(_run_scripts(path))
    assert DECLARED_INSTALL in scripts, (
        f"{path.name} runs pytest but does not install {DECLARED_INSTALL}"
    )


@pytest.mark.parametrize("path", _workflows_running_pytest(), ids=lambda p: p.name)
def test_no_workflow_installs_test_packages_by_hand(path):
    """A package named on a pip line is a package pyproject.toml does not control."""
    stray: set[str] = set()
    for script in _run_scripts(path):
        for line in script.splitlines():
            stray |= _named_packages(line)
    assert not stray, f"{path.name} installs {sorted(stray)} outside pyproject.toml"


def test_the_detector_tells_a_name_from_a_flag_or_a_target():
    """Otherwise a green run would mean only that the detector is broken."""
    assert _named_packages('pip install -e ".[dev]"') == set()
    assert _named_packages("pip install -e .") == set()
    assert _named_packages("pip install pytest-codspeed --only-binary :all:") == set()
    assert _named_packages("pip install pytest pytest-cov") == {"pytest", "pytest-cov"}
    assert _named_packages('pip install "ruff>=0.16"') == {"ruff"}
    assert _named_packages("python -m pip install --upgrade pip") == set()


def test_the_rule_looks_at_something():
    """A check that matched no workflow would pass for the wrong reason."""
    assert _workflows_running_pytest(), "no workflow runs pytest?"


# ─── the Python versions the suite runs on ──────────────────────────────────
#
# tests.yml carried "Keep in sync with the classifiers in pyproject.toml" over
# its matrix, and a comment is not what keeps two lists in step. The classifiers
# are the versions the package says it supports; the matrix is where that is
# checked, so the two lists are the same list.
#
# One more row runs the version *after* the last stable one, from its
# development branch, and is allowed to fail. Python 3.15 goes final on
# 2026-10-09 (PEP 790): a dependency without a wheel for it should turn up as a
# yellow row before the release, not as a red matrix after the classifier is
# added. mailradar and patchradar have had the row since 3.14-dev.

TESTS_WORKFLOW = WORKFLOWS / "tests.yml"
PYPROJECT = ROOT / "pyproject.toml"
CLASSIFIED = re.compile(r"^Programming Language :: Python :: (3\.\d+)$")


def _classified_versions() -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    found = [m.group(1) for c in data["project"]["classifiers"] if (m := CLASSIFIED.match(c))]
    assert found, "pyproject.toml names no Python version"
    return found


def _test_job() -> dict:
    workflow = yaml.safe_load(TESTS_WORKFLOW.read_text(encoding="utf-8"))
    return workflow["jobs"]["test"]


def _next_minor(version: str) -> str:
    major, minor = version.split(".")
    return f"{major}.{int(minor) + 1}"


def test_the_suite_runs_on_every_version_the_classifiers_claim_and_no_other():
    matrix = _test_job()["strategy"]["matrix"]
    # str(): an unquoted 3.10 reaches here as the float 3.1, and is then the
    # version the classifier does not name, which is the right outcome.
    assert [str(v) for v in matrix["python-version"]] == _classified_versions()
    assert matrix.get("experimental") == [False], "the stable rows have to say they are not experimental"


def test_the_next_python_runs_as_a_row_that_may_fail():
    job = _test_job()
    stable = _classified_versions()
    rows = [row for row in job["strategy"]["matrix"].get("include", []) if row.get("experimental") is True]

    assert rows == [{"python-version": f"{_next_minor(stable[-1])}-dev", "experimental": True}], (
        f"the experimental row is the version after {stable[-1]}, from its development branch"
    )
    assert job.get("continue-on-error") == "${{ matrix.experimental }}", (
        "the experimental row has to be allowed to fail, and the stable rows must not be"
    )


def test_coverage_is_uploaded_from_a_stable_row():
    """A row that may fail may also produce no report; the upload belongs to one that
    has to pass. 3.12 is the version the Docker image runs."""
    upload = next(s for s in _test_job()["steps"] if "codecov" in s.get("uses", ""))
    guard = re.fullmatch(r"matrix\.python-version == '([\d.]+)'", upload["if"])

    assert guard, upload["if"]
    assert guard.group(1) in _classified_versions()
