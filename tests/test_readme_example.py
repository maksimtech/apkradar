"""The README says its examples are real output. Nothing checked that.

The `audit` example was captured from 2026.09.29 and described Bitwarden as
`Score: 80/100 — GOOD` with `✅ No trackers detected`. On the byte-identical
artifact — SHA-256 954967bb…d64b3, the bitwarden/android release v2026.9.0-bwpm —
2026.09.32 prints `70/100 — MODERATE` and one tracker, because the tracker
database now catches a Crashlytics instance the older version missed.

That is an improvement in the tool and a defect in the documentation: a corrected
false negative was left on display as current behaviour, and the paragraph under
it explained arithmetic (100 − 3×5 − 1×5 = 80) that no longer describes the app,
while asserting that Crashlytics is not on the tracker list.

The tables had drifted too, in a way nobody would notice by eye: the README drew
them with rounded corners and the renderer draws them square.

So the example is no longer maintained by hand. It is rendered from
tests/fixtures/readme_audit_example.json by the same code path `apkradar audit`
uses, and this test fails if the README stops matching. What it cannot catch is
the thing that caused the drift — the tracker database improving on a real APK —
since it has no APK. That needs the tool run on the file, and the README now says
which file by hash so the check is possible.
"""

from __future__ import annotations

import json
import pathlib
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import apkradar.scanner as scanner
from apkradar.cli import app
from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "readme_audit_example.json"

# Where the citation block starts. Everything from here on carries per-provision
# hashes and dates that change whenever the law cache is refreshed, so the README
# quotes the heading and elides the rest.
CITATIONS = "⚖️"


@pytest.fixture(scope="module")
def documented() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def example_result(documented) -> ScanResult:
    result = ScanResult(
        apk_path=documented["apk_path"],
        package_name=documented["package_name"],
        app_name=documented["app_name"],
        version_name=documented["version_name"],
        version_code=documented["version_code"],
        min_sdk=documented["min_sdk"],
        target_sdk=documented["target_sdk"],
        apk_format=documented["apk_format"],
        sha256=documented["sha256"],
    )
    result.trackers = [TrackerFound(**t) for t in documented["trackers"]]
    result.sensitive_permissions = [
        PermissionFound(**p) for p in documented["sensitive_permissions"]
    ]
    result.permissions = list(result.sensitive_permissions)
    result.extra_eu_transfers = [
        TransferFound(**t) for t in documented["extra_eu_transfers"]
    ]
    return result


@pytest.fixture(scope="module")
def rendered(example_result) -> str:
    """What `apkradar audit` prints for the documented findings."""
    with patch.object(scanner, "scan", lambda path, **kw: example_result):
        outcome = CliRunner().invoke(app, ["audit", example_result.apk_path])
    assert outcome.exit_code == 0, outcome.output
    return outcome.output


def _lines(text: str) -> list[str]:
    """Trailing spaces are what rich uses to centre a table title, and what
    editors strip on save. Neither is a documentation defect."""
    return [line.rstrip() for line in text.splitlines()]


# ── the fixture is the case the README describes ────────────────────────────


def test_the_fixture_scores_what_it_claims(example_result, documented):
    """100 − 10×1 tracker − 5×3 permissions − 5×1 transfer = 70."""
    assert example_result.score == documented["expected_score"]
    assert example_result.score_label == documented["expected_label"]


# ── the README quotes it verbatim ───────────────────────────────────────────


def test_the_readme_example_is_current_output(rendered):
    """Every line of the report, in order, as the tool prints it."""
    report = rendered.split(CITATIONS)[0]
    readme = _lines(README.read_text(encoding="utf-8"))

    wanted = [line for line in _lines(report) if line]
    missing = [line for line in wanted if line not in readme]

    assert not missing, (
        "the README no longer matches what audit prints:\n  "
        + "\n  ".join(missing[:10])
    )


def test_the_readme_example_keeps_the_order(rendered):
    """Lines present but shuffled would still be wrong output."""
    report = [line for line in _lines(rendered.split(CITATIONS)[0]) if line]
    readme = _lines(README.read_text(encoding="utf-8"))

    at = -1
    for line in report:
        at = readme.index(line, at + 1)


def test_the_readme_mentions_the_citation_block(rendered):
    """`audit` prints the provisions it applied; the example used to stop short
    of it, so a third of the real output went undocumented."""
    assert CITATIONS in rendered
    assert CITATIONS in README.read_text(encoding="utf-8")


def test_the_readme_does_not_keep_the_old_numbers():
    """The stale figures, named so they cannot come back by a copy-paste."""
    readme = README.read_text(encoding="utf-8")

    assert "Score: 80/100 — GOOD" not in readme
    assert "100 − 3 permissions × 5 − 1 transfer × 5 = 80" not in readme


def test_the_readme_names_the_artifact_by_hash(documented):
    """So the one thing this test cannot check — the tracker database improving
    on the real file — stays checkable by hand."""
    readme = README.read_text(encoding="utf-8")

    assert documented["sha256"] in readme


def test_the_readme_states_the_version_it_was_captured_with():
    import apkradar

    assert apkradar.__version__ in README.read_text(encoding="utf-8")
