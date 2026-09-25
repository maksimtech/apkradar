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

The example is rendered here through a console this file declares — 80 columns,
no colour, `legacy_windows=False` — and not through whatever console the
developer happens to have. rich substitutes box characters when it decides the
terminal cannot draw them: `box.ROUNDED`, which is what the code asks for, comes
out square on a legacy Windows console and rounded everywhere else. Generating
the block from such a console rewrote the README's tables with the wrong glyphs
and the CI caught it, which is the whole point of having this test.

So the example is no longer maintained by hand. It is rendered from
tests/fixtures/readme_audit_example.json by the same code path `apkradar audit`
uses, and this test fails if the README stops matching. What it cannot catch is
the thing that caused the drift — the tracker database improving on a real APK —
since it has no APK. That needs the tool run on the file, and the README now says
which file by hash so the check is possible.
"""

from __future__ import annotations

import io
import json
import pathlib
from unittest.mock import patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

import apkradar.cli as cli
import apkradar.scanner as scanner
from apkradar.cli import app
from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound

# What the README shows: a terminal 80 columns wide, no colour, and able to draw
# the box characters the tables ask for.
CANONICAL_WIDTH = 80

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
    """What `apkradar audit` prints for the documented findings.

    Through a console this test owns, so that the result does not depend on the
    machine running it. Left to `Console()`, rich asks the environment whether it
    can draw box characters and answers differently on a legacy Windows console
    than on the CI runner — and the README can only show one of the two.
    """
    buffer = io.StringIO()
    canonical = Console(
        file=buffer,
        width=CANONICAL_WIDTH,
        legacy_windows=False,
        no_color=True,
        highlight=False,
    )
    with patch.object(cli, "console", canonical), \
         patch.object(scanner, "scan", lambda path, **kw: example_result):
        outcome = CliRunner().invoke(app, ["audit", example_result.apk_path])
    assert outcome.exit_code == 0, buffer.getvalue() or outcome.output
    return buffer.getvalue()


def test_the_rendering_is_the_canonical_one(rendered):
    """A guard on the guard: if this file is ever made to render through a legacy
    Windows console, the tables come out square, the README gets regenerated with
    the wrong glyphs, and every assertion below still passes. It happened once."""
    assert "╭" in rendered, "box characters were substituted; see the docstring"
    assert "┌" not in rendered


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
