"""The coverage upload proves which repository it comes from, and names its file.

Codecov wants an upload authenticated even for a public repository, and files it
under the project its token belongs to, not under the repository that sends it.
Until 2026-11-22 every Radar authenticated with a `CODECOV_TOKEN` secret, and three
of them held exeradar's: their reports went to exeradar's project for at least a
month, and `codecov/patch` on their pull requests had nothing of its own to compare
(maksimtech/patchradar#111). This repository's token was its own, but nothing kept
it so. With OIDC, GitHub itself tells Codecov which repository the job runs in, so
no report can land in another project; there is no secret to copy or mix up. The job
needs `id-token: write` for that, and a token in the step would only be ignored next
to `use_oidc` and mislead whoever reads it.

The report was also named with `file:`, an input codecov-action v7 does not have
("Unexpected input(s) 'file'" in every run): the upload worked only because the
action found coverage.xml by searching for it. `files:` is the input it reads.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "tests.yml"


def _uploads():
    text = WORKFLOW.read_text(encoding="utf-8")
    jobs = yaml.safe_load(text)["jobs"]
    return text, [(name, job, step) for name, job in jobs.items() for step in job.get("steps", [])
                  if str(step.get("uses", "")).startswith("codecov/codecov-action@")]


def test_the_upload_proves_which_repository_it_comes_from():
    text, uploads = _uploads()
    assert uploads, "nothing uploads coverage"
    for name, job, step in uploads:
        options = step.get("with") or {}
        assert options.get("use_oidc") is True, f"{name}: the upload does not use OIDC"
        assert "token" not in options, f"{name}: a token next to use_oidc is ignored"
        assert (job.get("permissions") or {}).get("id-token") == "write", (
            f"{name}: without id-token: write the job cannot ask GitHub for the OIDC token")
    assert "secrets.CODECOV_TOKEN" not in text, "the secret is still read somewhere"


def test_the_report_is_named_with_an_input_the_action_reads():
    _, uploads = _uploads()
    for name, _, step in uploads:
        options = step.get("with") or {}
        assert "file" not in options, f"{name}: codecov-action v7 has no `file` input"
        assert options.get("files") == "coverage.xml", f"{name}: the report is not named"
