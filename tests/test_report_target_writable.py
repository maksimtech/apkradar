"""`audit --output` refuses a target it cannot write, before the scan and without a traceback.

Measured on 2026-10-09 in the published image:

    docker run --rm -v .../apk:/data:ro maksimtech/apkradar:latest \
        audit /data/org.mozilla.fennec_fdroid_1570020.apk --output /data/x.html

The whole audit ran and printed, and then the command ended in a Rich traceback
through `console.save_html` — `OSError: [Errno 30] Read-only file system` — with
exit code 1. `_check_report_target` looked at the extension and at whether the
parent directory existed, and a read-only directory exists. So does a directory
that happens to have the report's name. Both are knowable before the APK is
opened, which is the whole point of checking the target first.

The directory case is the portable fixture; the read-only one needs chmod and
is skipped where that means nothing (Windows, root).
"""

from __future__ import annotations

import os
import stat
import sys

import pytest
from typer.testing import CliRunner

from apkradar.cli import _check_report_target, app
from tests.android_files import manifest, write_apk

runner = CliRunner()


@pytest.fixture
def apk(tmp_path):
    return write_apk(tmp_path / "app.apk", manifest("com.example.app"))


def test_a_directory_with_the_reports_name_is_refused_up_front(tmp_path):
    target = tmp_path / "report.html"
    target.mkdir()
    with pytest.raises(ValueError, match="directory"):
        _check_report_target(str(target))


def test_the_command_exits_2_and_says_so_without_a_traceback(tmp_path, apk):
    target = tmp_path / "report.html"
    target.mkdir()
    outcome = runner.invoke(app, ["audit", apk, "--output", str(target)])
    assert outcome.exit_code == 2, outcome.output
    assert "Traceback" not in outcome.output
    assert "report.html" in outcome.output
    assert "Score" not in outcome.output          # refused before the scan, not after


@pytest.mark.skipif(sys.platform == "win32", reason="a read-only directory is not read-only for its owner on Windows")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root writes anywhere")
def test_a_read_only_directory_is_refused_up_front(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(ValueError, match="write"):
            _check_report_target(str(ro / "report.html"))
    finally:
        ro.chmod(stat.S_IRWXU)
