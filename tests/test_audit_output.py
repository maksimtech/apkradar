"""`audit --output` must actually write the report.

The option was declared on the command and never read in its body: the flag
was accepted, the scan ran, the report went to the terminal, and no file was
ever written — with or without --full. Nothing failed, so nothing said so.
"""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.scanner import ScanResult

runner = CliRunner()


def audited() -> ScanResult:
    return ScanResult(
        apk_path="demo.apk",
        package_name="com.example.demo",
        app_name="Demo",
        version_name="1.2.3",
        sha256="abc123",
    )


def run_audit(args: list[str]):
    with patch("apkradar.scanner.scan", return_value=audited()):
        return runner.invoke(app, ["audit", *args])


def test_output_writes_a_file(tmp_path):
    target = tmp_path / "report.txt"
    result = run_audit(["demo.apk", "--output", str(target)])

    assert result.exit_code == 0, result.output
    assert target.exists(), "--output was accepted but nothing was written"
    assert target.stat().st_size > 0


def test_the_file_holds_what_the_terminal_showed(tmp_path):
    target = tmp_path / "report.txt"
    result = run_audit(["demo.apk", "--output", str(target)])

    assert result.exit_code == 0, result.output
    written = target.read_text(encoding="utf-8")
    assert "com.example.demo" in written
    assert "Demo" in written
    # The point of the file is to be the report, not a summary of it.
    assert "1.2.3" in written


def test_the_short_flag_works_too(tmp_path):
    target = tmp_path / "report.txt"
    run_audit(["demo.apk", "-o", str(target)])
    assert target.exists()


def test_html_is_written_as_html(tmp_path):
    target = tmp_path / "report.html"
    run_audit(["demo.apk", "--output", str(target)])

    written = target.read_text(encoding="utf-8")
    assert written.lstrip().startswith("<!DOCTYPE html")
    assert "com.example.demo" in written


def test_an_extension_it_does_not_know_is_refused_before_the_scan(tmp_path):
    """Refusing the name after the analysis would throw the work away.

    The same rule the other tools follow: guess nothing, and say which
    extensions are known.
    """
    target = tmp_path / "report.xlsx"

    def must_not_run(*args, **kwargs):
        raise AssertionError("the APK must not be scanned before the name is checked")

    with patch("apkradar.scanner.scan", side_effect=must_not_run):
        result = runner.invoke(app, ["audit", "demo.apk", "--output", str(target)])

    assert result.exit_code == 2
    assert not target.exists()
    assert ".txt" in result.output or ".html" in result.output


def test_without_the_option_nothing_is_written(tmp_path, monkeypatch):
    """The regression guard: the default must stay terminal-only."""
    monkeypatch.chdir(tmp_path)
    result = run_audit(["demo.apk"])

    assert result.exit_code == 0
    assert list(tmp_path.iterdir()) == []


def test_a_directory_that_is_not_there_is_refused(tmp_path):
    target = tmp_path / "no" / "such" / "dir" / "report.txt"

    def must_not_run(*args, **kwargs):
        raise AssertionError("the APK must not be scanned for an unwritable target")

    with patch("apkradar.scanner.scan", side_effect=must_not_run):
        result = runner.invoke(app, ["audit", "demo.apk", "--output", str(target)])

    assert result.exit_code == 2


def test_a_failed_scan_writes_no_file(tmp_path):
    """A report of an analysis that did not happen would be worse than none."""
    target = tmp_path / "report.txt"
    broken = ScanResult(apk_path="demo.apk", error="not an APK")

    with patch("apkradar.scanner.scan", return_value=broken):
        result = runner.invoke(app, ["audit", "demo.apk", "--output", str(target)])

    assert result.exit_code == 1
    assert not target.exists()
