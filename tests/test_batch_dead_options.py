"""`batch` declared --full and --output and read neither.

Both flags were accepted in silence and did nothing: no directory was created, no
file was written, no full-stack analysis ran, and no message explained why. In the
46 lines of the function body each name appeared exactly once — in the signature.

A flag that is accepted and ignored is worse than one that does not exist: the
reader has no way to tell "ran and found nothing" from "never ran".

Found on 2026-09-25. cookieradar's batch already had the shape this needs,
including the name-collision set, so these tests are written against that
behaviour rather than inventing one.
"""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.scanner import ScanResult

runner = CliRunner()


def listing(tmp_path, *names) -> str:
    path = tmp_path / "list.txt"
    path.write_text("\n".join(names) + "\n", encoding="utf-8")
    return str(path)


def ok(name: str, package: str | None = None) -> ScanResult:
    return ScanResult(apk_path=name, package_name=package or f"com.example.{name.split('.')[0]}")


# ── --output ────────────────────────────────────────────────────────────────


def test_output_writes_one_report_per_apk(tmp_path):
    reports = tmp_path / "reports"
    names = ["a.apk", "b.apk"]
    with patch("apkradar.scanner.scan", side_effect=[ok(n) for n in names]):
        result = runner.invoke(
            app, ["batch", listing(tmp_path, *names), "--output", str(reports)]
        )

    assert result.exit_code == 0, result.output
    written = sorted(p.name for p in reports.iterdir()) if reports.is_dir() else []
    assert len(written) == 2, written


def test_output_creates_the_directory(tmp_path):
    reports = tmp_path / "does" / "not" / "exist"
    with patch("apkradar.scanner.scan", side_effect=[ok("a.apk")]):
        runner.invoke(app, ["batch", listing(tmp_path, "a.apk"), "-o", str(reports)])

    assert reports.is_dir()


def test_output_says_where_it_wrote(tmp_path):
    reports = tmp_path / "reports"
    with patch("apkradar.scanner.scan", side_effect=[ok("a.apk")]):
        result = runner.invoke(
            app, ["batch", listing(tmp_path, "a.apk"), "--output", str(reports)]
        )

    assert "reports" in result.output


def test_two_apks_with_the_same_basename_do_not_overwrite_each_other(tmp_path):
    """`x/app.apk` and `y/app.apk` are two results, not one.

    cookieradar keeps a set of used names for exactly this; silently writing one
    file would lose a report without saying so.
    """
    names = ["one/app.apk", "two/app.apk"]
    reports = tmp_path / "reports"
    with patch("apkradar.scanner.scan", side_effect=[ok(n) for n in names]):
        runner.invoke(app, ["batch", listing(tmp_path, *names), "-o", str(reports)])

    assert len(list(reports.iterdir())) == 2, sorted(p.name for p in reports.iterdir())


def test_a_file_where_the_directory_should_be_is_refused(tmp_path):
    """Not a traceback, and not a silent no-op."""
    blocker = tmp_path / "reports"
    blocker.write_text("i am a file", encoding="utf-8")

    with patch("apkradar.scanner.scan", side_effect=[ok("a.apk")]):
        result = runner.invoke(
            app, ["batch", listing(tmp_path, "a.apk"), "-o", str(blocker)]
        )

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_a_failed_scan_writes_no_report(tmp_path):
    """A report of an analysis that did not happen is worse than no file."""
    reports = tmp_path / "reports"
    bad = ScanResult(apk_path="bad.apk", error="EOCD signature not found")
    with patch("apkradar.scanner.scan", side_effect=[bad, ok("good.apk")]):
        runner.invoke(
            app, ["batch", listing(tmp_path, "bad.apk", "good.apk"), "-o", str(reports)]
        )

    written = sorted(p.name for p in reports.iterdir())
    assert len(written) == 1, written


def test_without_output_nothing_is_written(tmp_path):
    with patch("apkradar.scanner.scan", side_effect=[ok("a.apk")]):
        runner.invoke(app, ["batch", listing(tmp_path, "a.apk")])

    assert not (tmp_path / "reports").exists()


# ── --full ──────────────────────────────────────────────────────────────────


def test_full_runs_the_downstream_analysis(tmp_path):
    """The flag has to reach the three-way integration, per APK."""
    seen: list[str] = []
    with patch("apkradar.scanner.scan", side_effect=[ok("a.apk", "com.example.app")]), \
         patch("apkradar.cli._full_stack_domain", side_effect=lambda d, **kw: seen.append(d)), \
         patch("apkradar.utils.get_all_domains", return_value=["example.com"]):
        result = runner.invoke(app, ["batch", listing(tmp_path, "a.apk"), "--full"])

    assert seen == ["example.com"], (seen, result.output)


def test_without_full_the_downstream_is_not_touched(tmp_path):
    seen: list[str] = []
    with patch("apkradar.scanner.scan", side_effect=[ok("a.apk", "com.example.app")]), \
         patch("apkradar.cli._full_stack_domain", side_effect=lambda d, **kw: seen.append(d)), \
         patch("apkradar.utils.get_all_domains", return_value=["example.com"]):
        runner.invoke(app, ["batch", listing(tmp_path, "a.apk")])

    assert seen == []


def test_full_does_not_run_for_an_apk_that_failed(tmp_path):
    """There is no package name to derive a domain from."""
    seen: list[str] = []
    bad = ScanResult(apk_path="bad.apk", error="EOCD signature not found")
    with patch("apkradar.scanner.scan", side_effect=[bad]), \
         patch("apkradar.cli._full_stack_domain", side_effect=lambda d, **kw: seen.append(d)), \
         patch("apkradar.utils.get_all_domains", return_value=["example.com"]):
        runner.invoke(app, ["batch", listing(tmp_path, "bad.apk"), "--full"])

    assert seen == []


def test_each_domain_is_analysed_once_across_the_whole_batch(tmp_path):
    """Two APKs that share a domain should not pay for it twice.

    The issue notes it: --full on a batch fans out to MailRadar, SSL and
    CookieRadar per domain per APK, so a shared cache is worth having at the
    same time as the flag.

    Both kinds of domain count now. The publisher domain is resolved apart
    from get_all_domains, so mocking that one is no longer the whole picture,
    and these two APKs share a package prefix — hence a publisher domain too.
    Each must be analysed once, not once per APK.
    """
    seen: list[str] = []
    names = ["a.apk", "b.apk"]
    with patch("apkradar.scanner.scan", side_effect=[ok(n) for n in names]), \
         patch("apkradar.cli._full_stack_domain", side_effect=lambda d, **kw: seen.append(d)), \
         patch("apkradar.utils.get_all_domains", return_value=["shared.example"]):
        runner.invoke(app, ["batch", listing(tmp_path, *names), "--full"])

    assert seen.count("shared.example") == 1, seen
    assert seen.count("example.com") == 1, seen
    assert len(seen) == len(set(seen)), seen
