"""How `apkradar batch` reads the file it is given.

CookieRadar's `batch` already answers all four of these questions, and the
command here is the same command against a different kind of target — but it
opens the file with a bare `open(file)`, which means:

- the locale decides the encoding, so a UTF-8 list of paths is misread on a
  Windows console and read correctly on Linux CI: the worst kind of difference,
  because the suite is green where nobody is standing;
- a byte order mark, which is what Notepad writes by default, becomes part of
  the first path, and that path then "does not exist";
- an OSError that is not FileNotFoundError — a directory, a permission — is not
  caught at all, so the user gets a traceback instead of a message.

Found on 2026-09-24 while making the Windows suites runnable: the same family
as the cp1252 crash already in the backlog, on the input side this time.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from apkradar.cli import app

runner = CliRunner()


def _scanned():
    """A scan that succeeds, so the test is about reading and nothing else."""
    from apkradar.scanner import ScanResult
    return ScanResult(apk_path="x.apk", package_name="com.example.demo")


def _batch(path):
    with patch("apkradar.scanner.scan", return_value=_scanned()):
        return runner.invoke(app, ["batch", str(path)])


def test_a_utf8_list_is_read_as_utf8_whatever_the_console_says(tmp_path):
    """The file is UTF-8 because we say so, not because the locale agrees.

    Asserting on the path, not on the count: read through cp1252 the count is
    still two, and "app-città.apk" comes back as "app-cittÃ .apk" — a name that
    will not open, reported as though it had.
    """
    listing = tmp_path / "apk.txt"
    listing.write_text("app-città.apk\napp-日本.apk\n", encoding="utf-8")

    result = _batch(listing)

    assert "Loaded 2 APKs" in result.output, result.output
    assert "app-città.apk" in result.output, result.output
    assert "app-日本.apk" in result.output, result.output


def test_a_byte_order_mark_is_not_part_of_the_first_path(tmp_path):
    """Notepad writes a BOM by default; it must not be pasted onto a filename.

    The mark is U+FEFF when decoded as UTF-8 and "ï»¿" when decoded as cp1252,
    so both spellings are refused: either one means the first path is wrong.
    """
    listing = tmp_path / "apk.txt"
    listing.write_text("first.apk\nsecond.apk\n", encoding="utf-8-sig")

    result = _batch(listing)

    assert "﻿" not in result.output
    assert "ï»¿" not in result.output
    assert "Auditing first.apk" in result.output, result.output
    assert "Loaded 2 APKs" in result.output, result.output


def test_a_file_that_is_not_utf8_is_refused_with_a_message(tmp_path):
    """Not a traceback: the user is told which file and why."""
    listing = tmp_path / "apk.txt"
    listing.write_bytes("caffè.apk\n".encode("latin-1"))

    result = _batch(listing)

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "apk.txt" in result.output


def test_a_directory_instead_of_a_file_is_refused_with_a_message(tmp_path):
    """The mistake is easy to make with tab completion, and it used to raise."""
    result = _batch(tmp_path)

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_a_missing_file_still_says_so(tmp_path):
    """The one case that was already handled; it must survive the others."""
    result = _batch(tmp_path / "nope.txt")

    assert result.exit_code != 0
    assert "nope.txt" in result.output


@pytest.mark.parametrize("line", ["# commented", "  # indented", "", "   "])
def test_comments_and_blank_lines_are_still_skipped(tmp_path, line):
    listing = tmp_path / "apk.txt"
    listing.write_text(f"{line}\nreal.apk\n", encoding="utf-8")

    result = _batch(listing)

    assert "Loaded 1 APKs" in result.output, result.output
