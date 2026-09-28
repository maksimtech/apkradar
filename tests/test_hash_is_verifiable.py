"""
APKRadar — the package's digest must be shown whole.

The report printed `SHA256:  af0db3dc4a74b14b...`: sixteen characters out of
sixty-four. A digest serves one purpose, being verified, and sixteen characters
verify nothing — they do not compare with the hash the store publishes, they
cannot be looked up in a list, they cannot be reported in an annex. Whoever wants
to check has to recompute it and has nothing to check it against.

Two inconsistencies showed the defect before anyone looked for it:

- the letter to the DPO (`templates/dpo_letter_it.txt`) uses `{{ sha256 }}`
  whole, so the third party receiving the challenge has the complete digest and
  the analyst who has to verify it does not;
- the law citations print the 64 characters of the hash of the text applied. The
  tool was stricter with the wording of a provision than with the evidence.

The spreadsheet truncates the same way, and it is the deliverable that stays in
the reader's hands afterwards: there a wide column costs nothing.
"""
from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.scanner import ScanResult

runner = CliRunner()

# Un digest vero di 64 caratteri: quello del pacchetto base di 112 Where ARE U
# non serve, serve che la lunghezza sia quella giusta e che non si ripeta.
DIGEST = "af0db3dc4a74b14b9c2e7f1d05a836be41cc9df2e8b7a05614d3f2c8b9071e5a"


def _scanned() -> ScanResult:
    return ScanResult(
        apk_path="demo.apk",
        package_name="com.example.demo",
        app_name="Demo",
        version_name="1.0",
        version_code="1",
        sha256=DIGEST,
        apk_format="apk",
    )


def test_the_report_shows_the_whole_digest():
    with patch("apkradar.scanner.scan", return_value=_scanned()):
        result = runner.invoke(app, ["audit", "demo.apk"])

    assert result.exit_code == 0, result.output
    # Senza ritorni a capo in mezzo: un'impronta spezzata su due righe si
    # incolla male tanto quanto una troncata.
    assert DIGEST in result.output.replace("\n", "")


def test_the_report_does_not_offer_a_truncated_digest():
    """A truncation with an ellipsis looks like a digest and is not one."""
    with patch("apkradar.scanner.scan", return_value=_scanned()):
        result = runner.invoke(app, ["audit", "demo.apk"])

    assert f"{DIGEST[:16]}..." not in result.output


def test_the_spreadsheet_cell_holds_the_whole_digest(tmp_path):
    from openpyxl import load_workbook

    from apkradar.excel import write_results

    target = tmp_path / "referto.xlsx"
    write_results([_scanned()], str(target))

    book = load_workbook(target)
    cells = {
        str(cell.value)
        for sheet in book.worksheets
        for row in sheet.iter_rows()
        for cell in row
        if cell.value
    }
    assert DIGEST in cells, "il foglio non porta l'impronta intera"
