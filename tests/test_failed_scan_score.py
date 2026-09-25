"""A file that could not be opened has no score, and "0" is not the word for it.

A truncated APK — 359 KB of a 64 MB download — was reported as:

    Score: 0/100 — CRITICAL
    Error: End of central directory record (EOCD) signature not found

and in batch, in the same column as real results:

    🔴 CRITICAL — 0/100 — 0 trackers, 0 sensitive permissions

Zero out of a hundred is the score of the worst possible app. This file was never
parsed, so "0 trackers, 0 sensitive permissions" is not a measurement — it is the
initial value of a counter, printed as a finding.

It is the same distinction exeradar draws between `unsigned` and `unknown`: "bad"
and "could not tell" are different answers, and a report that conflates them
invites a comparison that has no meaning. The error handling itself was already
good — clear message, exit 1, `1/4 scans failed` — so only the label was wrong.

Found on 2026-09-25.
"""

from __future__ import annotations

from apkradar.scanner import ScanResult

EOCD = "End of central directory record (EOCD) signature not found"


def failed(**kwargs) -> ScanResult:
    return ScanResult(apk_path="telegram-troncato.apk", error=EOCD, **kwargs)


def scored(trackers=0, permissions=0) -> ScanResult:
    """A result that really was measured, for contrast."""
    from apkradar.scanner import PermissionFound, TrackerFound

    result = ScanResult(apk_path="real.apk", package_name="com.example")
    for i in range(trackers):
        result.trackers.append(TrackerFound(name=f"T{i}", package=f"com.t{i}", category="ads"))
    for i in range(permissions):
        pf = PermissionFound(permission=f"p{i}", description="d", gdpr_relevant=True)
        result.permissions.append(pf)
        result.sensitive_permissions.append(pf)
    return result


# ── the number ──────────────────────────────────────────────────────────────


def test_a_failed_scan_has_no_score():
    assert failed().score is None


def test_a_skipped_scan_has_no_score():
    assert failed(skipped=True).score is None


def test_a_real_scan_still_has_one():
    """The change must not take the score away from results that have one."""
    assert scored(trackers=1, permissions=3).score == 75


def test_zero_is_still_reachable_by_a_real_app():
    """0/100 has to keep meaning "measured, and as bad as it gets"."""
    assert scored(trackers=10).score == 0


# ── the word ────────────────────────────────────────────────────────────────


def test_a_failed_scan_is_not_labelled_critical():
    """CRITICAL is a verdict. There was no verdict to reach."""
    assert failed().score_label != "CRITICAL"


def test_the_label_says_it_could_not_be_determined():
    assert failed().score_label in ("N/A", "UNKNOWN")


def test_a_genuinely_critical_app_keeps_the_label():
    assert scored(trackers=10).score_label == "CRITICAL"


# ── what the reader sees ────────────────────────────────────────────────────


def test_the_report_does_not_print_a_number_out_of_a_hundred(capsys):
    from apkradar.cli import _print_result

    _print_result(failed())
    out = capsys.readouterr().out

    assert "0/100" not in out, out
    assert "N/A" in out or "UNKNOWN" in out, out


def test_the_report_still_prints_the_error(capsys):
    """Losing the score must not lose the reason."""
    from apkradar.cli import _print_result

    _print_result(failed())

    assert "EOCD" in capsys.readouterr().out


def test_a_scored_report_is_unchanged(capsys):
    from apkradar.cli import _print_result

    _print_result(scored(trackers=1, permissions=3))

    assert "75/100" in capsys.readouterr().out


# ── the batch line, where the two sat side by side ──────────────────────────


def test_the_batch_line_does_not_claim_counts_it_never_measured(capsys):
    """"0 trackers, 0 sensitive permissions" was the counter, not a finding."""
    from apkradar.cli import _batch_line

    _batch_line(failed())
    out = capsys.readouterr().out

    assert "0 trackers" not in out, out
    assert "0/100" not in out, out


def test_the_batch_line_for_a_real_result_keeps_its_counts(capsys):
    from apkradar.cli import _batch_line

    _batch_line(scored(trackers=1, permissions=3))
    out = capsys.readouterr().out

    assert "75/100" in out
    assert "1 tracker" in out


# ── the spreadsheet ─────────────────────────────────────────────────────────


def test_the_excel_cell_is_empty_rather_than_zero():
    """A 0 in a spreadsheet column gets averaged, sorted and charted."""
    result = failed()
    value = "" if result.score is None else result.score

    assert value == ""
