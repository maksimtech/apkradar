"""androguard's own DEBUG log does not belong in an audit report.

Measured on six real APKs on 2026-09-25: between 98.7% and 99.5% of everything
`apkradar audit` wrote was androguard's loguru output. On fdroid.apk, 8,201 log
lines against 42 lines of report. A reader looking for the findings has to scroll
past nine thousand lines of AXML parser chatter to reach them, and a CI job that
captures the output stores megabytes of it.

androguard 4.1.4 logs through loguru, whose default handler writes DEBUG to
stderr. Nothing in this package ever referenced loguru, so the library's logger
was never quietened.

Checked through loguru's own API rather than by counting lines on stderr: a sink
records which module each entry came from, so the assertion is about androguard
being silenced and not about how many lines some particular APK happens to
produce.
"""

from __future__ import annotations

import contextlib

import pytest

loguru = pytest.importorskip("loguru", reason="androguard logs through loguru")


def _records_from_androguard() -> list[str]:
    """Provoke androguard into logging, and report what reached a sink.

    AXMLPrinter logs at DEBUG on construction — it is the first thing in the
    sample of noise attached to the issue — and it raises on malformed input,
    which is what makes it usable here: no APK file is needed.
    """
    from loguru import logger

    seen: list[str] = []
    handler = logger.add(lambda m: seen.append(m.record["name"]), level="DEBUG")
    try:
        from androguard.core.axml import AXMLPrinter

        # It raises on malformed input, which is fine: the log happens first, and
        # the log is what is being measured.
        with contextlib.suppress(Exception):
            AXMLPrinter(b"\x03\x00\x08\x00" + b"\x00" * 20)
    finally:
        logger.remove(handler)
    return [name for name in seen if name and name.startswith("androguard")]


def test_importing_the_scanner_silences_androguard():
    """Importing the package is enough: no call has to remember to do it."""
    import apkradar.scanner  # noqa: F401 — imported for its effect

    assert _records_from_androguard() == []


def test_the_silencing_is_not_a_blanket_mute():
    """Only androguard is quietened; this package's own logging must survive.

    logger.disable() takes a module prefix, and disabling the wrong one — or
    everything — would hide a real message from apkradar itself.
    """
    from loguru import logger

    import apkradar.scanner  # noqa: F401

    seen: list[str] = []
    handler = logger.add(lambda m: seen.append(m.record["message"]), level="DEBUG")
    try:
        logger.debug("a message from apkradar")
    finally:
        logger.remove(handler)

    assert "a message from apkradar" in seen


def test_verbose_puts_androguards_log_back():
    """--verbose asks for this level of detail, so it has to deliver it.

    Before this, the flag only affected the full-stack messages and the library
    log appeared whether it was passed or not — which is the wrong way round.
    """
    import apkradar.scanner as scanner

    assert hasattr(scanner, "set_library_logging"), (
        "no way to re-enable androguard's log for --verbose"
    )

    scanner.set_library_logging(True)
    try:
        assert _records_from_androguard() != []
    finally:
        scanner.set_library_logging(False)

    assert _records_from_androguard() == []


# ── the flag has to reach it ────────────────────────────────────────────────


@pytest.mark.parametrize("verbose", [False, True])
def test_audit_passes_the_verbose_flag_through(monkeypatch, tmp_path, verbose):
    """The function existing is not enough if the command never calls it.

    Before this, --verbose changed only the full-stack messages: androguard's log
    appeared whether it was passed or not, which is the wrong way round for a
    flag whose whole purpose is asking for detail.
    """
    from typer.testing import CliRunner

    import apkradar.cli as cli
    import apkradar.scanner as scanner

    # Patched on the module, not on cli: audit imports both names inside its own
    # body, so the rebinding happens at call time and this is what it picks up.
    # The scan itself is left to run and fail on four bytes — the assertion is
    # about the flag reaching the library, and that happens before the scan.
    asked: list[bool] = []
    monkeypatch.setattr(scanner, "set_library_logging", lambda on: asked.append(on))

    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK\x03\x04")
    args = ["audit", str(apk)] + (["--verbose"] if verbose else [])
    CliRunner().invoke(cli.app, args)

    assert asked and asked[0] is verbose, asked
