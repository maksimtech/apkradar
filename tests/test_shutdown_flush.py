"""
APKRadar — the spinner must leave nothing in Rich's buffer.

While `console.status()` runs, Rich replaces `sys.stdout` and `sys.stderr` with a
`FileProxy` that holds text until it meets a newline. `Live` puts the original
streams back **without flushing that buffer**: a partial line written by a library
stays there, and is printed only when the interpreter finalises the object, at a
point where importing is no longer possible:

    Exception ignored while finalizing file <rich.file_proxy.FileProxy object …>
    ImportError: sys.meta_path is None, Python is likely shutting down

Observed on 112 Where ARE U with rich 15.0.0 and Python 3.14.7, with the report
already printed in full and an exit code of 0.

A successful analysis therefore ends in a traceback, and whoever is watching has
no way of knowing the result was valid: in a demonstration that message counts
for more than the whole report.

The test runs in a subprocess because finalisation is the thing being measured,
and inside pytest's own process it would never happen. It needs a `Console` that
believes it is a terminal: Rich installs the proxy only in that case, which is why
the defect cannot be seen through a pipe.
"""
import subprocess
import sys

# Un `Console` che si crede un terminale: Rich installa il proxy solo in quel
# caso, ed è la ragione per cui in pipe il difetto non si vede.
_SHUTDOWN_SCRIPT = """
import sys
from unittest.mock import patch

import typer
from rich.console import Console

import apkradar.cli as cli
import apkradar.scanner as scanner
from apkradar.scanner import ScanResult


def fake_scan(path, **kwargs):
    # Una libreria che tiene un riferimento a sys.stdout mantiene vivo il
    # FileProxy di Rich oltre la fine dello spinner, con la riga parziale dentro.
    global held_stdout
    held_stdout = sys.stdout
    sys.stdout.write("partial-line-without-newline")
    return ScanResult(apk_path=path, error="analisi finta")


with patch.object(scanner, "scan", fake_scan), \\
     patch.object(cli, "console", Console(force_terminal=True, width=250)):
    try:
        cli.app(["audit", "qualsiasi.apk"], standalone_mode=False)
    except typer.Exit:
        pass
"""


def test_audit_leaves_nothing_in_the_proxy_buffer():
    proc = subprocess.run(
        [sys.executable, "-c", _SHUTDOWN_SCRIPT],
        capture_output=True, text=True, timeout=120,
        encoding="utf-8", errors="replace",
    )

    assert proc.returncode == 0, proc.stderr
    assert "sys.meta_path is None" not in proc.stderr
    assert "Exception ignored" not in proc.stderr
    # E la riga parziale non va persa: svuotare il buffer significa stamparla,
    # non buttarla. Una correzione che la scartasse passerebbe i due controlli
    # sopra e nasconderebbe l'output di una libreria.
    assert "partial-line-without-newline" in proc.stdout
