"""
APKRadar — lo spinner non deve lasciare niente nel buffer di Rich.

Osservato su 112 Where ARE U con rich 15.0.0 e Python 3.14.7, a referto già
stampato per intero e con uscita 0:

    Exception ignored while finalizing file <rich.file_proxy.FileProxy object …>
    Traceback (most recent call last):
      File "…/rich/file_proxy.py", line 53, in flush
      …
    ImportError: sys.meta_path is None, Python is likely shutting down

Mentre `console.status()` gira, Rich sostituisce `sys.stdout` e `sys.stderr` con
un `FileProxy` che trattiene il testo finché non incontra un newline. `Live`
ripristina i flussi originali **senza svuotare quel buffer**: una riga parziale
scritta da una libreria — androguard lo fa — resta lì, e viene stampata soltanto
quando l'interprete finalizza l'oggetto, quando importare non è più possibile.

Un'analisi andata a buon fine finisce quindi con un traceback, e chi guarda non
ha modo di sapere che il risultato era valido: in una dimostrazione quel
messaggio vale più di tutto il referto.

Il test gira in un sottoprocesso perché la finalizzazione è ciò che si sta
misurando, e dentro il processo di pytest non avverrebbe mai.
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
    sys.stdout.write("riga-parziale-senza-newline")
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
    assert "riga-parziale-senza-newline" in proc.stdout
