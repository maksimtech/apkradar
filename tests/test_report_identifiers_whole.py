"""An identifier in a report table is folded onto the next line, never cut.

Measured on 2026-10-09: `apkradar audit fennec.apk --output report.html` through
a pipe — which is how a report is saved from a script, and how Rich settles on
80 columns — wrote the tracker table as

    │ Google advertising ID                │ com.google.android.gms.ads.identifi… │
    │ (AdvertisingIdClient)                │                                      │

The tracker's name was folded, because Rich folds text by default; the package
was cut, because the column was marked `style="dim"` and nothing else, and Rich's
default for a cell it cannot fit is an ellipsis. The saved HTML holds
`identifi…` and nowhere the string `ads.identifier`. That column *is* the
finding — the package is what identifies the SDK, and what a reader greps the
APK for — and a report file does not know how wide the terminal was.

The same applies to the host column of the vendor table, which holds names like
`mlpa-nonprod-dev-mozilla.freetls.fastly.net`.
"""

from __future__ import annotations

import pytest
from rich.console import Console

from apkradar import cli
from apkradar.scanner import ScanResult, TrackerFound

LONG_PACKAGE = "com.google.android.gms.ads.identifier"
LONG_HOST = "weatherapi.market.xiaomi.com"       # Breezy Weather 6.2.2, standard build


@pytest.fixture
def narrow(monkeypatch):
    """The 80 columns Rich falls back to when stdout is not a terminal."""
    console = Console(width=80, force_terminal=False, no_color=True, record=True)
    monkeypatch.setattr(cli, "console", console)
    return console


def _result():
    return ScanResult(
        apk_path="fennec.apk",
        package_name="org.mozilla.fennec_fdroid",
        app_name="Fennec",
        version_name="157.0.0",
        version_code="1570020",
        sha256="04a5f4d3e49fc36a67ff4b530910c994e4ff81d6f6649cf3f75e48ddb49247a9",
        trackers=[TrackerFound(package=LONG_PACKAGE, name="Google advertising ID (AdvertisingIdClient)")],
        dex_hosts=[LONG_HOST, "safebrowsing.googleapis.com", "www.googleapis.com"],
    )


def _column(text: str, index: int) -> str:
    """One table column read down the rows, so a cell folded over two lines is whole again."""
    cells = []
    for line in text.splitlines():
        if line.strip().startswith("│"):
            parts = [part.strip() for part in line.strip().strip("│").split("│")]
            if len(parts) > index:
                cells.append(parts[index])
    return "".join(cells)


def test_the_package_is_written_whole(narrow):
    cli._print_result(_result())
    text = narrow.export_text()
    assert "…" not in text
    assert LONG_PACKAGE in _column(text, 1)


def test_a_long_host_in_the_vendor_table_is_written_whole(monkeypatch):
    """Narrower still, so that the vendor table's host column has to fold too."""
    console = Console(width=56, force_terminal=False, no_color=True, record=True)
    monkeypatch.setattr(cli, "console", console)
    cli._print_result(_result())
    text = console.export_text()
    assert "…" not in text
    assert LONG_HOST in _column(text, 0)
