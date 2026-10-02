"""The console block for the hosts an APK carries in its code.

The extraction has its own tests; this is about what a reader is told about it,
and the sentence that matters most is the one that refuses a claim. A host in a
DEX string literal is a host the code *can* reach. An app offering fifty weather
providers carries fifty endpoints and talks to the one that is configured, so the
block says "reachable by the code, not observed in traffic" and deducts nothing.
A reader who takes the list for traffic has been given a list of accusations.

Three more things are asserted because each one is a place the block could lie by
omission: a truncated list has to say it stopped, a list longer than the display
limit has to count what it is not showing, and a specification URI has to be kept
and labelled rather than quietly dropped — a tool that reclassifies an endpoint as
documentation hides exactly what it was built to show.

`cli.console` is replaced with a fresh recording Console rather than having its
`file` reassigned. That attribute is a property that falls back to `sys.stdout`,
so reading it and putting it back pins the stream for every test that runs after —
which is a bug this suite has already had once.
"""

from __future__ import annotations

import pytest
from rich.console import Console

from apkradar import cli
from apkradar.scanner import ScanResult


@pytest.fixture
def printed(monkeypatch):
    """Whatever the block wrote, as plain text with the wrapping taken out."""
    console = Console(width=120, force_terminal=False, no_color=True, record=True)
    monkeypatch.setattr(cli, "console", console)

    def render(**fields) -> str:
        cli._print_hosts(ScanResult(apk_path="sample.apk", **fields))
        return " ".join(console.export_text().split())

    return render


def test_nothing_carried_prints_no_block(printed):
    """Not an empty section: an APK with no hosts in its code gets no heading.

    The DEX of a small app really does hold none, and a heading over an empty
    space reads as a failed extraction.
    """
    assert printed(dex_hosts=[]) == ""


def test_the_count_and_the_refusal_travel_together(printed):
    text = printed(dex_hosts=["api.example.com", "cdn.example.net"])

    assert "2 endpoints" in text
    assert "not observed in traffic" in text


def test_one_endpoint_is_not_called_endpoints(printed):
    # The closing bracket is part of the assertion: without it "1 endpoint" also
    # matches "1 endpoints", which is the thing being ruled out.
    assert "(1 endpoint)" in printed(dex_hosts=["api.example.com"])


def test_a_specification_uri_is_counted_apart_from_the_endpoints(printed):
    """`w3.org` arrives as an XML namespace, not as a server the code calls."""
    text = printed(dex_hosts=["api.example.com", "w3.org"])

    assert "1 endpoint" in text
    assert "1 reference" in text
    assert "references: w3.org" in text


def test_a_vendor_behind_a_host_is_named(printed):
    """The overlap with the transfer check, and the reason the extraction exists:
    an app can carry Google endpoints while shipping none of Google's SDKs."""
    text = printed(dex_hosts=["googleapis.com", "api.example.com"])

    assert "Google LLC (USA)" in text
    assert "under a vendor this tool reports on (1)" in text


def test_no_vendor_table_when_no_host_has_one(printed):
    text = printed(dex_hosts=["api.example.com"])

    assert "under a vendor" not in text


def test_a_truncated_list_says_where_it_stopped(printed):
    """Silence here would be the worst case in the block: a reader would take a
    capped list for the whole of it."""
    text = printed(dex_hosts=["api.example.com"], dex_hosts_truncated=True)

    assert "stopped at 1" in text


def test_beyond_the_display_limit_the_rest_are_counted_not_listed(printed):
    """The count stays true even though the list is cut — the alternative is a
    dump that has stopped being evidence."""
    many = [f"h{n:03d}.example.com" for n in range(cli.HOSTS_SHOWN + 5)]

    text = printed(dex_hosts=many)

    assert f"{cli.HOSTS_SHOWN + 5} endpoints" in text
    assert "and 5 more" in text
    assert many[0] in text
    assert many[cli.HOSTS_SHOWN] not in text


def test_a_list_that_fits_is_shown_whole_with_nothing_added(printed):
    many = [f"h{n:03d}.example.com" for n in range(cli.HOSTS_SHOWN)]

    text = printed(dex_hosts=many)

    assert "more" not in text
    assert many[-1] in text
