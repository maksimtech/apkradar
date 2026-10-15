"""The hosts an app contacts at runtime, read from a capture, against the hosts its code carries.

`apkradar.hosts` reports what the DEX can reach and says, on purpose, that it is not
traffic. This is the other half: a capture taken while the app runs — PCAPdroid on a
phone, tcpdump on an emulator — read for the names the connections went to, and set
against the DEX. Nothing here contacts anything: the capture is a file already on disk.

Two kinds of input. The derived captures are written by tests/capture_files.py from the
packet formats. The recorded one, pcapdroid_kids_app_first_launch_recorded.pcap, was
taken on 2026-10-15 on a Motorola moto g17 (Android 15) with PCAPdroid 1.9.1, filtered
on com.gameitech.preschool.abc123.tracing.learning 1.8 at its first launch after
`pm clear`, with nobody touching the screen for 64 seconds. Of its 917 packets the
fixture keeps the 30 that are DNS or a TLS ClientHello, byte for byte, with their
original record headers: the rest is encrypted and adds nothing a test can read.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkradar import observe
from apkradar.cli import app
from apkradar.scanner import ScanResult
from tests.android_files import dex_blob, manifest, write_apk
from tests.capture_files import (
    LINKTYPE_ETHERNET,
    client_hello,
    dns_query,
    dns_response,
    ethernet,
    http_request,
    ip,
    tcp,
    udp,
    write_capture,
)

FIXTURES = Path(__file__).parent / "fixtures"
RECORDED = FIXTURES / "pcapdroid_kids_app_first_launch_recorded.pcap"

PHONE = "10.215.173.1"       # PCAPdroid's VPN address on the device
GOOGLE = "142.250.180.66"    # one Google front end serving several names
DNS = "10.215.173.2"

runner = CliRunner()


def by_name(capture: observe.Capture) -> dict[str, observe.ObservedHost]:
    return {h.host: h for h in capture.hosts}


# --- reading a capture ----------------------------------------------------------


def test_the_name_comes_from_the_tls_server_name(tmp_path):
    path = write_capture(tmp_path / "c.pcap", [(100.0, ip(PHONE, GOOGLE, tcp(40001, 443, client_hello("a.example"))))])
    found = by_name(observe.read_capture(path))
    assert list(found) == ["a.example"]
    assert found["a.example"].how == frozenset({"tls"})


def test_two_connections_to_one_address_keep_their_own_bytes(tmp_path):
    """Google serves many names from one address. Grouping by server address summed
    every connection to it under each of its names — measured on the recorded
    capture before this test existed, where two hosts showed the same 406,060 bytes."""
    a = ip(PHONE, GOOGLE, tcp(40001, 443, client_hello("a.example")))
    b = ip(PHONE, GOOGLE, tcp(40002, 443, client_hello("b.example") + b"\x00" * 100))
    found = by_name(observe.read_capture(write_capture(tmp_path / "c.pcap", [(1.0, a), (2.0, b)])))
    assert found["a.example"].bytes == len(a)
    assert found["b.example"].bytes == len(b)


def test_both_directions_of_a_connection_are_counted(tmp_path):
    hello = ip(PHONE, GOOGLE, tcp(40001, 443, client_hello("a.example")))
    reply = ip(GOOGLE, PHONE, tcp(443, 40001, b"\x17\x03\x03" + b"\x00" * 200))
    found = by_name(observe.read_capture(write_capture(tmp_path / "c.pcap", [(1.0, hello), (1.2, reply)])))
    assert found["a.example"].bytes == len(hello) + len(reply)


def test_first_contact_is_counted_from_the_first_packet_of_the_capture(tmp_path):
    packets = [
        (50.0, ip(PHONE, DNS, udp(5353, 53, dns_query("a.example")))),
        (52.5, ip(PHONE, GOOGLE, tcp(40001, 443, client_hello("a.example")))),
    ]
    capture = observe.read_capture(write_capture(tmp_path / "c.pcap", packets))
    assert by_name(capture)["a.example"].first_seen == pytest.approx(2.5)
    assert capture.duration == pytest.approx(2.5)


def test_a_connection_without_a_server_name_is_named_by_the_dns_answer(tmp_path):
    """QUIC carries its server name encrypted, so a UDP 443 flow is known only by the
    address the DNS answered with."""
    packets = [
        (1.0, ip(DNS, PHONE, udp(53, 5353, dns_response("quic.example", GOOGLE)))),
        (1.1, ip(PHONE, GOOGLE, udp(40001, 443, b"\xc0" + b"\x00" * 60))),
    ]
    found = by_name(observe.read_capture(write_capture(tmp_path / "c.pcap", packets)))
    assert found["quic.example"].how == frozenset({"dns"})


def test_an_address_nothing_names_is_reported_as_the_address(tmp_path):
    packets = [(1.0, ip(PHONE, "203.0.113.9", tcp(40001, 8443, b"\x00" * 10)))]
    found = by_name(observe.read_capture(write_capture(tmp_path / "c.pcap", packets)))
    assert found["203.0.113.9"].how == frozenset({"address"})


def test_plain_http_is_named_by_its_host_header_and_flagged(tmp_path):
    packets = [(1.0, ip(PHONE, "198.51.100.7", tcp(40001, 80, http_request("cleartext.example"))))]
    host = by_name(observe.read_capture(write_capture(tmp_path / "c.pcap", packets)))["cleartext.example"]
    assert host.how == frozenset({"http"})
    assert host.cleartext


def test_the_names_asked_of_dns_are_kept_in_order(tmp_path):
    packets = [
        (1.0, ip(PHONE, DNS, udp(5353, 53, dns_query("first.example", ident=1)))),
        (2.0, ip(PHONE, DNS, udp(5354, 53, dns_query("second.example", ident=2)))),
        (3.0, ip(PHONE, DNS, udp(5355, 53, dns_query("first.example", ident=3)))),
    ]
    capture = observe.read_capture(write_capture(tmp_path / "c.pcap", packets))
    assert capture.dns_names == ("first.example", "second.example")


def test_ipv6_is_read(tmp_path):
    phone6, server6 = "fd00::1", "2a00:1450:4002:80b::2002"
    packets = [
        (1.0, ip("fd00::53", phone6, udp(53, 5353, dns_response("six.example", server6)))),
        (1.1, ip(phone6, server6, tcp(40001, 443, client_hello("six.example")))),
    ]
    found = by_name(observe.read_capture(write_capture(tmp_path / "c.pcap", packets)))
    assert found["six.example"].how == frozenset({"tls"})


def test_an_ethernet_capture_is_read_like_a_raw_one(tmp_path):
    """tcpdump on an emulator or a laptop writes Ethernet frames; PCAPdroid writes raw IP."""
    frame = ethernet(ip(PHONE, GOOGLE, tcp(40001, 443, client_hello("eth.example"))))
    capture = observe.read_capture(write_capture(tmp_path / "c.pcap", [(1.0, frame)], linktype=LINKTYPE_ETHERNET))
    assert "eth.example" in by_name(capture)


def test_a_pcapng_file_is_refused_by_name(tmp_path):
    """PCAPdroid, tcpdump -w and Wireshark's "pcap" all write the classic format this
    reads. A pcapng file is refused with the conversion to run, not read as garbage."""
    path = tmp_path / "c.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    with pytest.raises(observe.CaptureError, match="pcapng"):
        observe.read_capture(path)


def test_a_link_type_this_cannot_read_is_refused_by_number(tmp_path):
    """Linux cooked capture (113) is what `tcpdump -i any` writes. Reading its frames
    as IP would yield no host and look like an app that contacted nothing."""
    path = write_capture(tmp_path / "c.pcap", [(1.0, b"\x00" * 40)], linktype=113)
    with pytest.raises(observe.CaptureError, match="link type 113"):
        observe.read_capture(path)


def test_a_file_that_is_no_capture_is_refused(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a capture", encoding="utf-8")
    with pytest.raises(observe.CaptureError, match="not a pcap"):
        observe.read_capture(path)


def test_a_truncated_capture_yields_what_it_holds(tmp_path):
    """A capture stopped mid-write ends in half a record. What came before it is
    still evidence and is returned."""
    hello = ip(PHONE, GOOGLE, tcp(40001, 443, client_hello("a.example")))
    path = Path(write_capture(tmp_path / "c.pcap", [(1.0, hello)]))
    path.write_bytes(path.read_bytes() + b"\x01\x02\x03")
    assert "a.example" in by_name(observe.read_capture(path))


# --- the recorded capture ----------------------------------------------------------


def test_the_recorded_first_launch_names_the_ad_server_first():
    capture = observe.read_capture(RECORDED)
    order = [h.host for h in capture.hosts]
    assert order[0] == "googleads.g.doubleclick.net"
    assert set(order) == {
        "googleads.g.doubleclick.net", "www.gstatic.com", "fonts.googleapis.com", "fonts.gstatic.com",
        "lh3.googleusercontent.com", "pagead2.googlesyndication.com", "csi.gstatic.com",
    }
    assert all(h.how == frozenset({"tls"}) for h in capture.hosts)
    assert capture.hosts[0].first_seen < 2.0


def test_the_recorded_first_launch_asked_dns_for_the_quic_host_too():
    """www.googletagservices.com went over QUIC, whose packets the fixture does not
    keep; its DNS query is there."""
    assert "www.googletagservices.com" in observe.read_capture(RECORDED).dns_names


# --- against the code --------------------------------------------------------------


def _capture_of(*names: str) -> observe.Capture:
    hosts = tuple(observe.ObservedHost(n, float(i), 100, frozenset({"tls"}), False) for i, n in enumerate(names))
    return observe.Capture(hosts=hosts, dns_names=names, duration=float(len(names)), packets=len(names))


def test_contacted_hosts_are_split_by_whether_the_code_carries_them():
    code = ["googleads.g.doubleclick.net", "only-in-the-code.example.net"]
    result = observe.compare(code, _capture_of("googleads.g.doubleclick.net", "www.gstatic.com"))
    assert result.in_code == ("googleads.g.doubleclick.net",)
    assert result.runtime_only == ("www.gstatic.com",)


def test_a_consent_platform_in_the_code_and_never_contacted_is_reported():
    """The finding of the recorded run: Google's consent SDK is in the DEX, an ad is
    requested in the first second, and the consent platform is never asked."""
    code = ["fundingchoicesmessages.google.com", "googleads.g.doubleclick.net"]
    result = observe.compare(code, _capture_of("googleads.g.doubleclick.net"))
    assert result.consent_not_contacted == (("fundingchoicesmessages.google.com", "Google UMP"),)
    assert result.consent_contacted == ()


def test_a_consent_platform_contacted_is_reported_with_its_first_contact():
    capture = _capture_of("googleads.g.doubleclick.net", "sdk.privacy-center.org")
    result = observe.compare([], capture)
    assert result.consent_contacted == (("sdk.privacy-center.org", "Didomi"),)


def test_a_consent_platform_is_matched_on_a_whole_label():
    assert observe.consent_platform("cookielaw.org.attacker.example") is None
    assert observe.consent_platform("cdn.cookielaw.org") == "OneTrust"


# --- the command --------------------------------------------------------------------


def _apk(tmp_path: Path, *urls: str) -> str:
    return write_apk(tmp_path / "app.apk", manifest("com.example.kids"), dex=dex_blob(urls=urls))


def test_observe_reports_the_runtime_hosts_against_the_code(tmp_path):
    apk = _apk(tmp_path, "https://googleads.g.doubleclick.net/mads/gma", "https://fundingchoicesmessages.google.com/a")
    outcome = runner.invoke(app, ["observe", apk, "--capture", str(RECORDED)], terminal_width=200)
    assert outcome.exit_code == 0, outcome.output
    text = " ".join(outcome.output.split())     # Rich folds long lines at its own width
    assert "Hosts contacted at runtime (7" in text
    assert "googleads.g.doubleclick.net" in text and "www.gstatic.com" in text
    assert "fundingchoicesmessages.google.com" in text
    assert "never contacted during the capture" in text


def test_observe_refuses_an_unreadable_capture_before_opening_the_apk(tmp_path):
    bad = tmp_path / "c.pcapng"
    bad.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    outcome = runner.invoke(app, ["observe", str(tmp_path / "missing.apk"), "--capture", str(bad)])
    assert outcome.exit_code == 2
    assert "pcapng" in outcome.output
    assert "Auditing" not in outcome.output


def test_observe_needs_a_capture():
    outcome = runner.invoke(app, ["observe", "app.apk"])
    assert outcome.exit_code != 0


def test_the_scan_result_hosts_are_what_compare_reads():
    """observe passes the scanner's own host list: the same list the audit prints."""
    result = ScanResult(apk_path="a.apk", dex_hosts=["googleads.g.doubleclick.net"])
    assert observe.compare(result.dex_hosts, _capture_of("googleads.g.doubleclick.net")).in_code
