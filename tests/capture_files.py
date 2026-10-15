"""Real network captures for the tests: classic pcap files written byte by byte.

Derived data, like android_files.py: no capture of anything but the recorded fixture
is committed, so the ones the tests read are built here from the formats themselves —
the pcap file header and record headers of libpcap, IPv4 (RFC 791) and IPv6 (RFC 8200)
headers, TCP and UDP, a DNS message (RFC 1035), a TLS ClientHello with its
server_name extension (RFC 8446, RFC 6066) and an HTTP/1.1 request. Checksums are left
at zero: nothing that reads a capture after the fact verifies them, and neither does
the code under test.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101


def client_hello(server_name: str) -> bytes:
    """A TLS record holding a ClientHello whose only extension is server_name."""
    name = server_name.encode("ascii")
    entry = b"\x00" + struct.pack(">H", len(name)) + name           # host_name(0), length, name
    sni = struct.pack(">HH", 0, len(entry) + 2) + struct.pack(">H", len(entry)) + entry
    body = (
        b"\x03\x03" + b"\x00" * 32                                    # legacy_version, random
        + b"\x00"                                                     # session id: empty
        + struct.pack(">H", 2) + b"\x13\x01"                          # one cipher suite
        + b"\x01\x00"                                                 # compression: null
        + struct.pack(">H", len(sni)) + sni
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def http_request(host: str, path: str = "/") -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n".encode("ascii")


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def dns_query(name: str, ident: int = 1, qtype: int = 1) -> bytes:
    return struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _qname(name) + struct.pack(">HH", qtype, 1)


def dns_response(name: str, address: str, ident: int = 1) -> bytes:
    """A response with one answer, A or AAAA depending on `address`, compressed onto the question."""
    v6 = ":" in address
    rdata = socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, address)
    qtype = 28 if v6 else 1
    question = _qname(name) + struct.pack(">HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(rdata)) + rdata
    return struct.pack(">HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question + answer


def tcp(sport: int, dport: int, payload: bytes = b"") -> tuple[int, bytes]:
    return 6, struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> tuple[int, bytes]:
    return 17, struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def ip(src: str, dst: str, segment: tuple[int, bytes]) -> bytes:
    """An IPv4 or IPv6 packet carrying `segment`, as returned by tcp() or udp()."""
    proto, body = segment
    if ":" in src:
        return (
            struct.pack(">IHBB", 6 << 28, len(body), proto, 64)
            + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + body
        )
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + body


def ethernet(packet: bytes) -> bytes:
    ethertype = 0x86DD if packet[0] >> 4 == 6 else 0x0800
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack(">H", ethertype) + packet


def pcap(packets: list[tuple[float, bytes]], linktype: int = LINKTYPE_RAW) -> bytes:
    """A classic pcap file, little-endian, microsecond timestamps."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, data in packets:
        sec = int(ts)
        out += struct.pack("<IIII", sec, round((ts - sec) * 1_000_000), len(data), len(data)) + data
    return out


def write_capture(path: str | Path, packets: list[tuple[float, bytes]], linktype: int = LINKTYPE_RAW) -> str:
    Path(path).write_bytes(pcap(packets, linktype))
    return str(path)
