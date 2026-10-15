"""
APKRadar — the hosts an app contacts at runtime, against the hosts its code carries.

`apkradar.hosts` reads the DEX and says what the code *can* reach; it is careful not
to call that traffic. This module reads what an app *did* reach: a capture taken while
it ran — PCAPdroid on a phone, filtered on the app, or tcpdump on an emulator — and
sets the names its connections went to against the DEX.

Measured on 2026-10-15 on a children's tracing app, first launch after `pm clear`,
nobody touching the screen: an ad request to googleads.g.doubleclick.net within the
first second, then eight hosts in the first eighteen seconds, five of them carried
nowhere in the DEX because the ad's own content requests them at runtime — and
fundingchoicesmessages.google.com, the consent platform of the SDK in the DEX, never
contacted. Neither half could show that alone.

What it reads is names, not content. A connection is named by the server name of its
TLS ClientHello, by the Host header of a plain HTTP request, by the DNS answer for its
address, or, when nothing names it, by the address. Nothing is decrypted, and nothing
is contacted: the capture is a file already on disk.
"""
from __future__ import annotations

import datetime
import json
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

# The consent platforms whose endpoints are known, by registrable domain or exact
# host, matched on a whole label. Not a list of every CMP: one that is not here is
# simply not labelled, and the report says only what this list can support.
CONSENT_HOSTS = {
    "fundingchoicesmessages.google.com": "Google UMP",
    "privacy-center.org": "Didomi",
    "cookielaw.org": "OneTrust",
    "onetrust.io": "OneTrust",
    "cookiebot.com": "Cookiebot",
    "usercentrics.eu": "Usercentrics",
    "cmp.inmobi.com": "InMobi Choice",
}

# Link types read: Ethernet, and raw IP as PCAPdroid writes it (101; 228 and 229 are
# raw IPv4 and raw IPv6). Anything else is refused by number: read as IP, its frames
# would yield no host, which looks exactly like an app that contacted nothing.
_LINKTYPE_ETHERNET = 1
_LINKTYPES_RAW = {101, 228, 229}

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class CaptureError(ValueError):
    """The file is not a capture this module can read; the message says what to do."""


@dataclass(frozen=True)
class ObservedHost:
    host: str
    first_seen: float          # seconds from the first packet of the capture
    bytes: int                 # both directions, every connection to this name
    how: frozenset[str]        # "tls", "http", "dns" or "address": what named it
    cleartext: bool            # a plain HTTP request went to it


@dataclass(frozen=True)
class Capture:
    hosts: tuple[ObservedHost, ...]    # by first contact
    dns_names: tuple[str, ...]         # names asked of DNS, in the order first asked
    duration: float
    packets: int


@dataclass(frozen=True)
class Comparison:
    in_code: tuple[str, ...]                          # contacted, and carried in the DEX
    runtime_only: tuple[str, ...]                     # contacted, carried nowhere in the DEX
    consent_contacted: tuple[tuple[str, str], ...]    # (host, platform)
    consent_not_contacted: tuple[tuple[str, str], ...]


def consent_platform(host: str) -> str | None:
    """The consent platform `host` belongs to, for the platforms in CONSENT_HOSTS."""
    host = host.lower().rstrip(".")
    for domain, platform in CONSENT_HOSTS.items():
        if host == domain or host.endswith("." + domain):
            return platform
    return None


def _records(path: str | Path):
    """(timestamp, IP packet) for every record of a classic pcap file."""
    data = Path(path).read_bytes()
    if data[:4] == _PCAPNG_MAGIC:
        raise CaptureError(
            f"{Path(path).name} is pcapng; this reads classic pcap. Convert it with "
            "`editcap -F pcap <in.pcapng> <out.pcap>`, or save it as pcap"
        )
    if len(data) < 24 or data[:4] not in _MAGIC:
        raise CaptureError(f"{Path(path).name} is not a pcap capture")
    endian, scale = _MAGIC[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    if linktype != _LINKTYPE_ETHERNET and linktype not in _LINKTYPES_RAW:
        raise CaptureError(
            f"{Path(path).name} has link type {linktype}; this reads Ethernet (1) and raw IP (101)"
        )
    offset = 24
    while offset + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(endian + "IIII", data[offset:offset + 16])
        frame = data[offset + 16:offset + 16 + incl]
        if len(frame) < incl:
            break               # a capture stopped mid-write: what came before stands
        offset += 16 + incl
        if linktype == _LINKTYPE_ETHERNET:
            ethertype = struct.unpack(">H", frame[12:14])[0] if len(frame) >= 14 else 0
            if ethertype not in (0x0800, 0x86DD):
                continue
            frame = frame[14:]
        yield sec + frac / scale, frame


def _ip(packet: bytes) -> tuple[str, str, int, bytes] | None:
    """(source, destination, protocol, payload) of an IPv4 or IPv6 packet."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        ihl = (packet[0] & 0x0F) * 4
        return (socket.inet_ntop(socket.AF_INET, packet[12:16]), socket.inet_ntop(socket.AF_INET, packet[16:20]),
                packet[9], packet[ihl:])
    if version == 6 and len(packet) >= 40:
        return (socket.inet_ntop(socket.AF_INET6, packet[8:24]), socket.inet_ntop(socket.AF_INET6, packet[24:40]),
                packet[6], packet[40:])
    return None


def _dns_name(msg: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    for _ in range(128):
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            end = offset + 2 if end is None else end
            offset = ((length & 0x3F) << 8) | msg[offset + 1]
            continue
        if length == 0:
            return ".".join(labels).lower(), (offset + 1 if end is None else end)
        labels.append(msg[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    raise ValueError("DNS name loops")


def _dns(msg: bytes) -> tuple[list[str], list[str]]:
    """(names asked, addresses answered) of one DNS message.

    The answered addresses belong to the name *asked*, not to the last name of a CNAME
    chain: googleads.g.doubleclick.net answers through pagead46.l.doubleclick.net, and
    the app asked for the first.
    """
    qdcount, ancount = struct.unpack(">HH", msg[4:8])
    offset, asked, addresses = 12, [], []
    for _ in range(qdcount):
        name, offset = _dns_name(msg, offset)
        asked.append(name)
        offset += 4
    for _ in range(ancount):
        _, offset = _dns_name(msg, offset)
        rtype, _, _, rdlength = struct.unpack(">HHIH", msg[offset:offset + 10])
        offset += 10
        rdata = msg[offset:offset + rdlength]
        if rtype == 1 and rdlength == 4:
            addresses.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == 28 and rdlength == 16:
            addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))
        offset += rdlength
    return asked, addresses


def _server_name(payload: bytes) -> str | None:
    """The server_name of a TLS ClientHello, or None."""
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 9 + 2 + 32
        p += 1 + payload[p]
        p += 2 + struct.unpack(">H", payload[p:p + 2])[0]
        p += 1 + payload[p]
        end = p + 2 + struct.unpack(">H", payload[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", payload[p:p + 4])
            if ext_type == 0:
                length = struct.unpack(">H", payload[p + 7:p + 9])[0]
                return payload[p + 9:p + 9 + length].decode("ascii", "replace").lower()
            p += 4 + ext_len
    except (IndexError, struct.error):
        return None
    return None


_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def _http_host(payload: bytes) -> str | None:
    if not payload.startswith(_HTTP_METHODS):
        return None
    for line in payload.split(b"\r\n")[1:]:
        if not line:
            break
        if line.lower().startswith(b"host:"):
            return line[5:].strip().split(b":")[0].decode("ascii", "replace").lower()
    return None


@dataclass
class _Connection:
    first: float
    bytes: int = 0
    tls: str | None = None
    http: str | None = None


def read_capture(path: str | Path) -> Capture:
    """The hosts a capture's connections went to, by first contact.

    A connection is one client port talking to one server address and port. Grouping
    by server address alone summed every connection to a front end that serves many
    names — measured on Google's — under each of those names.
    """
    start: float | None = None
    last = 0.0
    packets = 0
    named_by_dns: dict[str, str] = {}
    asked: dict[str, None] = {}
    connections: dict[tuple[str, int, int, int], _Connection] = {}
    for ts, frame in _records(path):
        packets += 1
        start = ts if start is None else start
        last = ts
        layer = _ip(frame)
        if layer is None:
            continue
        src, dst, proto, body = layer
        if proto not in (6, 17) or len(body) < 8:
            continue
        sport, dport = struct.unpack(">HH", body[:4])
        payload = body[(body[12] >> 4) * 4:] if proto == 6 and len(body) >= 20 else body[8:]
        if proto == 17 and 53 in (sport, dport):
            try:
                names, addresses = _dns(payload)
            except (IndexError, ValueError, struct.error):
                continue
            for name in names:
                asked.setdefault(name)
            for address in addresses:
                if names:
                    named_by_dns[address] = names[0]
            continue
        server, port, client = (dst, dport, sport) if dport < sport else (src, sport, dport)
        conn = connections.setdefault((server, port, proto, client), _Connection(first=ts - start))
        conn.bytes += len(frame)
        if proto == 6 and payload:
            conn.tls = conn.tls or _server_name(payload)
            conn.http = conn.http or _http_host(payload)

    if start is None:
        return Capture(hosts=(), dns_names=(), duration=0.0, packets=0)

    gathered: dict[str, dict] = {}
    for (server, _port, _proto, _client), conn in connections.items():
        if conn.tls:
            name, how = conn.tls, "tls"
        elif conn.http:
            name, how = conn.http, "http"
        elif server in named_by_dns:
            name, how = named_by_dns[server], "dns"
        else:
            name, how = server, "address"
        entry = gathered.setdefault(name, {"first": conn.first, "bytes": 0, "how": set(), "cleartext": False})
        entry["first"] = min(entry["first"], conn.first)
        entry["bytes"] += conn.bytes
        entry["how"].add(how)
        entry["cleartext"] = entry["cleartext"] or conn.http is not None

    hosts = tuple(sorted(
        (
            ObservedHost(name, e["first"], e["bytes"], frozenset(e["how"]), e["cleartext"])
            for name, e in gathered.items()
        ),
        key=lambda h: (h.first_seen, h.host),
    ))
    return Capture(hosts=hosts, dns_names=tuple(asked), duration=last - start, packets=packets)


# --- decrypted traffic --------------------------------------------------------------
#
# A capture names hosts; it cannot say what an ad request asked for. Decrypted traffic
# can, and HAR 1.2 is what mitmproxy, HTTP Toolkit, Charles and the browsers export:
# JSON, read without a library. Only the requests of the Google Mobile Ads SDK are
# read, and only for parameters Google documents; the many it does not (`adid_p`,
# `idtypel`, `pvidl`, ...) are left alone rather than guessed at.

_AD_HOST = "googleads.g.doubleclick.net"
_AD_PATH = "/mads/gma"


@dataclass(frozen=True)
class HttpRequest:
    at: float                       # seconds from the first entry
    method: str
    host: str
    path: str
    params: dict[str, str] = field(repr=False)   # query and form body; may hold identifiers


@dataclass(frozen=True)
class AdRequest:
    at: float
    path: str
    app: str | None                 # msid
    format: str | None
    child_directed: str | None      # tfcd
    under_age: str | None           # tfua
    non_personalized: str | None    # npa
    advertising_id: bool            # rdid present and not empty; the value is never kept
    gdpr: str | None
    consent_string: bool            # gdpr_consent present and not empty
    max_content_rating: str | None  # max_ad_content_rating
    test_request: bool              # adtest=on: an emulator or a registered test device


def read_har(path: str | Path) -> tuple[HttpRequest, ...]:
    """Every request of a HAR file, with its query and form parameters, by time."""
    name = Path(path).name
    try:
        data = json.loads(Path(path).read_bytes().decode("utf-8"))
        entries = data["log"]["entries"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise CaptureError(f"{name} is not a HAR file; export the decrypted traffic as HAR 1.2") from exc
    requests: list[tuple[float, HttpRequest]] = []
    for item in entries:
        req = item.get("request") or {}
        url = urlsplit(req.get("url", ""))
        params = dict(parse_qsl(url.query, keep_blank_values=True))
        post = req.get("postData") or {}
        if "x-www-form-urlencoded" in post.get("mimeType", "") and post.get("text"):
            params.update(parse_qsl(post["text"], keep_blank_values=True))
        try:
            started = datetime.datetime.fromisoformat(item["startedDateTime"]).timestamp()
        except (KeyError, ValueError):
            started = 0.0
        host = (url.hostname or "").lower()
        requests.append((started, HttpRequest(0.0, req.get("method", ""), host, url.path, params)))
    if not requests:
        return ()
    first = min(t for t, _ in requests)
    return tuple(sorted(
        (HttpRequest(t - first, r.method, r.host, r.path, r.params) for t, r in requests), key=lambda r: r.at
    ))


def ad_requests(requests: tuple[HttpRequest, ...] | list[HttpRequest]) -> list[AdRequest]:
    """The ad requests of the Google Mobile Ads SDK, with the documented parameters that matter here."""
    found = []
    for r in requests:
        if r.host != _AD_HOST or r.path != _AD_PATH:
            continue
        p = r.params
        found.append(AdRequest(
            at=r.at, path=r.path, app=p.get("msid"), format=p.get("format"),
            child_directed=p.get("tfcd"), under_age=p.get("tfua"), non_personalized=p.get("npa"),
            advertising_id=bool(p.get("rdid")), gdpr=p.get("gdpr"), consent_string=bool(p.get("gdpr_consent")),
            max_content_rating=p.get("max_ad_content_rating"), test_request=p.get("adtest") == "on",
        ))
    return found


def compare(code_hosts: list[str] | tuple[str, ...], capture: Capture) -> Comparison:
    """The contacted hosts split by whether the DEX carries them, and the consent platforms on either side."""
    code = {h.lower() for h in code_hosts}
    contacted = [h.host for h in capture.hosts]
    seen = set(contacted)
    return Comparison(
        in_code=tuple(h for h in contacted if h in code),
        runtime_only=tuple(h for h in contacted if h not in code),
        consent_contacted=tuple((h, p) for h in contacted if (p := consent_platform(h))),
        consent_not_contacted=tuple(
            (h, p) for h in sorted(code) if (p := consent_platform(h)) and h not in seen
        ),
    )
