"""
APKRadar — the hosts an APK carries in its code.

Until now the domain list came from three places: the package name, the Play
listing, and deep links in the manifest. None of them is where an application
keeps the servers it actually talks to — those are string literals in the DEX,
and R8 does not touch them. It renames classes and methods, so a release build
tells you nothing about its dependencies; the URLs survive verbatim.

Measured on Breezy Weather 6.2.2 on 2026-10-02: the manifest declared one deep
link and the package name guessed one domain, while the DEX held **161** hosts in
the `standard` build — 153 endpoints and 8 specification URIs — against 53 in the
`freenet` one. The same audit reported "no extra-EU transfers" on a build
carrying AccuWeather, NOAA, JMA, Baidu and Xiaomi endpoints — correctly, because
that check reads SDK packages and those providers ship no SDK. This module is the
other half of that question: of the two builds, `standard` carries five hosts
belonging to vendors this tool reports on and `freenet` carries none, which is a
difference neither the score nor any other finding could show.

What it does **not** do is decide that the application talks to any of them. A
host in a string literal is a host the code can reach, which is not traffic: an
application offering fifty weather providers contains fifty endpoints and
contacts the one that is configured. So nothing here deducts a point, and the
report says "carried in the code" rather than "contacted". Establishing the
second needs a runtime observation, which is a different tool.
"""
from __future__ import annotations

import re
import zipfile

# Bounded on purpose. An obfuscated DEX can hold an arbitrary number of
# URL-shaped strings, and a report is read by a person: beyond this the list has
# stopped being evidence and become a dump. `truncated` on the result says when
# the limit was reached, so a caller is never silently handed a partial answer.
MAX_HOSTS = 500

# Matched against the whole buffer rather than parsed per string: DEX stores its
# strings with a length prefix and MUTF-8 encoding, so finding the string table
# costs a parse of the file format to locate text that a byte scan finds anyway.
# Only `http://` and `https://` count — a bare hostname is indistinguishable
# from a class name, a resource id or an author's e-mail domain, and guessing
# would fill the list with things that are not endpoints.
_URL = re.compile(rb"https?://([A-Za-z0-9][A-Za-z0-9.\-]{1,252})")

# Read in chunks so a large DEX never lands in memory whole, the same way
# `scanner._packages_in_dex` reads it.
DEX_CHUNK_SIZE = 4 * 1024 * 1024

# Enough to hold `https://` and the longest hostname a DNS name may be, so a URL
# split across two chunks is matched on the whole of it.
_OVERLAP = len("https://") + 253

# Hosts that are specifications, schemas and licences rather than servers the
# code calls. They are kept and labelled rather than dropped: a tool that
# silently reclassifies an endpoint as documentation hides exactly what it was
# built to show. The set is therefore narrow by design — a standards body, a
# licence text, an XML namespace — and anything arguable stays an endpoint.
#
# `www.opengis.net` and `www.w3.org` arrive as XML namespace URIs, which are
# identifiers and not addresses: nothing dereferences them.
REFERENCE_HOSTS = frozenset({
    "w3.org",
    "opengis.net",
    "ietf.org",
    "rfc-editor.org",
    "creativecommons.org",
    "opendatacommons.org",
    "gnu.org",
    "apache.org",
    "schemas.android.com",
    "developer.android.com",
    "schemas.xmlsoap.org",
    "purl.org",
    "xmlpull.org",
    "json-schema.org",
    "iana.org",
    "unicode.org",
    "oasis-open.org",
    # Measured on F-Droid builds on 2026-10-09. ExoPlayer's PlayReady code holds
    # `http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense`, the
    # SOAPAction of a licence request, and the vendor table below named it as
    # *Microsoft Corporation (USA)* on Nextcloud, AntennaPod, NewPipe and Fennec
    # alike — none of which talks to Microsoft. `http://ns.adobe.com/xap/1.0/` is
    # the XMP namespace of a photo's metadata; `http://xml.org/sax/features/…`
    # and `http://javax.xml.XMLConstants/feature/…` are parser feature names;
    # `https://spdx.org/licenses/` is where licence identifiers are defined.
    "schemas.microsoft.com",
    "ns.adobe.com",
    "xml.org",
    "javax.xml.xmlconstants",
    "spdx.org",
})

# Names RFC 2606 reserves for documentation and tests. They resolve to nothing
# and belong to nobody, so `https://mirror.example.com/fdroid/repo` in F-Droid's
# code — a sample repository address — is not an endpoint the code can reach.
# Kept and labelled like the hosts above, for the same reason.
RESERVED_NAMES = frozenset({"example.com", "example.net", "example.org"})
RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost"})

# Hosts belonging to the vendors `scanner.EXTRA_EU_TRANSFERS` already names, so
# the two findings agree when both see the same company. Keyed on the
# registrable domain and matched by suffix.
#
# Deliberately confined to those vendors. Resolving the jurisdiction of an
# arbitrary endpoint is not something a static scan can do — a `.org` may be
# hosted anywhere, an adequacy decision may apply, and a table guessing at it
# would put legal conclusions about a hundred national weather services into a
# letter to a DPO. What this does is answer one question it can answer: is this
# host one of the companies this tool already reports on.
VENDOR_HOSTS = {
    "google.com": "Google LLC (USA)",
    "googleapis.com": "Google LLC (USA)",
    "gstatic.com": "Google LLC (USA)",
    "googleadservices.com": "Google LLC (USA)",
    "doubleclick.net": "Google LLC (USA)",
    "facebook.com": "Meta Platforms Inc. (USA)",
    "fbcdn.net": "Meta Platforms Inc. (USA)",
    "amazonaws.com": "Amazon Web Services (USA)",
    "microsoft.com": "Microsoft Corporation (USA)",
    "appcenter.ms": "Microsoft Corporation (USA)",
    "appsflyer.com": "AppsFlyer Ltd. (USA/Israel)",
    "adjust.com": "Adjust GmbH (Germany) → USA",
    "amplitude.com": "Amplitude Inc. (USA)",
    "mixpanel.com": "Mixpanel Inc. (USA)",
    "tiktok.com": "ByteDance Ltd. (China/USA)",
    "bytedance.com": "ByteDance Ltd. (China/USA)",
    "yandex.com": "Yandex LLC (Russia)",
    "yandex.ru": "Yandex LLC (Russia)",
    "huawei.com": "Huawei Technologies (China)",
    "hicloud.com": "Huawei Technologies (China)",
    "xiaomi.com": "Xiaomi Corporation (China)",
    "mi.com": "Xiaomi Corporation (China)",
    "baidu.com": "Baidu Inc. (China)",
}

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# The bytes `_URL` will consume inside a host, as single-byte values: a match
# followed by one of these did not reach the end of the hostname.
_HOST_BYTES = frozenset(
    bytes([b]) for b in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
)


def _valid_host(host: str) -> bool:
    """Whether `host` is a hostname, rather than something URL-shaped.

    A DEX is full of format strings — `https://%s/v1/`, `https://{host}/` — and
    of URLs built by concatenation, so the bytes after a scheme are frequently
    not a host at all. The rules are DNS's: labels of 1 to 63 characters from
    letters, digits and hyphens, not starting or ending with a hyphen, 253
    characters in total, and at least two labels.

    The last label must be alphabetic, which also excludes IPv4 literals. That is
    a deliberate omission rather than an oversight: an endpoint written as an
    address is worth reporting, but `_URL` would equally match a version string
    or a byte offset that happens to follow a scheme, and a false endpoint in
    this list is worse than a missing one.
    """
    if not 3 < len(host) <= 253 or host.endswith("."):
        return False
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return False
    tld = labels[-1]
    return tld.isalpha() and 2 <= len(tld) <= 24


def is_reference(host: str) -> bool:
    """Whether `host` is a specification, schema, licence or reserved name rather than a server."""
    if host.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    return any(
        host == ref or host.endswith("." + ref)
        for ref in REFERENCE_HOSTS | RESERVED_NAMES
    )


def vendor_of(host: str) -> str | None:
    """The company behind `host`, for the vendors this tool already reports on."""
    for domain, entity in VENDOR_HOSTS.items():
        if host == domain or host.endswith("." + domain):
            return entity
    return None


def _hosts_in_buffer(buf: bytes, *, final: bool) -> set[str]:
    """The hosts in one buffer.

    A match ending at the buffer's last byte is dropped unless this is the final
    buffer: the caller carries an overlap forward, so the whole of it comes back
    next time. Without this a URL cut by a chunk boundary yields its own prefix,
    and the prefix is often a valid-looking hostname of its own — `api.exam` out
    of `api.example.com` passes every rule in `_valid_host`.
    """
    found: set[str] = set()
    for match in _URL.finditer(buf):
        end = match.end()
        if end == len(buf) and not final:
            continue
        # The same rule as the boundary above, against a different cut. `_URL`
        # stops after 253 host characters because that is the DNS limit, so a
        # longer string leaves the regex holding a truncation of it — and a
        # truncation that happens to end at a dot is a perfectly well-formed
        # hostname that never existed. If the next byte could still be part of
        # the host, what was matched is not the whole of it.
        if end < len(buf) and buf[end:end + 1] in _HOST_BYTES:
            continue
        host = match.group(1).decode("ascii", "ignore").rstrip(".-").lower()
        if _valid_host(host):
            found.add(host)
    return found


def hosts_in_dex(apk_path: str) -> tuple[list[str], bool]:
    """Every host the APK's DEX files carry, sorted, and whether MAX_HOSTS was hit.

    Never raises: an APK this cannot read yields whatever was collected, the way
    the tracker search does. The host list is an addition to a report, and no
    scan is failed over it.
    """
    found: set[str] = set()
    truncated = False
    try:
        with zipfile.ZipFile(apk_path) as z:
            for name in [n for n in z.namelist() if n.endswith(".dex")]:
                if truncated:
                    break
                with z.open(name) as fh:
                    tail = b""
                    while True:
                        chunk = fh.read(DEX_CHUNK_SIZE)
                        if not chunk:
                            # The tail of the last chunk still has to be read as
                            # a final buffer, or a URL at the very end of a DEX
                            # is dropped by the boundary rule above.
                            found |= _hosts_in_buffer(tail, final=True)
                            break
                        buf = tail + chunk
                        found |= _hosts_in_buffer(buf, final=False)
                        # More than the limit, not the limit itself: a DEX
                        # carrying exactly MAX_HOSTS hosts was read in full,
                        # and used to be reported as stopped at 500.
                        if len(found) > MAX_HOSTS:
                            truncated = True
                            break
                        tail = buf[-_OVERLAP:]
    except Exception:
        pass

    ordered = sorted(found)
    if len(ordered) > MAX_HOSTS:
        return ordered[:MAX_HOSTS], True
    return ordered, truncated
