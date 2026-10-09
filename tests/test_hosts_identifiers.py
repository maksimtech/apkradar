"""URIs that are identifiers, and names reserved for documentation, are not endpoints.

Measured on 2026-10-09 on F-Droid builds. Nextcloud 35.0.1 (classes2.dex) carries

    http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense
    http://ns.adobe.com/xap/1.0/

— the first is the SOAPAction of a PlayReady licence request as ExoPlayer writes
it, the second the XMP namespace of a photo's metadata. Both are identifiers: a
URI nobody dereferences, the same kind as `schemas.android.com`. The hosts block
listed the first under "Of those, under a vendor this tool reports on" as
*Microsoft Corporation (USA)* — on Nextcloud, AntennaPod, NewPipe and Fennec, each
of which contains the same ExoPlayer constant and none of which talks to
Microsoft. A reader takes that table for a transfer.

F-Droid 2.0.1 (classes3.dex) carries `https://mirror.example.com/fdroid/repo`
and `https://example.com/fdroid/repo`, and the list showed example.com,
example.net, example.org, mirror.example.{com,net,org} and dummy.example as
endpoints the code can reach. RFC 2606 reserves those names for documentation
and tests; they resolve to nothing and belong to nobody.

Neither class is dropped: the block keeps and labels them as references, which is
what they are, so a reader can still see the list is complete.
"""

from __future__ import annotations

import pytest

from apkradar.hosts import hosts_in_dex, is_reference
from apkradar.scanner import ScanResult
from tests.android_files import dex_blob, manifest, write_apk

IDENTIFIERS = (
    "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense",   # Nextcloud 35.0.1, ExoPlayer PlayReady
    "http://ns.adobe.com/xap/1.0/",                                         # Nextcloud 35.0.1, XMP namespace
    "http://xml.org/sax/features/namespaces",                               # F-Droid 2.0.1, SAX feature
    "http://javax.xml.XMLConstants/feature/secure-processing",              # Nextcloud 35.0.1, JAXP feature
    "https://spdx.org/licenses/",                                           # F-Droid 2.0.1, licence identifiers
)

RESERVED = (
    "https://mirror.example.com/fdroid/repo",      # F-Droid 2.0.1
    "https://example.com/fdroid/repo",             # F-Droid 2.0.1
    "https://example.net/", "https://example.org/", "https://www.example.com/",
    "https://dummy.example/",                      # Nextcloud 35.0.1
    "https://host.test/", "https://x.invalid/", "http://api.localhost/",
)

ENDPOINTS = (
    "https://nextcloud.com/", "https://api.map.baidu.com/", "https://schemas.microsoft.com.evil.net/",
    "https://example-corp.com/", "https://example.com.br/", "https://testbed.org/",
)


@pytest.fixture
def carried(tmp_path):
    path = write_apk(
        tmp_path / "app.apk",
        manifest("com.example.app"),
        dex=dex_blob([], IDENTIFIERS + RESERVED + ENDPOINTS),
    )
    hosts, truncated = hosts_in_dex(path)
    assert not truncated
    return ScanResult(apk_path=path, dex_hosts=hosts)


@pytest.mark.parametrize("url", IDENTIFIERS + RESERVED)
def test_an_identifier_or_a_reserved_name_is_a_reference(url):
    host = url.split("/")[2].lower()
    assert is_reference(host), host


@pytest.mark.parametrize("url", ENDPOINTS)
def test_a_host_that_merely_resembles_one_is_still_an_endpoint(url):
    host = url.split("/")[2].lower()
    assert not is_reference(host), host


def test_the_hosts_are_all_still_in_the_list(carried):
    assert len(carried.dex_hosts) == len(IDENTIFIERS) + len(RESERVED) + len(ENDPOINTS)


def test_only_the_servers_are_endpoints(carried):
    assert sorted(found.host for found in carried.dex_endpoints) == sorted(
        url.split("/")[2].lower() for url in ENDPOINTS
    )


def test_no_vendor_is_named_for_a_namespace(carried):
    """schemas.microsoft.com is not Microsoft Corporation receiving data."""
    assert [found.host for found in carried.dex_vendor_hosts] == ["api.map.baidu.com"]
