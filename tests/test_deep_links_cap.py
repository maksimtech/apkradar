"""Deep-link hosts are the publisher's site only when there are a few of them.

Measured on OsmAnd~ 5.4.9 (net.osmand.plus, F-Droid build 540903, SHA-256
247cb0a10959ebe9d254e00ab42580f7d728ece3e2e5e2e0d28106012a0eeaef) on 2026-10-09:
the manifest declares 427 deep-link hosts — maps.google.com and some 200 Google
country domains, map.baidu.com, maps.yandex.ru, here.com, maps.apple.com,
openstreetmap.org — because the app opens links to other maps. `audit --full`
took every one of them as "SDK or deep-link domain found in the APK" and would
have run MailRadar, a TLS handshake and a headless browser against each: at the
~30 s per domain measured on Mastodon the same day, about three and a half hours
of traffic to Google's, Baidu's and Yandex's servers, about an app that talks to
none of them. NewPipe declares 56 (youtube.com, soundcloud.com, bandcamp.com…)
for the same reason.

An intent filter says which links the app *opens*. One or two hosts are the
publisher pointing at their own site; dozens are the app being a client of other
people's. So above MAX_DEEP_LINK_DOMAINS none is audited, the hosts stay in the
scan result as data, and the report says how many were set aside and why.

The fixture is a real APK (tests/android_files.py) whose manifest declares 24 of
OsmAnd's hosts, copied from that manifest.
"""

from __future__ import annotations

import pytest
from rich.console import Console

from apkradar import cli
from apkradar.scanner import ScanResult, scan
from apkradar.utils import MAX_DEEP_LINK_DOMAINS, deep_link_domains, deep_links_set_aside, get_all_domains
from tests.android_files import manifest, write_apk

OSMAND_HOSTS = (
    "osmand.net", "download.osmand.net", "openstreetmap.org", "www.openstreetmap.org",
    "osm.org", "maps.google.com", "maps.google.it", "maps.google.de", "maps.google.fr",
    "maps.google.co.uk", "maps.google.com.br", "www.google.com", "www.google.it",
    "map.baidu.com", "map.baidu.cn", "maps.yandex.ru", "maps.yandex.com", "here.com",
    "www.here.com", "maps.apple.com", "ge0.me", "map.qq.com", "maps.googlee.com",
    "www.googlemaps.com",
)


@pytest.fixture
def osmand(tmp_path):
    result = scan(write_apk(tmp_path / "osmand.apk", manifest("net.osmand.plus", hosts=OSMAND_HOSTS)))
    assert result.error is None
    return result


@pytest.fixture
def printed(monkeypatch):
    console = Console(width=120, force_terminal=False, no_color=True, record=True)
    monkeypatch.setattr(cli, "console", console)

    def render(result) -> str:
        cli._note_deep_links(result)
        return " ".join(console.export_text().split())

    return render


def test_the_fixture_declares_more_than_the_cap(osmand):
    assert len(osmand.manifest_domains) == len(OSMAND_HOSTS) > MAX_DEEP_LINK_DOMAINS


def test_the_hosts_stay_in_the_result_as_data(osmand):
    assert set(osmand.manifest_domains) == set(OSMAND_HOSTS)


def test_none_of_them_is_a_domain_to_audit(osmand):
    assert deep_link_domains(osmand.manifest_domains) == []


def test_only_the_publisher_candidate_is_still_audited(osmand):
    """osmand.net — from the package name, not from the 24 deep links that also name it."""
    assert get_all_domains(osmand) == ["osmand.net"]


def test_the_set_aside_hosts_are_counted(osmand):
    assert sorted(deep_links_set_aside(osmand.manifest_domains)) == sorted(OSMAND_HOSTS)


def test_a_few_deep_links_are_still_the_publishers_site():
    few = ["antennapod.org", "www.subscribeonandroid.com"]
    assert deep_link_domains(few) == few
    assert deep_links_set_aside(few) == []


def test_platform_hosts_do_not_count_towards_the_cap():
    """play.google.com and a social page were never going to be audited."""
    own = [f"host{i}.example" for i in range(MAX_DEEP_LINK_DOMAINS)]
    assert deep_link_domains(own + ["play.google.com", "facebook.com"]) == own


def test_the_report_says_how_many_were_set_aside_and_why(osmand, printed):
    text = printed(osmand)
    assert f"{len(OSMAND_HOSTS)} deep-link hosts" in text
    assert "not analysed" in text
    assert "maps.google.com" not in text   # a count, not a list of other people's domains


def test_no_note_when_nothing_was_set_aside(printed):
    assert printed(ScanResult(apk_path="a.apk", manifest_domains=["antennapod.org"])) == ""
