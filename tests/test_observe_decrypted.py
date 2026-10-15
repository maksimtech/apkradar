"""The ad requests an app sent, read from decrypted traffic exported as HAR.

A capture names hosts; it cannot say what an ad request asked for. Decrypted traffic
can: mitmproxy, HTTP Toolkit, Charles and the browsers all export HAR 1.2, which is
JSON and needs no library to read. This reads the requests of the Google Mobile Ads
SDK (`/mads/gma` on googleads.g.doubleclick.net) for the parameters that answer the
questions a children's app raises — is it tagged child-directed, does it send the
advertising ID, does it carry a consent string, is the content rating capped — and
says nothing about the parameters Google does not document.

The recorded fixture, mitmproxy_kids_app_ad_requests_recorded.har, holds the six
requests to googleads.g.doubleclick.net/mads/ of com.gameitech.preschool.abc123.
tracing.learning 1.8 on 2026-10-15, on an Android 16 emulator (Google APIs x86_64,
ARM translation) behind mitmproxy 12.2.3 with its CA among the system certificates.
The requests are verbatim; the response bodies — the ads — are left out. The SDK
treats an emulator as a test device, so these requests carry `adtest=on`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkradar import observe
from apkradar.cli import app
from tests.android_files import dex_blob, manifest, write_apk

FIXTURES = Path(__file__).parent / "fixtures"
RECORDED = FIXTURES / "mitmproxy_kids_app_ad_requests_recorded.har"
CAPTURE = FIXTURES / "pcapdroid_kids_app_first_launch_recorded.pcap"

runner = CliRunner()


def har(tmp_path: Path, *entries: dict) -> str:
    path = tmp_path / "flows.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "entries": list(entries)}}), encoding="utf-8")
    return str(path)


def entry(url: str, started: str = "2026-10-15T20:00:00+00:00", method: str = "GET", form: str | None = None) -> dict:
    request: dict = {"method": method, "url": url, "headers": [], "queryString": []}
    if form is not None:
        request["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": form}
    return {"startedDateTime": started, "request": request, "response": {"status": 200}}


# --- the recorded requests --------------------------------------------------------


def test_only_ad_requests_are_read_not_the_sdk_s_static_files():
    """Four of the six requests load the SDK's own HTML and script; two ask for an ad."""
    requests = observe.ad_requests(observe.read_har(RECORDED))
    assert len(requests) == 2
    assert all(r.path == "/mads/gma" for r in requests)


def test_the_recorded_request_is_tagged_child_directed_and_sends_no_advertising_id():
    first = observe.ad_requests(observe.read_har(RECORDED))[0]
    assert first.app == "com.gameitech.preschool.abc123.tracing.learning"
    assert first.format == "interstitial_mb"
    assert first.child_directed == "1"
    assert first.under_age is None
    assert first.non_personalized is None
    assert first.advertising_id is False
    assert first.gdpr is None
    assert first.consent_string is False
    assert first.max_content_rating is None


def test_the_recorded_request_is_a_test_request():
    """An emulator is a test device to the SDK: what it is served may differ from what a
    phone is served, and the report has to say so."""
    assert all(r.test_request for r in observe.ad_requests(observe.read_har(RECORDED)))


def test_the_requests_are_timed_from_the_first_entry():
    requests = observe.ad_requests(observe.read_har(RECORDED))
    assert requests[0].at < requests[1].at
    assert requests[1].at - requests[0].at == pytest.approx(40.1, abs=0.5)


# --- what the parameters can say ----------------------------------------------------


def test_parameters_in_a_form_body_are_read(tmp_path):
    form = "format=banner&rdid=00000000-1111-2222-3333-444444444444&gdpr=1&gdpr_consent=CPx&npa=1&tfua=1"
    url = "https://googleads.g.doubleclick.net/mads/gma?msid=org.example"
    path = har(tmp_path, entry(url, method="POST", form=form))
    r = observe.ad_requests(observe.read_har(path))[0]
    assert (r.format, r.advertising_id, r.gdpr, r.consent_string, r.non_personalized, r.under_age) == (
        "banner", True, "1", True, "1", "1")


def test_the_advertising_id_is_never_kept_only_whether_it_was_sent(tmp_path):
    aaid = "00000000-1111-2222-3333-444444444444"
    path = har(tmp_path, entry(f"https://googleads.g.doubleclick.net/mads/gma?rdid={aaid}"))
    r = observe.ad_requests(observe.read_har(path))[0]
    assert r.advertising_id is True
    assert aaid not in repr(r)


def test_an_empty_advertising_id_is_not_an_advertising_id(tmp_path):
    path = har(tmp_path, entry("https://googleads.g.doubleclick.net/mads/gma?rdid="))
    assert observe.ad_requests(observe.read_har(path))[0].advertising_id is False


def test_requests_to_other_hosts_are_not_ad_requests(tmp_path):
    path = har(tmp_path, entry("https://example.net/mads/gma?tfcd=1"))
    assert observe.ad_requests(observe.read_har(path)) == []


# --- files that are not HAR -----------------------------------------------------------


def test_a_file_that_is_not_json_is_refused(tmp_path):
    path = tmp_path / "flows.har"
    path.write_bytes(b"\x00\x01mitmproxy native flows")
    with pytest.raises(observe.CaptureError, match="not a HAR"):
        observe.read_har(path)


def test_json_without_a_log_is_refused(tmp_path):
    path = tmp_path / "flows.har"
    path.write_text('{"entries": []}', encoding="utf-8")
    with pytest.raises(observe.CaptureError, match="not a HAR"):
        observe.read_har(path)


# --- the command ------------------------------------------------------------------------


def _apk(tmp_path: Path) -> str:
    return write_apk(tmp_path / "app.apk", manifest("com.example.kids"),
                     dex=dex_blob(urls=["https://googleads.g.doubleclick.net/mads/gma"]))


def test_observe_reads_decrypted_requests_without_a_capture(tmp_path):
    outcome = runner.invoke(app, ["observe", _apk(tmp_path), "--decrypted", str(RECORDED)], terminal_width=200)
    assert outcome.exit_code == 0, outcome.output
    text = " ".join(outcome.output.split())
    assert "Ad requests in the decrypted traffic (2)" in text
    assert "interstitial_mb" in text
    assert "test request" in text
    assert "Hosts contacted at runtime" not in text


def test_observe_reads_both_together(tmp_path):
    args = ["observe", _apk(tmp_path), "--capture", str(CAPTURE), "--decrypted", str(RECORDED)]
    outcome = runner.invoke(app, args, terminal_width=200)
    assert outcome.exit_code == 0, outcome.output
    text = " ".join(outcome.output.split())
    assert "Hosts contacted at runtime" in text and "Ad requests in the decrypted traffic" in text


def test_observe_needs_a_capture_or_decrypted_traffic(tmp_path):
    outcome = runner.invoke(app, ["observe", _apk(tmp_path)])
    assert outcome.exit_code == 2
    assert "--capture" in outcome.output and "--decrypted" in outcome.output


def test_observe_refuses_an_unreadable_har_before_opening_the_apk(tmp_path):
    bad = tmp_path / "flows.har"
    bad.write_bytes(b"\x00\x01")
    outcome = runner.invoke(app, ["observe", str(tmp_path / "missing.apk"), "--decrypted", str(bad)])
    assert outcome.exit_code == 2
    assert "not a HAR" in outcome.output
    assert "Auditing" not in outcome.output
