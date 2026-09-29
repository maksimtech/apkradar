"""
ApkRadar — how the parked-domain probe reaches a domain.

`looks_parked` decides whether a report says a publisher's domain is for sale,
and every test of it injects `fetch`, so the real `_fetch` had no test at all.
That is where the scheme is chosen, which makes it the one part worth pinning:

  * HTTPS is tried first, because what comes back decides an allegation and over
    cleartext anyone on the path can put a for-sale marker in the body.
  * HTTP is still tried after it, because a parked domain often has no
    certificate for the name, and refusing to look would hide exactly the
    domains this exists to find.

Both halves have to hold. Keeping only the first would quietly stop finding
parked domains — the failure that looks like good news — and keeping only the
second is where this started.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from apkradar import publisher


class Response:
    def __init__(self, url: str, text: str = "") -> None:
        self.url = url
        self.text = text


class FakeClient:
    """Records the URLs asked for, and answers as the script says."""

    def __init__(self, script: dict[str, object]) -> None:
        self.script = script
        self.asked: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def get(self, url: str):
        self.asked.append(url)
        answer = self.script.get(url)
        if answer is None:
            raise AssertionError(f"the probe asked for {url}, which is unscripted")
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def client(monkeypatch):
    """Installs a FakeClient and hands back a builder for the script."""
    made: list[FakeClient] = []

    def build(script):
        def Client(**_kwargs):
            made.append(FakeClient(script))
            return made[-1]
        monkeypatch.setattr(httpx, "Client", Client)
        return made
    return build


def test_https_is_tried_first(client):
    made = client({"https://example.com": Response("https://example.com/", "hello")})

    final, body = publisher._fetch("example.com")

    assert made[0].asked == ["https://example.com"], "http was tried, or tried first"
    assert final == "https://example.com/"
    assert body == "hello"


def test_http_answers_when_https_cannot(client):
    """The parked domain case: no certificate for the name, so https raises and
    the probe has to keep looking."""
    made = client({
        "https://parked.example": httpx.ConnectError("no route"),
        "http://parked.example": Response("https://dan.com/buy/parked.example", "for sale"),
    })

    final, body = publisher._fetch("parked.example")

    assert made[0].asked == ["https://parked.example", "http://parked.example"]
    assert final == "https://dan.com/buy/parked.example"
    assert body == "for sale"


def test_a_certificate_error_is_a_reason_to_fall_back_and_not_to_stop(client):
    """An expired or wrong-name certificate is the ordinary state of a parked
    domain, and httpx raises it as an HTTPError like any other."""
    made = client({
        "https://expired.example": httpx.ConnectError("certificate verify failed"),
        "http://expired.example": Response("http://expired.example/", "buy this domain"),
    })

    assert publisher._fetch("expired.example")[1] == "buy this domain"
    assert len(made[0].asked) == 2


def test_both_failing_raises_so_the_verdict_is_cannot_tell(client):
    """`looks_parked` turns this into False. "Unreachable" must not read as "for
    sale": dropping a real publisher's domain would hide the row that matters."""
    client({
        "https://gone.example": httpx.ConnectError("no route"),
        "http://gone.example": httpx.ConnectError("no route"),
    })

    with pytest.raises(httpx.HTTPError):
        publisher._fetch("gone.example")

    assert publisher.looks_parked("gone.example") is False


def test_the_body_is_cut_short(client):
    """The marker search reads a prefix; a parked page that ships a megabyte of
    scripts should not be held in memory to find "for sale" in its first lines."""
    client({"https://big.example": Response("https://big.example/", "x" * 100_000)})

    assert len(publisher._fetch("big.example")[1]) == publisher._SNIFF


def test_the_fallback_works_against_a_real_socket():
    """The one thing a fake client cannot prove.

    Every test above replaces httpx.Client, so they all pass whatever httpx does
    with a TLS failure. If a future version raised something outside
    httpx.HTTPError there, `except httpx.HTTPError` would stop catching it, the
    fallback would never run in production, and these tests would stay green —
    apkradar would silently stop finding parked domains, which is the failure that
    looks like good news.

    A local listener answering http and nothing on https is the shape of a parked
    domain with no certificate for its own name. Nothing is replaced here:
    `looks_parked` runs the shipped path with the real client over a real socket.

    Checked against the network on 2026-09-29 as well, on nine real domains: the
    https-first change altered no verdict, and python.org, example.com and
    maksimtech.com moved from cleartext to https. The one case the network could
    not reach was this one — neverssl.com timed out on both schemes — which is why
    it lives here instead of in a notebook.
    """
    page = b"<html><body><h1>Buy this domain</h1></body></html>"

    class Lander(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Lander)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert publisher.looks_parked(f"127.0.0.1:{server.server_address[1]}") is True
    finally:
        server.shutdown()
        server.server_close()


def test_an_https_only_site_is_never_asked_over_cleartext(client):
    """The point of the change. A real publisher's site answers https, so the
    body that decides the allegation cannot be rewritten in transit."""
    made = client({"https://real.example": Response("https://real.example/", "our apps")})

    publisher._fetch("real.example")

    assert not any(url.startswith("http://") for url in made[0].asked)
