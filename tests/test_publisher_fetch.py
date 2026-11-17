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

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from apkradar import publisher


class Response:
    def __init__(self, url: str, text: str = "") -> None:
        self.url = url
        self.text = text
        self.status_code = 200
        self.headers: dict[str, str] = {}


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
    """Installs a FakeClient and hands back a builder for the script.

    Every name counts as a public address here: these tests are about the scheme,
    and the .example names they use are in no DNS."""
    made: list[FakeClient] = []
    monkeypatch.setattr(publisher, "_is_public", lambda host: True)

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


def test_the_fallback_works_against_a_real_socket(monkeypatch):
    """The one thing a fake client cannot prove.

    Every test above replaces httpx.Client, so they all pass whatever httpx does
    with a TLS failure. If a future version raised something outside
    httpx.HTTPError there, `except httpx.HTTPError` would stop catching it, the
    fallback would never run in production, and these tests would stay green —
    apkradar would silently stop finding parked domains, which is the failure that
    looks like good news.

    A local listener answering http and nothing on https is the shape of a parked
    domain with no certificate for its own name. Nothing is replaced here but
    the address check, which since 2026-11-17 refuses the loopback the listener
    is on: `looks_parked` runs the shipped path with the real client over a real
    socket.

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

    monkeypatch.setattr(publisher, "_is_public", lambda host: host == "127.0.0.1")
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


# ── where the probe may go ────────────────────────────────────────────────────
#
# Found by the 2026-11-17 bug hunt (_hunt/scripts/redirect_probe.py): the probe ran
# with follow_redirects=True, so a candidate domain answering 302 to
# http://127.0.0.1:<port>/router/admin had the tool GET that page — a blind request
# into the network APKRadar runs from, from `send` too, without --full. The domain is
# whatever a Play listing or a package name says, so whoever wrote either chose it.
# Redirects are followed by hand now, at most MAX_REDIRECTS of them, and every URL,
# the first one included, only to a host whose every address is a public one.

REAL_CLIENT = httpx.Client
REAL_GETADDRINFO = socket.getaddrinfo

# What DNS answers in these tests. Anything else, save a numeric address, is unknown.
NAMES = {
    "parked.example": "93.184.215.14",
    "forsale.godaddy.com": "160.153.0.120",
    "intranet.example": "10.1.2.3",
    "localhost": "127.0.0.1",
    "rebound.example": "192.168.0.10",
}


@pytest.fixture
def web(monkeypatch):
    """Scripted answers behind httpx.MockTransport; the hosts asked, in order."""
    routes: dict[str, httpx.Response] = {}
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.host)
        answer = routes.get(str(request.url))
        if answer is None:
            raise httpx.ConnectError("unscripted", request=request)
        return answer

    def Client(**kwargs):
        return REAL_CLIENT(transport=httpx.MockTransport(handler), **kwargs)

    def getaddrinfo(host, port, *args, **kwargs):
        if host in NAMES:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (NAMES[host], 0))]
        return REAL_GETADDRINFO(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)

    monkeypatch.setattr(httpx, "Client", Client)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return routes, asked


def redirect(to: str) -> httpx.Response:
    return httpx.Response(302, headers={"Location": to})


@pytest.mark.parametrize("target", [
    "http://127.0.0.1:8080/router/admin?x=1",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.64.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fd00::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://127.1/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://localhost/",
    "http://intranet.example/",
    "https://rebound.example/",
])
def test_a_redirect_into_a_private_network_is_not_followed(web, target):
    routes, asked = web
    routes["https://parked.example"] = redirect(target)
    with pytest.raises(publisher.RedirectRefused):
        publisher._fetch("parked.example")
    assert asked == ["parked.example"]
    assert publisher.looks_parked("parked.example") is False


def test_a_redirect_to_a_public_address_is_still_followed(web):
    """The marketplace a parked domain lands on is how most of them are found."""
    routes, asked = web
    routes["https://parked.example"] = redirect("https://forsale.godaddy.com/forsale/parked.example")
    routes["https://forsale.godaddy.com/forsale/parked.example"] = httpx.Response(403, text="")
    assert publisher.looks_parked("parked.example") is True
    assert asked == ["parked.example", "forsale.godaddy.com"]


def test_a_relative_redirect_stays_on_the_host_it_came_from(web):
    routes, asked = web
    routes["https://parked.example"] = redirect("/lander")
    routes["https://parked.example/lander"] = httpx.Response(200, text="This domain is for sale")
    assert publisher._fetch("parked.example") == ("https://parked.example/lander", "This domain is for sale")
    assert asked == ["parked.example", "parked.example"]


def test_redirects_stop_after_the_limit(web):
    routes, asked = web
    routes["https://parked.example"] = redirect("https://parked.example/1")
    for n in range(1, 20):
        routes[f"https://parked.example/{n}"] = redirect(f"https://parked.example/{n + 1}")
    with pytest.raises(publisher.RedirectRefused, match="more than"):
        publisher._fetch("parked.example")
    assert len(asked) == publisher.MAX_REDIRECTS + 1


@pytest.mark.parametrize("domain", ["intranet.example", "localhost", "127.0.0.1:8080", "nowhere.example"])
def test_a_candidate_on_a_private_network_or_unknown_to_dns_is_never_asked(web, domain):
    _, asked = web
    assert publisher.looks_parked(domain) is False
    assert asked == []


def test_the_hunt_s_two_servers_are_not_reached():
    """_hunt/scripts/redirect_probe.py, over real sockets: A answers 302 to B, both on
    the loopback. B was requested; now neither is, A being on the loopback itself."""
    hits: list[str] = []

    class Record(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"internal admin page")

        def log_message(self, *_args):
            pass

    b = ThreadingHTTPServer(("127.0.0.1", 0), Record)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{b.server_address[1]}/router/admin?x=1")
            self.end_headers()

        def log_message(self, *_args):
            pass

    a = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    for server in (a, b):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert publisher.looks_parked(f"127.0.0.1:{a.server_address[1]}") is False
        assert hits == []
    finally:
        for server in (a, b):
            server.shutdown()
            server.server_close()
