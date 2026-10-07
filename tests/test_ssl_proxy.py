"""The SSL check must go through the proxy when there is one.

`_check_ssl` opened a raw TCP socket to port 443. Behind a corporate proxy
that blocks direct outbound connections, that cannot work: the connection
hangs until the five-second timeout and every domain comes back "timeout",
which reads as a broken certificate rather than a blocked network.

The rest of the toolchain already honours HTTPS_PROXY, because httpx reads it
from the environment by default. Only this one check did not.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from unittest.mock import MagicMock, patch

import pytest

from apkradar import cli


@pytest.fixture(autouse=True)
def no_inherited_proxy(monkeypatch):
    """The developer's own environment must not decide what these test."""
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                 "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------
# reading the environment
# --------------------------------------------------------------------------


def test_no_proxy_configured_means_a_direct_connection(monkeypatch):
    assert cli._proxy_for_https() is None


@pytest.mark.parametrize("name", ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"])
def test_every_spelling_of_the_variable_is_read(monkeypatch, name):
    """Unix tooling has used the lower-case spellings for decades."""
    monkeypatch.setenv(name, "http://proxy.example.com:3128")
    assert cli._proxy_for_https() == ("proxy.example.com", 3128)


def test_http_proxy_is_the_fallback(monkeypatch):
    """A site with only HTTP_PROXY set still means "do not go direct"."""
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.com:8080")
    assert cli._proxy_for_https() == ("proxy.example.com", 8080)


def test_https_proxy_wins_over_http_proxy(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://wrong.example.com:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://right.example.com:3128")
    assert cli._proxy_for_https() == ("right.example.com", 3128)


def test_a_proxy_without_a_port_defaults_to_3128(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com")
    assert cli._proxy_for_https() == ("proxy.example.com", 3128)


def test_a_value_that_is_not_a_url_is_ignored_rather_than_crashing(monkeypatch):
    """A malformed variable must not take the whole audit down."""
    monkeypatch.setenv("HTTPS_PROXY", "not a url at all")
    assert cli._proxy_for_https() is None


def test_no_proxy_exempts_the_domain(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
    monkeypatch.setenv("NO_PROXY", "internal.example.com,localhost")
    assert cli._proxy_for_https("internal.example.com") is None
    assert cli._proxy_for_https("other.example.com") == ("proxy.example.com", 3128)


def test_no_proxy_wildcard_disables_the_proxy(monkeypatch):
    """`NO_PROXY=*` is "no proxy for any host" to curl, requests and httpx alike.

    It was not read that way here, and the certificate check went through the
    proxy all the same.
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
    monkeypatch.setenv("NO_PROXY", "*")
    assert cli._proxy_for_https("example.com") is None


# --------------------------------------------------------------------------
# using it
# --------------------------------------------------------------------------


def test_without_a_proxy_it_connects_to_the_host(monkeypatch):
    seen = []

    def fake_connect(address, timeout=None):
        seen.append(address)
        return MagicMock()

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    with patch.object(ssl.SSLContext, "wrap_socket", side_effect=OSError("stop here")):
        cli._check_ssl("example.com")

    assert seen == [("example.com", 443)]


def test_with_a_proxy_it_connects_to_the_proxy_instead(monkeypatch):
    """The bug: this used to go straight to example.com:443 and hang."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
    seen = []

    def fake_connect(address, timeout=None):
        seen.append(address)
        sock = MagicMock()
        sock.recv.return_value = b"HTTP/1.1 200 Connection established\r\n\r\n"
        return sock

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    with patch.object(ssl.SSLContext, "wrap_socket", side_effect=OSError("stop here")):
        cli._check_ssl("example.com")

    assert seen == [("proxy.example.com", 3128)]


def test_it_asks_the_proxy_to_tunnel_to_the_real_host(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
    sent = []

    def fake_connect(address, timeout=None):
        sock = MagicMock()
        sock.sendall.side_effect = lambda data: sent.append(data)
        sock.recv.return_value = b"HTTP/1.1 200 Connection established\r\n\r\n"
        return sock

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    with patch.object(ssl.SSLContext, "wrap_socket", side_effect=OSError("stop here")):
        cli._check_ssl("example.com")

    request = b"".join(sent).decode()
    assert request.startswith("CONNECT example.com:443 HTTP/1.1")
    assert "Host: example.com:443" in request
    assert request.endswith("\r\n\r\n")


def test_a_proxy_that_refuses_the_tunnel_is_an_error_not_a_bad_certificate(monkeypatch):
    """403 from the proxy says nothing about the site's certificate.

    Reporting it as "invalid" would put a red mark against a domain whose
    certificate was never seen.
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")

    def fake_connect(address, timeout=None):
        sock = MagicMock()
        sock.recv.return_value = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        return sock

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    status, expiry = cli._check_ssl("example.com")

    assert status == "error"
    assert expiry is None


class _RecordingProxy:
    """A real HTTP proxy endpoint on 127.0.0.1, in a thread, that keeps the bytes it receives.

    It grants every tunnel, as a permissive proxy would: what a client wrote
    before the blank line is all there is to look at, and an injected header is
    only ever visible from this side of the socket.
    """

    def __init__(self) -> None:
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()[:2]
        self.received = bytearray()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                with contextlib.suppress(OSError):
                    while b"\r\n\r\n" not in self.received:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        self.received += chunk
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    conn.recv(1)    # until the client hangs up

    def close(self) -> None:
        self._stop.set()
        self._thread.join(5)
        self.listener.close()


@pytest.fixture
def recording_proxy():
    proxy = _RecordingProxy()
    yield proxy
    proxy.close()


def test_the_recording_proxy_sees_a_well_formed_tunnel_request(recording_proxy):
    """The witness below is only worth something if it records a real request."""
    sock = cli._open_tunnel(recording_proxy.address, "example.com", 5)
    sock.close()
    recording_proxy.close()

    assert bytes(recording_proxy.received) == (
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )


def test_connect_request_cannot_be_injected_through_the_domain(recording_proxy):
    """The domain is written into the CONNECT request line, and it can come from
    a deep link in the APK's manifest. Written in unchecked, a CR/LF in it added
    headers of the APK's choosing to what the proxy received.
    """
    tunnel = None
    with contextlib.suppress(ValueError, OSError):
        tunnel = cli._open_tunnel(
            recording_proxy.address,
            "evil.com:443 HTTP/1.1\r\nX-Injected: yes\r\nFoo: bar",
            5,
        )
    if tunnel is not None:
        tunnel.close()
    recording_proxy.close()

    assert b"X-Injected" not in recording_proxy.received
