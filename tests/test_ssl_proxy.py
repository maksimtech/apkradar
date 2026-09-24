"""The SSL check must go through the proxy when there is one.

`_check_ssl` opened a raw TCP socket to port 443. Behind a corporate proxy
that blocks direct outbound connections, that cannot work: the connection
hangs until the five-second timeout and every domain comes back "timeout",
which reads as a broken certificate rather than a blocked network.

The rest of the toolchain already honours HTTPS_PROXY, because httpx reads it
from the environment by default. Only this one check did not.
"""

from __future__ import annotations

import socket
import ssl
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
