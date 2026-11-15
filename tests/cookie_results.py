"""CookieRadar results with the shape its scanner returns, for the `--full` tests.

A MagicMock with two tracker lists let `--full` decide the verdict on half the
evidence for as long as it did: nothing in it had a status, a cookie or a
clicked refusal to be read. These are CookieRadar's own dataclasses; only the
browser that would have filled them is missing.
"""
from __future__ import annotations

import pytest

scanner = pytest.importorskip("cookieradar.scanner")


def tracker(domain: str):
    return scanner.TrackerRequest(url=f"https://{domain}/t.js", domain=domain,
                                  resource_type="script", timestamp=0.0)


def cookie_result(pre=(), rej=(), *, reject_clicked=True, status=200, pre_cookies=(),
                  url="https://publisher.example"):
    """Trackers per session, cookies before any choice, whether the refusal was clicked."""
    S = scanner.SessionResult
    return scanner.ScanResult(
        url=url,
        pre_consent=S("pre-consent", trackers=[tracker(d) for d in pre],
                      cookies=list(pre_cookies), banner_found=True, status=status),
        post_accept=S("post-accept", banner_found=True, consent_clicked=True, status=status),
        post_reject=S("post-reject", trackers=[tracker(d) for d in rej],
                      banner_found=True, consent_clicked=reject_clicked, status=status),
    )
