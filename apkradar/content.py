"""
APKRadar — asking the artifact whether it names a domain.

The third witness on who publishes an app, and the most constrained one. It
answers a single question about a single host — *does this package mention it,
and does the mention look deliberate* — and it cannot answer with a domain. That
is deliberate: a function that returns hosts would be a way to introduce a new
target to audit, and this exists only to corroborate a candidate that another
source already named.

Measured on 112 Where ARE U (SHA-256 af0db3dc…b751): the base APK names
`where.areu.lombardia.it` nine times, including the URL of its privacy notice,
and `beta80group.it` — the software house that built it — not once. The app knows
who publishes it. On abc 123 Tracing neither candidate appears at all, which is
the honest outcome for an app that says nothing about itself: no corroboration,
nothing established.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# A mention is deliberate if the app points at a page of this kind, or if it
# names the host repeatedly. One bare occurrence is a coincidence until something
# else says otherwise: a string in a resource, a changelog, a comment.
POLICY_PATHS = (
    "/privacy",
    "/privacy-policy",
    "/informativa",
    "/terms",
    "/termini",
    "/legal",
    "/tos",
)

REPEATED_IS_DELIBERATE = 3

# Enough of a URL to report back, and no further: whatever follows a quote, a
# NUL or whitespace in a binary is not part of it.
_URL_TAIL = r"[^\s\x00\"'<>`\\]*"

# A domain ends where the label ends. Without this, `gameitech.in` matches inside
# `gameitech.info` and corroborates a host nobody named.
_NOT_A_LABEL_CHAR = r"(?![a-z0-9\-])"
_NOT_A_LABEL_CHAR_BEFORE = r"(?<![a-z0-9\-.])"


@dataclass(frozen=True)
class Mention:
    """What the package says about one host.

    `readable` is the difference between "the app does not mention it" and "the
    file could not be opened". Only the first is evidence.
    """

    count: int = 0
    policy_url: str | None = None
    readable: bool = True

    @property
    def deliberate(self) -> bool:
        if not self.readable:
            return False
        return bool(self.policy_url) or self.count >= REPEATED_IS_DELIBERATE


def mentions_of(domain: str, apk_path: str | Path) -> Mention:
    """How often `apk_path` names `domain`, and whether it points at a policy page.

    Reads the file as bytes. The compressed entries of an APK hide most of their
    strings, so this undercounts by design — it never overcounts, and one
    deliberate mention is all the question needs.
    """
    if not domain:
        return Mention()

    try:
        data = Path(apk_path).read_bytes()
    except OSError:
        return Mention(readable=False)

    host = re.escape(domain.strip().lower())
    text = data.decode("latin-1").lower()

    occurrences = re.findall(f"{_NOT_A_LABEL_CHAR_BEFORE}{host}{_NOT_A_LABEL_CHAR}", text)

    policy = None
    for match in re.finditer(
        f"https?://{host}{_NOT_A_LABEL_CHAR}{_URL_TAIL}", text
    ):
        url = match.group()
        if any(part in url for part in POLICY_PATHS):
            policy = _as_written(data, match.start(), len(url))
            break

    return Mention(count=len(occurrences), policy_url=policy)


def _as_written(data: bytes, start: int, length: int) -> str:
    """The URL with its original capitalisation, since the search was lowercased."""
    return data[start : start + length].decode("latin-1")
