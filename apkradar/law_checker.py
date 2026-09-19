"""
APKRadar — GDPR provisions for audit findings.

Maps what an audit found to the GDPR provisions it concerns, and cites each
one with the SHA-256 of the exact text applied and the date of that wording.
The text is downloaded from EUR-Lex on every audit and compared with the
local cache; without network the cached copy is cited.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from apkradar import law_fetcher
from apkradar.law_cache import LawCache
from apkradar.law_fetcher import LawFetchError

LAW_NAME = "GDPR"

# Finding → cited provisions, in report order
FINDING_ARTICLES = {
    "tracker": ("5(1)(a)", "6"),
    "extra_eu": ("46",),
    "consent": ("7",),
    "sensitive": ("9",),
}


@dataclass(frozen=True)
class Citation:
    finding: str
    article: str
    sha256: Optional[str]         # None when the text could not be obtained
    version_date: Optional[str]   # YYYY-MM-DD the wording was downloaded


@dataclass
class LawCheckResult:
    citations: list[Citation]
    # "eur-lex": verified now; "cache": EUR-Lex unreachable, cached copy;
    # "unavailable": no text at all; "none": nothing to cite
    source: str
    # Cited provisions whose text changed since the last audit → previous SHA-256
    changed: dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


def findings_of(result, consent_violation: bool = False) -> list[str]:
    """
    Kinds of finding in a scan result, in the order of FINDING_ARTICLES.

    Args:
        result: ScanResult
        consent_violation: CookieRadar found trackers that persist after the
            user rejected them (audit --full)
    """
    found = {
        "tracker": bool(result.trackers),
        "extra_eu": bool(result.extra_eu_transfers),
        "consent": consent_violation,
        "sensitive": bool(result.sensitive_permissions),
    }
    return [finding for finding in FINDING_ARTICLES if found[finding]]


def check(
    result,
    *,
    consent_violation: bool = False,
    cache: Optional[LawCache] = None,
    now: Optional[datetime] = None,
) -> LawCheckResult:
    """Cite the GDPR provisions that apply to the findings of `result`."""
    cited = [
        (finding, ref)
        for finding in findings_of(result, consent_violation)
        for ref in FINDING_ARTICLES[finding]
    ]
    if not cited:
        return LawCheckResult(citations=[], source="none")

    cache = cache or LawCache()
    now = now or datetime.now(timezone.utc)
    changed: dict[str, str] = {}
    error = None

    try:
        provisions = law_fetcher.fetch_provisions(now=now)
    except LawFetchError as e:
        error = str(e)
        provisions = cache.load()
        source = "cache" if any(ref in provisions for _, ref in cited) else "unavailable"
    else:
        source = "eur-lex"
        try:
            provisions, changed = cache.update(provisions, checked_at=law_fetcher.utc_stamp(now))
        except OSError:
            pass  # the text just downloaded can still be cited

    refs = {ref for _, ref in cited}
    citations = []
    for finding, ref in cited:
        provision = provisions.get(ref)
        citations.append(Citation(
            finding=finding,
            article=ref,
            sha256=provision.sha256 if provision else None,
            version_date=provision.fetched_at[:10] if provision else None,
        ))
    return LawCheckResult(
        citations=citations,
        source=source,
        changed={ref: sha for ref, sha in changed.items() if ref in refs},
        error=error,
    )


def format_citation(citation: Citation) -> str:
    return (
        f"Norma applicata: {LAW_NAME} art. {citation.article}\n"
        f"SHA256: {citation.sha256 or 'non disponibile'}\n"
        f"Versione del: {citation.version_date or 'non disponibile'}"
    )
