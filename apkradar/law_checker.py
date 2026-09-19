"""
APKRadar — EU and Italian law provisions for audit findings.

Maps what an audit found to the provisions it concerns, and cites each one
with the SHA-256 of the exact text applied and the date of that wording. The
text is downloaded on every audit (EUR-Lex, or Normattiva for Italian law)
and compared with the local cache; without network the cached copy is cited.

Shared by the Radar tools: only the mapping section is specific to APKRadar.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from apkradar import law_fetcher
from apkradar.law_cache import LawCache
from apkradar.law_fetcher import CONSUMER_CODE, DIGITAL_CONTENT, GDPR, Act, LawFetchError

# ─── Mapping: APKRadar findings → provisions ──────────────────────────────────

# Finding → cited provisions, in report order
FINDING_ARTICLES = {
    "tracker": ((GDPR, "5(1)(a)"), (GDPR, "6")),
    "tracker_undisclosed": ((DIGITAL_CONTENT, "8(1)(b)"),),
    "extra_eu": ((GDPR, "46"),),
    "consent": ((GDPR, "7"),),
    "sensitive": ((GDPR, "9"),),
    "permissions_undisclosed": ((CONSUMER_CODE, "49"),),
}

# APKRadar cannot read what the app declares (privacy policy, the store's data
# safety section): the "undisclosed" findings say so in their titles.
FINDING_TITLES = {
    "tracker": "Tracker e SDK di terze parti",
    "tracker_undisclosed": "Tracker non dichiarati? Da verificare rispetto all'informativa dell'app",
    "extra_eu": "Trasferimenti extra-UE",
    "consent": "Consenso",
    "sensitive": "Permessi sensibili",
    "permissions_undisclosed": "Permessi eccessivi non dichiarati? Da verificare rispetto alle informazioni precontrattuali",
}

# Articles downloaded and cached even when not cited, by act: the GDPR
# articles that explain the others (definitions, information, processors)
ALSO_FETCH: dict = {GDPR: ("4", "5", "6", "7", "9", "13", "28", "46")}


def findings_of(result, consent_violation: bool = False) -> dict[str, list[str]]:
    """
    Findings in an APKRadar ScanResult, with what triggered each.

    Args:
        result: ScanResult
        consent_violation: CookieRadar found trackers that persist after the
            user rejected them (audit --full)
    """
    found: dict[str, list[str]] = {}
    if result.trackers:
        names = [tracker.name for tracker in result.trackers]
        found["tracker"] = names
        found["tracker_undisclosed"] = names
    if result.extra_eu_transfers:
        found["extra_eu"] = [transfer.entity for transfer in result.extra_eu_transfers]
    if consent_violation:
        found["consent"] = ["tracker ancora attivi dopo il rifiuto (CookieRadar)"]
    if result.sensitive_permissions:
        permissions = [
            f"{perm.permission.split('.')[-1]} ({perm.description})"
            for perm in result.sensitive_permissions
        ]
        found["sensitive"] = permissions
        found["permissions_undisclosed"] = permissions
    return {finding: found[finding] for finding in FINDING_ARTICLES if finding in found}


def notes_of(result, consent_violation: bool = False) -> list[str]:
    return []


# ─── Citations ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Citation:
    finding: str
    law: str                      # act as cited: "GDPR"
    article: str                  # "32(1)(a)"
    sha256: Optional[str]         # None when the text could not be obtained
    version_date: Optional[str]   # YYYY-MM-DD the wording was downloaded


@dataclass(frozen=True)
class ActStatus:
    act: Act
    # "verified": downloaded now from the act's source (EUR-Lex or Normattiva);
    # "cache": source unreachable, cached copy; "unavailable": no text at all
    source: str
    error: Optional[str] = None


@dataclass
class LawCheckResult:
    citations: list[Citation]
    acts: list[ActStatus] = field(default_factory=list)
    # What triggered each finding, e.g. {"critical": ["CVE-2026-1234"]}
    evidence: dict[str, list[str]] = field(default_factory=dict)
    # "GDPR art. 32" → SHA-256 of its previous text, for cited provisions
    # whose text changed since the last audit
    changed: dict[str, str] = field(default_factory=dict)
    # Remarks without a citation, e.g. why no verdict was possible
    notes: list[str] = field(default_factory=list)


def check(
    subject,
    *,
    cache: Optional[LawCache] = None,
    now: Optional[datetime] = None,
    **context,
) -> LawCheckResult:
    """
    Cite the provisions that apply to the findings about `subject`.

    `context` is passed on to findings_of and notes_of: what the audit found
    besides `subject` itself.
    """
    evidence = findings_of(subject, **context)
    notes = notes_of(subject, **context)
    cited = [
        (finding, act, ref)
        for finding in evidence
        for act, ref in FINDING_ARTICLES[finding]
    ]
    if not cited:
        return LawCheckResult(citations=[], notes=notes)

    cache = cache or LawCache()
    now = now or datetime.now(timezone.utc)

    acts = list(dict.fromkeys(act for _, act, _ in cited))
    fresh = {}
    errors = {}
    for act in acts:
        # The articles cited ("32(1)(a)" is part of article 32) and ALSO_FETCH
        articles = tuple(dict.fromkeys(
            [ref.split("(")[0] for _, a, ref in cited if a == act] + list(ALSO_FETCH.get(act, ()))
        ))
        try:
            provisions = law_fetcher.fetch_provisions(act, articles, now=now)
        except LawFetchError as e:
            errors[act] = str(e)
        else:
            fresh.update({p.key: p for p in provisions.values()})

    changed = {}
    try:
        if fresh:
            provisions, changed = cache.update(fresh, checked_at=law_fetcher.utc_stamp(now))
        else:
            provisions = cache.load()
    except OSError:
        provisions = {**cache.load(), **fresh}   # the text just downloaded can still be cited

    statuses = []
    for act in acts:
        if act not in errors:
            statuses.append(ActStatus(act, "verified"))
        else:
            cached = any((act.celex, ref) in provisions for _, a, ref in cited if a == act)
            statuses.append(ActStatus(act, "cache" if cached else "unavailable", errors[act]))

    citations = []
    for finding, act, ref in cited:
        provision = provisions.get((act.celex, ref))
        citations.append(Citation(
            finding=finding,
            law=act.name,
            article=ref,
            sha256=provision.sha256 if provision else None,
            version_date=provision.fetched_at[:10] if provision else None,
        ))

    names = {act.celex: act.name for act in acts}
    cited_keys = {(act.celex, ref) for _, act, ref in cited}
    return LawCheckResult(
        citations=citations,
        acts=statuses,
        evidence=evidence,
        changed={
            f"{names[celex]} art. {article}": sha
            for (celex, article), sha in changed.items()
            if (celex, article) in cited_keys
        },
        notes=notes,
    )


def format_citation(citation: Citation) -> str:
    return (
        f"Norma applicata: {citation.law} art. {citation.article}\n"
        f"SHA256: {citation.sha256 or 'non disponibile'}\n"
        f"Versione del: {citation.version_date or 'non disponibile'}"
    )
