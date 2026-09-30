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
from datetime import UTC, datetime

from apkradar import law_fetcher
from apkradar.law_cache import Key, LawCache
from apkradar.law_fetcher import CONSUMER_CODE, DIGITAL_CONTENT, GDPR, Act, LawFetchError, Provision

# ─── Mapping: APKRadar findings → provisions ──────────────────────────────────

# Finding → cited provisions, in report order
FINDING_ARTICLES = {
    "tracker": ((GDPR, "5(1)(a)"), (GDPR, "6")),
    "tracker_undisclosed": ((DIGITAL_CONTENT, "8(1)(b)"),),
    "extra_eu": ((GDPR, "46"),),
    "consent": ((GDPR, "7"),),
    "sensitive": ((GDPR, "5(1)(c)"), (GDPR, "6")),
    "special_category": ((GDPR, "9"),),
    "permissions_undisclosed": ((CONSUMER_CODE, "49"),),
}

# ─── Which permissions can reach a special category of data ───────────────────
#
# Art. 9(1) lists what a special category is, exhaustively: racial or ethnic
# origin, political opinions, religious or philosophical beliefs, trade union
# membership, genetic data, biometric data processed *for the purpose of uniquely
# identifying* a natural person, data concerning health, and data concerning sex
# life or sexual orientation. Nothing else is in it.
#
# Until 2026-09-30 the `sensitive` finding cited art. 9 for every permission in
# scanner.SENSITIVE_PERMISSIONS — twenty-eight of them, including storage read,
# calendar, device accounts and the advertising identifier. That citation went
# into a letter addressed to a data protection officer, which is the worst place
# for a legal claim that does not hold: it is the part a DPO can dismiss without
# reading the rest, and the findings underneath it are sound.
#
# Two cases are worth naming because they look like art. 9 and are not:
#
#   location      Not a special category. It can *reveal* one — a weekly visit
#                 to a place of worship, a clinic — but that is an inference
#                 from a purpose and a pattern, not a property of the
#                 permission, and this audit reads a manifest. Art. 5(1)(c) and
#                 art. 6 are what apply, and they apply to every entry here.
#   biometrics    USE_BIOMETRIC and USE_FINGERPRINT ask the operating system to
#                 authenticate the user. Android does the matching itself and
#                 hands the app a boolean; the template never leaves the secure
#                 hardware. Art. 9 requires biometric data processed for the
#                 purpose of uniquely identifying someone, and an app that
#                 receives no biometric data is not processing any.
#
# What is left is health data, and it stays conditional, because the article
# turns on what the data is used for and a manifest does not say. The letter
# asks; it does not allege.
#
# The reason is held in both languages the letter is written in. It reaches a
# data protection officer inside an Italian sentence, and an English clause
# dropped into the middle of it is how a reader learns the paragraph was
# assembled rather than written.
_SPECIAL_CATEGORY_PERMISSIONS = {
    "android.permission.BODY_SENSORS": {
        "en": "heart rate and comparable vital signs, which are data concerning health",
        "it": "frequenza cardiaca e parametri vitali analoghi, che sono dati relativi alla salute",
    },
    "android.permission.BODY_SENSORS_BACKGROUND": {
        "en": "heart rate and comparable vital signs, read while the app is in the background",
        "it": (
            "frequenza cardiaca e parametri vitali analoghi, letti mentre "
            "l'applicazione è in background"
        ),
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "en": (
            "physical activity, which concerns health where it is used to infer a "
            "health status rather than to count steps for their own sake"
        ),
        "it": (
            "attività fisica, che riguarda la salute quando è usata per inferire uno "
            "stato di salute e non per contare i passi in quanto tali"
        ),
    },
}

# Health Connect addresses each kind of record with its own permission —
# android.permission.health.READ_HEART_RATE and some fifty others — so the prefix
# is matched rather than the names listed. None of these are in
# scanner.SENSITIVE_PERMISSIONS yet; when one is added, it arrives here already
# cited correctly instead of silently joining the art. 9 claim by default.
_HEALTH_CONNECT_PREFIX = "android.permission.health."
_HEALTH_CONNECT_REASON = {
    "en": "a Health Connect record, which is data concerning health",
    "it": "un record di Health Connect, che è un dato relativo alla salute",
}


def special_category_reason(permission: str, lang: str = "en") -> str | None:
    """Why art. 9 is in play for this permission, or None if it is not.

    None is the answer for most of them, and saying so is the point: an audit
    that cites art. 9 for a calendar permission has said nothing a controller
    needs to answer.

    `lang` follows the letter's own languages and falls back to English, the way
    the template does — a missing translation must not silence the finding.
    """
    if permission.startswith(_HEALTH_CONNECT_PREFIX):
        return _HEALTH_CONNECT_REASON.get(lang, _HEALTH_CONNECT_REASON["en"])
    reasons = _SPECIAL_CATEGORY_PERMISSIONS.get(permission)
    if reasons is None:
        return None
    return reasons.get(lang, reasons["en"])


# APKRadar cannot read what the app declares (privacy policy, the store's data
# safety section): the "undisclosed" findings say so in their titles.
FINDING_TITLES = {
    "tracker": "Third-party trackers and SDKs",
    "tracker_undisclosed": "Trackers not disclosed? To be checked against the app's privacy notice",
    "extra_eu": "Transfers outside the EU",
    "consent": "Consent",
    "sensitive": "Sensitive permissions",
    "special_category": "Permissions that can reach a special category of data",
    "permissions_undisclosed": (
        "Excessive permissions not disclosed? "
        "To be checked against the pre-contractual information"
    ),
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
        found["consent"] = ["trackers still active after rejection (CookieRadar)"]
    if result.sensitive_permissions:
        permissions = [
            f"{perm.permission.split('.')[-1]} ({perm.description})"
            for perm in result.sensitive_permissions
        ]
        found["sensitive"] = permissions
        found["permissions_undisclosed"] = permissions
        special = [
            f"{perm.permission.split('.')[-1]} ({perm.description}): {reason}"
            for perm in result.sensitive_permissions
            if (reason := special_category_reason(perm.permission))
        ]
        if special:
            found["special_category"] = special
    return {finding: found[finding] for finding in FINDING_ARTICLES if finding in found}


def notes_of(result, consent_violation: bool = False) -> list[str]:
    return []


# ─── Citations ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Citation:
    finding: str
    law: str                      # act as cited: "GDPR"
    article: str                  # "32(1)(a)"
    sha256: str | None         # None when the text could not be obtained
    version_date: str | None   # YYYY-MM-DD the wording was downloaded


@dataclass(frozen=True)
class ActStatus:
    act: Act
    # "verified": downloaded now from the act's source (EUR-Lex or Normattiva);
    # "cache": source unreachable, cached copy; "unavailable": no text at all
    source: str
    error: str | None = None


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
    cache: LawCache | None = None,
    now: datetime | None = None,
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
    now = now or datetime.now(UTC)

    acts = list(dict.fromkeys(act for _, act, _ in cited))
    # Keyed by (celex, article) — the cache's key, not the fetcher's.
    fresh: dict[Key, Provision] = {}
    errors: dict[Act, str] = {}
    for act in acts:
        # The articles cited ("32(1)(a)" is part of article 32) and ALSO_FETCH
        articles = tuple(dict.fromkeys(
            [ref.split("(")[0] for _, a, ref in cited if a == act] + list(ALSO_FETCH.get(act, ()))
        ))
        try:
            by_article = law_fetcher.fetch_provisions(act, articles, now=now)
        except LawFetchError as e:
            errors[act] = str(e)
        else:
            fresh.update({p.key: p for p in by_article.values()})

    changed: dict[Key, str] = {}
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
        f"Provision applied: {citation.law} art. {citation.article}\n"
        f"SHA256: {citation.sha256 or 'not available'}\n"
        f"Version of: {citation.version_date or 'not available'}"
    )
