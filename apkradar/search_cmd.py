"""
APKRadar — App lookup module.
Lookup app info by package name from Google Play Store.

One `except Exception` used to answer three different questions with the same
sentence, "App not found on Google Play":

  the store said no        the listing is genuinely absent from that store
  the store said nothing   a timeout, a 429, a changed page, no network
  nobody asked the store   google-play-scraper is not installed

The second and third are not findings about an application, and the first is not
a finding about an application either until the store it was asked of is named:
`google_play_scraper.app` defaults to `lang="en", country="us"`, so an app
published only in Europe answered "not found" from a shop it was never in. None
of that was written down, and a web search for "<package> removed banned" then
supplied a "removal reason" for whichever of the three had happened.

So `status` says which of the three it was, the store that answered is part of the
answer, and the web abstract is labelled as what it is: an unverified hint, only
ever fetched when the store did say no.
"""
from __future__ import annotations

from dataclasses import dataclass

# What google_play_scraper asks for unless told otherwise. Kept as the default so
# that no result changes silently, and recorded in every AppInfo so that a report
# says which shop it is talking about.
DEFAULT_LANG = "en"
DEFAULT_COUNTRY = "us"

LISTED = "listed"           # the store returned a listing
NOT_LISTED = "not_listed"   # the store answered, and it has no such app
UNKNOWN = "unknown"         # nothing was established either way


@dataclass
class AppInfo:
    package_name: str
    title: str
    developer: str
    score: float
    installs: str
    category: str
    description: str
    # Free text the developer types into the Play console: it is a real site as
    # often as it is a helpdesk tenant or a Facebook page, so it is weighed
    # against the package name rather than trusted — see apkradar.publisher.
    developer_website: str = ""
    status: str = LISTED
    # The store that answered. "not listed" means nothing without it.
    lang: str = DEFAULT_LANG
    country: str = DEFAULT_COUNTRY
    # Why there is no listing here, in the words of whatever failed. Present for
    # UNKNOWN, and for NOT_LISTED where the library said something useful.
    error: str | None = None
    # A web search abstract about the package name. Not a reason, not verified,
    # and not evidence of anything: a starting point for somebody to check.
    removal_hint: str | None = None

    @property
    def available(self) -> bool:
        """True only when the store returned a listing.

        False therefore still means three different things — read `status` when
        the difference matters, which it does anywhere the answer is printed or
        acted upon.
        """
        return self.status == LISTED

    @property
    def not_listed(self) -> bool:
        return self.status == NOT_LISTED

    @property
    def undetermined(self) -> bool:
        return self.status == UNKNOWN


def lookup(
    package_name: str,
    *,
    lang: str = DEFAULT_LANG,
    country: str = DEFAULT_COUNTRY,
) -> AppInfo:
    """
    Lookup app info by package name.

    Args:
        package_name: Android package name
        lang: listing language asked of the store
        country: store to ask — the answer is about that store and no other

    Returns:
        AppInfo, with `status` saying whether the store returned a listing,
        answered that it has none, or did not answer at all. It never raises:
        the caller is usually a scan, and a store that is having a bad afternoon
        does not invalidate what the APK itself said.
    """
    def no_listing(status: str, error: str | None, hint: str | None = None) -> AppInfo:
        """The fields written out rather than splatted from a dict.

        A dict of mixed values collapses to `dict[str, object]` and mypy then
        rejects every argument of the call it is splatted into — measured on
        patchradar's debian_status on 2026-09-28, seven errors from one `**`.
        """
        return AppInfo(
            package_name=package_name,
            title="",
            developer="",
            score=0.0,
            installs="",
            category="",
            description="",
            status=status,
            lang=lang,
            country=country,
            error=error,
            removal_hint=hint,
        )

    try:
        from google_play_scraper import app
        from google_play_scraper.exceptions import NotFoundError
    except ImportError as exc:                       # nobody asked the store
        return no_listing(UNKNOWN, f"google-play-scraper unavailable: {exc}")

    try:
        r = app(package_name, lang=lang, country=country)
    except NotFoundError as exc:                     # the store answered: no
        return no_listing(NOT_LISTED, str(exc) or None, _web_abstract(package_name))
    except Exception as exc:                         # the store answered nothing
        # Timeouts, 429s, a page that changed shape. Reporting this as "removed"
        # is how a working app came to be described as taken down, so it is not
        # reported as anything about the app.
        return no_listing(UNKNOWN, f"{type(exc).__name__}: {exc}")

    return AppInfo(
        package_name=package_name,
        title=r.get("title", ""),
        developer=r.get("developer", ""),
        score=r.get("score", 0.0) or 0.0,
        installs=r.get("installs", "unknown"),
        category=r.get("genre", "unknown"),
        description=(r.get("description", "") or "")[:300],
        developer_website=r.get("developerWebsite", "") or "",
        status=LISTED,
        lang=lang,
        country=country,
    )


def _web_abstract(package_name: str) -> str | None:
    """A web search abstract about the package name, or None.

    Called only when the store has said it has no such app, and its result is
    printed as an unverified hint. It is a search for
    "<package> removed banned Google Play Store", so it answers that query and
    not the question of why an app is gone: DuckDuckGo will return an abstract
    about a namesake, about the vendor, or about Play policy in general, and any
    of them would read as the reason if it were labelled one.
    """
    try:
        import httpx
        r = httpx.get(
            "https://api.duckduckgo.com/",
            params={
                "q": f"{package_name} removed banned Google Play Store",
                "format": "json",
                "no_html": 1
            },
            timeout=5,
        )
        data = r.json()
        abstract = data.get("AbstractText", "")
        if abstract:
            return abstract[:300]
        return None
    except Exception:
        return None
