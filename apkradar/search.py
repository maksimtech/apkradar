"""
APKRadar — App search module.
Search apps by name or package ID on Google Play Store.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class AppResult:
    package_name: str
    title: str
    developer: str
    score: float
    installs: str
    category: str
    description: str
    icon_url: str
    available: bool = True
    removal_reason: Optional[str] = None


def search_by_name(query: str, lang: str = "it", country: str = "it", limit: int = 5) -> list[AppResult]:
    """
    Search apps by name on Google Play Store.

    Args:
        query: App name to search
        lang: Language code
        country: Country code
        limit: Max results to return

    Returns:
        List of AppResult objects
    """
    try:
        from google_play_scraper import search

        results = search(query, lang=lang, country=country, n_hits=limit)
        return [
            AppResult(
                package_name=r.get("appId", ""),
                title=r.get("title", ""),
                developer=r.get("developer", ""),
                score=r.get("score", 0.0) or 0.0,
                installs=r.get("installs", "unknown"),
                category=r.get("genre", "unknown"),
                description=(r.get("description", "") or "")[:200],
                icon_url=r.get("icon", ""),
            )
            for r in results
        ]
    except Exception as e:
        raise RuntimeError(f"Search failed: {e}") from e


def get_app_info(package_name: str) -> AppResult:
    """
    Get app info by package name.
    If not found, searches for removal reason.

    Args:
        package_name: Android package name

    Returns:
        AppResult — available=False if not found
    """
    try:
        from google_play_scraper import app

        r = app(package_name)
        return AppResult(
            package_name=package_name,
            title=r.get("title", ""),
            developer=r.get("developer", ""),
            score=r.get("score", 0.0) or 0.0,
            installs=r.get("installs", "unknown"),
            category=r.get("genre", "unknown"),
            description=(r.get("description", "") or "")[:200],
            icon_url=r.get("icon", ""),
            available=True,
        )
    except Exception:
        # App not found — search for removal reason
        reason = _search_removal_reason(package_name)
        return AppResult(
            package_name=package_name,
            title="",
            developer="",
            score=0.0,
            installs="",
            category="",
            description="",
            icon_url="",
            available=False,
            removal_reason=reason,
        )


def _search_removal_reason(package_name: str) -> Optional[str]:
    """
    Search web for app removal reason.

    Args:
        package_name: Android package name

    Returns:
        Removal reason string or None
    """
    try:
        import httpx

        query = f"{package_name} removed banned Google Play Store reason"
        # DuckDuckGo instant answer API
        r = httpx.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": 1},
            timeout=5,
        )
        data = r.json()
        abstract = data.get("AbstractText", "")
        if abstract:
            return abstract[:300]
        return None
    except Exception:
        return None
