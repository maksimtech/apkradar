"""
APKRadar — App lookup module.
Lookup app info by package name from Google Play Store.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class AppInfo:
    package_name: str
    title: str
    developer: str
    score: float
    installs: str
    category: str
    description: str
    available: bool = True
    removal_reason: Optional[str] = None


def lookup(package_name: str) -> AppInfo:
    """
    Lookup app info by package name.

    Args:
        package_name: Android package name

    Returns:
        AppInfo object
    """
    try:
        from google_play_scraper import app
        r = app(package_name)
        return AppInfo(
            package_name=package_name,
            title=r.get("title", ""),
            developer=r.get("developer", ""),
            score=r.get("score", 0.0) or 0.0,
            installs=r.get("installs", "unknown"),
            category=r.get("genre", "unknown"),
            description=(r.get("description", "") or "")[:300],
            available=True,
        )
    except Exception:
        reason = _search_removal_reason(package_name)
        return AppInfo(
            package_name=package_name,
            title="",
            developer="",
            score=0.0,
            installs="",
            category="",
            description="",
            available=False,
            removal_reason=reason,
        )


def _search_removal_reason(package_name: str) -> Optional[str]:
    """Search web for app removal reason."""
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
