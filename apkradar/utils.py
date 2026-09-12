"""
APKRadar — Utility functions.
"""
from __future__ import annotations


def package_to_domain(package_name: str) -> str | None:
    """
    Extract publisher domain from Android package name.

    Examples:
        com.scopely.monopolygo → scopely.com
        com.google.android.gms → google.com
        io.branch.referral → branch.io
        me.bitwarden.vault → bitwarden.me

    Args:
        package_name: Android package name (e.g. com.example.app)

    Returns:
        Domain string or None if cannot be determined
    """
    if not package_name:
        return None

    parts = package_name.strip().split(".")

    if len(parts) < 2:
        return None

    tld = parts[0]
    sld = parts[1]

    # Standard reverse domain: com.company.app → company.com
    return f"{sld}.{tld}"


def domain_to_url(domain: str) -> str:
    """Convert domain to HTTPS URL."""
    if domain.startswith("http"):
        return domain
    return f"https://{domain}"
