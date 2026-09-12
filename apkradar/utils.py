"""
APKRadar — Utility functions.
"""
from __future__ import annotations


# Second-level segments that are too generic to be a company name
# e.g. com.game.myapp → "game" is not the company, "myapp" might be
GENERIC_SEGMENTS = {
    "game", "games", "app", "apps", "android", "mobile",
    "dev", "development", "software", "tech", "digital",
    "studio", "studios", "media", "labs", "lab", "inc",
    "llc", "ltd", "corp", "group", "team", "project",
}


def package_to_domain(package_name: str) -> str | None:
    """
    Extract publisher domain from Android package name.

    Uses heuristics to find the most meaningful domain:
    - Skips generic second-level segments (game, app, mobile, etc.)
    - Falls back to package name parts when domain is ambiguous

    Examples:
        com.scopely.monopolygo     → scopely.com
        com.google.android.gms     → google.com
        io.branch.referral         → branch.io
        me.bitwarden.vault         → bitwarden.me
        com.game.asteroids_revenge → asteroids-revenge.com (fallback)
        com.facebook.katana        → facebook.com

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

    tld = parts[0]   # com, net, io, me, org...
    sld = parts[1]   # company or generic segment

    # If second segment is generic, try third segment
    if sld.lower() in GENERIC_SEGMENTS and len(parts) > 2:
        company = parts[2].replace("_", "-").lower()
        return f"{company}.{tld}"

    return f"{sld}.{tld}"


def domain_to_url(domain: str) -> str:
    """Convert domain to HTTPS URL."""
    if domain.startswith("http"):
        return domain
    return f"https://{domain}"


def extract_domains_from_apk(apk) -> list[str]:
    """
    Extract declared HTTPS domains from APK manifest deep links.

    Args:
        apk: androguard APK object

    Returns:
        List of domains found in intent filters
    """
    domains = []
    try:
        # Parse XML manifest for deep link hosts
        xml = apk.get_android_manifest_axml().get_xml()
        import re
        # Find android:host attributes with real domains
        hosts = re.findall(r'android:host="([^"]+)"', xml)
        for host in hosts:
            host = host.strip()
            if not host or host.startswith(".") or "{" in host:
                continue
            # Skip localhost and IP addresses
            if host in ("localhost", "127.0.0.1") or host.startswith("192."):
                continue
            # Must look like a domain
            if "." in host and not host.startswith("*"):
                domains.append(host)
    except Exception:
        pass
    return list(set(domains))
