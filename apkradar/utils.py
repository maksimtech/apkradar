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
# SDK → domini noti
SDK_DOMAINS = {
    "com.google.firebase":        ["firebase.google.com", "firebaseapp.com"],
    "com.google.android.gms":     ["google.com", "googleapis.com"],
    # AdMob. Not the advertising-ID reader that lives under the same prefix:
    # scanner.SIGNATURE_EXCEPTIONS keeps these two domains off an app that only
    # reads the identifier, which is most of them.
    "com.google.android.gms.ads": ["googleadservices.com", "doubleclick.net"],
    "com.facebook":               ["facebook.com", "fbcdn.net"],
    "com.appsflyer":              ["appsflyer.com"],
    "com.applovin":               ["applovin.com"],
    "com.unity3d.ads":            ["unity.com", "unityads.unity3d.com"],
    "com.ironsource.mediationsdk":["ironsrc.com", "supersonic.com"],
    "com.inmobi":                 ["inmobi.com"],
    "com.mixpanel.android":       ["mixpanel.com"],
    "io.sentry":                  ["sentry.io"],
    "com.crashlytics":            ["firebase.google.com"],
    "com.adjust.sdk":             ["adjust.com"],
    "com.vungle":                 ["vungle.com"],
    "com.chartboost":             ["chartboost.com"],
    "com.mopub":                  ["mopub.com"],
    "com.snap.adkit":             ["snapchat.com"],
    "com.tiktok.sdk":             ["tiktok.com", "bytedance.com"],
    "com.yandex.metrica":         ["appmetrica.yandex.com"],
    "com.amplitude.api":          ["amplitude.com"],
    "com.segment.analytics":      ["segment.com", "segment.io"],
    "io.branch.referral":         ["branch.io"],
    "com.onesignal":              ["onesignal.com"],
    "com.newrelic.agent.android": ["newrelic.com"],
    "com.instabug":               ["instabug.com"],
    "com.bugsnag.android":        ["bugsnag.com"],
    "com.datadog":                ["datadoghq.com"],
    "com.microsoft.appcenter":    ["appcenter.ms"],
    "com.huawei.hms.analytics":   ["hicloud.com"],
    "com.xiaomi.mipush":          ["xiaomi.com"],
    "com.baidu.mobads":           ["baidu.com"],
}

def package_to_domain(package_name: str) -> str | None:
    """
    Extract publisher domain from Android package name.

    Uses heuristics to find the most meaningful domain:
    - Skips generic second-level segments (game, app, mobile, etc.)
    - Falls back to package name parts when domain is ambiguous

    The result is lowercased: `it.Beta80Group.whereareu` used to give
    `Beta80Group.it` from this branch while the generic-segment branch below
    lowercased its own, and `get_all_domains` collects into a set — so the
    capitals bought a second MailRadar, SSL and CookieRadar run on the same host.

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
        return f"{company}.{tld}".lower()

    # `_` is legal in a package name and not in a hostname: com.my_company.app
    # gave my_company.com here while the branch above already said my-company.
    return f"{sld.replace('_', '-')}.{tld}".lower()


def domain_to_url(domain: str) -> str:
    """Convert domain to HTTPS URL.

    The scheme is matched whole: `httpbin.org` starts with "http" and is a host.
    """
    if domain.startswith(("http://", "https://")):
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
        # androguard 4 serialises to bytes. A str pattern on bytes raises
        # TypeError, which the `except` below swallowed: on every real APK this
        # returned nothing, and only the tests' str mocks ever saw a deep link.
        if isinstance(xml, bytes):
            xml = xml.decode("utf-8", "replace")
        import re

        from apkradar.hosts import _valid_host
        # Find android:host attributes with real domains
        hosts = re.findall(r'android:host="([^"]+)"', xml)
        for host in hosts:
            host = host.strip().lower()
            # A deep-link host goes on to MailRadar, the certificate check and
            # the CONNECT line sent to a proxy, so it has to be a hostname. The
            # DEX scan's rules: they also refuse every IP literal — 10.0.2.2 is
            # the emulator's host, not the publisher's — wildcards, `{}`
            # placeholders, and anything with a space or a CR/LF in it. Only
            # 127.0.0.1 and 192.* used to be refused.
            if _valid_host(host):
                domains.append(host)
    except Exception:
        pass
    return list(set(domains))


def extract_sdk_domains(trackers: list) -> list[str]:
    """
    Extract known domains for detected trackers/SDKs.

    These domains are audited — mail records, certificate, cookies — and named in
    the letter, so a wrong one is an accusation about somebody's traffic. Two
    things were wrong until 2026-09-30:

    - the match was `startswith(prefix) or prefix in package`, and a substring
      test on a package name has no reason to be right: it is now segment-aware,
      the same rule the scanner uses.
    - `com.google.android.gms.ads.identifier` — the class that reads the
      advertising ID, present in a large share of apps through libraries that do
      not advertise — inherited AdMob's googleadservices.com and doubleclick.net.

    A tracker still collects the domains of every prefix it lives under:
    Firebase Analytics is reached through googleapis.com as well as its own host.

    Args:
        trackers: List of TrackerFound objects

    Returns:
        List of unique domains associated with detected SDKs
    """
    from apkradar.scanner import SIGNATURE_EXCEPTIONS, _in_package

    domains = []
    for tracker in trackers:
        for sdk_prefix, sdk_domains in SDK_DOMAINS.items():
            if not _in_package(tracker.package, sdk_prefix):
                continue
            if any(
                _in_package(tracker.package, exc)
                for exc in SIGNATURE_EXCEPTIONS.get(sdk_prefix, ())
            ):
                continue
            domains.extend(sdk_domains)
    return list(set(domains))


# Above this many deep-link hosts, the manifest is not pointing at the publisher's
# site: it is listing the sites whose links the app opens. OsmAnd~ 5.4.9 declares
# 427 — maps.google.com and some 200 Google country domains, map.baidu.com,
# maps.yandex.ru, here.com, maps.apple.com — because it opens links to other
# maps; NewPipe declares 56 for youtube.com, soundcloud.com, bandcamp.com and a
# list of PeerTube instances. `audit --full` took each as a domain to analyse,
# which on OsmAnd meant MailRadar, a TLS handshake and a headless browser against
# 427 hosts: about three and a half hours, at the ~30 s per domain measured on
# 2026-10-09, of traffic to Google, Baidu and Yandex about an app that talks to
# none of them. Ten is well above anything a publisher declares for itself (the
# most seen is F-Droid's four) and well below any app's list of other people's.
MAX_DEEP_LINK_DOMAINS = 10


def _own_deep_links(hosts) -> list[str]:
    from apkradar.publisher import is_platform_host

    return [host for host in dict.fromkeys(hosts) if not is_platform_host(host)]


def deep_link_domains(hosts) -> list[str]:
    """Deep-link hosts worth auditing: the publisher's own, not the platforms'.

    An app declaring `where.areu.lombardia.it` in an intent filter is pointing at
    its publisher. An app declaring `play.google.com` is pointing at the store,
    which nearly all of them do — auditing the mail records and cookies of
    Google's store page once per APK measures nothing about the app.

    And an app declaring dozens is pointing at everybody else's: none of those is
    audited, see MAX_DEEP_LINK_DOMAINS. `deep_links_set_aside` says which, so the
    report can give the count without printing the list.

    Only deep links are filtered this way. SDK domains come from trackers found
    in the file, where facebook.com is the domain the finding is about.
    """
    own = _own_deep_links(hosts)
    return [] if len(own) > MAX_DEEP_LINK_DOMAINS else own


def deep_links_set_aside(hosts) -> list[str]:
    """The deep-link hosts not audited because there were too many of them."""
    own = _own_deep_links(hosts)
    return own if len(own) > MAX_DEEP_LINK_DOMAINS else []


def publisher_domains(result) -> list[str]:
    """The publisher's own domain, or nothing — see apkradar.publisher.

    At most one: the Google Play listing when it names a site, the reverse-DNS of
    the package name only when it does not. This used to return both whenever the
    two differed, which meant auditing the domain of whoever built the app.

    Offline and pure, so it cannot know whether a domain is for sale; the caller
    that analyses these passes them through `publisher.without_parked` first.
    """
    from apkradar.publisher import from_result

    return [domain for domain, _ in from_result(result).candidates]


def get_all_domains(result, apk=None) -> list[str]:
    """
    Get all domains associated with an APK scan result.

    Combines:
    - Publisher domain candidates (package name and/or Google Play listing)
    - SDK domains (from detected trackers)
    - Deep link domains (from the manifest, collected during the scan)

    Args:
        result: ScanResult object
        apk: androguard APK object (optional, for a manifest not already read)

    Returns:
        List of unique domains to audit
    """
    domains = set()

    # 1. Publisher candidates, labelled where they are printed — see publisher.py
    domains.update(publisher_domains(result))

    # 2. SDK domains from detected trackers
    sdk_domains = extract_sdk_domains(result.trackers)
    domains.update(sdk_domains)

    # 3. Deep link domains from the manifest. Read during the scan: the only
    #    caller passed no apk, so this branch was unreachable from `audit --full`.
    declared = list(getattr(result, "manifest_domains", None) or [])
    if apk:
        declared += extract_domains_from_apk(apk)
    domains.update(deep_link_domains(declared))

    return list(domains)
