"""
APKRadar — Which domain belongs to the publisher, and how well we know it.

Reversing the Android package name gives the reverse-DNS of whoever built the
app. That is the publisher often enough to be tempting — org.wikipedia,
com.nextcloud.client, com.moonactive.coinmaster all come out right — and wrong
often enough to matter: it.Beta80Group.whereareu gives the supplier's domain for
an app published by a regional health agency, and com.x8bit.bitwarden gives a
Spanish software firm with no connection to Bitwarden.

Google Play's developerWebsite is not the answer either. It is free text the
developer fills in, and for Coin Master it is a Zendesk helpdesk tenant whose
mail posture is largely Zendesk's configuration. Measured on four apps, Play is
right three times out of four and the package name once — so neither source is
authoritative, and the useful thing is not a better guess but knowing which case
you are in.

So: consult both, drop the platform tenants, and keep the provenance attached to
the domain wherever it travels. A domain is treated as established only when the
two independent sources agree or when the sender states it — everything else is
labelled a guess, and a guess does not support an art. 32 allegation against a
named legal entity.

At most one domain is ever analysed as the publisher's. When the two sources
differ the listing wins and the reverse-DNS guess is set aside — kept as data,
never printed — because that guess is the domain of whoever built the app, and
running MailRadar, SSL and CookieRadar over it puts findings against a company
that is not the subject of the report. And a candidate that answers with a
domain-for-sale page is dropped too: it has no holder to attribute anything to,
and a report that audits a domain on the market invalidates itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

# Hosts that serve many customers. A tenant under one of these is not the
# publisher's own domain: its mail records, its certificate and its cookies are
# the platform's doing, so a finding there says nothing about the publisher.
# Social profiles and app-store pages are here for the same reason — plus they
# are not domains anyone can hold responsible under art. 32.
PLATFORM_HOSTS = frozenset({
    # helpdesks
    "zendesk.com", "freshdesk.com", "helpscoutdocs.com", "intercom.help",
    "helpshift.com", "crisp.help", "tawk.help",
    # site builders and static hosting
    "wixsite.com", "wix.com", "weebly.com", "webnode.page", "jimdosite.com",
    "squarespace.com", "square.site", "godaddysites.com", "mystrikingly.com",
    "carrd.co", "webflow.io", "wordpress.com", "blogger.com", "tumblr.com",
    "github.io", "gitlab.io", "pages.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "firebaseapp.com", "web.app", "appspot.com",
    "notion.site", "sites.google.com", "docs.google.com", "drive.google.com",
    "groups.google.com", "play.google.com", "forsale.godaddy.com",
    "onrender.com", "glitch.me", "repl.co", "bubbleapps.io",
    # shops
    "myshopify.com", "etsy.com", "gumroad.com", "itch.io",
    # social and stores
    "facebook.com", "fb.me", "fb.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "youtu.be", "t.me", "telegram.me",
    "discord.gg", "discord.com", "reddit.com", "medium.com", "vk.com",
    "apps.apple.com", "itunes.apple.com", "amazon.com", "galaxystore.samsung.com",
})

# Blogspot answers on dozens of country domains (blogspot.it, blogspot.com.br…),
# too many to list.
_BLOGSPOT = re.compile(r"(^|\.)blogspot\.[a-z]{2,}(\.[a-z]{2,})?$")

_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*:(//)?", re.IGNORECASE)
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$")
_ALL_DIGITS = re.compile(r"^[\d.]+$")

# Where a domain-for-sale page lives. A candidate whose redirects end on one of
# these hosts is on the market: it has no holder to answer for a finding, and
# whoever buys it next inherits one made about somebody else.
FOR_SALE_HOSTS = frozenset({
    "forsale.godaddy.com", "sedo.com", "sedoparking.com", "afternic.com",
    "dan.com", "undeveloped.com", "hugedomains.com", "buydomains.com",
    "parkingcrew.net", "bodis.com", "above.com", "domainmarket.com",
    "brandbucket.com", "squadhelp.com", "atom.com", "namebright.com",
    "domainnamesales.com", "efty.com", "sav.com", "dynadot.com",
})

# Some parkings answer on the domain itself with no redirect, so the page's own
# words are a second signal. Patterns rather than substrings: a lander writes
# "the domain example.com is for sale", with the name in the middle, and every
# phrase here has to be about the domain — "buy now" on its own is half the web.
FOR_SALE_MARKERS = (
    # The dot is allowed: the name sits inside the sentence, as in "the domain
    # example.com is for sale".
    re.compile(r"domain\b[^!?]{0,60}?is for sale", re.I),
    re.compile(r"buy this domain", re.I),
    re.compile(r"this domain may be for sale", re.I),
    re.compile(r"(owner|holder) of this domain", re.I),
    re.compile(r"inquire about this domain", re.I),
    re.compile(r"questo dominio[^.!?]{0,40}(in vendita|è in vendita)", re.I),
)

# Enough of the page to find a phrase in, and no more.
_SNIFF = 4096

# What each provenance means, in the words that get printed next to the domain.
PROVENANCE_LABELS = {
    "agreed": "package name and Google Play listing agree",
    "corroborated": "from Google Play listing, and the app points at it",
    "stated": "stated by the sender",
    "play_listing": "from Google Play listing — unverified",
    "package_name": "guessed from package name — unverified",
}


def is_platform_host(host: str) -> bool:
    """True when the host belongs to a platform rather than to a publisher.

    Both the host itself and anything under it: `zendesk.com` is Zendesk's, and
    `moonactive.zendesk.com` is a tenant on Zendesk's infrastructure. Neither
    tells you anything about Moon Active.
    """
    if not host:
        return False
    host = host.lower()
    if _BLOGSPOT.search(host):
        return True
    return any(host == known or host.endswith(f".{known}") for known in PLATFORM_HOSTS)


def normalise_site(value: str | None) -> str | None:
    """A bare lowercase hostname out of whatever a free-text field holds.

    Play's developerWebsite is typed in by hand: it arrives with schemes, paths,
    ports, trailing dots, capitals, `www.`, and sometimes it is not a URL at all.
    Anything that is not a hostname returns None rather than a string that would
    later be printed as "the publisher domain".
    """
    if not value:
        return None
    text = _SCHEME.sub("", value.strip())
    if not text:
        return None

    host = re.split(r"[/?#]", text, maxsplit=1)[0]
    if "@" in host:                      # mailto:, or user@host
        return None
    host = host.split(":")[0].strip().rstrip(".").lower()

    if "." not in host or not _HOSTNAME.match(host):
        return None
    if _ALL_DIGITS.match(host):          # an IP address is not a publisher domain
        return None
    if host.startswith("www."):
        host = host[4:]
    return host or None


def _fetch(domain: str) -> tuple[str, str]:
    """Follow `http://domain` and report where it ended up, and what it said.

    Plain http, because that is what a parked domain answers on and a real site
    redirects from. Failures raise: `looks_parked` treats them as "cannot tell",
    which is not the same as "for sale".
    """
    import httpx

    with httpx.Client(follow_redirects=True, timeout=8.0) as client:
        response = client.get(f"http://{domain}")
        # The status is not the point — GoDaddy's lander answers 403 — the URL it
        # settled on is.
        return str(response.url), response.text[:_SNIFF]


def looks_parked(domain: str, fetch=None) -> bool:
    """Whether the domain answers with a for-sale page.

    Two signals: the redirects end on a domain marketplace, or the page says it
    is for sale. Anything that cannot be reached returns False — dropping a real
    publisher's domain because of a timeout would hide the one row that matters.
    """
    if not domain:
        return False
    try:
        final, body = (fetch or _fetch)(domain)
    except Exception:  # noqa: BLE001 - unreachable is not for sale
        return False

    host = normalise_site(final)
    if host and any(
        host == known or host.endswith(f".{known}") for known in FOR_SALE_HOSTS
    ):
        return True
    return any(marker.search(body or "") for marker in FOR_SALE_MARKERS)


@dataclass(frozen=True)
class PublisherDomain:
    """What is known about the publisher's domain, and on whose word.

    `best` is the one domain worth calling the publisher's, and there is at most
    one: the Google Play listing when it names a site, the reverse-DNS of the
    package name only when it does not. `verified` is narrower — agreement
    between two independent sources, or a human saying so — and is what a formal
    allegation needs.
    """

    from_package: str | None = None
    from_play: str | None = None
    stated: str | None = None
    rejected_package: str | None = None
    rejected_play: str | None = None
    # The reverse-DNS guess, set aside because the Play listing named a different
    # domain. Kept as data and never printed: it is usually the domain of whoever
    # built the app, and that company is not the subject of the audit.
    overridden_by_play: str | None = None
    # Candidates that answer with a domain-for-sale page. Recorded so the report
    # can say why it has nothing, and never printed for the same reason as above.
    parked: tuple[str, ...] = ()
    # What the package says about the domain Play declared. Only that one: the
    # package name and the app's contents are both the builder's work, so one
    # confirming the other is a single party speaking twice.
    corroboration: object | None = None

    @property
    def agreed(self) -> bool:
        return bool(
            self.from_package and self.from_play and self.from_package == self.from_play
        )

    @property
    def set_aside(self) -> frozenset[str]:
        """Every domain that was considered and will not be analysed.

        One set because there is one question — "may this domain appear in the
        report?" — and it used to be answered from four separate fields. The
        caller that builds the list of SDK domains as "everything that is not a
        publisher candidate" took a domain dropped from the candidates and
        analysed it as an SDK domain instead.
        """
        return frozenset(
            domain
            for domain in (
                self.overridden_by_play,
                self.rejected_play,
                self.rejected_package,
                *self.parked,
            )
            if domain
        )

    @property
    def corroborated(self) -> bool:
        """The Play listing, and the app pointing at the same host.

        Restricted to `from_play` on purpose. Corroborating the reverse-DNS guess
        with the contents of the APK would be the developer agreeing with
        themselves, and it would put an art. 32 finding back on whoever built the
        app rather than on whoever publishes it.
        """
        mention = self.corroboration
        return bool(
            self.from_play
            and self.best == self.from_play
            and mention is not None
            and getattr(mention, "deliberate", False)
        )

    @property
    def verified(self) -> bool:
        """Established, as opposed to guessed. Three things do that.

        The sender says so; the two declared sources agree; or the listing is
        confirmed by the package itself — two parties that did not copy from each
        other naming the same host.
        """
        return bool(self.stated) or self.agreed or self.corroborated

    @property
    def best(self) -> str | None:
        """The publisher's domain, or None when none of the sources gave one."""
        if self.stated:
            return self.stated
        if self.agreed:
            return self.from_package
        return self.from_play or self.from_package

    @property
    def provenance(self) -> str:
        """Where `best` came from, or "none" when there is no domain at all."""
        if self.stated:
            return "stated"
        if self.agreed:
            return "agreed"
        if self.corroborated:
            return "corroborated"
        if self.from_play:
            return "play_listing"
        if self.from_package:
            return "package_name"
        return "none"

    @property
    def candidates(self) -> list[tuple[str, str]]:
        """The publisher's domain with its provenance, or nothing.

        At most one. It used to hold two whenever the sources differed, so that
        both could be reported and neither chosen — and the second one was, in
        the case that started this, the corporate domain of the software house
        that built the app. Analysing it put three findings against a company
        that is not the subject of the report; see test_guess_set_aside.py.
        """
        domain = self.best
        return [(domain, self.provenance)] if domain else []

    def label(self, domain: str | None = None) -> str:
        """The provenance of one candidate, in words."""
        target = domain or self.best
        for candidate, source in self.candidates:
            if candidate == target:
                return PROVENANCE_LABELS[source]
        return "provenance unknown"

    def describe(self, domain: str | None = None) -> str:
        """`domain (how we know it)` — the form used wherever it is printed."""
        target = domain or self.best
        if not target:
            return "no publisher domain established"
        return f"{target} ({self.label(target)})"

    @property
    def note(self) -> str:
        """One line on why there is no established domain, or an empty string.

        It never names a domain that was set aside. The point of setting one
        aside is that it is somebody else's, and printing it in an audit — even
        under "not analysed" — puts a third party's domain in a document about
        this app.
        """
        if self.verified:
            return ""
        if self.parked and not self.best:
            return (
                "the only candidate answers with a domain-for-sale page, so it "
                "has no holder to attribute anything to and was not analysed"
            )
        if self.overridden_by_play and self.best:
            return (
                f"{self.best} comes from the Google Play listing, which is free "
                "text and unverified; the package name suggested a different "
                "domain and was not consulted further"
            )
        if self.best:
            return f"{self.best} is {self.label(self.best)}"
        if self.rejected_package or self.rejected_play:
            rejected = self.rejected_play or self.rejected_package
            return f"the only candidate was {rejected}, which belongs to a platform"
        return "no candidate domain could be derived"


def resolve(
    package_name: str | None,
    play_site: str | None = None,
    stated: str | None = None,
    corroboration: object | None = None,
) -> PublisherDomain:
    """Weigh the package name against what Play says, and keep both labelled.

    A platform tenant is dropped from either side but remembered, so the report
    can say why a source produced nothing. The one exception is agreement: two
    independent sources naming the same host are not overruled by the filter —
    that is how Zendesk's own app would keep zendesk.com.
    """
    from apkradar.utils import package_to_domain

    guessed = package_to_domain(package_name or "")
    declared = normalise_site(play_site)
    asserted = normalise_site(stated)

    rejected_package = rejected_play = None
    if not (guessed and declared and guessed == declared):
        if guessed and is_platform_host(guessed):
            guessed, rejected_package = None, guessed
        if declared and is_platform_host(declared):
            declared, rejected_play = None, declared

    # The listing wins over the reverse-DNS of the package name, and the guess is
    # then not a candidate at all. Play is right three times out of four in the
    # cases measured, and the fourth — a helpdesk tenant — has already been
    # removed above; what the guess adds in the other three is an audit of
    # whoever compiled the app.
    overridden = None
    if guessed and declared and guessed != declared:
        overridden, guessed = guessed, None

    return PublisherDomain(
        from_package=guessed,
        from_play=declared,
        stated=asserted,
        rejected_package=rejected_package,
        rejected_play=rejected_play,
        overridden_by_play=overridden,
        # Attached only when the listing survived: there is nothing for the
        # package to confirm if Play named no usable domain.
        corroboration=corroboration if declared else None,
    )


def without_parked(pub: PublisherDomain, check=None) -> PublisherDomain:
    """The same result with any for-sale candidate removed.

    Separate from `resolve()` because it asks the network, and `resolve()` is a
    pure function that the offline paths depend on. One request at most: only the
    publisher's candidate is checked, never the SDK domains — those are subjects
    of the tracker analysis, not parties to an allegation.

    A domain the sender stated is checked too. If they named one that is on the
    market they need to know before the letter goes out, not after.
    """
    check = check or looks_parked
    domain = pub.best
    if not domain or not check(domain):
        return pub

    return replace(
        pub,
        from_package=None if pub.from_package == domain else pub.from_package,
        from_play=None if pub.from_play == domain else pub.from_play,
        stated=None if pub.stated == domain else pub.stated,
        parked=(*pub.parked, domain),
    )


def from_result(result, stated: str | None = None) -> PublisherDomain:
    """resolve() for a ScanResult, whose Play fields may never have been filled."""
    return resolve(
        getattr(result, "package_name", "") or "",
        getattr(result, "developer_site", "") or None,
        stated,
        getattr(result, "site_mention", None),
    )
