"""
APKRadar — GDPR text from EUR-Lex.

Downloads the GDPR (CELEX 32016R0679) from EUR-Lex and extracts the articles
that APKRadar reports cite, down to paragraph and point: "5", "5(1)",
"5(1)(a)". Each provision carries the SHA-256 of its text, so a report can
state exactly which wording of the law it applied.

The hash is computed on the UTF-8 text stored with it: whitespace collapsed to
single spaces, footnote references removed, paragraphs of an article one per
line. Anyone can recompute it from the text in ~/.apkradar/law_cache.json.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Iterator, Optional, Union

import httpx

from apkradar import __version__

CELEX = "32016R0679"
SOURCE_URL = "https://eur-lex.europa.eu/legal-content/{lang}/TXT/HTML/?uri=CELEX:{celex}"

# 4 definitions, 5 principles, 6 lawfulness, 7 consent, 9 special categories,
# 13 information, 28 processor, 46 transfers subject to appropriate safeguards
ARTICLES = ("4", "5", "6", "7", "9", "13", "28", "46")

USER_AGENT = f"APKRadar/{__version__} (+https://github.com/maksimtech/apkradar)"


class LawFetchError(Exception):
    """EUR-Lex could not be reached, or its page did not contain the articles."""


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_stamp(moment: datetime) -> str:
    """ISO 8601 UTC timestamp, e.g. 2026-09-19T14:00:00Z."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Provision:
    article: str       # "5(1)(a)"
    text: str
    sha256: str
    fetched_at: str    # when this wording was downloaded, ISO 8601 UTC
    celex: str = CELEX

    @classmethod
    def from_text(cls, article: str, text: str, fetched_at: str) -> "Provision":
        return cls(article=article, text=text, sha256=text_sha256(text), fetched_at=fetched_at)

    @classmethod
    def from_dict(cls, data: dict) -> "Provision":
        values = {key: data[key] for key in ("article", "text", "sha256", "fetched_at", "celex")}
        if not all(isinstance(value, str) for value in values.values()):
            raise TypeError("provision fields must be strings")
        return cls(**values)

    def to_dict(self) -> dict:
        return asdict(self)


# ─── HTML → tree ──────────────────────────────────────────────────────────────

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}
_BLOCK = {"p", "div", "table", "tbody", "thead", "tr", "td", "th", "li", "ul", "ol", "br"}


class _Element:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag: str, attrs: dict):
        self.tag = tag
        self.attrs = attrs
        self.children: list[Union[_Element, str]] = []


class _TreeBuilder(HTMLParser):
    """Minimal DOM. Drops scripts, styles and footnote references."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Element("#root", {})
        self._stack = [self.root]
        self._skipping = 0

    def _skip(self, tag: str, attrs: dict) -> bool:
        # Footnote references look like <a href="#ntr19-...">(19)</a>
        return tag in ("script", "style") or (
            tag == "a" and (attrs.get("href") or "").startswith("#ntr")
        )

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if self._skipping:
            if tag not in _VOID:
                self._skipping += 1
            return
        if self._skip(tag, attrs):
            self._skipping = 1
            return
        element = _Element(tag, attrs)
        self._stack[-1].children.append(element)
        if tag not in _VOID:
            self._stack.append(element)

    def handle_startendtag(self, tag, attrs):
        if not self._skipping:
            self._stack[-1].children.append(_Element(tag, dict(attrs)))

    def handle_endtag(self, tag):
        if self._skipping:
            if tag not in _VOID:
                self._skipping -= 1
            return
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == tag:
                del self._stack[i:]
                return

    def handle_data(self, data):
        if not self._skipping:
            self._stack[-1].children.append(data)


def _elements(node: _Element) -> Iterator[_Element]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed([c for c in current.children if isinstance(c, _Element)]))


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    text = re.sub(r"\s+", " ", text)
    # Removing a footnote reference leaves "Consiglio ;"
    text = re.sub(r" (?=[;,.:])", "", text)
    return text.strip()


def _raw_text(node: Union[_Element, str]) -> str:
    if isinstance(node, str):
        return node
    inner = "".join(_raw_text(child) for child in node.children)
    return f" {inner} " if node.tag in _BLOCK else inner


def _text(node: Union[_Element, str]) -> str:
    return normalize_text(_raw_text(node))


# ─── Tree → provisions ────────────────────────────────────────────────────────

_PARAGRAPH_ID = re.compile(r"^\d{3}\.\d{3}$")   # <div id="005.001"> is art. 5(1)
_NUMBERED = re.compile(r"^(\d+)\) ")            # art. 4: "1) «dato personale»: ..."
_LETTER = re.compile(r"^([a-z]{1,4})\)$")       # table label cell: "a)"


def _is_heading(node: _Element) -> bool:
    classes = node.attrs.get("class") or ""
    return "oj-ti-art" in classes or "eli-title" in classes


def _flatten(nodes: list) -> Iterator[Union[_Element, str]]:
    """Paragraph content as a sequence of <p>, <table> and loose text."""
    for node in nodes:
        if isinstance(node, str):
            if node.strip():
                yield node
        elif _is_heading(node):
            continue
        elif node.tag in ("div", "tbody") and not _PARAGRAPH_ID.match(node.attrs.get("id", "")):
            yield from _flatten(node.children)
        else:
            yield node


def _table_point(table: _Element) -> Optional[tuple[str, str]]:
    """(letter, text) of a point laid out as a label cell and a text cell."""
    rows = [
        row
        for child in table.children if isinstance(child, _Element)
        for row in ([child] if child.tag == "tr" else child.children if child.tag == "tbody" else [])
        if isinstance(row, _Element) and row.tag == "tr"
    ]
    if len(rows) != 1:
        return None
    # Direct cells only: a nested table inside the text cell is part of its text
    cells = [c for c in rows[0].children if isinstance(c, _Element) and c.tag == "td"]
    if len(cells) < 2:
        return None
    label = _text(cells[0])
    match = _LETTER.match(label)
    if not match:
        return None
    content = " ".join(_text(cell) for cell in cells[1:])
    return match.group(1), normalize_text(f"{label} {content}")


def _parse_block(nodes: list, prefix: str) -> tuple[list[str], dict[str, str]]:
    """
    Split paragraph content into lines and cite-able points.

    Lettered points are tables, "a)" | "text". Numbered points (the
    definitions of art. 4) are paragraphs starting with "1)"; their own
    lettered sub-points stay part of them.
    """
    items: list[tuple[Optional[str], list[str]]] = []
    numbered = False
    for node in _flatten(nodes):
        point = _table_point(node) if isinstance(node, _Element) and node.tag == "table" else None
        if point is not None:
            letter, text = point
            if numbered:
                items[-1][1].append(text)
            else:
                items.append((f"{prefix}({letter})", [text]))
            continue
        text = _text(node)
        if not text:
            continue
        match = _NUMBERED.match(text)
        numbered = bool(match)
        items.append((f"{prefix}({match.group(1)})" if match else None, [text]))

    lines = [" ".join(parts) for _, parts in items]
    points = {ref: " ".join(parts) for ref, parts in items if ref}
    return lines, points


def _parse_article(article: _Element, number: str) -> dict[str, str]:
    texts: dict[str, str] = {}
    paragraphs = [
        e for e in _elements(article)
        if e.tag == "div" and _PARAGRAPH_ID.match(e.attrs.get("id", ""))
    ]
    if paragraphs:
        lines = []
        for div in paragraphs:
            ref = f"{number}({int(div.attrs['id'].split('.')[1])})"
            paragraph_lines, points = _parse_block(div.children, ref)
            texts[ref] = " ".join(paragraph_lines)
            texts.update(points)
            lines.append(texts[ref])
    else:
        lines, points = _parse_block(article.children, number)
        texts.update(points)
    texts[number] = "\n".join(lines)
    return texts


def parse_articles(html: str, articles: tuple[str, ...] = ARTICLES) -> dict[str, str]:
    """
    Extract articles from an EUR-Lex HTML page.

    Returns:
        Text by reference, for each article and each of its paragraphs and
        points: {"5": ..., "5(1)": ..., "5(1)(a)": ...}.

    Raises:
        LawFetchError: an article is missing, e.g. the page is not the act.
    """
    builder = _TreeBuilder()
    builder.feed(html)
    builder.close()
    by_id = {e.attrs["id"]: e for e in _elements(builder.root) if e.tag == "div" and "id" in e.attrs}

    texts: dict[str, str] = {}
    for number in articles:
        article = by_id.get(f"art_{number}")
        parsed = _parse_article(article, number) if article is not None else {}
        if not parsed.get(number):
            raise LawFetchError(f"Article {number} not found in the EUR-Lex page")
        texts.update(parsed)
    return texts


# ─── Download ─────────────────────────────────────────────────────────────────

def fetch_html(url: str, *, client: Optional[httpx.Client] = None, timeout: float = 30.0) -> str:
    """Download a page. Anything but HTTP 200 is an error: EUR-Lex answers
    some automated requests with 202 and a JavaScript challenge."""
    headers = {"User-Agent": USER_AGENT}
    try:
        if client is None:
            with httpx.Client(timeout=timeout, follow_redirects=True) as own_client:
                response = own_client.get(url, headers=headers)
        else:
            response = client.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise LawFetchError(f"EUR-Lex unreachable: {e}") from e
    if response.status_code != 200:
        raise LawFetchError(f"EUR-Lex answered HTTP {response.status_code}")
    return response.text


def fetch_provisions(
    articles: tuple[str, ...] = ARTICLES,
    *,
    lang: str = "IT",
    now: Optional[datetime] = None,
    client: Optional[httpx.Client] = None,
) -> dict[str, Provision]:
    """Download the GDPR from EUR-Lex and return the provisions of `articles`."""
    html = fetch_html(SOURCE_URL.format(lang=lang, celex=CELEX), client=client)
    fetched_at = utc_stamp(now or datetime.now(timezone.utc))
    return {
        ref: Provision.from_text(ref, text, fetched_at)
        for ref, text in parse_articles(html, articles).items()
    }
