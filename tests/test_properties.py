"""Properties, checked against generated input rather than chosen examples.

detect_format decides which extractor runs, on a path that came from a user or
from a spreadsheet cell. It must answer one of four words for any string at
all, including strings that are not paths.

The `normalize_text` block is the most valuable one here, and the reason is not
the parser: its output is hashed, and that hash is what tells an operator "the
law changed". A normalisation that is not idempotent would report a change in a
text that nobody edited.
"""

from __future__ import annotations

import zipfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from apkradar.extractor import detect_format
from apkradar.law_fetcher import normalize_text

FORMATS = {"apk", "xapk", "apkm", "unknown"}

# ── Which extractor runs ────────────────────────────────────────────────────

_NAME = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126,
                           blacklist_characters='<>:"|?*\\/'),
    max_size=40,
)


@given(_NAME)
def test_the_answer_is_always_one_of_the_four_documented_words(name):
    """A fifth answer would reach a dispatch that has no branch for it."""
    assert detect_format(name) in FORMATS


# A stem with no dot of its own, and never empty: ".apk" with nothing in front
# is a dotfile, which is a different case and gets its own test below.
_STEM = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126,
                           blacklist_characters='<>:"|?*\\/.'),
    min_size=1, max_size=40,
).filter(lambda s: s.strip())


@given(_STEM, st.sampled_from(["apk", "xapk", "apkm"]))
def test_a_known_extension_decides_without_opening_the_file(stem, ext):
    """The path need not exist: the extension is read, not the contents."""
    assert detect_format(f"{stem}.{ext}") == ext


@given(_STEM, st.sampled_from(["APK", "XaPk", "APKM", "aPkM"]))
def test_the_extension_is_read_without_regard_to_case(stem, ext):
    """Windows and spreadsheets both hand over upper-case names."""
    assert detect_format(f"{stem}.{ext}") == ext.lower()


@given(st.sampled_from([".apk", ".xapk", ".apkm"]))
def test_a_name_that_is_only_an_extension_is_a_dotfile_not_a_format(name):
    """Pinning what Path() decides, because it is surprising.

    Path(".apk").suffix is "" — the whole name is the stem of a hidden file —
    so this falls through to the content check and, with no such file, answers
    "unknown". That is the right answer; it is just not the obvious one.
    """
    assert detect_format(name) == "unknown"


@given(st.sampled_from(["txt", "zip", "jpg", "exe", "tar", "gz", ""]))
def test_an_unreadable_path_with_no_known_extension_is_unknown(ext):
    """Not a crash, and not a guess: the caller is told nothing was recognised."""
    name = "does-not-exist" + (f".{ext}" if ext else "")
    assert detect_format(name) == "unknown"


@pytest.mark.parametrize(
    ("member", "expected"),
    [("AndroidManifest.xml", "apk"), ("manifest.json", "apkm"), ("nothing.txt", "unknown")],
)
def test_a_zip_with_no_known_extension_is_judged_by_its_contents(member, expected, tmp_path):
    """The fall-through path: an .apk renamed to .bin is still an APK.

    A plain parametrised case, not a property: the interesting axis here is
    which member the archive holds, and there are three of them.
    """
    path = tmp_path / "bundle.bin"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(member, b"{}" if member.endswith(".json") else b"x")
    assert detect_format(str(path)) == expected


# ── The hash that decides "the law changed" ─────────────────────────────────

_LEGAL_TEXT = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=0x2FFF, blacklist_categories=("Cs",)),
    max_size=400,
)


@given(_LEGAL_TEXT)
@settings(max_examples=300)
def test_normalising_twice_says_the_same_as_normalising_once(text):
    """If this ever failed, the cache would report a change nobody made."""
    once = normalize_text(text)
    assert normalize_text(once) == once


@given(_LEGAL_TEXT)
def test_the_normal_form_holds_no_run_of_spaces_and_no_edges(text):
    result = normalize_text(text)
    assert "  " not in result
    assert result == result.strip()


@given(_LEGAL_TEXT)
def test_the_normal_form_never_leaves_a_space_before_punctuation(text):
    """"Consiglio ;" is what a removed footnote reference leaves behind."""
    result = normalize_text(text)
    for mark in ";,.:":
        assert f" {mark}" not in result
