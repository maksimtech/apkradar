"""The isolation in conftest.py holds for every fixture, not only for tests.

tests/test_readme_example.py renders `apkradar audit` in a module-scoped fixture.
pytest sets up a module-scoped fixture before the function-scoped ones, the autouse
isolation included, so that run had the real home and the real network: it reached
EUR-Lex and rewrote the user's ~/.apkradar/law_cache.json. Seen on 2026-11-17, by
running the suite with HOME and USERPROFILE pointed at an empty folder: the folder
had a .apkradar/law_cache.json afterwards, and that file alone wrote it.

The fixture below is module-scoped on purpose: what it sees is what any
module-scoped fixture sees.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from apkradar import law_cache, law_fetcher


@pytest.fixture(scope="module")
def seen_by_a_module_fixture():
    return os.environ.get("APKRADAR_HOME"), law_fetcher.fetch_html, law_cache.default_cache_path()


def test_a_module_scoped_fixture_has_no_network(seen_by_a_module_fixture):
    _, fetch, _ = seen_by_a_module_fixture
    assert getattr(fetch, "__module__", None) != law_fetcher.__name__, "the real fetch_html, reaching EUR-Lex"


def test_a_module_scoped_fixture_writes_into_the_test_home(seen_by_a_module_fixture, tmp_path_factory):
    home, _, cache = seen_by_a_module_fixture
    base = tmp_path_factory.getbasetemp().resolve()
    assert home and Path(home).resolve().is_relative_to(base)
    assert Path(cache).is_relative_to(base)
