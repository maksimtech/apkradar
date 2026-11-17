"""Shared test setup: no test may reach EUR-Lex or write to ~/.apkradar.

The isolation is set up twice. Once for the session, before any fixture runs: a
module-scoped fixture is set up before the function-scoped ones, so with the
per-test isolation alone tests/test_readme_example.py ran `apkradar audit` with the
real home and the real network, and rewrote the user's ~/.apkradar/law_cache.json
(2026-11-17). And once per test, so that each one starts from an empty home.

pytest_sessionfinish then checks the real ~/.apkradar: if anything under it
changed during the run, the run fails and says what changed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apkradar import law_fetcher

# Read once, at import, before any fixture can change what Path.home() answers.
REAL_HOME = Path.home() / ".apkradar"

_BEFORE = pytest.StashKey[dict[str, tuple[int, int]]]()


def _no_network(*args, **kwargs):
    raise law_fetcher.LawFetchError("network disabled in tests")


def _snapshot(directory: Path) -> dict[str, tuple[int, int]]:
    """Every file under `directory`, with its size and modification time."""
    found = {}
    if directory.is_dir():
        for path in directory.rglob("*"):
            if path.is_file():
                stat = path.stat()
                found[str(path.relative_to(directory))] = (stat.st_size, stat.st_mtime_ns)
    return found


def pytest_sessionstart(session):
    session.config.stash[_BEFORE] = _snapshot(REAL_HOME)


def pytest_sessionfinish(session, exitstatus):
    before = session.config.stash.get(_BEFORE, None)
    if before is None:
        return
    after = _snapshot(REAL_HOME)
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    if changed:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"tests wrote under the real {REAL_HOME}: {', '.join(changed)}", red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(scope="session", autouse=True)
def _isolate_session(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("APKRADAR_HOME", str(tmp_path_factory.mktemp("apkradar-home")))
        patch.setattr(law_fetcher, "fetch_html", _no_network)
        yield


@pytest.fixture(autouse=True)
def _isolate_law_checker(tmp_path, monkeypatch):
    monkeypatch.setenv("APKRADAR_HOME", str(tmp_path / "apkradar-home"))
    monkeypatch.setattr(law_fetcher, "fetch_html", _no_network)
