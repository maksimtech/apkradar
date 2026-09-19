"""Shared test setup: no test may reach EUR-Lex or write to ~/.apkradar."""
import pytest

from apkradar import law_fetcher


@pytest.fixture(autouse=True)
def _isolate_law_checker(tmp_path, monkeypatch):
    monkeypatch.setenv("APKRADAR_HOME", str(tmp_path / "apkradar-home"))

    def no_network(*args, **kwargs):
        raise law_fetcher.LawFetchError("network disabled in tests")

    monkeypatch.setattr(law_fetcher, "fetch_html", no_network)
