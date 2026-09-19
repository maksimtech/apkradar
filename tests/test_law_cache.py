"""Tests for the local cache of GDPR provisions."""
import json
from pathlib import Path

from apkradar.law_cache import LawCache, default_cache_path
from apkradar.law_fetcher import Provision

DAY1 = "2026-09-19T14:00:00Z"
DAY2 = "2026-10-01T09:30:00Z"


def _p(article, text, fetched_at=DAY1):
    return Provision.from_text(article, text, fetched_at)


def test_default_path_is_under_apkradar_home(tmp_path, monkeypatch):
    monkeypatch.setenv("APKRADAR_HOME", str(tmp_path / "home"))
    assert default_cache_path() == tmp_path / "home" / "law_cache.json"


def test_default_path_without_env(monkeypatch):
    monkeypatch.delenv("APKRADAR_HOME", raising=False)
    assert default_cache_path() == Path.home() / ".apkradar" / "law_cache.json"


def test_missing_file_is_empty(tmp_path):
    assert LawCache(tmp_path / "law_cache.json").load() == {}


def test_first_update_stores_everything(tmp_path):
    path = tmp_path / "sub" / "law_cache.json"
    cache = LawCache(path)
    provisions, changed = cache.update({"5(1)(a)": _p("5(1)(a)", "a) testo;")}, checked_at=DAY1)

    assert changed == {}
    assert provisions["5(1)(a)"].text == "a) testo;"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["checked_at"] == DAY1
    assert data["entries"] == [_p("5(1)(a)", "a) testo;").to_dict()]
    assert cache.load() == provisions


def test_same_text_keeps_the_original_version(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({"6": _p("6", "testo")}, checked_at=DAY1)

    provisions, changed = cache.update({"6": _p("6", "testo", DAY2)}, checked_at=DAY2)

    assert changed == {}
    # The version date is when this text was first fetched
    assert provisions["6"].fetched_at == DAY1
    assert json.loads(cache.path.read_text(encoding="utf-8"))["checked_at"] == DAY2


def test_changed_text_replaces_entry_and_reports_old_hash(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    old = _p("6", "testo")
    cache.update({"6": old}, checked_at=DAY1)

    provisions, changed = cache.update({"6": _p("6", "testo modificato", DAY2)}, checked_at=DAY2)

    assert changed == {"6": old.sha256}
    assert provisions["6"].text == "testo modificato"
    assert provisions["6"].fetched_at == DAY2
    assert cache.load()["6"].text == "testo modificato"


def test_entries_not_fetched_again_are_kept(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({"6": _p("6", "sei"), "9": _p("9", "nove")}, checked_at=DAY1)

    provisions, _ = cache.update({"6": _p("6", "sei", DAY2)}, checked_at=DAY2)

    assert set(provisions) == {"6", "9"}


def test_corrupt_file_is_empty(tmp_path):
    path = tmp_path / "law_cache.json"
    path.write_text("{not json", encoding="utf-8")
    assert LawCache(path).load() == {}


def test_unexpected_structure_is_empty(tmp_path):
    path = tmp_path / "law_cache.json"
    path.write_text('["a", "b"]', encoding="utf-8")
    assert LawCache(path).load() == {}


def test_entry_whose_hash_does_not_match_its_text_is_dropped(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({"6": _p("6", "sei"), "9": _p("9", "nove")}, checked_at=DAY1)

    data = json.loads(cache.path.read_text(encoding="utf-8"))
    for entry in data["entries"]:
        if entry["article"] == "9":
            entry["text"] = "nove, modificato a mano"
    cache.path.write_text(json.dumps(data), encoding="utf-8")

    assert set(cache.load()) == {"6"}


def test_no_temporary_file_left(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({"6": _p("6", "sei")}, checked_at=DAY1)
    assert [p.name for p in tmp_path.iterdir()] == ["law_cache.json"]


def test_file_is_utf8_readable(tmp_path):
    cache = LawCache(tmp_path / "law_cache.json")
    cache.update({"9": _p("9", "1. È vietato trattare «dati»")}, checked_at=DAY1)
    assert "È vietato trattare «dati»" in cache.path.read_text(encoding="utf-8")
