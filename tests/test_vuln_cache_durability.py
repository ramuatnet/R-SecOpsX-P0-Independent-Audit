"""Regression tests: an unreadable advisory cache is never overwritten.

The pinned ``reports/.vuln_cache.json`` is part of the golden-corpus fixture
(``analysis/validation/corpus.py``: 380 pinned package/version pairs anchor
the SCA labels).  A read failure used to be silently converted into "the
cache is empty", and the next save persisted that emptiness: a concurrent
reader that caught the file mid-write reduced the committed 6,860 entries to
one scan's 23 queries, after which a since-withdrawn advisory was re-queried
live and cached as a permanent negative -- a corpus false negative with no
trace of its cause.

The contract pinned here:

* a corrupt/unreadable cache loads as ``{}`` (so the scan itself still works)
  AND latches the failure so no later save replaces the file;
* a genuinely absent cache is a fresh start and saves normally;
* saves are write-then-rename, so no reader can observe a half-written file
  and no ``.tmp`` is left behind.
"""
from __future__ import annotations

import json

from scanner import vulnerability_intel as vi


def _patch(monkeypatch, tmp_path, failed: bool = False):
    monkeypatch.setattr(vi, "CACHE_FILE", tmp_path / ".vuln_cache.json")
    monkeypatch.setattr(vi, "_CACHE_LOAD_FAILED", failed)


def test_unreadable_cache_is_never_overwritten(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    cache_file = vi.CACHE_FILE
    cache_file.write_text("{ this is not json", encoding="utf-8")
    before = cache_file.read_bytes()

    assert vi._load_cache() == {}
    assert vi._CACHE_LOAD_FAILED is True

    vi._save_cache({"PyPI|example|1.0.0": [{"id": "PYSEC-0000-0000"}]})

    assert cache_file.read_bytes() == before, (
        "a cache this process could not read must not be replaced")
    assert not cache_file.with_name(cache_file.name + ".tmp").exists()


def test_absent_cache_is_a_fresh_start_and_saves(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    cache_file = vi.CACHE_FILE

    assert vi._load_cache() == {}
    assert vi._CACHE_LOAD_FAILED is False

    vi._save_cache({"PyPI|example|1.0.0": [{"id": "PYSEC-0000-0000"}]})

    payload = json.loads(cache_file.read_text(encoding="utf-8"))
    assert payload["schema_version"] == vi.CACHE_SCHEMA_VERSION
    assert payload["entries"]["PyPI|example|1.0.0"][0]["id"] == "PYSEC-0000-0000"
    assert not cache_file.with_name(cache_file.name + ".tmp").exists()

    # round-trips through the normal load path
    assert vi._load_cache()["PyPI|example|1.0.0"][0]["id"] == "PYSEC-0000-0000"


def test_wrapped_v3_cache_loads_entries(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    vi.CACHE_FILE.write_text(json.dumps({
        "schema_version": 3, "source": "OSV",
        "entries": {"npm|left-pad|1.0.0": []},
    }), encoding="utf-8")

    assert vi._load_cache() == {"npm|left-pad|1.0.0": []}
    assert vi._CACHE_LOAD_FAILED is False


def test_legacy_flat_cache_still_loads(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    vi.CACHE_FILE.write_text(
        json.dumps({"npm|left-pad|1.0.0": [{"id": "GHSA-xxxx"}]}),
        encoding="utf-8")

    assert vi._load_cache()["npm|left-pad|1.0.0"][0]["id"] == "GHSA-xxxx"
    assert vi._CACHE_LOAD_FAILED is False


def test_failure_flag_survives_a_later_successful_read(monkeypatch, tmp_path):
    """Once this process has proven it cannot trust the file, saving stays off."""
    _patch(monkeypatch, tmp_path)
    vi.CACHE_FILE.write_text("{ corrupt", encoding="utf-8")
    vi._load_cache()
    assert vi._CACHE_LOAD_FAILED is True

    # another writer repairs the file mid-process; the flag must persist.
    vi.CACHE_FILE.write_text(json.dumps({"entries": {}}), encoding="utf-8")
    vi._load_cache()

    assert vi._CACHE_LOAD_FAILED is True
    vi._save_cache({"a": []})
    payload = json.loads(vi.CACHE_FILE.read_text(encoding="utf-8"))
    assert "entries" in payload and payload["entries"] == {}, (
        "no save may happen once a load in this process has failed")
