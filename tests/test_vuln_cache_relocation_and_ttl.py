"""The advisory store must survive relocation, and must not live forever.

Two changes pinned here, both of which trade directly against the air-gap
behaviour in ``test_v11_offline_airgap.py``.

RELOCATION
----------
``.vuln_cache.json`` and ``.intel_feed_cache.json`` lived under ``reports/``.
That tree is disposable scan output -- the first thing excluded when the tool
is migrated to a server -- and it held the *only* thing offline CVE matching
had to work with. Moving them to ``data/`` is not cosmetic: shipping the tool
without ``reports/`` used to silently cost the offline path its entire CVE
coverage.

An existing store is *adopted*, never moved. Losing 6,860 curated entries over
a path change would be far worse than leaving a stale file behind, so the
original stays until an operator confirms the copy.

STALENESS
---------
A complete advisory record used to be cached forever, which meant a CVE
published after a package's first scan -- or one since withdrawn -- never
reached a later report. TTL-driven refresh fixes that, but it must never make
the offline path worse: an advisory from last month beats no advisory at all,
so age only disqualifies a record when we can actually re-ask.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from scanner import vulnerability_intel as vi


def _pkg(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    return {"name": name, "version": version, "ecosystem": ecosystem}


_COMPLETE_ADVISORY = {
    "id": "GHSA-ttl-test",
    "published": "2023-01-01T00:00:00Z",
    "severity": "HIGH",
    "cvss": 7.5,
}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    """data/ and reports/ under a tmp root, with globals reset per test."""
    monkeypatch.setattr(vi, "CACHE_FILE", tmp_path / "data" / ".vuln_cache.json")
    monkeypatch.setattr(vi, "_CACHE_LOAD_FAILED", False)
    vi._CACHE_FETCHED.clear()
    monkeypatch.delenv("RSECOPSX_ADVISORY_TTL_DAYS", raising=False)
    monkeypatch.delenv("RSECOPSX_LIVE_FEEDS", raising=False)
    yield
    vi._CACHE_FETCHED.clear()


def _key(name="requests", version="2.31.0", ecosystem="PyPI") -> str:
    return vi._cache_key(name, version, ecosystem)


def _write(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _stamp(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


# ------------------------------------------------------------- relocation --

def test_store_lives_under_data_not_reports():
    assert vi.CACHE_FILE.parts[-2] == "data"


def test_legacy_reports_cache_is_adopted_when_data_is_empty(tmp_path):
    """A pre-relocation store must be read, not ignored."""
    _write(tmp_path / "reports" / ".vuln_cache.json", {
        "schema_version": 3, "source": "OSV",
        "entries": {_key(): [_COMPLETE_ADVISORY]},
        "fetched": {_key(): _stamp(1)},
    })

    assert vi._load_cache()[_key()] == [_COMPLETE_ADVISORY]


def test_adoption_does_not_move_or_delete_the_original(tmp_path):
    """The old file stays put until an operator confirms the copy."""
    legacy = tmp_path / "reports" / ".vuln_cache.json"
    _write(legacy, {"entries": {_key(): [_COMPLETE_ADVISORY]}})

    vi._load_cache()
    vi._save_cache(vi._load_cache())

    assert legacy.exists(), "adoption must copy, never consume the original"
    assert vi.CACHE_FILE.exists()


def test_data_cache_wins_over_legacy_when_both_exist(tmp_path):
    _write(tmp_path / "reports" / ".vuln_cache.json",
           {"entries": {_key(): [{"id": "OLD"}]}})
    _write(tmp_path / "data" / ".vuln_cache.json",
           {"schema_version": vi.CACHE_SCHEMA_VERSION,
            "entries": {_key(): [{"id": "NEW"}]}})

    assert vi._load_cache()[_key()][0]["id"] == "NEW"


def test_save_creates_the_data_directory(tmp_path):
    """The old import-time mkdir is gone; saving must still work cold."""
    assert not vi.CACHE_FILE.parent.exists()
    vi._save_cache({_key(): [_COMPLETE_ADVISORY]})
    assert vi.CACHE_FILE.exists()


def test_legacy_lookup_is_derived_from_the_live_cache_file(tmp_path):
    """A patched CACHE_FILE must not pull in a developer's real store."""
    assert vi._legacy_cache_file() == (
        tmp_path / "reports" / ".vuln_cache.json")


# --------------------------------------------------------------- staleness --

def test_fresh_entry_is_served_from_cache_without_a_query(monkeypatch):
    _write(vi.CACHE_FILE, {
        "schema_version": vi.CACHE_SCHEMA_VERSION,
        "entries": {_key(): [_COMPLETE_ADVISORY]},
        "fetched": {_key(): _stamp(1)},
    })
    with mock.patch.object(vi, "_post_json") as stub:
        results = vi.query_osv_batch([_pkg("requests", "2.31.0")])

    assert not stub.called
    assert results[_key()] == [_COMPLETE_ADVISORY]


def test_stale_entry_is_requeried_when_online(monkeypatch):
    """Past the TTL and reachable, the advisory store should refresh."""
    _write(vi.CACHE_FILE, {
        "schema_version": vi.CACHE_SCHEMA_VERSION,
        "entries": {_key(): [_COMPLETE_ADVISORY]},
        "fetched": {_key(): _stamp(90)},
    })
    monkeypatch.setattr(vi, "_post_json",
                        lambda *a, **k: {"results": [{"vulns": []}]})

    results = vi.query_osv_batch([_pkg("requests", "2.31.0")])

    assert results[_key()] == [], "a stale record must be replaceable"
    assert vi.ADVISORY_SERVICE_STATUS["stale_requeried"] == 1
    assert vi.ADVISORY_SERVICE_STATUS["from_cache"] == 0


def test_stale_entry_is_still_served_when_offline(monkeypatch):
    """Offline must never lose coverage just because the data is old."""
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")
    _write(vi.CACHE_FILE, {
        "schema_version": vi.CACHE_SCHEMA_VERSION,
        "entries": {_key(): [_COMPLETE_ADVISORY]},
        "fetched": {_key(): _stamp(400)},
    })

    def explode(*a, **k):
        raise AssertionError("network egress while offline")

    monkeypatch.setattr(vi, "_post_json", explode)
    results = vi.query_osv_batch([_pkg("requests", "2.31.0")])

    assert results[_key()] == [_COMPLETE_ADVISORY]
    assert vi.ADVISORY_SERVICE_STATUS["from_cache"] == 1
    assert vi.ADVISORY_SERVICE_STATUS["stale_requeried"] == 0


def test_undated_legacy_entry_counts_as_stale(monkeypatch):
    """A record with no timestamp has unknown age, so it refreshes once."""
    _write(vi.CACHE_FILE, {
        "schema_version": vi.CACHE_SCHEMA_VERSION,
        "entries": {_key(): [_COMPLETE_ADVISORY]},
    })
    monkeypatch.setattr(vi, "_post_json",
                        lambda *a, **k: {"results": [{"vulns": []}]})

    vi.query_osv_batch([_pkg("requests", "2.31.0")])

    assert vi.ADVISORY_SERVICE_STATUS["stale_requeried"] == 1


def test_successful_refresh_is_dated_for_the_next_run(monkeypatch):
    monkeypatch.setattr(vi, "_post_json",
                        lambda *a, **k: {"results": [{"vulns": []}]})

    vi.query_osv_batch([_pkg("requests", "2.31.0")])

    key = _key()
    assert key in vi._CACHE_FETCHED
    # Round-trips through the on-disk envelope.
    vi._save_cache({})
    envelope = json.loads(vi.CACHE_FILE.read_text(encoding="utf-8"))
    assert envelope["fetched"][key] == vi._CACHE_FETCHED[key]


def test_ttl_is_operator_tunable_but_never_zero(monkeypatch):
    monkeypatch.setenv("RSECOPSX_ADVISORY_TTL_DAYS", "7")
    assert vi._advisory_ttl_days() == 7.0

    # 0 would mean re-query every run -- how an unattended scheduler eats a
    # rate limit. Floor it instead of honouring a self-harming value.
    monkeypatch.setenv("RSECOPSX_ADVISORY_TTL_DAYS", "0")
    assert vi._advisory_ttl_days() == 1.0

    monkeypatch.setenv("RSECOPSX_ADVISORY_TTL_DAYS", "nonsense")
    assert vi._advisory_ttl_days() == vi.DEFAULT_ADVISORY_TTL_DAYS


def test_ttl_respected_by_the_staleness_decision(monkeypatch):
    monkeypatch.setenv("RSECOPSX_ADVISORY_TTL_DAYS", "90")
    vi._CACHE_FETCHED[_key()] = _stamp(30)
    assert vi._cache_entry_stale(_key()) is False

    vi._CACHE_FETCHED[_key()] = _stamp(120)
    assert vi._cache_entry_stale(_key()) is True
