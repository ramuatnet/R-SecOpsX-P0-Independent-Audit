"""Turning the feeds off must actually turn them off -- and say what it cost.

OBSERVED DEFECT
---------------
Four of the five network clients in this codebase already honour
``RSECOPSX_LIVE_FEEDS=0``: EPSS and KEV in :mod:`analysis.live_intel_feeds`,
HuggingFace enrichment (``RSX_HF_ENRICH``), NVD (``RSX_NVD_ENRICH``, opt-in)
and secret live validation (``--live-secrets``, opt-in). OSV -- the *primary*
advisory source -- did not. Its transport went straight to ``urlopen`` with no
gate, so an operator who set the documented air-gap switch still had
``api.osv.dev`` POSTed to for every package the disk cache could not answer.

That made the switch untrue. A report produced "offline" was not offline.

THE FIX AND ITS TWO HALVES
--------------------------
Gating lives in the transport (:func:`_post_json` / :func:`_get_json`) rather
than at the one call site, so any endpoint added later inherits the guarantee
instead of quietly reopening the hole. :func:`query_osv_batch` then reports the
consequence, because the dangerous outcome here is the same one documented in
``test_v11_advisory_fail_open.py``: a scan that checks nothing and reads as an
all-clear.

Which is why these tests assert three things, not one:

1. No bytes leave the process.
2. The local advisory store still answers -- offline must degrade, not blank out.
3. Whatever the local store could NOT answer is disclosed. Silence is the bug.
"""
from __future__ import annotations

import json
from unittest import mock

import pytest

from scanner import vulnerability_intel as vi
from scanner.vulnerability_intel import (
    ADVISORY_SERVICE_STATUS,
    AdvisoryServiceDisabled,
    _cache_key,
    _get_json,
    _post_json,
    query_osv_batch,
)


def _pkg(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    return {"name": name, "version": version, "ecosystem": ecosystem}


# A record the cache treats as authoritative: present, so it is not re-fetched.
_COMPLETE_ADVISORY = {
    "id": "GHSA-offline-test",
    "published": "2023-01-01T00:00:00Z",
    "severity": "HIGH",
    "cvss": 7.5,
}


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path):
    """Never touch the real 20 MB advisory cache from a test."""
    with mock.patch.object(vi, "CACHE_FILE", tmp_path / "cache.json"):
        yield


@pytest.fixture(autouse=True)
def _no_accidental_feeds(monkeypatch):
    """A test that forgets to set the switch must not reach the network."""
    monkeypatch.delenv("RSECOPSX_LIVE_FEEDS", raising=False)


def _seed_cache(entries: dict) -> None:
    vi.CACHE_FILE.write_text(
        json.dumps({
            "schema_version": vi.CACHE_SCHEMA_VERSION,
            "source": "OSV",
            "entries": entries,
        }),
        encoding="utf-8",
    )


def _must_not_reach_network(*args, **kwargs):
    raise AssertionError("network egress attempted while live feeds are disabled")


# ------------------------------------------------- nothing leaves the process --

def test_post_json_refuses_to_contact_osv_when_disabled(monkeypatch):
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")
    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        with pytest.raises(AdvisoryServiceDisabled):
            _post_json(vi.OSV_BATCH_URL, {"queries": []})


def test_get_json_refuses_to_contact_osv_when_disabled(monkeypatch):
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")
    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        with pytest.raises(AdvisoryServiceDisabled):
            _get_json("https://api.osv.dev/v1/vulns/GHSA-offline-test")


@pytest.mark.parametrize("setting", ["0", "false", "no", "off", "OFF", "  "])
def test_every_documented_off_value_blocks_egress(monkeypatch, setting):
    """The switch is spelled several ways; all of them must work."""
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", setting)
    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        with pytest.raises(AdvisoryServiceDisabled):
            _post_json(vi.OSV_BATCH_URL, {"queries": []})


# -------------------------------------- the local store must still be consulted --

def test_cached_advisory_is_served_when_disabled(monkeypatch):
    """Offline must degrade to the local store, not to an empty report."""
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")
    pkg = _pkg("requests", "2.31.0")
    _seed_cache({_cache_key("requests", "2.31.0", "PyPI"): [_COMPLETE_ADVISORY]})

    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        results = query_osv_batch([pkg])

    assert results[_cache_key("requests", "2.31.0", "PyPI")] == [_COMPLETE_ADVISORY]
    assert ADVISORY_SERVICE_STATUS["from_cache"] == 1


def test_cache_serving_does_not_latch_a_failure(monkeypatch):
    """A fully-cached offline run lost nothing, so it must not claim an outage."""
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")
    _seed_cache({_cache_key("requests", "2.31.0", "PyPI"): [_COMPLETE_ADVISORY]})

    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        query_osv_batch([_pkg("requests", "2.31.0")])

    assert ADVISORY_SERVICE_STATUS["live_feeds_disabled"] is True
    assert ADVISORY_SERVICE_STATUS["unanswered_due_to_offline"] == 0
    # Nothing went unasked, so inventing a coverage gap would be the report lying.
    assert ADVISORY_SERVICE_STATUS["available"] is True
    assert ADVISORY_SERVICE_STATUS["failures"] == []
    assert "coverage_note" not in ADVISORY_SERVICE_STATUS


# ---------------------------------------- what the local store cannot answer --

def test_uncached_package_is_disclosed_as_unchecked(monkeypatch):
    """The air-gap must be visible in the report, never silent."""
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")

    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        results = query_osv_batch([_pkg("flask", "3.0.0")])

    assert results == {}
    status = ADVISORY_SERVICE_STATUS
    assert status["live_feeds_disabled"] is True
    assert status["unanswered_due_to_offline"] == 1
    assert status["queries_attempted"] == 1
    assert status["queries_answered"] == 0
    assert status["available"] is False

    # Disclosed as a choice, not misreported as an incident.
    assert status["failures"] == []
    assert "NOT checked" in status["coverage_note"]
    assert "RSECOPSX_LIVE_FEEDS" in status["coverage_note"]


def test_mixed_run_reports_exact_offline_gap(monkeypatch):
    """Cached hits are credited; only the unanswered remainder is flagged."""
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")
    _seed_cache({_cache_key("requests", "2.31.0", "PyPI"): [_COMPLETE_ADVISORY]})

    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        query_osv_batch([
            _pkg("requests", "2.31.0"),
            _pkg("flask", "3.0.0"),
            _pkg("django", "5.0"),
        ])

    status = ADVISORY_SERVICE_STATUS
    assert status["from_cache"] == 1
    assert status["unanswered_due_to_offline"] == 2
    # ``queries_attempted`` counts only packages that missed the local store --
    # the same denominator the live-failure note uses, so the two paths agree.
    # Total input is derivable: from_cache (1) + unanswered (2) = 3.
    assert status["queries_attempted"] == 2
    assert "2 of 2 packages" in status["coverage_note"]


def test_offline_result_is_reachable_through_the_sbom_exporter(monkeypatch):
    """The disclosure must survive to the surface main.py actually reads."""
    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")

    with mock.patch("urllib.request.urlopen", _must_not_reach_network):
        query_osv_batch([_pkg("flask", "3.0.0")])

    from scanner import sbom as sbom_mod
    surfaced = sbom_mod.advisory_service_status()
    assert surfaced["live_feeds_disabled"] is True
    assert surfaced["available"] is False


# ----------------------------------------------- default behaviour is unchanged --

def test_default_still_allows_live_lookup(monkeypatch):
    """RSECOPSX_LIVE_FEEDS unset means on -- matching live_intel_feeds."""
    assert "RSECOPSX_LIVE_FEEDS" not in __import__("os").environ
    assert vi.live_feeds_enabled() is True

    with mock.patch.object(
        vi, "_post_json", return_value={"results": [{"vulns": []}]}
    ) as stub:
        query_osv_batch([_pkg("flask", "3.0.0")])

    assert stub.called
    assert ADVISORY_SERVICE_STATUS["live_feeds_disabled"] is False


def test_disabled_service_is_a_distinct_exception_type():
    """An outage is an incident; a switch is a setting. Never conflate them."""
    assert not issubclass(AdvisoryServiceDisabled, vi.AdvisoryServiceUnavailable)
