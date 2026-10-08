"""The external advisory lookup must fail open, and its absence must be disclosed.

OBSERVED DEFECT
---------------
A sweep of the prodtest AI Benchmarks corpus recorded `autogen-main` at rc=1 with
a traceback through `generate_sbom`. Re-running the identical scan gave rc=0 and
232 findings, so the failure was intermittent -- which makes it worse than a
deterministic bug, because a scan that sometimes produces no artifact cannot be
distinguished from one that has not been run.

CAUSE
-----
`query_osv_batch` guarded its HTTP call with

    except (urllib.error.URLError, TimeoutError, OSError):
        continue

That is the right guard for a transport failure. It misses the case that actually
occurs in the field: an intermediary (corporate proxy, captive portal, rate
limiter) answers with HTTP **200** and an HTML body. `urlopen` then raises
nothing, and `json.loads` raises `JSONDecodeError` -- which subclasses ValueError,
not OSError. The exception propagated out of query_osv_batch, out of
enrich_packages_with_external_vulns, out of generate_sbom and aborted the scan.

A JSON array rather than an object was equally fatal: `data.get("results")` on a
list raises AttributeError with even less context.

THE DANGEROUS OUTCOME IS NOT THE CRASH
--------------------------------------
The crash at least fails loudly. The silent version is worse: returning an empty
result set makes every package look CVE-free, and the report says "no known
vulnerabilities" when the truth is "the database was never consulted". So these
tests assert two separate properties -- the scan survives, AND the report is
told the lookup did not happen.
"""
from __future__ import annotations

import io
import json
import urllib.error
from unittest import mock

import pytest

from scanner import vulnerability_intel as vi
from scanner import sbom as sbom_mod
from scanner.vulnerability_intel import (
    ADVISORY_SERVICE_STATUS,
    AdvisoryServiceUnavailable,
    _decode_json_object,
    query_osv_batch,
)


def _pkg(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    return {"name": name, "version": version, "ecosystem": ecosystem}


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path):
    """Never touch the real advisory cache from a test."""
    with mock.patch.object(vi, "CACHE_FILE", tmp_path / "cache.json"):
        yield


# ------------------------------------------------------- the parse contract --

def test_html_body_is_rejected_with_a_reason_naming_the_service():
    """A 200 with an HTML body must be recognisable as a service problem."""
    with pytest.raises(AdvisoryServiceUnavailable) as exc:
        _decode_json_object(b"<html><body>Proxy error</body></html>",
                            "https://api.osv.dev/v1/querybatch")

    assert "api.osv.dev" in str(exc.value)
    assert "not JSON" in str(exc.value)


def test_json_array_body_is_rejected():
    """A JSON array parses fine and then fails at .get() with no context."""
    with pytest.raises(AdvisoryServiceUnavailable) as exc:
        _decode_json_object(b"[1, 2, 3]", "https://api.osv.dev/v1/querybatch")

    assert "list" in str(exc.value)


def test_valid_object_body_is_returned():
    assert _decode_json_object(b'{"results": []}', "u") == {"results": []}


# ---------------------------------------------------------- fail open, loudly --

def test_html_response_does_not_abort_the_batch_query():
    """The regression itself: an HTML body must cost CVE data, not the scan."""
    with mock.patch.object(
        vi, "_post_json",
        side_effect=AdvisoryServiceUnavailable("body was HTML"),
    ):
        results = query_osv_batch([_pkg("requests", "2.31.0")])

    assert results == {}
    assert ADVISORY_SERVICE_STATUS["available"] is False


def test_transport_error_does_not_abort_the_batch_query():
    with mock.patch.object(
        vi, "_post_json", side_effect=urllib.error.URLError("no route to host")
    ):
        results = query_osv_batch([_pkg("requests", "2.31.0")])

    assert results == {}
    assert ADVISORY_SERVICE_STATUS["available"] is False


def test_failure_is_disclosed_not_swallowed():
    """Zero CVEs must never be reported without saying the lookup was skipped."""
    with mock.patch.object(
        vi, "_post_json", side_effect=AdvisoryServiceUnavailable("body was HTML")
    ):
        query_osv_batch([_pkg("requests", "2.31.0")])

    status = ADVISORY_SERVICE_STATUS
    assert status["available"] is False
    assert status["queries_attempted"] == 1
    assert status["queries_answered"] == 0
    assert status["failures"], "the reason for the failure must be recorded"
    # The wording matters: it must not permit "absent CVE" to be read as "safe".
    assert "NOT" in status["coverage_note"]
    assert "evidence" in status["coverage_note"]


def test_results_of_the_wrong_type_do_not_abort_the_query():
    """`results` being a dict rather than a list is the same class of defect."""
    with mock.patch.object(vi, "_post_json", return_value={"results": {"a": 1}}):
        results = query_osv_batch([_pkg("requests", "2.31.0")])

    assert results == {}
    assert ADVISORY_SERVICE_STATUS["available"] is False


def test_one_bad_batch_does_not_abandon_the_remaining_batches():
    """A transient failure on batch 1 must not cost batches 2+."""
    batches = {"n": 0}

    def flaky(url, payload, timeout=30):
        batches["n"] += 1
        if batches["n"] == 1:
            raise AdvisoryServiceUnavailable("intermittent")
        return {"results": [{"vulns": []} for _ in payload["queries"]]}

    pkgs = [_pkg(f"p{i}", "1.0.0") for i in range(vi.BATCH_SIZE + 5)]

    with mock.patch.object(vi, "_post_json", side_effect=flaky):
        query_osv_batch(pkgs)

    status = ADVISORY_SERVICE_STATUS
    assert status["queries_attempted"] == vi.BATCH_SIZE + 5
    assert status["queries_answered"] == 5, "the second batch must still be queried"


def test_successful_query_reports_available():
    with mock.patch.object(vi, "_post_json", return_value={"results": [{"vulns": []}]}):
        query_osv_batch([_pkg("requests", "2.31.0")])

    assert ADVISORY_SERVICE_STATUS["available"] is True
    assert ADVISORY_SERVICE_STATUS["queries_answered"] == 1


# --------------------------------------------------------- the generate_sbom guard --

def test_generate_sbom_survives_an_enrichment_outage(tmp_path):
    """The second guard: an unanticipated enrichment failure must not take the
    SBOM down with it. Before it, one raising enrichment meant zero artifacts."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    with mock.patch.object(
        sbom_mod, "enrich_packages_with_external_vulns",
        side_effect=RuntimeError("something unforeseen"),
    ):
        pkgs = sbom_mod.generate_sbom(str(project))

    assert pkgs, "the SBOM must still list the declared dependency"
    names = {p.get("name") for p in pkgs}
    assert any("requests" in str(n).lower() for n in names)


def test_enrichment_outage_is_disclosed_through_the_sbom_api(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    with mock.patch.object(
        sbom_mod, "enrich_packages_with_external_vulns",
        side_effect=RuntimeError("something unforeseen"),
    ):
        sbom_mod.generate_sbom(str(project))

    status = sbom_mod.advisory_service_status()
    assert status["available"] is False
    assert "NOT evidence" in status["impact"]


def test_advisory_status_is_available_on_a_clean_run(tmp_path):
    """The disclosure block must exist even when nothing went wrong.

    A field that only appears on failure is a field readers learn to ignore.
    """
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    def passthrough(packages):
        return packages

    with mock.patch.object(
        sbom_mod, "enrich_packages_with_external_vulns", side_effect=passthrough
    ):
        sbom_mod.generate_sbom(str(project))

    status = sbom_mod.advisory_service_status()
    assert "available" in status
    assert status["disclosure"]