"""G-001 (live FIRST.org EPSS) + G-002 (live CISA KEV catalog).

Ground truth
------------
Taken from ``reports/gap_register.json`` (G-001/G-002) and from the two feeds'
own response documents, captured **before** any of this code existed:

``GET https://api.first.org/data/v1/epss?cve=A,B``
    ``{"status":"OK","total":N,"data":[{"cve","epss","percentile","date"}]}``
    — ``epss`` and ``percentile`` arrive as *strings*; ``date`` is the feed's
    own as-of day, and ``Cache-Control: max-age=86400`` sets the cadence.

``GET .../known_exploited_vulnerabilities.json``
    ``{"catalogVersion","dateReleased","count","vulnerabilities":[``
    ``{"cveID","vendorProject","product","vulnerabilityName","dateAdded",``
    ``"dueDate","knownRansomwareCampaignUse", ...}]}``
    — catalog 2026.10.04 carried **1734** records against the 9-row and 7-row
    seed tables R-SecOpsX shipped with.

Every test below is hermetic.  Live behaviour is exercised against a *local*
HTTP server serving exactly those shapes, or against a pre-seeded dated cache.
Nothing here reaches the public internet, so the suite cannot be flaky, cannot
be slow, and — most importantly — cannot silently fall back to offline and
still "pass" while proving nothing about the live path.

The contract under test
-----------------------
1. ``LIVE_FEED`` is **earned**: only an actual lookup may produce it, and a
   dated snapshot of one keeps it with its original ``as_of``.
2. A live KEV miss is *evidence* (the whole catalog was consulted) —
   ``False + LIVE_FEED``.  An offline miss is the *absence* of evidence —
   ``False + STATIC_REFERENCE``.  The two must never collapse into each other.
3. Provenance still gates nothing: given identical **values**, the live and
   offline paths must produce identical buckets, priorities and decisions.
4. Network failure degrades to the seed tables and says so.  It never raises,
   never hangs a scan, and never converts a miss into a number.
"""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from analysis import live_intel_feeds as feeds
from analysis.epss_intelligence_engine import (
    STATIC_EPSS_SCORES,
    enrich_epss_intelligence,
    epss_intelligence_summary,
)
from analysis.intelligence_provenance import (
    LIVE_FEED,
    NOT_AVAILABLE,
    PROVENANCE_TOKENS,
    STATIC_INTELLIGENCE_NOTE,
    STATIC_REFERENCE,
    known_provenance,
    intelligence_note,
    note_from_payload,
    provenance_pair,
)
from analysis.kev_intelligence_engine import (
    KNOWN_EXPLOITED_CVES as KEV_ENGINE_SEED_SET,
    enrich_kev_intelligence,
    kev_intelligence_summary,
)
from analysis.vulnerability_age_engine import (
    KNOWN_EXPLOITED_CVES as AGE_ENGINE_SEED_SET,
    STATIC_CVE_DATES,
    enrich_vulnerability_age,
    vulnerability_age_summary,
)

# ---------------------------------------------------------------------------
# Fixtures — authored from the feed documents above, not from product output
# ---------------------------------------------------------------------------

KEV_HIT = {
    "name": "log4j-core",
    "version": "2.14.1",
    "cve": "CVE-2021-44228",
    "severity": "Critical",
    "cvss": 10.0,
    "reachability_status": "REACHABLE",
}

KEV_MISS = {
    "name": "lodash",
    "version": "4.17.20",
    "cve": "CVE-2021-23337",
    "severity": "High",
    "cvss": 7.5,
    "reachability_status": "NOT_REACHABLE",
}

NO_IDENTIFIER = {
    "name": "mystery-lib",
    "version": "1.0.0",
    "severity": "High",
    "cvss": 7.5,
    "reachability_status": "NOT_REACHABLE",
}

EPSS_DOCUMENT = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 2,
    "offset": 0,
    "limit": 100,
    "data": [
        {
            "cve": "CVE-2021-44228",
            "epss": "0.999990000",
            "percentile": "1.000000000",
            "date": "2026-10-05",
        },
        {
            "cve": "CVE-2021-23337",
            "epss": "0.213330000",
            "percentile": "0.975390000",
            "date": "2026-10-05",
        },
    ],
}

KEV_DOCUMENT = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.10.04",
    "dateReleased": "2026-10-04T18:52:56.0635Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Apache Log4j2 JNDI Features RCE",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2022-0001",
            "vendorProject": "Example",
            "product": "Unrelated",
            "vulnerabilityName": "Unrelated entry",
            "dateAdded": "2022-01-01",
            "dueDate": "2022-01-15",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


@pytest.fixture(autouse=True)
def _isolate_process_feed():
    """The feed set is process-wide; never let one test leak into the next."""
    feeds.reset_default_feed()
    yield
    feeds.reset_default_feed()


@pytest.fixture
def local_feed_server():
    """A local HTTP server serving canned feed documents.

    ``responses`` is mutable, so a test can register a route after the fixture
    has bound a port.  Anything unregistered answers 404, which exercises the
    HTTPError fallback rather than a happy path.
    """
    responses: dict[str, tuple[int, bytes]] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib naming
            key = self.path.split("?", 1)[0]
            status, body = responses.get(key, (404, b"{}"))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):  # keep pytest output clean
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", responses
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _write_cache(path, entries, schema=feeds.CACHE_SCHEMA_VERSION):
    path.write_text(
        json.dumps({"schema_version": schema, "entries": entries}),
        encoding="utf-8",
    )
    return path


def _epss_entries(mapping):
    """Build a *fresh* on-disk EPSS snapshot for the given CVE -> score map."""
    epoch = time.time()
    return {
        f"epss|{cve}": {
            "score": score,
            "percentile": score,
            "as_of": "2026-10-05",
            "fetched_at_epoch": epoch,
            "fetched_at": "2026-10-05T00:00:00+00:00",
        }
        for cve, score in mapping.items()
    }


def _kev_entries(records):
    return {
        "kev|catalog": {
            "records": records,
            "fetched_at_epoch": time.time(),
            "fetched_at": "2026-10-04T18:52:56+00:00",
            "catalog_version": KEV_DOCUMENT["catalogVersion"],
            "date_released": KEV_DOCUMENT["dateReleased"],
            "count": len(records),
        }
    }


# ---------------------------------------------------------------------------
# 1. The vocabulary is closed and LIVE_FEED is earned
# ---------------------------------------------------------------------------

def test_01_live_feed_is_a_token_and_an_unrecognised_label_is_not_static():
    assert "LIVE_FEED" in PROVENANCE_TOKENS
    assert known_provenance(LIVE_FEED) == LIVE_FEED
    assert known_provenance(STATIC_REFERENCE) == STATIC_REFERENCE

    # The dangerous direction: an inherited label we do not recognise must not
    # become STATIC_REFERENCE, because "it came from an offline table" is
    # itself a claim we would then be inventing.
    assert known_provenance("SMUGGLED_IN_STRING") == NOT_AVAILABLE
    assert known_provenance("SMUGGLED_IN_STRING") != STATIC_REFERENCE
    assert known_provenance(None) == NOT_AVAILABLE


def test_02_engine_without_a_feed_never_claims_live():
    """The offline/air-gapped contract: no feed passed, no LIVE_FEED."""
    sbom = enrich_kev_intelligence([dict(KEV_HIT), dict(KEV_MISS)])
    sbom = enrich_vulnerability_age(sbom)
    sbom = enrich_epss_intelligence(sbom)

    for pkg in sbom:
        assert pkg["kev_provenance"] == STATIC_REFERENCE
        assert pkg["epss_provenance"] == STATIC_REFERENCE

    assert epss_intelligence_summary(sbom)["live_feeds_used"] is False
    assert kev_intelligence_summary(sbom)["live_feeds_used"] is False
    assert vulnerability_age_summary(sbom)["live_feeds_used"] is False


def test_03_dated_cache_snapshot_is_live_feed_and_triggers_no_refetch(tmp_path):
    """A cached row is a dated snapshot of the feed, not a second opinion."""
    cache = _write_cache(
        tmp_path / "intel.json",
        _epss_entries({"CVE-2021-23337": 0.21333}),
    )
    feed = feeds.EPSSFeed(cache_path=cache, enabled=True)

    got = feed.scores_for(["CVE-2021-23337"])

    assert feed.fetch_attempts == 0, "a fresh cache must not hit the network"
    assert got["CVE-2021-23337"].provenance == LIVE_FEED
    assert got["CVE-2021-23337"].as_of == "2026-10-05"
    assert got["CVE-2021-23337"].score == 0.21333
    assert got["CVE-2021-23337"].source == "FIRST_ORG_EPSS"


def test_04_stale_cache_still_reports_live_feed_with_its_original_as_of(tmp_path):
    """Stale-but-real beats refetched-and-failed; the date travels either way."""
    entries = _epss_entries({"CVE-2021-44228": 0.99999})
    entries["epss|CVE-2021-44228"]["fetched_at_epoch"] = time.time() - 90 * 86400
    cache = _write_cache(tmp_path / "intel.json", entries)

    # Enabled but pointed at a route the local server does not serve -> 404.
    feed = feeds.EPSSFeed(cache_path=cache, enabled=True, timeout=2)
    monkey_base = "http://127.0.0.1:1"  # refused instantly, never routed
    feeds.EPSS_API_URL, saved = monkey_base + "/epss", feeds.EPSS_API_URL
    try:
        got = feed.scores_for(["CVE-2021-44228"])
    finally:
        feeds.EPSS_API_URL = saved

    assert got["CVE-2021-44228"].provenance == LIVE_FEED
    assert got["CVE-2021-44228"].as_of == "2026-10-05"
    assert feed.last_error, "the transport failure must be recorded, not hidden"


# ---------------------------------------------------------------------------
# 2. The real document shapes, over real HTTP
# ---------------------------------------------------------------------------

def test_05_live_epss_fetch_parses_the_documented_shape(
    local_feed_server, tmp_path, monkeypatch
):
    base, responses = local_feed_server
    responses["/epss"] = (200, json.dumps(EPSS_DOCUMENT).encode("utf-8"))
    monkeypatch.setattr(feeds, "EPSS_API_URL", base + "/epss")

    feed = feeds.EPSSFeed(cache_path=tmp_path / "intel.json", enabled=True)
    got = feed.scores_for(["CVE-2021-44228", "CVE-2021-23337"])

    assert feed.fetch_successes == 1
    # "epss" arrives as a string in the real document; the client must cast it.
    assert got["CVE-2021-23337"].score == pytest.approx(0.21333)
    assert got["CVE-2021-23337"].percentile == pytest.approx(0.97539)
    assert got["CVE-2021-44228"].as_of == "2026-10-05"
    assert {v.provenance for v in got.values()} == {LIVE_FEED}

    sbom = enrich_epss_intelligence([dict(KEV_MISS), dict(KEV_HIT)], feed=feed)
    by_cve = {p["cve"]: p for p in sbom}
    assert by_cve["CVE-2021-23337"]["epss_provenance"] == LIVE_FEED
    assert by_cve["CVE-2021-23337"]["epss_score"] == pytest.approx(0.21333)
    assert by_cve["CVE-2021-23337"]["epss_source"] == "FIRST_ORG_EPSS"
    assert by_cve["CVE-2021-23337"]["epss_method"] == "LIVE_FIRST_ORG_EPSS_V1"
    assert by_cve["CVE-2021-23337"]["epss_as_of"] == "2026-10-05"

    summary = epss_intelligence_summary(sbom)
    assert summary["provenance"] == LIVE_FEED
    assert summary["summary_status"] == "LIVE_FIRST_ORG_EPSS_V1"
    assert summary["live_feeds_used"] is True
    assert summary["as_of"] == "2026-10-05"


def test_06_live_kev_fetch_parses_the_documented_shape(
    local_feed_server, tmp_path, monkeypatch
):
    base, responses = local_feed_server
    responses["/kev"] = (200, json.dumps(KEV_DOCUMENT).encode("utf-8"))
    monkeypatch.setattr(feeds, "KEV_FEED_URL", base + "/kev")

    feed = feeds.KEVFeed(cache_path=tmp_path / "intel.json", enabled=True)
    sbom = enrich_kev_intelligence([dict(KEV_HIT), dict(KEV_MISS)], feed=feed)
    by_cve = {p["cve"]: p for p in sbom}

    hit, miss = by_cve["CVE-2021-44228"], by_cve["CVE-2021-23337"]

    # A hit: live answer plus the catalog's own detail.
    assert hit["kev_status"] is True
    assert hit["kev_provenance"] == LIVE_FEED
    assert hit["kev_source"] == "CISA_KEV_LIVE"
    assert hit["kev_method"] == "LIVE_CISA_KEV_V1"
    assert hit["kev_vendor"] == "Apache"
    assert hit["kev_ransomware_use"] == "Known"
    assert hit["kev_catalog_version"] == "2026.10.04"
    assert hit["kev_as_of"] == KEV_DOCUMENT["dateReleased"]
    assert hit["kev_priority"] == "P0_REACHABLE_KEV"

    # A miss: the whole catalog was consulted, so this is evidence.
    assert miss["kev_status"] is False
    assert miss["kev_provenance"] == LIVE_FEED, (
        "a miss against a fetched catalog is an observation, not an assumption"
    )
    assert miss["kev_method"] == "LIVE_CISA_KEV_NO_MATCH"
    # ...and it must not inherit seed-table detail it never matched.
    assert "kev_vendor" not in miss
    assert "kev_ransomware_use" not in miss
    assert miss["kev_priority"] == "NO_KEV_SIGNAL"

    summary = kev_intelligence_summary(sbom)
    assert summary["provenance"] == LIVE_FEED
    assert summary["summary_status"] == "LIVE_CISA_KEV_V1"
    assert summary["live_feeds_used"] is True
    assert summary["catalog_version"] == "2026.10.04"
    assert summary["kev_packages"] == 1


# ---------------------------------------------------------------------------
# 3. The two kinds of miss are different claims
# ---------------------------------------------------------------------------

def test_07_a_live_miss_and_an_offline_miss_are_not_the_same_claim():
    offline = enrich_kev_intelligence([dict(KEV_MISS)])[0]
    assert offline["kev_status"] is False
    assert offline["kev_provenance"] == STATIC_REFERENCE

    # Same boolean, different epistemic status -> different rendered wording.
    offline_note = intelligence_note(STATIC_REFERENCE, STATIC_REFERENCE)
    live_note = intelligence_note(LIVE_FEED, LIVE_FEED, kev_as_of="2026.10.04")

    assert "not present in the offline table" in offline_note
    assert "absent from that catalog" in live_note
    assert "not present in the offline table" not in live_note
    assert "2026.10.04" in live_note

    # And the tokens themselves must remain distinguishable forever.
    assert offline["kev_provenance"] != LIVE_FEED


def test_08_an_item_with_no_identifier_is_never_labelled_live(local_feed_server, tmp_path, monkeypatch):
    """No CVE means no question was asked, so no LIVE_FEED answer exists."""
    base, responses = local_feed_server
    responses["/epss"] = (200, json.dumps(EPSS_DOCUMENT).encode("utf-8"))
    responses["/kev"] = (200, json.dumps(KEV_DOCUMENT).encode("utf-8"))
    monkeypatch.setattr(feeds, "EPSS_API_URL", base + "/epss")
    monkeypatch.setattr(feeds, "KEV_FEED_URL", base + "/kev")

    epss_feed = feeds.EPSSFeed(cache_path=tmp_path / "a.json", enabled=True)
    kev_feed = feeds.KEVFeed(cache_path=tmp_path / "b.json", enabled=True)

    sbom = enrich_kev_intelligence([dict(NO_IDENTIFIER)], feed=kev_feed)
    sbom = enrich_epss_intelligence(sbom, feed=epss_feed)
    pkg = sbom[0]

    assert pkg["kev_provenance"] == NOT_AVAILABLE
    assert pkg["kev_status"] is False
    assert pkg["epss_provenance"] == NOT_AVAILABLE
    assert pkg["epss_score"] is None
    assert pkg["epss_method"] == "EPSS_NOT_AVAILABLE"

    # No question was asked about this item, so it must not advertise which
    # catalog it was not asked against.  Otherwise a payload where nothing was
    # consultable publishes `kev_catalog_version: 2026.10.04` beside
    # `kev: NOT_AVAILABLE` — a version of a catalog nothing was checked
    # against.  The summary and the payload banner inherit the same rule.
    assert pkg.get("kev_catalog_version") is None
    assert pkg.get("kev_as_of") is None
    assert pkg.get("epss_as_of") is None

    kis = kev_intelligence_summary(sbom)
    assert kis["provenance"] == NOT_AVAILABLE
    assert kis["live_feeds_used"] is False
    assert kis["catalog_version"] is None
    assert kis["as_of"] is None


def test_09_a_miss_the_feed_never_answered_does_not_become_a_number(local_feed_server, tmp_path, monkeypatch):
    """Never upgrade a miss: absent stays absent, it does not inherit a seed."""
    base, responses = local_feed_server
    responses["/epss"] = (200, json.dumps(EPSS_DOCUMENT).encode("utf-8"))
    monkeypatch.setattr(feeds, "EPSS_API_URL", base + "/epss")

    feed = feeds.EPSSFeed(cache_path=tmp_path / "intel.json", enabled=True)
    # CVE-1999-0001 is in neither the feed document nor STATIC_EPSS_SCORES.
    pkg = enrich_epss_intelligence([{"cve": "CVE-1999-0001"}], feed=feed)[0]

    assert pkg["epss_score"] is None
    assert pkg["epss_provenance"] == NOT_AVAILABLE
    assert pkg["epss_method"] == "EPSS_NOT_AVAILABLE"


# ---------------------------------------------------------------------------
# 4. Provenance still gates nothing
# ---------------------------------------------------------------------------

def test_10_provenance_changes_no_decision_given_the_same_values(tmp_path):
    """The live path must be a labelling change, not a scoring change.

    Feed the live engine the *same numbers* the seed table holds: every bucket,
    priority and decision must come out identical, with only the label moving.
    """
    cache = _write_cache(
        tmp_path / "intel.json",
        _epss_entries({"CVE-2021-44228": 0.975, "CVE-2021-23337": 0.021}),
    )
    feed = feeds.EPSSFeed(cache_path=cache, enabled=True)

    offline = enrich_epss_intelligence([dict(KEV_HIT), dict(KEV_MISS)])
    live = enrich_epss_intelligence(
        [dict(KEV_HIT), dict(KEV_MISS)], feed=feed
    )

    for before, after in zip(offline, live):
        assert before["epss_score"] == after["epss_score"]
        assert before["epss_bucket"] == after["epss_bucket"]
        assert before["epss_priority"] == after["epss_priority"]
        assert before["epss_provenance"] == STATIC_REFERENCE
        assert after["epss_provenance"] == LIVE_FEED

    # The summary counts (which drive report sections) are identical too.
    off_s, live_s = epss_intelligence_summary(offline), epss_intelligence_summary(live)
    for key in ("total_vulnerable_packages", "known_epss_packages",
                "very_high_exploit_probability", "p0_immediate_packages",
                "epss_buckets", "epss_priority_counts"):
        assert off_s[key] == live_s[key], key
    # Only the honesty fields differ.
    assert off_s["live_feeds_used"] is False
    assert live_s["live_feeds_used"] is True


def test_11_summary_never_launders_one_static_row_into_an_all_live_headline():
    sbom = [
        {"cve": "CVE-2021-44228", "epss_score": 0.975,
         "epss_provenance": LIVE_FEED, "epss_as_of": "2026-10-05",
         "epss_bucket": "VERY_HIGH_EXPLOIT_PROBABILITY",
         "epss_priority": "P0_IMMEDIATE"},
        {"cve": "CVE-2021-23337", "epss_score": 0.021,
         "epss_provenance": STATIC_REFERENCE,
         "epss_bucket": "LOW_EXPLOIT_PROBABILITY",
         "epss_priority": "P3_STANDARD"},
    ]
    summary = epss_intelligence_summary(sbom)

    assert summary["provenance"] == STATIC_REFERENCE, (
        "the headline may never be stronger than its weakest member"
    )
    assert summary["live_feeds_used"] is True
    assert summary["provenance_counts"] == {
        STATIC_REFERENCE: 1,
        LIVE_FEED: 1,
    }

    kev = kev_intelligence_summary([
        {"cve": "CVE-1", "kev_status": True, "kev_provenance": LIVE_FEED,
         "kev_priority": "P0_REACHABLE_KEV", "reachability_status": "REACHABLE"},
        {"cve": "CVE-2", "kev_status": False, "kev_provenance": STATIC_REFERENCE,
         "kev_priority": "NO_KEV_SIGNAL"},
    ])
    assert kev["provenance"] == STATIC_REFERENCE
    assert kev["live_feeds_used"] is True

    age = vulnerability_age_summary([
        {"cve": "CVE-1", "kev_status": True, "kev_provenance": LIVE_FEED},
        {"cve": "CVE-2", "kev_status": False, "kev_provenance": STATIC_REFERENCE},
    ])
    assert age["kev_provenance"] == STATIC_REFERENCE
    assert age["live_feeds_used"] is True


def test_12_unreachable_feed_degrades_to_seed_tables_and_says_so(tmp_path):
    """An air-gapped host must still get a report, honestly captioned."""
    epss_feed = feeds.EPSSFeed(cache_path=tmp_path / "a.json", enabled=True, timeout=2)
    kev_feed = feeds.KEVFeed(cache_path=tmp_path / "b.json", enabled=True, timeout=2)
    saved_epss, saved_kev = feeds.EPSS_API_URL, feeds.KEV_FEED_URL
    # 127.0.0.1 port 1 is refused immediately and never routed anywhere.
    feeds.EPSS_API_URL, feeds.KEV_FEED_URL = (
        "http://127.0.0.1:1/epss", "http://127.0.0.1:1/kev"
    )
    try:
        sbom = enrich_kev_intelligence([dict(KEV_HIT), dict(KEV_MISS)], feed=kev_feed)
        sbom = enrich_epss_intelligence(sbom, feed=epss_feed)
    finally:
        feeds.EPSS_API_URL, feeds.KEV_FEED_URL = saved_epss, saved_kev

    assert epss_feed.last_error, "the failure must be recorded, not swallowed"
    assert kev_feed.last_error, "the failure must be recorded, not swallowed"

    by_cve = {p["cve"]: p for p in sbom}
    # Seed tables still answer, so the report is not empty ...
    assert by_cve["CVE-2021-44228"]["epss_score"] == pytest.approx(
        STATIC_EPSS_SCORES["CVE-2021-44228"]
    )
    assert by_cve["CVE-2021-44228"]["kev_status"] is True
    # ... and every label admits where the value came from.
    for pkg in sbom:
        assert pkg["epss_provenance"] == STATIC_REFERENCE
        assert pkg["kev_provenance"] == STATIC_REFERENCE

    assert epss_intelligence_summary(sbom)["live_feeds_used"] is False
    assert kev_intelligence_summary(sbom)["live_feeds_used"] is False
    assert kev_intelligence_summary(sbom)["provenance"] == STATIC_REFERENCE


def test_13_operator_off_switch_is_explicit(monkeypatch):
    cases = {
        None: True,
        "1": True,
        "true": True,
        "TRUE": True,
        "yes": True,
        "on": True,
        "0": False,
        "false": False,
        "no": False,
        "off": False,
        "": False,
        "garbage": True,  # only an explicit negative disables; no guessing
    }
    for value, expected in cases.items():
        if value is None:
            monkeypatch.delenv("RSECOPSX_LIVE_FEEDS", raising=False)
        else:
            monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", value)
        assert feeds.live_feeds_enabled() is expected, value

        feeds.reset_default_feed()
        group = feeds.default_feed()
        assert (group.epss is None) is (not expected), value
        assert (group.kev is None) is (not expected), value
        assert bool(group.reasons) is (not expected), value
        feeds.reset_default_feed()


# ---------------------------------------------------------------------------
# 5. The whole payload, end to end
# ---------------------------------------------------------------------------

def _live_pipeline(epss_feed, kev_feed, *pkgs):
    """The exact order main.py calls the enrichers, with feeds supplied."""
    sbom = [dict(p) for p in pkgs]
    sbom = enrich_kev_intelligence(sbom, feed=kev_feed)
    sbom = enrich_vulnerability_age(sbom)
    sbom = enrich_epss_intelligence(sbom, feed=epss_feed)
    return sbom


def test_14_live_answer_survives_the_age_pass(local_feed_server, tmp_path, monkeypatch):
    """The hazard that motivated test_09 of the G-003 suite, end to end.

    ``vulnerability_age_engine`` rewrites ``kev_status`` from its own 7-record
    set *after* the KEV pass.  It must be unable to overwrite or relabel a live
    catalog answer, at package level and in the nested ``vulnerability_intelligence``
    records that PDF, Excel and CycloneDX all render.
    """
    base, responses = local_feed_server
    responses["/kev"] = (200, json.dumps(KEV_DOCUMENT).encode("utf-8"))
    monkeypatch.setattr(feeds, "KEV_FEED_URL", base + "/kev")
    kev_feed = feeds.KEVFeed(cache_path=tmp_path / "intel.json", enabled=True)

    nested = dict(KEV_MISS)
    nested["vulnerabilities"] = [{"cve": "CVE-2021-23337", "severity": "High"}]

    sbom = enrich_kev_intelligence([dict(KEV_HIT), nested], feed=kev_feed)
    sbom = enrich_vulnerability_age(sbom)
    by_cve = {p["cve"]: p for p in sbom}

    # CVE-2021-44228 is IN the live catalog but NOT in the local 7-record set,
    # so a downgrade here would be the exact regression this guards.
    assert by_cve["CVE-2021-44228"]["kev_status"] is True
    assert by_cve["CVE-2021-44228"]["kev_provenance"] == LIVE_FEED

    # CVE-2021-23337 is in neither: live miss survives too.
    assert by_cve["CVE-2021-23337"]["kev_status"] is False
    assert by_cve["CVE-2021-23337"]["kev_provenance"] == LIVE_FEED

    # The nested record for the same identifier inherits rather than contradicts.
    nested_records = by_cve["CVE-2021-23337"]["vulnerability_intelligence"]
    assert nested_records[0]["kev_provenance"] == LIVE_FEED
    assert nested_records[0]["kev_status"] is False

    assert vulnerability_age_summary(sbom)["kev_provenance"] == LIVE_FEED


def test_15_full_payload_banner_and_renderer_caption_follow_the_data(
    local_feed_server, tmp_path, monkeypatch
):
    import main as main_module

    base, responses = local_feed_server
    responses["/epss"] = (200, json.dumps(EPSS_DOCUMENT).encode("utf-8"))
    responses["/kev"] = (200, json.dumps(KEV_DOCUMENT).encode("utf-8"))
    monkeypatch.setattr(feeds, "EPSS_API_URL", base + "/epss")
    monkeypatch.setattr(feeds, "KEV_FEED_URL", base + "/kev")

    epss_feed = feeds.EPSSFeed(cache_path=tmp_path / "a.json", enabled=True)
    kev_feed = feeds.KEVFeed(cache_path=tmp_path / "b.json", enabled=True)
    sbom = _live_pipeline(epss_feed, kev_feed, KEV_HIT, KEV_MISS)

    payload = {
        "sbom": sbom,
        "metadata": {},
        "epss_intelligence_summary": epss_intelligence_summary(sbom),
        "kev_intelligence_summary": kev_intelligence_summary(sbom),
        "vulnerability_age_summary": vulnerability_age_summary(sbom),
    }
    banner = main_module._apply_epss_kev_provenance_banner(payload)

    assert banner["live_feeds_wired"] is True
    assert banner["epss"] == LIVE_FEED
    assert banner["kev"] == LIVE_FEED
    assert banner["kev_catalog_version"] == "2026.10.04"
    assert "LIVE_FEED" in banner["note"]
    assert "not present in the offline table" not in banner["note"]

    # The renderer reads the payload, not the constant: a live workbook is
    # captioned live.
    assert provenance_pair(payload) == (LIVE_FEED, LIVE_FEED)
    rendered = note_from_payload(payload)
    assert "LIVE_FEED" in rendered
    assert rendered == banner["note"]
    assert "not present in the offline table" not in rendered

    # With no intelligence at all, the shared offline sentence is the honest
    # default - and it is still reached through the same single builder.
    assert note_from_payload(None) == STATIC_INTELLIGENCE_NOTE
    assert note_from_payload({}) == STATIC_INTELLIGENCE_NOTE
    assert provenance_pair({}) == (STATIC_REFERENCE, STATIC_REFERENCE)


def test_16_offline_payload_banner_still_reports_not_wired():
    """The negative control for the banner: enabled-but-unreachable == False."""
    import main as main_module

    sbom = enrich_kev_intelligence([dict(KEV_HIT)])
    sbom = enrich_epss_intelligence(sbom)
    payload = {
        "sbom": sbom,
        "metadata": {},
        "epss_intelligence_summary": epss_intelligence_summary(sbom),
        "kev_intelligence_summary": kev_intelligence_summary(sbom),
    }
    banner = main_module._apply_epss_kev_provenance_banner(payload)

    assert banner["live_feeds_wired"] is False
    assert banner["epss"] == STATIC_REFERENCE
    assert banner["kev"] == STATIC_REFERENCE
    assert "STATIC_REFERENCE" in banner["note"]


def test_17_cache_schema_mismatch_is_ignored_not_trusted(tmp_path):
    """A cache written by a future version must not be misread as current."""
    stale = _write_cache(
        tmp_path / "intel.json",
        _epss_entries({"CVE-2021-44228": 0.975}),
        schema=999,
    )
    feed = feeds.EPSSFeed(cache_path=stale, enabled=False)
    got = feed.scores_for(["CVE-2021-44228"])
    assert got == {}, "a schema we do not understand must be treated as empty"


# ---------------------------------------------------------------------------
# 6. A defect the benchmark found, pinned so it cannot come back
# ---------------------------------------------------------------------------

def test_18_seed_set_must_not_claim_cisa_lists_an_identifier_it_does_not():
    """Regression for a false CISA attribution found by the benchmark.

    ``analysis/benchmark_intel_feeds.py`` reconciled every compiled-in KEV
    entry against CISA's live catalog and reported one ``SEED_TABLE_INVENTION``:

    **CVE-2024-3094 (XZ Utils backdoor) was in both seed sets**, complete with
    an invented ``kev_added_date`` (2024-04-01) and ``due_date`` (2024-04-22)
    written in CISA's own field format — presenting a catalog row that does not
    exist as fact.

    Evidence it was never in KEV:
      * CISA's live catalog, version 2026.10.04 (1734 records), does not
        contain the identifier — confirmed by the benchmark's snapshot and by a
        second direct fetch of the feed document.
      * CISA published an *alert* on 2024-03-29 ("Reported Supply Chain
        Compromise Affecting XZ Utils Data Compression Library"), which is not
        a KEV entry.  KEV requires reliable evidence of in-the-wild
        exploitation, and none was observed for this backdoor.

    Withdrawing the attribution must not withdraw the risk signal: the CVE
    keeps its disclosure date (age), its CVSS and its EPSS score.
    """
    bogus = "CVE-2024-3094"

    assert bogus not in KEV_ENGINE_SEED_SET, (
        "seed table claims CISA KEV lists an identifier CISA does not publish"
    )
    assert bogus not in AGE_ENGINE_SEED_SET, (
        "seed table claims CISA KEV lists an identifier CISA does not publish"
    )

    # The risk signal itself must survive the correction.
    assert bogus in STATIC_CVE_DATES, "age signal must not be withdrawn"
    assert STATIC_CVE_DATES[bogus].startswith("2024-03-29")

    # And no entry anywhere may carry KEV-only fields for it.
    assert not any(
        bogus in str(key) for key in KEV_ENGINE_SEED_SET
    )

    # Offline behaviour agrees with what the live catalog returns.
    pkg = enrich_kev_intelligence([{"cve": bogus}])[0]
    assert pkg["kev_status"] is False
    assert pkg["kev_provenance"] == STATIC_REFERENCE


def test_19_rendered_note_never_contradicts_the_token_it_reports():
    """The banner header and the sentence beside it must agree, always.

    Found by running ``main.py`` end to end and reading the emitted
    ``metadata.epss_kev_provenance`` of the resulting report: the header read
    ``kev: NOT_AVAILABLE`` while the note immediately beside it asserted
    ``'STATIC_REFERENCE'``.  The KEV branch of ``intelligence_note`` lumped
    ``NOT_AVAILABLE`` in with ``STATIC_REFERENCE`` and hardcoded the label in
    prose, so the sentence was describing a different payload than the header.

    The invariant is stated structurally rather than by example, so it also
    covers any future pairing: the note must mention exactly the two tokens the
    banner reports, in field order, and no others.
    """
    tokens = (LIVE_FEED, STATIC_REFERENCE, NOT_AVAILABLE)

    for epss in tokens:
        for kev in tokens:
            note = intelligence_note(epss, kev)
            mentioned = re.findall(
                r"'(LIVE_FEED|STATIC_REFERENCE|NOT_AVAILABLE)'", note
            )
            assert mentioned == [epss, kev], (
                f"banner says epss={epss} kev={kev} but the note reads "
                f"{mentioned}: {note}"
            )

    # And the payload-level path must agree with the pair it derives.
    payload = {
        "metadata": {},
        "epss_intelligence_summary": {"provenance": NOT_AVAILABLE},
        "kev_intelligence_summary": {"provenance": STATIC_REFERENCE},
    }
    pair = provenance_pair(payload)
    assert pair == (NOT_AVAILABLE, STATIC_REFERENCE)
    derived = note_from_payload(payload)
    assert re.findall(
        r"'(LIVE_FEED|STATIC_REFERENCE|NOT_AVAILABLE)'", derived
    ) == list(pair), derived

    # A payload with no intelligence at all still falls back to the single
    # shared constant rather than inventing a sentence.
    assert note_from_payload({}) == STATIC_INTELLIGENCE_NOTE
    assert note_from_payload(None) == STATIC_INTELLIGENCE_NOTE
