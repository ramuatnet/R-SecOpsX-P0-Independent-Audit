"""G-003 — static EPSS/KEV must be labelled STATIC_REFERENCE until live.

Ground truth for this gap comes from ``reports/gap_register.json`` (G-003) and
``docs/enterprise_capability_matrix.md``, which both require that non-live
intelligence carry an explicit ``STATIC_REFERENCE`` label in reporting until
G-001 (live EPSS) and G-002 (live CISA KEV) are wired.

The defect being closed
-----------------------
Before G-003 the engines wrote ``epss_method`` / ``kev_method`` but **no
reporter ever read them**, and ``vulnerability_age_engine`` wrote
``kev_status`` / ``actively_exploited`` with no provenance field at all.  A
reader of the PDF, Excel, VEX or CycloneDX output saw ``EPSS 0.975`` and
``KEV No`` and could not tell those came from an eight-row offline table
compiled into the build rather than from FIRST.org / CISA.

What these tests pin down
-------------------------
1. Every EPSS/KEV value carries a provenance token.
2. ``kev_status False`` is still labelled ``STATIC_REFERENCE`` — the honesty
   core: an offline miss is not evidence of absence from the live catalog.
3. **Labelling changes no number, no bucket, no priority and no decision.**
4. Every human- and machine-facing report surface renders the label.
5. ``LIVE_FEED`` is **earned, never assumed**: with no feed supplied nothing
   may claim it (see below), and ``tests/test_v11_g001_g002_live_feeds.py``
   pins the converse — a feed lookup is the only thing that may.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from analysis.intelligence_provenance import (
    EPSS_PROVENANCE,
    KEV_PROVENANCE,
    LIVE_FEED,
    NOT_AVAILABLE,
    STATIC_INTELLIGENCE_NOTE,
    STATIC_REFERENCE,
)
from analysis.epss_intelligence_engine import (
    enrich_epss_intelligence,
    epss_intelligence_summary,
)
from analysis.kev_intelligence_engine import (
    enrich_kev_intelligence,
    kev_intelligence_summary,
)
from analysis.vulnerability_age_engine import (
    enrich_vulnerability_age,
    vulnerability_age_summary,
)

# ---------------------------------------------------------------------------
# Fixtures — authored from the offline tables themselves, not from scanner
# output, so the expectations below are independent of any enrichment run.
# ---------------------------------------------------------------------------

KEV_HIT = {
    "name": "log4j-core",
    "version": "2.14.1",
    "cve": "CVE-2021-44228",
    "severity": "Critical",
    "cvss": 10.0,
    "epss": 0.975,
    "reachability_status": "REACHABLE",
}

KEV_MISS = {
    "name": "lodash",
    "version": "4.17.20",
    "cve": "CVE-2021-23337",
    "severity": "High",
    "cvss": 7.5,
    "epss": 0.021,
    "reachability_status": "NOT_REACHABLE",
}

NO_SCORE = {
    "name": "mystery-lib",
    "version": "1.0.0",
    "cve": "CVE-1999-0001",
    "severity": "High",
    "cvss": 7.5,
    "epss": None,
    "reachability_status": "NOT_REACHABLE",
}


def _pipeline(*pkgs):
    """Run the three enrichers in the exact order main.py calls them."""
    sbom = [dict(p) for p in pkgs]
    sbom = enrich_kev_intelligence(sbom)     # main.py:2652
    sbom = enrich_vulnerability_age(sbom)    # main.py:2658
    sbom = enrich_epss_intelligence(sbom)    # main.py:2682
    return sbom


def _payload(*pkgs):
    sbom = _pipeline(*pkgs)
    return {
        "sbom": sbom,
        "metadata": {},
        "kev_intelligence_summary": kev_intelligence_summary(sbom),
        "epss_intelligence_summary": epss_intelligence_summary(sbom),
        "vulnerability_age_summary": vulnerability_age_summary(sbom),
    }


# ---------------------------------------------------------------------------
# 1. Token vocabulary
# ---------------------------------------------------------------------------

def test_01_canonical_tokens_are_the_documented_ones():
    assert STATIC_REFERENCE == "STATIC_REFERENCE"
    assert NOT_AVAILABLE == "NOT_AVAILABLE"
    # LIVE_FEED must exist so wiring G-001/G-002 is a data change, not a
    # schema change - and it may only ever be produced by an actual feed
    # lookup (see test_v11_g001_g002_live_feeds.py), never by default.
    assert LIVE_FEED == "LIVE_FEED"


def test_02_constants_resolve_to_static_reference():
    assert EPSS_PROVENANCE == STATIC_REFERENCE
    assert KEV_PROVENANCE == STATIC_REFERENCE


def test_03_nothing_claims_a_live_feed():
    """Negative control: with no feed supplied, nothing may assert LIVE_FEED.

    ``_pipeline`` deliberately calls the enrichers without a feed (that is the
    offline/air-gapped contract), so this is the same code path an operator
    with ``RSECOPSX_LIVE_FEEDS=0`` runs.  LIVE_FEED may only ever be produced
    by an actual catalog lookup, never inherited, defaulted or guessed —
    ``test_v11_g001_g002_live_feeds.py`` proves the converse.
    """
    sbom = _pipeline(KEV_HIT, KEV_MISS, NO_SCORE)
    for pkg in sbom:
        assert pkg.get("epss_provenance") != LIVE_FEED
        assert pkg.get("kev_provenance") != LIVE_FEED

    assert EPSS_PROVENANCE != LIVE_FEED
    assert KEV_PROVENANCE != LIVE_FEED
    assert LIVE_FEED not in json.dumps(
        {
            "epss_intelligence_summary": epss_intelligence_summary(sbom),
            "kev_intelligence_summary": kev_intelligence_summary(sbom),
            "vulnerability_age_summary": vulnerability_age_summary(sbom),
        }
    )


def test_04_note_explains_what_static_reference_means():
    assert "STATIC_REFERENCE" in STATIC_INTELLIGENCE_NOTE
    assert "FIRST.org" in STATIC_INTELLIGENCE_NOTE
    assert "CISA" in STATIC_INTELLIGENCE_NOTE
    # The sentence must state the KEV-False semantics explicitly, otherwise a
    # reader can still read "KEV No" as "confirmed not exploited".
    assert "not present in the offline table" in STATIC_INTELLIGENCE_NOTE


# ---------------------------------------------------------------------------
# 2. Per-record provenance at every write site
# ---------------------------------------------------------------------------

def test_05_epss_hit_is_labelled_and_scored():
    pkg = _pipeline(KEV_HIT)[0]
    assert pkg["epss_score"] == 0.975
    assert pkg["epss_provenance"] == STATIC_REFERENCE
    assert pkg["epss_method"] == "STATIC_OFFLINE_EPSS_V1"


def test_06_epss_miss_is_labelled_not_available():
    pkg = _pipeline(NO_SCORE)[0]
    assert pkg["epss_score"] is None
    # Absence has its own token - it is not silently promoted to a static value.
    assert pkg["epss_provenance"] == NOT_AVAILABLE
    assert pkg["epss_provenance"] != STATIC_REFERENCE
    assert pkg["epss_bucket"] == "UNKNOWN"
    assert pkg["epss_method"] == "EPSS_NOT_AVAILABLE"


def test_07_kev_hit_carries_provenance():
    pkg = _pipeline(KEV_HIT)[0]
    assert pkg["kev_status"] is True
    assert pkg["actively_exploited"] is True
    assert pkg["kev_provenance"] == STATIC_REFERENCE


def test_08_kev_miss_is_still_labelled_static_reference():
    """The honesty core of G-003.

    ``kev_status False`` means "absent from the offline seed table", not
    "absent from the live CISA KEV catalog".  Both branches must therefore
    carry STATIC_REFERENCE, and the False branch must never be left bare.
    """
    pkg = _pipeline(KEV_MISS)[0]
    assert pkg["kev_status"] is False
    assert pkg["kev_provenance"] == STATIC_REFERENCE
    assert pkg["kev_method"] == "NO_KEV_MATCH"


def test_09_vulnerability_age_write_sites_are_labelled():
    """vulnerability_age_engine rewrites kev_status from its own offline set.

    Both of its write sites must carry provenance, otherwise the age pass
    silently strips the label the KEV pass just wrote.
    """
    for seed in (KEV_HIT, KEV_MISS):
        enriched = enrich_vulnerability_age([dict(seed)])
        assert enriched[0]["kev_provenance"] == STATIC_REFERENCE
        assert "kev_status" in enriched[0]

    # ------------------------------------------------------------------
    # RESTATED at G-001/G-002 — deliberately not weakened.
    #
    # The original guard counted literal ``= KEV_PROVENANCE`` writes because
    # until the live feeds were wired there was exactly one correct label.
    # Both sites now assign a derived variable, because a site that has
    # already seen a live CISA answer has to be able to say LIVE_FEED —
    # hard-coding KEV_PROVENANCE there would be the very defect this guard
    # exists to catch (the age pass downgrading a live answer to offline).
    #
    # So the guard now asserts what it always meant to: **no write site may
    # bypass the provenance vocabulary.**  That is strictly broader than the
    # old literal count — it also rejects ``= None``, ``= x or y`` and
    # ``= item.get(...)``, which the old string count would have sailed past
    # as long as two other sites still matched.
    # ------------------------------------------------------------------
    src = (
        Path(__file__).resolve().parents[1]
        / "analysis" / "vulnerability_age_engine.py"
    ).read_text(encoding="utf-8")

    tokens = {"KEV_PROVENANCE", "LIVE_FEED", "STATIC_REFERENCE", "NOT_AVAILABLE"}
    ident = r"[A-Za-z_][A-Za-z0-9_]*"

    sites = [
        rhs.split("#")[0].strip()
        for rhs in re.findall(
            r'item\["kev_provenance"\]\s*=\s*([^\n]+)', src
        )
    ]
    assert len(sites) >= 2, (
        f"expected two distinct write sites, found {len(sites)}: {sites}"
    )

    for rhs in sites:
        assert re.fullmatch(ident, rhs), (
            f"write site bypasses the provenance vocabulary with a compound "
            f"expression: {rhs!r}"
        )
        if rhs in tokens:
            continue
        # Resolve the identifier the site assigns from.  Every assignment to
        # it in this module must itself be a canonical token, a conditional
        # over canonical tokens, or a laundering call into the vocabulary.
        assigned = [
            v.strip()
            for v in re.findall(rf"(?m)^\s*{rhs}\s*=\s*([^\n#]+)", src)
        ]
        assert assigned, f"{rhs!r} is never assigned in this module"
        for value in assigned:
            if value.startswith("known_provenance("):
                assert value.endswith(")"), f"malformed laundering call: {value!r}"
                continue
            branches = [value.split(" if ")[0].strip()]
            if " else " in value:
                branches.append(value.rsplit(" else ", 1)[-1].strip())
            for branch in branches:
                assert branch in tokens, (
                    f"write-site variable {rhs!r} is fed {value!r}; branch "
                    f"{branch!r} is not a provenance token"
                )

    # And the specific hazard this test is named for: a live answer reached
    # this engine, the local 7-CVE set must not overwrite or relabel it.
    live_pkg = dict(KEV_MISS)          # CVE-2021-23337 is not in the local set
    live_pkg["kev_status"] = True
    live_pkg["kev_provenance"] = LIVE_FEED
    live_pkg["normalized_cve"] = KEV_MISS["cve"]
    aged = enrich_vulnerability_age([live_pkg])[0]
    assert aged["kev_status"] is True, "local 7-CVE set overturned a live answer"
    assert aged["kev_provenance"] == LIVE_FEED, "local pass downgraded a live answer"

    # Same for an offline yes: the two sets disagree on coverage, not on
    # truth, so this pass may supply a hit but may never refute one.
    static_true = dict(KEV_MISS)
    static_true["kev_status"] = True
    static_true["kev_provenance"] = STATIC_REFERENCE
    static_true["normalized_cve"] = KEV_MISS["cve"]
    aged_static = enrich_vulnerability_age([static_true])[0]
    assert aged_static["kev_status"] is True, "local set refuted an offline yes"
    assert aged_static["kev_provenance"] == STATIC_REFERENCE


def test_10_summaries_publish_provenance():
    sbom = _pipeline(KEV_HIT, KEV_MISS, NO_SCORE)

    epss = epss_intelligence_summary(sbom)
    assert epss["provenance"] == STATIC_REFERENCE
    assert epss["summary_status"] == "STATIC_OFFLINE_EPSS_INTELLIGENCE_V1"

    kev = kev_intelligence_summary(sbom)
    assert kev["provenance"] == STATIC_REFERENCE
    assert kev["summary_status"] == "STATIC_OFFLINE_CISA_KEV_V1"

    age = vulnerability_age_summary(sbom)
    assert age["kev_provenance"] == STATIC_REFERENCE
    assert age["kev_packages"] == 1


# ---------------------------------------------------------------------------
# 3. Labelling must not change a single decision
# ---------------------------------------------------------------------------

def test_11_epss_values_and_decisions_are_unchanged():
    """Provenance is an honesty label, not a scoring input."""
    pkgs = {p["name"]: p for p in _pipeline(KEV_HIT, KEV_MISS, NO_SCORE)}

    hit = pkgs["log4j-core"]
    assert hit["epss_score"] == 0.975
    assert hit["epss_bucket"] == "VERY_HIGH_EXPLOIT_PROBABILITY"
    # kev_status True and reachability REACHABLE -> P0.
    assert hit["epss_priority"] == "P0_IMMEDIATE"

    miss = pkgs["lodash"]
    assert miss["epss_score"] == 0.021
    assert miss["epss_bucket"] == "LOW_EXPLOIT_PROBABILITY"
    assert miss["epss_priority"] == "P3_STANDARD"

    unknown = pkgs["mystery-lib"]
    assert unknown["epss_bucket"] == "UNKNOWN"
    assert unknown["epss_priority"] == "P3_STANDARD"


def test_12_kev_decisions_are_unchanged():
    pkgs = {p["name"]: p for p in _pipeline(KEV_HIT, KEV_MISS)}

    assert pkgs["log4j-core"]["kev_priority"] == "P0_REACHABLE_KEV"
    assert pkgs["lodash"]["kev_priority"] == "NO_KEV_SIGNAL"

    # Outbreak / urgency decisions still keyed purely on the boolean.
    assert pkgs["log4j-core"]["outbreak_status"] not in (None, "")
    assert pkgs["lodash"]["actively_exploited"] is False


def test_13_provenance_does_not_convert_unknown_into_reachable():
    """A protected invariant: provenance must never gate reachability."""
    pkg = _pipeline(NO_SCORE)[0]
    assert pkg["epss_provenance"] == NOT_AVAILABLE
    assert pkg.get("reachability_status") == "NOT_REACHABLE"
    assert pkg.get("reachable") is not True
    assert pkg["kev_status"] is False


def test_14_summary_counts_unchanged_by_labelling():
    sbom = _pipeline(KEV_HIT, KEV_MISS, NO_SCORE)
    epss = epss_intelligence_summary(sbom)
    assert epss["total_vulnerable_packages"] == 3
    assert epss["known_epss_packages"] == 2
    assert epss["p0_immediate_packages"] == 1

    kev = kev_intelligence_summary(sbom)
    assert kev["kev_packages"] == 1
    assert kev["reachable_kev_packages"] == 1


# ---------------------------------------------------------------------------
# 4. Payload-level banner
# ---------------------------------------------------------------------------

def test_15_payload_banner_is_written_and_says_not_live():
    import main as main_module

    payload = _payload(KEV_HIT, KEV_MISS, NO_SCORE)
    banner = main_module._apply_epss_kev_provenance_banner(payload)

    written = payload["metadata"]["epss_kev_provenance"]
    assert written == banner
    assert written["epss"] == STATIC_REFERENCE
    assert written["kev"] == STATIC_REFERENCE
    assert written["live_feeds_wired"] is False
    assert "STATIC_REFERENCE" in written["note"]


def test_16_payload_banner_defaults_when_summaries_absent():
    import main as main_module

    payload = {"sbom": []}
    banner = main_module._apply_epss_kev_provenance_banner(payload)
    # Missing summaries must fall back to the honest static default rather
    # than to an empty/None value that reads as "unknown provenance".
    assert banner["epss"] == STATIC_REFERENCE
    assert banner["kev"] == STATIC_REFERENCE
    assert banner["live_feeds_wired"] is False


def test_17_banner_is_a_label_only():
    import main as main_module

    payload = _payload(KEV_HIT, KEV_MISS, NO_SCORE)
    before = json.dumps(payload["sbom"], sort_keys=True, default=str)
    main_module._apply_epss_kev_provenance_banner(payload)
    after = json.dumps(payload["sbom"], sort_keys=True, default=str)
    assert before == after


# ---------------------------------------------------------------------------
# 5. Report surfaces must render the label
# ---------------------------------------------------------------------------

def _story_text(story) -> str:
    chunks = []

    def _walk(flowable):
        text = getattr(flowable, "text", None)
        if isinstance(text, str):
            chunks.append(text)
            return
        cells = getattr(flowable, "_cellvalues", None)
        if cells:  # reportlab Table - the EPSS column lives here
            for row in cells:
                for cell in row:
                    if isinstance(cell, str):
                        chunks.append(cell)
                    elif hasattr(cell, "_cellvalues"):
                        _walk(cell)
                    else:
                        inner = getattr(cell, "text", None)
                        if isinstance(inner, str):
                            chunks.append(inner)
            return
        if hasattr(flowable, "getPlainText"):
            try:
                chunks.append(flowable.getPlainText())
            except Exception:  # pragma: no cover - defensive
                pass

    for flowable in story:
        _walk(flowable)
    return "\n".join(chunks)


def test_18_pdf_sbom_section_renders_the_label():
    from reporting.pdf_report import _sbom_section

    story = _sbom_section(_payload(KEV_HIT, KEV_MISS))
    text = _story_text(story)
    assert "STATIC_REFERENCE" in text
    assert "FIRST.org" in text


def test_19_pdf_label_is_a_footnote_not_a_value_rewrite():
    """The EPSS column must still show the raw score next to the label."""
    from reporting.pdf_report import _sbom_section

    text = _story_text(_sbom_section(_payload(KEV_HIT, KEV_MISS)))
    assert "0.975" in text


def _excel_text(ws) -> str:
    return "\n".join(
        str(cell.value)
        for row in ws.iter_rows()
        for cell in row
        if cell.value is not None
    )


def test_20_excel_sbom_sheet_carries_the_label():
    from openpyxl import Workbook

    from reporting.excel_report import _sbom

    wb = Workbook()
    _sbom(wb.active, _payload(KEV_HIT, KEV_MISS))
    text = _excel_text(wb.active)
    assert "STATIC_REFERENCE" in text
    assert "0.975" in text


def test_21_excel_sca_findings_sheet_carries_the_label():
    from openpyxl import Workbook

    from reporting.excel_report import _sca_findings

    wb = Workbook()
    _sca_findings(wb.active, _payload(KEV_HIT, KEV_MISS))
    assert "STATIC_REFERENCE" in _excel_text(wb.active)


def test_22_excel_exploitable_cves_sheet_carries_the_label():
    from openpyxl import Workbook

    from reporting.excel_report import _exploitable_cves

    wb = Workbook()
    _exploitable_cves(wb.active, _payload(KEV_HIT, KEV_MISS))
    text = _excel_text(wb.active)
    assert "STATIC_REFERENCE" in text
    # The sheet that asserts "CISA KEV" as a reason must show the label too.
    assert "CISA KEV" in text


def test_23_excel_exploitable_cves_empty_path_still_labelled():
    """Empty path says "no KEV/EPSS" - an offline miss, so it must be labelled."""
    from openpyxl import Workbook

    from reporting.excel_report import _exploitable_cves

    wb = Workbook()
    _exploitable_cves(wb.active, {"sbom": [], "metadata": {}})
    assert "STATIC_REFERENCE" in _excel_text(wb.active)


def test_24_vex_properties_carry_provenance():
    from reporting.vex_export import build_vex

    vex = build_vex(_payload(KEV_HIT, KEV_MISS, NO_SCORE))
    statements = vex["statements"]
    assert statements, "expected at least one VEX statement"

    by_id = {s["vulnerability"]["id"]: s for s in statements}

    hit = by_id["CVE-2021-44228"]["properties"]
    assert hit["kev_status"] is True
    assert hit["kev_provenance"] == STATIC_REFERENCE
    assert hit["epss_provenance"] == STATIC_REFERENCE

    miss = by_id["CVE-2021-23337"]["properties"]
    assert miss["kev_status"] is False
    # False + STATIC_REFERENCE is the pairing that stops a reader treating the
    # offline miss as a live-catalog assertion.
    assert miss["kev_provenance"] == STATIC_REFERENCE

    unknown = by_id["CVE-1999-0001"]["properties"]
    assert unknown["epss_provenance"] == NOT_AVAILABLE
    assert unknown["kev_provenance"] == STATIC_REFERENCE


def test_25_cyclonedx_vulnerability_properties_carry_provenance():
    from reporting.cyclonedx_export import _vulnerability

    payload = _payload(KEV_HIT, KEV_MISS, NO_SCORE)
    props = {}
    for pkg in payload["sbom"]:
        vuln = _vulnerability(pkg)
        assert vuln is not None
        names = {p["name"]: p["value"] for p in vuln["properties"]}
        props[names["rsecopsx:cve"]] = names

    assert props["CVE-2021-44228"]["rsecopsx:kev_status"] == "True"
    assert props["CVE-2021-44228"]["rsecopsx:kev_provenance"] == STATIC_REFERENCE
    assert props["CVE-2021-44228"]["rsecopsx:epss_provenance"] == STATIC_REFERENCE

    assert props["CVE-2021-23337"]["rsecopsx:kev_status"] == "False"
    assert props["CVE-2021-23337"]["rsecopsx:kev_provenance"] == STATIC_REFERENCE

    assert props["CVE-1999-0001"]["rsecopsx:epss_provenance"] == NOT_AVAILABLE


def test_26_cyclonedx_summary_properties_publish_provenance():
    from reporting.cyclonedx_export import _summary_properties

    payload = _payload(KEV_HIT, KEV_MISS, NO_SCORE)
    values = {
        p["name"]: json.loads(p["value"])
        for p in _summary_properties(payload)
        if p["name"] in {
            "rsecopsx:epss_intelligence_summary",
            "rsecopsx:kev_intelligence_summary",
        }
    }
    assert values["rsecopsx:epss_intelligence_summary"]["provenance"] == STATIC_REFERENCE
    assert values["rsecopsx:kev_intelligence_summary"]["provenance"] == STATIC_REFERENCE


# ---------------------------------------------------------------------------
# 6. No report surface may print an EPSS/KEV number without the label
# ---------------------------------------------------------------------------

def test_27_every_epss_rendering_module_uses_the_shared_note():
    """Drift control: the PDF and Excel wording must come from one source.

    RESTATED at G-001/G-002 — deliberately strengthened, not weakened.

    The original checked for the literal constant name, because until the
    feeds were wired the note *was* a constant.  It is now derived per payload
    (a workbook full of LIVE_FEED scores may not be captioned "not from the
    live feed"), so checking for the old name would only prove the renderers
    had stopped captioning their tables at all.  The invariant this test
    protects is sharper: **neither renderer may own a single word of the
    honesty sentence, and both must reach the one shared builder.**
    """
    root = Path(__file__).resolve().parents[1]
    # Prose fragments that must exist in exactly one module in the repository.
    # Compared on a letters/digits/spaces normalisation so that a sentence
    # broken across adjacent string literals — including the quote characters
    # that sit between them in the *source* — is still recognised as present.
    def norm(text: str) -> str:
        return " ".join(re.sub(r"[^A-Za-z0-9]+", " ", text).split())

    owned_by_shared_module = (
        "not present in the offline table",
        "confirmed not exploited",
        "live CISA Known Exploited Vulnerabilities catalog",
    )

    for rel in ("reporting/pdf_report.py", "reporting/excel_report.py"):
        raw = (root / rel).read_text(encoding="utf-8")
        assert "note_from_payload" in raw, f"{rel} must render the shared note"
        assert "provenance_pair" in raw, (
            f"{rel} must derive its provenance header from the shared module"
        )
        assert "from analysis.intelligence_provenance import" in raw, (
            f"{rel} must take its provenance vocabulary from the shared module"
        )
        src = norm(raw)
        for fragment in owned_by_shared_module:
            assert fragment not in src, (
                f"{rel} hand-rolled a copy of the shared honesty wording: "
                f"{fragment!r}"
            )

    # ...and the sentences really do live in that one module.
    shared = norm(
        (root / "analysis" / "intelligence_provenance.py").read_text(encoding="utf-8")
    )
    for fragment in owned_by_shared_module:
        assert fragment in shared, f"shared module lost {fragment!r}"


def test_28_label_reaches_the_emitted_pdf(tmp_path):
    """End-to-end: the label must survive layout and land in the shipped PDF.

    Story-level checks (test_18) prove the flowable exists; this proves
    ``generate_pdf_report`` does not drop or truncate it on the way to disk.
    """
    pypdf = pytest.importorskip("pypdf")

    from reporting.pdf_report import generate_pdf_report

    output = tmp_path / "g003.pdf"
    generate_pdf_report(_payload(KEV_HIT, KEV_MISS), str(output))

    assert output.exists() and output.stat().st_size > 0

    text = "\n".join(
        (page.extract_text() or "") for page in pypdf.PdfReader(str(output)).pages
    )
    assert "STATIC_REFERENCE" in text
    assert "FIRST.org" in text
    # The label must accompany the raw score, not replace it.
    assert "0.975" in text


def test_29_dependency_payload_views_carry_provenance():
    """JSON-only payload views have no renderer in front of them.

    ``_build_dependency_reporting_views`` publishes ``dependency_risk_register``,
    ``top_dependency_risks``, ``top_cves``, ``reachable_vulnerable_packages`` and
    ``not_observed_vulnerable_packages``.  A consumer reading any of those arrays
    directly must still be able to tell static from live.
    """
    import main as main_module

    payload = _payload(KEV_HIT, KEV_MISS, NO_SCORE)
    payload["sbom"][1]["reachability_priority"] = "REACHABLE_VULNERABLE"
    payload["sbom"][2]["reachability_priority"] = "NOT_OBSERVED_VULNERABLE"
    main_module._build_dependency_reporting_views(payload)

    keys = (
        "dependency_risk_register",
        "top_dependency_risks",
        "top_cves",
        "reachable_vulnerable_packages",
        "not_observed_vulnerable_packages",
    )
    for key in keys:
        rows = payload.get(key)
        assert isinstance(rows, list), key
        for row in rows:
            assert row.get("kev_status") in (True, False), (key, row)
            assert row.get("kev_provenance") == STATIC_REFERENCE, key
            if row.get("epss_score") is not None:
                assert row.get("epss_provenance") == STATIC_REFERENCE, key
            else:
                assert row.get("epss_provenance") == NOT_AVAILABLE, key

    # The register is ranked by KEV, so the labelled KEV hit must lead it.
    register = payload["dependency_risk_register"]
    assert register[0]["cve"] == "CVE-2021-44228"
    assert register[0]["kev_provenance"] == STATIC_REFERENCE


def test_30_cvss_from_the_compiled_in_advisory_table_is_labelled():
    """G-057: ``scanner/sbom.py::KNOWN_VULNS`` is a compiled-in snapshot.

    It supplies ``cvss`` and ``severity`` beside an ``epss`` that already
    carries ``epss_provenance``, so the CVSS literal was the one number from
    that table reaching the report with no way to tell it from a live NVD
    score.  Labelling it must change no value.
    """
    from scanner.sbom import KNOWN_VULNS, enrich_with_cve

    db_key = "flask" if "flask" in KNOWN_VULNS else next(iter(KNOWN_VULNS))
    probe_ver = "1.0.0"
    if not [v for v in KNOWN_VULNS[db_key] if v["affected"](probe_ver)]:
        pytest.skip("compiled-in table no longer matches the probe version")

    out = enrich_with_cve([{"name": db_key, "version": probe_ver}])
    hit = out[0]

    assert hit.get("cvss") is not None, "probe did not resolve a CVSS"
    assert hit.get("cvss_provenance") == STATIC_REFERENCE
    assert hit.get("cvss_method") == "STATIC_OFFLINE_CVSS_V1"

    # Labelling changes no number (contract item 3 above).
    worst = max((v for v in KNOWN_VULNS[db_key] if v["affected"](probe_ver)),
                key=lambda x: x["cvss"])
    assert hit["cvss"] == worst["cvss"]
    assert hit["severity"] == worst["severity"]
    assert hit["epss"] == worst.get("epss")


def test_31_absent_cvss_provenance_never_claims_a_source():
    """A package the table does not know must not inherit STATIC_REFERENCE.

    Unlabelled degrades to ``NOT_AVAILABLE`` through ``known_provenance`` --
    relabelling an unknown as offline would itself be a false claim.
    """
    from analysis.intelligence_provenance import known_provenance
    from scanner.sbom import enrich_with_cve

    out = enrich_with_cve([{"name": "rsecopsx-no-such-package-xyz", "version": "9.9.9"}])
    assert out[0].get("cvss_provenance") is None
    assert known_provenance(out[0].get("cvss_provenance")) == NOT_AVAILABLE
    assert known_provenance(out[0].get("cvss_provenance")) != STATIC_REFERENCE


def test_32_sbom_uses_the_shared_provenance_vocabulary_not_a_literal():
    """The token must come from the closed set's single definition."""
    raw = (Path(__file__).resolve().parents[1] / "scanner" / "sbom.py").read_text(
        encoding="utf-8")
    assert "from analysis.intelligence_provenance import" in raw
    assert '"STATIC_REFERENCE"' not in raw, "token must not be redefined here"
