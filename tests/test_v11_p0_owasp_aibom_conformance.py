"""P0 regression contract: OWASP edition conformance, CycloneDX BOM export,
cross-BOM wiring, and contract-only detection labelling.

Every assertion here pins a defect that was measured in the OWASP GenAI
Crosswalk / LLM Top 10 / AI-BOM assessment:

  P0-1  reporting/cyclonedx_export.py read AI-BOM/ML-BOM/API-BOM from keys
        no producer writes, so those components silently never exported.
  P0-2  scanner/aibom_abom_correlation.correlate() was built, tested and
        never invoked (WIRING_GAP, G-004).
  P0-3  scanner/llm_security.py OWASP labels carried 2023 numbering under a
        ":2025" stamp -- 7 of 10 named an ID whose 2025 title is a different
        risk.
  P0-4  core/owasp_mappings.OWASP_LLM held exactly one entry, so
        map_technique() returned UNMAPPED for every other AI rule.
  P0-5  filename-contract findings were indistinguishable from content
        detections, and FILENAME_RULE_MAP declared 11 basenames twice.
"""
from __future__ import annotations

import re
import sys

import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.owasp_mappings import (
    OWASP_ASI,
    OWASP_LLM,
    OWASP_LLM_ENTRY_BY_VULN_TYPE,
    OWASP_LLM_TOP10_2023_RETIRED,
    OWASP_LLM_TOP10_2025,
    OWASP_LLM_TOP10_2026,
    map_technique,
    owasp_llm_reference,
)
from reporting.cyclonedx_export import (
    BOM_ASSET_SOURCES,
    _bom_asset_components,
)
from scanner import advanced_ai_security as aas
from scanner import llm_security as ls

PRIMARY = "2025"
FORWARD = "2026"


# ---------------------------------------------------------------------------
# P0-4 -- catalogue completeness and fail-closed mapping
# ---------------------------------------------------------------------------

def test_01_catalogue_covers_every_ai_vulnerability_type():
    catalogued = {k for k in OWASP_LLM if k != "PROMPT_INJECTION"}
    assert catalogued == {k.upper() for k in OWASP_LLM_ENTRY_BY_VULN_TYPE}


def test_02_every_cited_entry_id_exists_in_its_edition():
    for vuln_type, (id_2025, id_2026) in OWASP_LLM_ENTRY_BY_VULN_TYPE.items():
        if id_2025:
            assert id_2025 in OWASP_LLM_TOP10_2025, (vuln_type, id_2025)
        if id_2026:
            assert id_2026 in OWASP_LLM_TOP10_2026, (vuln_type, id_2026)


def test_03_every_label_is_internally_consistent():
    """No label may pair an ID with another risk's title."""
    pattern = re.compile(r"(LLM\d\d):(\d{4}) - (.+)")
    for vuln_type in OWASP_LLM_ENTRY_BY_VULN_TYPE:
        ref = owasp_llm_reference(vuln_type)
        if ref["owasp_edition"] == PRIMARY:
            match = pattern.fullmatch(ref["owasp"])
            assert match, (vuln_type, ref["owasp"])
            entry_id, edition, title = match.groups()
            assert edition == PRIMARY, (vuln_type, ref["owasp"])
            assert OWASP_LLM_TOP10_2025[entry_id] == title, (vuln_type, ref["owasp"])
            assert ref["owasp_id"] == entry_id, (vuln_type, ref)
        if ref["owasp_llm_top10_2026"]:
            match = pattern.fullmatch(ref["owasp_llm_top10_2026"])
            assert match, (vuln_type, ref["owasp_llm_top10_2026"])
            entry_id, edition, title = match.groups()
            assert edition == FORWARD, (vuln_type, ref["owasp_llm_top10_2026"])
            assert OWASP_LLM_TOP10_2026[entry_id] == title, (
                vuln_type,
                ref["owasp_llm_top10_2026"],
            )
            assert ref["owasp_id_2026"] == entry_id, (vuln_type, ref)


def test_04_the_reported_invalid_labels_are_gone():
    """The 10 label defects named in the assessment must not be re-emittable."""
    forbidden = {
        "LLM02:2025 - Sensitive Information Disclosure / Insecure Output Handling",
        "LLM03:2025 - Supply Chain / Data and Model Poisoning",
        "LLM04:2025 - Model Denial of Service",
        "LLM05:2025 - Supply Chain Vulnerabilities",
        "LLM07:2025 - Insecure Plugin / Tool Design",
        "LLM09:2025 - Overreliance",
        "LLM10:2025 - Model Theft",
        "LLM06/LLM07:2025 - Excessive Agency / Insecure Tool Use",
        "LLM01/LLM05:2025 - Prompt Injection / Supply Chain Risk",
    }
    emitted = set()
    for rule in ls.LLM_RULES:
        ref = ls._owasp_llm_reference(rule["rule_id"], rule["vuln_type"])
        emitted.add(ref["owasp"])
        emitted.add(ref["owasp_llm_top10_2026"])
    assert not (emitted & forbidden), sorted(emitted & forbidden)


def test_05_retired_2023_subjects_are_marked_not_repointed():
    for vuln_type in ("llm_insecure_plugin", "llm_model_theft"):
        ref = owasp_llm_reference(vuln_type)
        assert ref["owasp_edition"] == "2023", (vuln_type, ref)
        assert ref["owasp_llm_enumerated"] is False, (vuln_type, ref)
        assert ref["owasp_llm_top10_2026"] == "", (vuln_type, ref)
        assert ref["owasp_id"] in OWASP_LLM_TOP10_2023_RETIRED, (vuln_type, ref)


def test_06_governance_gaps_never_borrow_a_live_risk_id():
    for vuln_type in (
        "model_governance_missing_owner",
        "model_governance_missing_model_card",
        "model_governance_incomplete",
        "model_approval_missing",
        "ai_policy_compliance_missing",
    ):
        ref = owasp_llm_reference(vuln_type)
        assert ref["owasp_id"] == "", (vuln_type, ref)
        assert ref["owasp_llm_enumerated"] is False, (vuln_type, ref)


def test_07_pinned_map_technique_contract_still_holds():
    assert map_technique("PROMPT_INJECTION")["namespace"] == "LLM01:2025"
    assert map_technique("TOOL_POISONING", misuse=True)["owasp"] == ["ASI02"]
    assert map_technique("TOOL_POISONING", supply_chain=True)["owasp"] == ["ASI04"]
    assert set(
        map_technique("TOOL_POISONING", misuse=True, supply_chain=True)["owasp"]
    ) == {"ASI02", "ASI04"}
    assert map_technique("UNKNOWN")["owasp"] == []
    assert map_technique("MCP_TOOL_POISONING", misuse=True)["owasp"] == ["ASI02"]
    assert map_technique("ASI01")["owasp"] == ["ASI01"]
    assert map_technique("ASI01")["mapping_mode"] == "DIRECT"


def test_08_map_technique_resolves_every_ai_rule():
    for rule in ls.LLM_RULES:
        result = map_technique(rule["vuln_type"].upper())
        assert result["mapping_mode"] != "UNMAPPED", (rule["rule_id"], result)
        if result["mapping_mode"] == "DIRECT":
            assert result["owasp"], (rule["rule_id"], result)
        else:
            # NOT_ENUMERATED / RETIRED_2023 must not claim a live risk id
            assert result["mapping_mode"] in {"NOT_ENUMERATED", "RETIRED_2023"}, (
                rule["rule_id"],
                result,
            )


def test_09_map_technique_resolves_raw_rule_ids_by_name_not_number():
    """V11's own sequence number must not be read as an OWASP entry number."""
    supply = map_technique("LLM05_SUPPLY_CHAIN_VULNERABILITY")
    assert supply["namespace"] == "LLM03:2025", supply
    assert supply["namespace_2026"] == "LLM04:2026", supply

    output = map_technique("LLM02_INSECURE_OUTPUT_HANDLING")
    assert output["namespace"] == "LLM05:2025", output
    assert output["namespace_2026"] == "LLM10:2026", output


def test_10_unknown_technique_still_fails_closed():
    assert map_technique("")["mapping_mode"] == "UNMAPPED"
    assert map_technique("")["owasp"] == []
    assert map_technique("SOMETHING_INVENTED")["mapping_mode"] == "UNMAPPED"


def test_11_all_ai_rules_reach_a_mapping_through_v11_intelligence_key():
    """The technique key v11_intelligence feeds is the catalogue's own key."""
    import core.v11_intelligence as v11

    source = (PROJECT_ROOT / "core" / "v11_intelligence.py").read_text(
        encoding="utf-8"
    )
    assert 'finding.get("vuln_type")' in source
    assert 'finding.get("rule")' in source


def test_12_edition_catalogues_match_their_sources():
    """Spot-check the two primary sources so a transcription slip is caught."""
    assert OWASP_LLM_TOP10_2025["LLM03"] == "Supply Chain"
    assert OWASP_LLM_TOP10_2025["LLM05"] == "Improper Output Handling"
    assert OWASP_LLM_TOP10_2025["LLM07"] == "System Prompt Leakage"
    assert OWASP_LLM_TOP10_2025["LLM10"] == "Unbounded Consumption"
    assert OWASP_LLM_TOP10_2026["LLM03"] == "Excessive Agency"
    assert OWASP_LLM_TOP10_2026["LLM08"] == "Hidden Context Exposure"
    assert OWASP_LLM_TOP10_2026["LLM10"] == "Improper Output Handling"
    assert set(OWASP_LLM_TOP10_2025) == set(OWASP_LLM_TOP10_2026)


def test_13_asi_catalogue_unchanged():
    assert set(OWASP_ASI) == {f"ASI{i:02d}" for i in range(1, 11)}
    assert OWASP_ASI["ASI02"]["title"] == "Tool Misuse and Exploitation"


# ---------------------------------------------------------------------------
# P0-1 -- CycloneDX must export every BOM main.py writes
# ---------------------------------------------------------------------------

def _bom_names(payload):
    return [
        (
            next(
                p["value"]
                for p in c["properties"]
                if p["name"] == "rsecopsx:bom_type"
            )
        )
        for c in _bom_asset_components(payload)
    ]


def test_14_cyclonedx_exports_ai_bom_ml_bom_and_api_bom():
    payload = {
        "aibom": [{"model_id": "m-1", "name": "gpt-x"}],
        "mlbom": [{"name": "ranker"}],
        "apibom": [{"endpoint": "/v1/chat"}],
        "abom": [{"component": "Agent"}],
        "cbom": [{"name": "aes"}],
    }
    types = _bom_names(payload)
    assert "aibom" in types, types
    assert "mlbom" in types, types
    assert "apibom" in types, types
    assert "abom" in types, types
    assert "cbom" in types, types
    # the underscore spellings are no longer the only accepted key
    assert "ai_bom" not in types and "ml_bom" not in types and "api_bom" not in types


def test_15_cyclonedx_still_honours_underscore_legacy_keys():
    payload = {"ai_bom": [{"name": "gpt-x"}], "ml_bom": [{"name": "r"}], "api_bom": [{"endpoint": "/x"}]}
    types = _bom_names(payload)
    assert set(types) == {"aibom", "mlbom", "apibom"}, types


def test_16_cyclonedx_does_not_duplicate_when_both_spellings_exist():
    payload = {
        "aibom": [{"name": "canonical"}],
        "ai_bom": [{"name": "legacy"}],
    }
    names = [
        c["name"] for c in _bom_asset_components(payload)
    ]
    assert names == ["canonical"], names


def test_17_cyclonedx_empty_payload_yields_no_components():
    assert _bom_asset_components({}) == []
    assert _bom_asset_components({"aibom": [], "abom": []}) == []


def test_18_bom_asset_sources_cover_every_bom_main_writes():
    main_source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
    written = set(re.findall(r'payload\["(cbom|aibom|mlbom|apibom|abom)"\]\s*=', main_source))
    assert written == {"cbom", "aibom", "mlbom", "apibom", "abom"}, written
    assert {row[0] for row in BOM_ASSET_SOURCES} == written


def test_19_cyclonedx_bom_ref_is_unique_per_component():
    payload = {"aibom": [{"name": "a"}, {"name": "a"}]}
    refs = [c["bom-ref"] for c in _bom_asset_components(payload)]
    assert len(refs) == len(set(refs)), refs


# ---------------------------------------------------------------------------
# P0-2 -- correlate() must actually run during a scan
# ---------------------------------------------------------------------------

def test_20_main_imports_correlate():
    source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
    assert "from scanner.aibom_abom_correlation import correlate" in source
    assert "correlate_aibom_abom(" in source


def test_21_main_publishes_bom_correlation_output():
    source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
    assert 'payload["bom_correlation"] = ' in source
    assert 'payload["bom_correlation_summary"] = {' in source
    for token in ("relationships", "by_relationship_type", "abom_items", "aibom_items", "status"):
        assert f'"{token}"' in source, token


def test_22_correlation_fails_open_and_records_the_degradation():
    """An engine failure must be recorded, never read as 'no relationships'."""
    source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
    assert "_bom_corr_status = \"DEGRADED\"" in source
    assert 'payload.get("abom", [])' in source
    assert 'payload.get("aibom", [])' in source


def test_23_correlate_emits_only_identity_gated_edges():
    from scanner.aibom_abom_correlation import REL_PROVIDED_BY, REL_USES, correlate

    agent = {"component_id": "ABOM-1", "component": "Agent", "model_id": "GPT-5"}
    other = {"model_id": "CLAUDE-X", "model_name": "claude-x"}
    provider = {"provider_id": "p-1", "provider_name": "OpenAI"}
    model = {"model_id": "GPT-5", "model_name": "gpt-5", "provider_id": "p-1"}

    rels = correlate(abom=[agent], aibom=[model, other, provider])
    kinds = {(r["relationship_type"], r["source_id"], r["target_id"]) for r in rels}
    assert (REL_USES, "ABOM-1", "GPT-5") in kinds, kinds
    assert not any(r["target_id"] == "CLAUDE-X" for r in rels), kinds
    assert (REL_PROVIDED_BY, "GPT-5", "p-1") in kinds, kinds


def test_24_correlate_with_no_input_emits_nothing():
    from scanner.aibom_abom_correlation import correlate

    agent = {"component_id": "ABOM-1", "component": "Agent", "model_id": "GPT-5"}
    model = {"model_id": "GPT-5"}

    assert correlate(abom=[], aibom=[]) == []
    assert correlate(abom=[agent], aibom=[]) == []
    assert correlate(abom=[], aibom=[model]) == []


# ---------------------------------------------------------------------------
# P0-5 -- contract findings are not detections
# ---------------------------------------------------------------------------

def test_25_contract_findings_are_flagged_contract_only():
    findings = aas.scan_advanced_ai_file(
        "ADV01_evasion_attack.py", "# contract case\nadversarial_evasion_attack\n"
    )
    contract = [f for f in findings if f.get("detection") == "Advanced AI Security Corpus Contract Fallback"]
    assert contract, findings
    for f in contract:
        assert f["contract_only"] is True
        assert f["validation_only"] is True
        assert f["confidence"] == "Contract"


def test_26_heuristic_findings_are_not_contract_only():
    findings = aas.scan_advanced_ai_file(
        "unrelated_module.py", "# controlled positive case\nuser_uploaded_training_data = True\n"
    )
    assert findings, findings
    for f in findings:
        assert f.get("contract_only") is None or f["contract_only"] is False, f
        assert f["detection"] == "Advanced AI Security Heuristic", f


def test_27_filename_rule_map_has_no_duplicate_basenames():
    """A dict literal cannot report duplicates at runtime, so assert against
    the source: each basename must be written exactly once."""
    source = (PROJECT_ROOT / "scanner" / "advanced_ai_security.py").read_text(
        encoding="utf-8"
    )
    header, _, rest = source.partition("FILENAME_RULE_MAP = {")
    body, _, _ = rest.partition("\n}")
    keys = re.findall(r'^\s{4}"([^"]+)":', body, flags=re.MULTILINE)
    assert len(keys) == len(set(keys)), sorted(
        k for k in set(keys) if keys.count(k) > 1
    )
    assert len(keys) == len(aas.FILENAME_RULE_MAP) == 52, len(keys)


def test_28_every_contract_basename_produces_exactly_one_contract_finding():
    for basename, contract in aas.FILENAME_RULE_MAP.items():
        findings = aas.scan_advanced_ai_file(basename, "# contract case\n")
        hits = [f for f in findings if f.get("contract_only")]
        assert len(hits) == 1, (basename, hits)
        assert hits[0]["rule_id"] == contract[0], (basename, hits[0]["rule_id"])
        assert hits[0]["vuln_type"] == contract[3], basename


# ---------------------------------------------------------------------------
# Compliance mapping -- every AI finding was falling through to the generic
# fallback (measured: 27/27 on the AI/LLM corpus, no OWASP or CWE control).
# ---------------------------------------------------------------------------

from scanner.compliance_mapper import (  # noqa: E402  (placement kept local)
    GENERIC_MAPPING,
    _mapping_for,
    compliance_summary,
    enrich_compliance,
)


def test_29_ai_findings_receive_owasp_and_cwe_controls():
    mapping = _mapping_for(
        {"vuln_type": "llm_prompt_injection", "rule_id": "LLM01_PROMPT_INJECTION", "cwe": "CWE-20"}
    )
    assert mapping["frameworks"]["OWASP"] == ["LLM01:2025 - Prompt Injection"]
    assert mapping["frameworks"]["CWE"] == ["CWE-20"]


def test_30_ai_compliance_mapping_is_strictly_additive():
    mapping = _mapping_for({"vuln_type": "llm_supply_chain", "cwe": "CWE-829"})
    assert mapping["frameworks"]["NIST 800-53"] == ["RA-5"]
    assert mapping["frameworks"]["ISO 27001"] == ["A.8.8"]
    assert mapping["frameworks"]["SOC 2"] == ["CC7.1"]
    assert mapping["control_theme"] == "Security Review"
    assert mapping["frameworks"]["OWASP"] == ["LLM03:2025 - Supply Chain"]
    assert mapping["frameworks"]["CWE"] == ["CWE-829"]


def test_31_owasp_label_follows_the_edition_catalogue_not_the_rule_number():
    mapping = _mapping_for({"vuln_type": "llm_insecure_output", "cwe": "CWE-94"})
    assert mapping["frameworks"]["OWASP"] == ["LLM05:2025 - Improper Output Handling"]


def test_32_governance_gaps_get_no_owasp_control():
    mapping = _mapping_for(
        {"vuln_type": "model_governance_missing_owner", "cwe": "CWE-693"}
    )
    assert "OWASP" not in mapping["frameworks"], mapping
    assert mapping["frameworks"]["NIST 800-53"] == ["RA-5"]


def test_33_retired_subject_keeps_its_own_editioned_label():
    mapping = _mapping_for({"vuln_type": "llm_insecure_plugin", "cwe": "CWE-749"})
    label = mapping["frameworks"]["OWASP"][0]
    assert label.startswith("LLM07:2023 - "), label
    assert "retired from the Top 10 in 2025" in label, label


def test_34_non_ai_findings_keep_their_specific_mapping():
    mapping = _mapping_for({"vuln_type": "hardcoded_secret"})
    assert mapping["control_theme"] == "Credential Protection"
    assert mapping["frameworks"]["OWASP"] == [
        "A07:2021 - Identification and Authentication Failures"
    ]
    assert mapping["frameworks"]["CWE"] == [
        "CWE-798 - Use of Hard-coded Credentials"
    ]


def test_35_unknown_types_do_not_borrow_a_risk_id():
    unknown = _mapping_for({"vuln_type": "something_not_catalogued", "cwe": "CWE-1"})
    assert unknown == GENERIC_MAPPING
    # an AI-looking type that is not in the catalogue must not gain an id
    invented = _mapping_for({"vuln_type": "llm_invented_type", "cwe": "CWE-1"})
    assert invented == GENERIC_MAPPING
    assert "OWASP" not in invented["frameworks"]


def test_36_enrich_compliance_and_summary_cover_ai_findings():
    findings = enrich_compliance(
        [
            {"vuln_type": "llm_prompt_injection", "cwe": "CWE-20"},
            {"vuln_type": "hardcoded_secret", "cwe": "CWE-798"},
        ]
    )
    assert "OWASP" in findings[0]["compliance_controls"]
    assert "OWASP" in findings[1]["compliance_controls"]
    summary = compliance_summary(findings)
    assert summary["OWASP"] == 2, summary
    assert summary["CWE"] == 2, summary
    assert summary["NIST 800-53"] == 2, summary
    # the AI finding's control theme is unchanged by this fix
    assert findings[0]["control_theme"] == "Security Review"


# ---------------------------------------------------------------------------
# Register guard -- reports/gap_register.json is the Phase 3 source of truth,
# so the rows added by this tranche have to keep its contract.
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402

from analysis.render_gap_register import build as _render  # noqa: E402
from analysis.render_gap_register import esc as _esc  # noqa: E402

_REQUIRED_GAP_KEYS = frozenset(
    {
        "id",
        "priority",
        "domain",
        "title",
        "problem",
        "reference_tool",
        "how_reference_does_it",
        "current_behavior",
        "actual_gap",
        "enterprise_essential",
        "research_relevant",
        "cost",
        "regression_risk",
        "implementation_location",
        "root_cause_class",
        "evidence_tier",
        "evidence",
    }
)


def _register() -> dict:
    return _json.loads(
        (PROJECT_ROOT / "reports" / "gap_register.json").read_text(encoding="utf-8")
    )


@pytest.mark.requires_prod_tree(artifact="reports/gap_register.json")
def test_37_register_rows_share_one_schema_and_a_closed_vocabulary():
    reg = _register()
    gaps = reg["gaps"]

    ids = [g["id"] for g in gaps]
    assert len(ids) == len(set(ids)), "duplicate gap ids"
    assert ids == sorted(ids), "gap ids are no longer ordered"

    for g in gaps:
        assert set(g) == _REQUIRED_GAP_KEYS, (g["id"], sorted(set(g) ^ _REQUIRED_GAP_KEYS))
        assert g["priority"] in {"P0", "P1", "P2", "P3"}, g["id"]
        assert g["evidence_tier"] in {
            "MEASURED_OPEN",
            "MEASURED_CLOSED",
            "UNMEASURED",
            "STRUCTURAL",
        }, g["id"]
        assert g["cost"] in {"XS", "S", "M", "L", "XL"}, g["id"]
        assert g["regression_risk"] in {"LOW", "MED", "HIGH"}, g["id"]
        # a root cause that has no definition is a label nobody can act on
        assert g["root_cause_class"] in reg["root_cause_classes"], (g["id"], g["root_cause_class"])
        # an absence is never enough on its own to claim a tier
        if g["evidence_tier"].startswith("MEASURED"):
            assert g["evidence"].strip(), g["id"]


@pytest.mark.requires_prod_tree(artifact="reports/gap_register.json")
def test_38_renderer_emits_every_register_row():
    reg = _register()
    rendered = _render(reg)
    assert rendered.count("G-") >= len(reg["gaps"])
    for g in reg["gaps"]:
        assert g["id"] in rendered, g["id"]
        assert _esc(g["title"]) in rendered, g["id"]
    # the closure ledger and the anti-creep section are both populated
    assert "| Outcome | Root-cause classes involved |" in rendered
    assert "| Considered | Why not |" in rendered


@pytest.mark.requires_prod_tree(artifact="reports/gap_register.json")
def test_39_closure_ledger_only_cites_defined_root_causes():
    reg = _register()
    assert reg["closed_this_program"], "closure ledger is empty"
    for entry in reg["closed_this_program"]:
        assert entry["item"].strip(), entry
        for cause in entry["root_causes"]:
            assert cause in reg["root_cause_classes"], cause

    # the five P0 rows this tranche claims to close must actually be closed
    by_id = {g["id"]: g for g in reg["gaps"]}
    for closed_id in ("G-004", "G-040", "G-041", "G-042", "G-043"):
        assert by_id[closed_id]["evidence_tier"] == "MEASURED_CLOSED", closed_id

    # rejected items must say why, so they are not silently re-proposed
    for rejected in reg["not_proposed"]:
        assert rejected["item"].strip() and rejected["reason"].strip(), rejected


@pytest.mark.requires_prod_tree(artifact="reports/gap_register.json")
def test_40_every_new_closure_is_backed_by_a_detector():
    by_id = {g["id"]: g for g in _register()["gaps"]}
    for closed_id in ("G-004", "G-040", "G-041", "G-042", "G-043"):
        evidence = by_id[closed_id]["evidence"]
        assert "tests/" in evidence, (
            closed_id,
            "closure recorded with no test reference -- a claim without a detector",
        )


@pytest.mark.requires_prod_tree(artifact="reports/gap_register.json")
def test_41_the_residual_gap_is_registered_not_absorbed_into_the_closure():
    by_id = {g["id"]: g for g in _register()["gaps"]}

    residual = by_id["G-039"]
    assert residual["evidence_tier"] == "MEASURED_OPEN", residual["evidence_tier"]
    assert residual["root_cause_class"] == "SCHEMA_ALIGNMENT_GAP"
    assert residual["regression_risk"] == "HIGH"
    # the manufacturer risk is stated where an implementer will read it
    assert "nomic-embed-text" in residual["implementation_location"]
    assert "PROVIDED_BY" in residual["implementation_location"]

    # closing G-004 must not silently claim the inert half is working too
    assert "G-039" in by_id["G-004"]["actual_gap"]
