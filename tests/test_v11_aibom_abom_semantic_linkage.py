from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.aibom_abom_correlation import correlate

# ---------------------------------------------------------------------------
# CONTRACT STATUS (updated 2026-10-06, after action item 5h)
#
# `correlate()` now implements identity gating:
#     an agent is linked ONLY to the model it declares (`model_id`,
#     else `model_name`); an agent declaring neither is boundary-associated
#     with the models supplied to the call; `model_resolution` never creates
#     nor suppresses a relationship.
#
# The two discrimination tests here (`..._unrelated_models_...` and
# `test_model_name_linkage_requires_exact_match`) are back in their original
# identity-gated form -- they were briefly restated as boundary association
# while correlate() had no gating.
#
# The other two remain migrated ON PURPOSE, because they pin the halves of
# the contract that are NOT identity discrimination:
#   * agent without model evidence => boundary association
#   * model_resolution is confidence, not a membership filter
#
# The irreconcilability proof (a PASSING test demanded the opposite of these
# under ungated code) is in docs/known_contract_conflicts.md.
# ---------------------------------------------------------------------------


def _rels(data):
    # correlate() is keyword-only: ABOM agents go in `abom`, AI-BOM
    # models/providers go in `aibom`. This fixture ships one combined list,
    # so split it by entity_type instead of passing it positionally.
    abom = [d for d in data if d.get("entity_type") == "AGENT"]
    aibom = [d for d in data if d.get("entity_type") != "AGENT"]
    return correlate(abom=abom, aibom=aibom)


def _types(data):
    return [
        (r["source_id"], r["relationship_type"], r["target_id"])
        for r in _rels(data)
    ]


def test_explicit_model_id_creates_agent_model_relationship():
    data = [
        {
            "entity_type": "AGENT",
            "component_id": "AGENT-001",
            "component": "ResearchAgent",
            "model_id": "AIBOM-MODEL-001",
            "evidence": ["agent.model_id"],
            "evidence_type": ["AST"],
            "confidence": "HIGH",
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-001",
            "model_name": "gpt-5",
            "provider_id": "AIBOM-PROVIDER-001",
            "model_resolution": "RESOLVED",
            "evidence": ["model='gpt-5'"],
            "evidence_type": ["AST"],
            "confidence": "HIGH",
        },
        {
            "entity_type": "PROVIDER",
            "provider_id": "AIBOM-PROVIDER-001",
            "provider_name": "OpenAI",
            "evidence": ["from openai import OpenAI"],
            "evidence_type": ["IMPORT_RESOLUTION"],
            "confidence": "HIGH",
        },
    ]

    relationships = _types(data)

    assert (
        "AGENT-001",
        "USES",
        "AIBOM-MODEL-001",
    ) in relationships


def test_unrelated_models_are_not_associated_with_agent():
    # Identity-gated (action item 5h): the agent declares model_id
    # AIBOM-MODEL-001, so model 002 must not be linked to it. Restored from
    # the boundary-contract form in force while correlate() had no gating.
    data = [
        {
            "entity_type": "AGENT",
            "component_id": "AGENT-001",
            "component": "ResearchAgent",
            "model_id": "AIBOM-MODEL-001",
            "evidence": ["agent.model_id"],
            "evidence_type": ["AST"],
            "confidence": "HIGH",
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-001",
            "model_name": "gpt-5",
            "provider_id": "AIBOM-PROVIDER-001",
            "model_resolution": "RESOLVED",
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-002",
            "model_name": "gpt-4.1",
            "provider_id": "AIBOM-PROVIDER-001",
            "model_resolution": "RESOLVED",
        },
        {
            "entity_type": "PROVIDER",
            "provider_id": "AIBOM-PROVIDER-001",
            "provider_name": "OpenAI",
        },
    ]

    relationships = _types(data)

    assert (
        "AGENT-001",
        "USES",
        "AIBOM-MODEL-001",
    ) in relationships

    assert (
        "AGENT-001",
        "USES",
        "AIBOM-MODEL-002",
    ) not in relationships

    # Structural invariants the contract guarantees alongside the gating.
    assert not any(src == "PROVIDER" for src, _, _ in relationships)
    assert not any(
        rel == "USES" and tgt == "AIBOM-PROVIDER-001"
        for _, rel, tgt in relationships
    )
    assert len(set(relationships)) == len(relationships)


def test_agent_without_model_evidence_is_associated_with_supplied_models():
    # Migrated from `test_agent_without_model_evidence_does_not_get_all_models`.
    #
    # Boundary association does not require agent-side model evidence; it
    # requires only that the agent carry a stable identity (`component_id`).
    data = [
        {
            "entity_type": "AGENT",
            "component_id": "AGENT-001",
            "component": "ResearchAgent",
            "evidence": ["agent declaration"],
            "evidence_type": ["AST"],
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-001",
            "model_name": "gpt-5",
            "model_resolution": "RESOLVED",
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-002",
            "model_name": "gpt-4.1",
            "model_resolution": "RESOLVED",
        },
    ]

    relationships = _types(data)

    agent_model_edges = [
        r for r in relationships
        if r[0] == "AGENT-001" and r[1] == "USES"
    ]

    assert sorted(e[2] for e in agent_model_edges) == [
        "AIBOM-MODEL-001",
        "AIBOM-MODEL-002",
    ]

    # Negative invariant: deduplication must hold under boundary association.
    assert len(agent_model_edges) == len(set(agent_model_edges))


def test_model_name_linkage_requires_exact_match():
    # Identity-gated (action item 5h): the agent declares model_name
    # "gpt-5", so only the matching model is linked. Restored from the
    # boundary-contract form in force while correlate() had no gating.
    data = [
        {
            "entity_type": "AGENT",
            "component_id": "AGENT-001",
            "component": "ResearchAgent",
            "model_name": "gpt-5",
            "evidence": ["model='gpt-5'"],
            "evidence_type": ["AST"],
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-001",
            "model_name": "gpt-5",
            "model_resolution": "RESOLVED",
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-002",
            "model_name": "gpt-4.1",
            "model_resolution": "RESOLVED",
        },
    ]

    relationships = _types(data)

    assert (
        "AGENT-001",
        "USES",
        "AIBOM-MODEL-001",
    ) in relationships

    assert (
        "AGENT-001",
        "USES",
        "AIBOM-MODEL-002",
    ) not in relationships

    # Negative invariant: no edge may be emitted twice.
    assert len(set(relationships)) == len(relationships)


def test_unresolved_model_still_creates_edge_when_agent_declares_it():
    # Identity-gated, resolution-neutral (action item 5h): the agent declares
    # model_id AIBOM-MODEL-001, so the edge is created even though the model's
    # resolution is UNKNOWN. `model_resolution` is confidence, never a
    # membership filter -- correlate() must not suppress an already identified
    # model. A model with no model_id at all is still excluded; see
    # semantic_hardening.py::test_missing_model_id_is_not_correlated.
    data = [
        {
            "entity_type": "AGENT",
            "component_id": "AGENT-001",
            "model_id": "AIBOM-MODEL-001",
            "evidence": ["agent.model_id"],
        },
        {
            "entity_type": "MODEL",
            "model_id": "AIBOM-MODEL-001",
            "model_name": "dynamic-model",
            "model_resolution": "UNKNOWN",
        },
    ]

    relationships = _types(data)

    assert (
        "AGENT-001",
        "USES",
        "AIBOM-MODEL-001",
    ) in relationships


print("AIBOM_ABOM_SEMANTIC_LINKAGE_CONTRACT_DEFINED")
