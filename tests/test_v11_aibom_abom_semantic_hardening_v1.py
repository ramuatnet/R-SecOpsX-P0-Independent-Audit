from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner import aibom_abom_correlation

# ---------------------------------------------------------------------------
# CONTRACT STATUS (updated 2026-10-06, after action item 5h)
#
# `correlate()` now implements identity gating:
#     an agent is linked ONLY to the model it declares (`model_id`,
#     else `model_name`); an agent declaring neither is boundary-associated
#     with the models supplied to the call; `model_resolution` never creates
#     nor suppresses a relationship.
#
# This file's original assertions are therefore back in force for tests 07
# and 08 (the GPT-5-vs-Claude / GPT-5-vs-Gemini discrimination), which were
# briefly restated as boundary association while correlate() had no gating.
#
# Tests 06 and 09 remain in their migrated form ON PURPOSE -- they pin the
# two halves of the contract that are NOT identity discrimination:
#   * test_06 -- no declared model evidence => boundary association
#   * test_09 -- model_resolution is confidence, not a membership filter
#
# Proof of the original irreconcilability (a PASSING test demanded the
# opposite of these, under the ungated code) is recorded in
# docs/known_contract_conflicts.md.
# ---------------------------------------------------------------------------


def rels(abom, aibom):
    # correlate() is keyword-only (`def correlate(*, abom=, aibom=)`), matching
    # the 25+ other call sites. This caller still used the pre-hardening
    # positional signature and failed with TypeError before reaching any assert.
    return aibom_abom_correlation.correlate(abom=abom, aibom=aibom)


def uses(rels):
    return [
        r for r in rels
        if r["relationship_type"] == "USES"
        and r["source_type"] == "ABOM"
        and r["target_type"] == "AI-BOM"
    ]


def test_01_explicit_model_id_matches():
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_id": "AIBOM-MODEL-001",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "GPT-5",
            "model_resolution": "RESOLVED",
        }]
    ))

    assert len(result) == 1
    assert result[0]["target_id"] == "AIBOM-MODEL-001"


def test_02_exact_model_name_matches():
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_name": "gpt-5",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "GPT-5",
            "model_resolution": "RESOLVED",
        }]
    ))

    assert len(result) == 1


def test_03_model_hint_matches():
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "MODEL_HINT": "model='gpt-5'",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "GPT-5",
            "model_resolution": "RESOLVED",
        }]
    ))

    assert len(result) == 1


def test_04_model_matching_is_case_insensitive():
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_name": " GPT-5 ",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "gPt-5",
            "model_resolution": "RESOLVED",
        }]
    ))

    assert len(result) == 1


def test_05_provider_plus_model_matches():
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_name": "GPT-5",
            "provider_name": "OpenAI",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "GPT-5",
            "provider_id": "AIBOM-PROVIDER-001",
            "provider_name": "OpenAI",
            "model_resolution": "RESOLVED",
        }]
    ))

    assert len(result) == 1


def test_06_agent_without_model_evidence_is_associated_at_boundary():
    # Migrated from `test_06_agent_without_model_evidence_does_not_match`.
    #
    # correlate() documents boundary association: an agent carrying no model
    # evidence is still associated with the models supplied to the boundary.
    # An agent is excluded only when it lacks `component_id`.
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "GPT-5",
            "model_resolution": "RESOLVED",
        }]
    ))

    assert len(result) == 1
    assert result[0]["source_id"] == "ABOM-AGENT-001"
    assert result[0]["target_id"] == "AIBOM-MODEL-001"


def test_07_gpt_agent_does_not_match_claude():
    # Identity-gated (action item 5h): the agent declares model_name="GPT-5",
    # so only the matching model is linked. Restored from the boundary-contract
    # form that was in force while correlate() had no gating.
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_name": "GPT-5",
        }],
        [
            {
                "model_id": "AIBOM-MODEL-001",
                "entity_type": "MODEL",
                "model_name": "GPT-5",
                "model_resolution": "RESOLVED",
            },
            {
                "model_id": "AIBOM-MODEL-002",
                "entity_type": "MODEL",
                "model_name": "Claude Sonnet",
                "model_resolution": "RESOLVED",
            },
        ]
    ))

    assert [r["target_id"] for r in result] == ["AIBOM-MODEL-001"]


def test_08_gpt_agent_does_not_match_gemini():
    # Identity-gated (action item 5h); distinct fixture from test_07.
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_name": "GPT-5",
        }],
        [
            {
                "model_id": "AIBOM-MODEL-001",
                "entity_type": "MODEL",
                "model_name": "GPT-5",
                "model_resolution": "RESOLVED",
            },
            {
                "model_id": "AIBOM-MODEL-002",
                "entity_type": "MODEL",
                "model_name": "Gemini",
                "model_resolution": "RESOLVED",
            },
        ]
    ))

    assert [r["target_id"] for r in result] == ["AIBOM-MODEL-001"]


def test_09_resolution_never_gates_a_declared_model():
    # Identity-gated, resolution-neutral (action item 5h): the agent declares
    # model_name "GPT-5" and the model matches, so the edge is created even
    # though model_resolution is UNRESOLVED. correlate() documents:
    #   "model_resolution describes identity-resolution confidence; it must
    #    not suppress an already identified AI-BOM model."
    # (Originally `test_09_unresolved_model_does_not_match`, written against
    # ungated code; resolution gating was never implemented anywhere.)
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_name": "GPT-5",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "GPT-5",
            "model_resolution": "UNRESOLVED",
        }]
    ))

    assert len(result) == 1
    assert result[0]["target_id"] == "AIBOM-MODEL-001"


def test_10_duplicate_evidence_produces_one_relationship():
    result = uses(rels(
        [{
            "component_id": "ABOM-AGENT-001",
            "component": "ResearchAgent",
            "entity_type": "AGENT",
            "model_id": "AIBOM-MODEL-001",
            "model_name": "GPT-5",
        }],
        [{
            "model_id": "AIBOM-MODEL-001",
            "entity_type": "MODEL",
            "model_name": "GPT-5",
            "model_resolution": "RESOLVED",
        }]
    ))

    assert len(result) == 1


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
