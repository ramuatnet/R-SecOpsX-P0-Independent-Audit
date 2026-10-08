"""Identity gating for AI-BOM <-> ABOM correlation (action item 5h).

`correlate()` must never report an agent as using a model it did not declare.

Contract under test
-------------------
1. An agent declaring ``model_id`` is linked ONLY to the model with that id.
2. An agent declaring ``model_name`` (and no ``model_id``) is linked ONLY to
   the model whose ``model_name`` matches, case/whitespace-insensitively.
3. ``model_id`` wins when the agent declares both.
4. An agent declaring NEITHER is boundary-associated with the supplied
   models (the documented P1 fallback) -- absence of a claim, not fabrication.
5. An agent that declares an identity no supplied model matches gets NO edge
   at all -- never a fall-through to some other model.
6. ``model_resolution`` is confidence, never a membership filter.
7. Gating is computed per agent, so one call can gate several agents
   independently.

Producers only ever emit ``model_id`` / ``model_name``, so those are the only
keys read -- no alternate or free-text keys, which keeps "no inference from
textual proximity" enforceable.
"""
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner import aibom_abom_correlation


def _agent(component_id="AGENT-001", **identity):
    """ABOM agent record; `identity` carries the fields under test."""
    return {"component_id": component_id, "entity_type": "AGENT", **identity}


def _model(model_id, model_name, resolution="RESOLVED", **extra):
    return {
        "model_id": model_id,
        "model_name": model_name,
        "model_resolution": resolution,
        **extra,
    }


GPT5 = ("AIBOM-MODEL-001", "GPT-5")
CLAUDE = ("AIBOM-MODEL-002", "Claude Sonnet")
GEMINI = ("AIBOM-MODEL-003", "Gemini")


def _correlate(abom, aibom):
    return aibom_abom_correlation.correlate(abom=abom, aibom=aibom)


def _uses(abom, aibom):
    """Return {target_id} of USES edges, plus the raw edges for pair checks."""
    rels = _correlate(abom, aibom)
    return {
        r["target_id"]
        for r in rels
        if r["relationship_type"] == "USES"
    }


# --- the named defect -----------------------------------------------------

def test_named_defect_gpt5_agent_is_not_linked_to_claude():
    agent = _agent(model_name="GPT-5")

    assert _uses([agent], [_model(*GPT5), _model(*CLAUDE)]) == {"AIBOM-MODEL-001"}


def test_named_defect_model_id_agent_is_not_linked_to_other_models():
    agent = _agent(model_id="AIBOM-MODEL-001")

    assert _uses(
        [agent],
        [_model(*GPT5), _model(*CLAUDE), _model(*GEMINI)],
    ) == {"AIBOM-MODEL-001"}


def test_matching_model_is_selected_by_identity_not_by_position():
    agent = _agent(model_name="GPT-5")
    supplied = [_model(*GPT5), _model(*CLAUDE), _model(*GPT5)]

    assert _uses([agent], supplied) == {"AIBOM-MODEL-001"}


# --- declaration precedence ----------------------------------------------

def test_model_id_wins_over_model_name():
    # id points at 002 while the name string matches 001's name.
    agent = _agent(model_id="AIBOM-MODEL-002", model_name="GPT-5")

    assert _uses([agent], [_model(*GPT5), _model(*CLAUDE)]) == {"AIBOM-MODEL-002"}


def test_model_id_comparison_is_case_and_whitespace_insensitive():
    agent = _agent(model_id="  AIBOM-MODEL-001 ")

    assert _uses([agent], [_model(*GPT5)]) == {"AIBOM-MODEL-001"}


def test_model_name_comparison_is_case_and_whitespace_insensitive():
    agent = _agent(model_name="  gPt-5 ")

    assert _uses([agent], [_model(*GPT5), _model(*CLAUDE)]) == {"AIBOM-MODEL-001"}


# --- no fabrication in either direction -----------------------------------

def test_declared_identity_matching_no_supplied_model_yields_no_edge():
    # The agent named something absent. Falling through to another model
    # would be exactly the fabrication 5h exists to prevent.
    agent = _agent(model_name="NOT-A-MODEL")

    assert _uses(
        [agent],
        [_model(*GPT5), _model(*CLAUDE), _model(*GEMINI)],
    ) == set()


def test_agent_with_blank_model_name_is_boundary_associated():
    # Whitespace is not a claim, so it must not act as a gate that silently
    # suppresses everything.
    agent = _agent(model_name="   ")

    assert _uses([agent], [_model(*GPT5), _model(*CLAUDE)]) == {
        "AIBOM-MODEL-001",
        "AIBOM-MODEL-002",
    }


def test_agent_without_model_evidence_is_boundary_associated():
    agent = _agent()

    assert _uses([agent], [_model(*GPT5), _model(*CLAUDE)]) == {
        "AIBOM-MODEL-001",
        "AIBOM-MODEL-002",
    }


def test_agent_without_component_id_is_never_a_source():
    agent = {"entity_type": "AGENT", "model_id": "AIBOM-MODEL-001"}

    assert not [
        r for r in _correlate([agent], [_model(*GPT5)])
        if r["relationship_type"] == "USES"
    ]


def test_model_without_model_id_is_never_a_target():
    agent = _agent(model_name="GPT-5")
    modelless = [{"model_name": "GPT-5", "model_resolution": "RESOLVED"}]

    assert _uses([agent], modelless) == set()


# --- resolution is confidence, not a membership filter --------------------

def test_unknown_resolution_does_not_suppress_a_declared_match():
    agent = _agent(model_name="GPT-5")

    assert _uses(
        [agent], [_model("AIBOM-MODEL-001", "GPT-5", "UNKNOWN")]
    ) == {"AIBOM-MODEL-001"}


def test_unresolved_resolution_does_not_suppress_a_declared_match():
    agent = _agent(model_id="AIBOM-MODEL-001")

    assert _uses(
        [agent], [_model("AIBOM-MODEL-001", "dynamic-model", "UNRESOLVED")]
    ) == {"AIBOM-MODEL-001"}


def test_resolution_still_falls_back_to_boundary_when_agent_declares_nothing():
    agent = _agent()

    assert _uses(
        [agent], [_model("AIBOM-MODEL-001", "gpt-5", "UNRESOLVED")]
    ) == {"AIBOM-MODEL-001"}


# --- per-agent scoping and structural guarantees --------------------------

def test_gating_is_computed_per_agent_within_one_call():
    agents = [
        _agent("AGENT-001", model_name="GPT-5"),
        _agent("AGENT-002", model_name="Claude Sonnet"),
    ]
    models = [_model(*GPT5), _model(*CLAUDE), _model(*GEMINI)]

    pairs = {
        (r["source_id"], r["target_id"])
        for r in _correlate(agents, models)
        if r["relationship_type"] == "USES"
    }

    assert pairs == {
        ("AGENT-001", "AIBOM-MODEL-001"),
        ("AGENT-002", "AIBOM-MODEL-002"),
    }


def test_gated_edges_are_deduplicated_and_deterministic():
    agent = _agent(model_name="GPT-5")
    models = [_model(*GPT5), _model(*CLAUDE)]

    first = _correlate([agent, dict(agent)], models + list(models))
    second = _correlate([agent, dict(agent)], models + list(models))

    keys = [
        (r["source_id"], r["relationship_type"], r["target_id"])
        for r in first
    ]

    assert len(keys) == len(set(keys))
    assert first == second
    assert first[0]["relationship_id"]


def test_agent_gating_does_not_affect_provider_relationships():
    agent = _agent(model_name="GPT-5")
    models = [
        _model(*GPT5, provider_id="AIBOM-PROVIDER-001"),
        {"provider_id": "AIBOM-PROVIDER-001", "provider_name": "OpenAI"},
    ]

    rels = _correlate([agent], models)

    assert [
        (r["source_id"], r["target_id"])
        for r in rels
        if r["relationship_type"] == "PROVIDED_BY"
    ] == [("AIBOM-MODEL-001", "AIBOM-PROVIDER-001")]
    assert _uses([agent], models) == {"AIBOM-MODEL-001"}


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
