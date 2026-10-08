from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner import aibom_abom_correlation


def test_unresolved_model_still_correlates_when_identity_exists():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "model_resolution": "UNKNOWN",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    uses = [
        r for r in relationships
        if r["relationship_type"] == "USES"
    ]

    assert len(uses) == 1
    assert uses[0]["source_id"] == "ABOM-AGENT-001"
    assert uses[0]["target_id"] == "AIBOM-MODEL-001"


def test_unresolved_model_does_not_change_relationship_identity():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    resolved = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "model_resolution": "RESOLVED",
    }

    unresolved = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "model_resolution": "UNKNOWN",
    }

    r_resolved = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[resolved],
    )

    r_unresolved = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[unresolved],
    )

    assert r_resolved[0]["relationship_id"] == r_unresolved[0]["relationship_id"]


def test_missing_model_id_is_not_correlated():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    model = {
        "model_name": "gpt-5",
        "model_resolution": "RESOLVED",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    assert not [
        r for r in relationships
        if r["relationship_type"] == "USES"
    ]


def test_missing_agent_identity_is_not_correlated():
    agent = {
        "component": "Agent",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    assert not [
        r for r in relationships
        if r["relationship_type"] == "USES"
    ]


def test_duplicate_agent_model_input_is_deduplicated():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent, agent.copy()],
        aibom=[model, model.copy()],
    )

    uses = [
        r for r in relationships
        if r["relationship_type"] == "USES"
    ]

    assert len(uses) == 1


def test_multiple_agents_can_use_same_model():
    agents = [
        {
            "component_id": "ABOM-AGENT-001",
            "component": "Agent",
        },
        {
            "component_id": "ABOM-AGENT-002",
            "component": "Agent",
        },
    ]

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=agents,
        aibom=[model],
    )

    pairs = {
        (r["source_id"], r["target_id"])
        for r in relationships
        if r["relationship_type"] == "USES"
    }

    assert pairs == {
        ("ABOM-AGENT-001", "AIBOM-MODEL-001"),
        ("ABOM-AGENT-002", "AIBOM-MODEL-001"),
    }


def test_model_resolution_does_not_create_false_relationship_to_other_model():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
        "model_id": "AIBOM-MODEL-001",
    }

    models = [
        {
            "model_id": "AIBOM-MODEL-001",
            "model_name": "gpt-5",
        },
        {
            "model_id": "AIBOM-MODEL-002",
            "model_name": "gpt-4.1",
        },
    ]

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=models,
    )

    uses = {
        r["target_id"]
        for r in relationships
        if r["relationship_type"] == "USES"
    }

    # This assertion changed with action item 5h (identity gating).
    # The test NAME has always said "does not create false relationship to
    # other model" -- the agent declares model_id AIBOM-MODEL-001, so
    # MODEL-002 is exactly the "other model" that must not receive an edge.
    # The previous expectation of {001, 002} encoded the ungated boundary
    # behaviour and contradicted this test's own title.
    assert uses == {
        "AIBOM-MODEL-001",
    }


def test_provider_relationship_requires_matching_provider_identity():
    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "provider_id": "AIBOM-PROVIDER-001",
    }

    provider = {
        "provider_id": "AIBOM-PROVIDER-001",
        "provider_name": "Provider",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[],
        aibom=[model, provider],
    )

    provided_by = [
        r for r in relationships
        if r["relationship_type"] == "PROVIDED_BY"
    ]

    assert len(provided_by) == 1
    assert provided_by[0]["source_id"] == "AIBOM-MODEL-001"
    assert provided_by[0]["target_id"] == "AIBOM-PROVIDER-001"


def test_unknown_provider_is_not_manufactured():
    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "provider_id": "AIBOM-PROVIDER-MISSING",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[],
        aibom=[model],
    )

    provided_by = [
        r for r in relationships
        if r["relationship_type"] == "PROVIDED_BY"
    ]

    assert provided_by == []


def test_relationship_output_is_deterministic():
    agents = [
        {
            "component_id": "ABOM-AGENT-002",
            "component": "Agent",
        },
        {
            "component_id": "ABOM-AGENT-001",
            "component": "Agent",
        },
    ]

    models = [
        {
            "model_id": "AIBOM-MODEL-002",
            "model_name": "gpt-4.1",
        },
        {
            "model_id": "AIBOM-MODEL-001",
            "model_name": "gpt-5",
        },
    ]

    first = aibom_abom_correlation.correlate(
        abom=agents,
        aibom=models,
    )

    second = aibom_abom_correlation.correlate(
        abom=list(reversed(agents)),
        aibom=list(reversed(models)),
    )

    assert first == second
