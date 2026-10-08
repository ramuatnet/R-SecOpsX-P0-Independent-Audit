from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner import aibom_abom_correlation


def test_agent_uses_model():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "bom_type": "ABOM",
        "component": "Agent",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "provider_id": "AIBOM-PROVIDER-001",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    assert relationships

    rel = relationships[0]

    assert rel["source_id"] == "ABOM-AGENT-001"
    assert rel["target_id"] == "AIBOM-MODEL-001"
    assert rel["relationship_type"] == "USES"


def test_agent_uses_multiple_models():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "bom_type": "ABOM",
        "component": "Agent",
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

    model_targets = {
        x["target_id"]
        for x in relationships
        if x["relationship_type"] == "USES"
    }

    assert model_targets == {
        "AIBOM-MODEL-001",
        "AIBOM-MODEL-002",
    }


def test_model_provider_relationship_is_preserved():
    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "provider_id": "AIBOM-PROVIDER-001",
    }

    provider = {
        "provider_id": "AIBOM-PROVIDER-001",
        "provider_name": "OpenAI",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[],
        aibom=[model, provider],
    )

    assert any(
        x["source_id"] == "AIBOM-MODEL-001"
        and x["target_id"] == "AIBOM-PROVIDER-001"
        and x["relationship_type"] == "PROVIDED_BY"
        for x in relationships
    )


def test_unresolved_model_is_not_fabricated():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    unresolved = {
        "model_id": None,
        "model_name": None,
        "model_resolution": "UNKNOWN",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[unresolved],
    )

    assert not any(
        x.get("relationship_type") == "USES"
        and x.get("target_id")
        for x in relationships
    )


def test_deterministic_relationship_id():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
    }

    r1 = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    r2 = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    assert r1 == r2
    assert r1[0]["relationship_id"]


def test_duplicate_relationships_are_removed():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent, agent],
        aibom=[model, model],
    )

    keys = {
        (
            x["source_id"],
            x["relationship_type"],
            x["target_id"],
        )
        for x in relationships
    }

    assert len(keys) == len(relationships)


def test_evidence_is_propagated():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
        "evidence": "agent = CrewAgent(...)",
        "evidence_type": ["AST", "IMPORT_RESOLUTION"],
        "confidence_level": "HIGH",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "model_name": "gpt-5",
        "evidence": "model='gpt-5'",
        "evidence_type": ["AST", "MODEL_HINT"],
        "confidence": "HIGH",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    rel = relationships[0]

    assert rel["evidence"]
    assert rel["evidence_type"]
    assert rel["confidence"]


def test_model_can_be_used_by_multiple_agents():
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
        (x["source_id"], x["target_id"])
        for x in relationships
        if x["relationship_type"] == "USES"
    }

    assert pairs == {
        ("ABOM-AGENT-001", "AIBOM-MODEL-001"),
        ("ABOM-AGENT-002", "AIBOM-MODEL-001"),
    }


def test_provider_is_not_treated_as_model():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "component": "Agent",
    }

    provider = {
        "provider_id": "AIBOM-PROVIDER-001",
        "provider_name": "OpenAI",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[provider],
    )

    assert not any(
        x["target_id"] == "AIBOM-PROVIDER-001"
        and x["relationship_type"] == "USES"
        for x in relationships
    )


def test_cross_bom_relationship_is_explicit():
    agent = {
        "component_id": "ABOM-AGENT-001",
        "bom_type": "ABOM",
        "component": "Agent",
    }

    model = {
        "model_id": "AIBOM-MODEL-001",
        "bom_type": "AI-BOM",
        "model_name": "gpt-5",
    }

    relationships = aibom_abom_correlation.correlate(
        abom=[agent],
        aibom=[model],
    )

    rel = relationships[0]

    assert rel["source_type"] == "ABOM"
    assert rel["target_type"] == "AI-BOM"


if __name__ == "__main__":
    print("AIBOM_ABOM_CORRELATION_CONTRACT_DEFINED")
