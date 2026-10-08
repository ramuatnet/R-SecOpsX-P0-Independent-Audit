from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.aibom_model import (
    CONTRACT_VERSION,
    AIBOMGraph,
    AIComponent,
    Deployment,
    Framework,
    Model,
    Provider,
    Provenance,
    Relationship,
)


def test_provider_has_stable_semantic_id():
    a = Provider.create("OpenAI")
    b = Provider.create("OpenAI")

    assert a.provider_id == "provider:openai"
    assert a.provider_id == b.provider_id


def test_model_has_stable_semantic_id():
    a = Model.create(
        "gpt-5",
        provider_name="OpenAI",
        usage_type="GENERATION",
        resolution="RESOLVED",
    )
    b = Model.create(
        "gpt-5",
        provider_name="OpenAI",
        usage_type="GENERATION",
        resolution="RESOLVED",
    )

    assert a.model_id == "model:openai:gpt-5"
    assert a.model_id == b.model_id


def test_framework_has_stable_semantic_id():
    framework = Framework.create(
        "LangChain",
        version="1.0",
        package="langchain",
    )

    assert framework.framework_id == "framework:langchain:1.0"


def test_deployment_has_deterministic_id():
    a = Deployment.create(
        endpoint="https://api.openai.com/v1",
        endpoint_type="OPENAI_API",
        deployment_type="REMOTE_API",
    )
    b = Deployment.create(
        endpoint="https://api.openai.com/v1",
        endpoint_type="OPENAI_API",
        deployment_type="REMOTE_API",
    )

    assert a.deployment_id == b.deployment_id


def test_provenance_is_preserved():
    provenance = Provenance(
        source="AST_LITERAL",
        evidence_type=("AST", "MODEL_HINT"),
        file="app.py",
        line=10,
        detector="AIBOM_AST_MODEL_RESOLUTION",
        confidence=0.9,
    )

    model = Model.create(
        "gpt-5",
        provider_name="OpenAI",
        provenance=[provenance],
    )

    data = model.to_dict()

    assert data["provenance"][0]["source"] == "AST_LITERAL"
    assert data["provenance"][0]["file"] == "app.py"
    assert data["provenance"][0]["line"] == 10
    assert data["provenance"][0]["confidence"] == 0.9


def test_relationship_is_deterministic():
    a = Relationship.create(
        "model:openai:gpt-5",
        "PROVIDED_BY",
        "provider:openai",
    )
    b = Relationship.create(
        "model:openai:gpt-5",
        "PROVIDED_BY",
        "provider:openai",
    )

    assert a.relationship_id == b.relationship_id


def test_graph_suppresses_duplicate_entities():
    graph = AIBOMGraph()

    graph.add_provider(Provider.create("OpenAI"))
    graph.add_provider(Provider.create("OpenAI"))

    graph.add_model(
        Model.create("gpt-5", provider_name="OpenAI")
    )
    graph.add_model(
        Model.create("gpt-5", provider_name="OpenAI")
    )

    assert len(graph.providers) == 1
    assert len(graph.models) == 1


def test_graph_preserves_multiple_models():
    graph = AIBOMGraph()

    graph.add_model(Model.create("gpt-5", provider_name="OpenAI"))
    graph.add_model(Model.create("gpt-4.1", provider_name="OpenAI"))

    assert len(graph.models) == 2
    assert {
        model.model_name for model in graph.models
    } == {"gpt-5", "gpt-4.1"}


def test_graph_relationships_are_first_class():
    graph = AIBOMGraph()

    provider = graph.add_provider(Provider.create("OpenAI"))
    model = graph.add_model(
        Model.create("gpt-5", provider_name="OpenAI")
    )

    relationship = graph.add_relationship(
        Relationship.create(
            model.model_id,
            "PROVIDED_BY",
            provider.provider_id,
        )
    )

    assert relationship.source_id == model.model_id
    assert relationship.target_id == provider.provider_id
    assert relationship.relationship_type == "PROVIDED_BY"


def test_graph_serialization_is_deterministic():
    graph = AIBOMGraph()

    provider = graph.add_provider(Provider.create("OpenAI"))
    model = graph.add_model(
        Model.create("gpt-5", provider_name="OpenAI")
    )

    graph.add_relationship(
        Relationship.create(
            model.model_id,
            "PROVIDED_BY",
            provider.provider_id,
        )
    )

    first = graph.to_json()
    second = graph.to_json()

    assert first == second


def test_empty_graph_is_valid():
    graph = AIBOMGraph()

    data = graph.to_dict()

    assert data["contract_version"] == CONTRACT_VERSION
    assert data["providers"] == []
    assert data["models"] == []
    assert data["frameworks"] == []
    assert data["deployments"] == []
    assert data["components"] == []
    assert data["relationships"] == []


def test_all_required_entity_types_exist():
    graph = AIBOMGraph()

    provider = graph.add_provider(Provider.create("OpenAI"))
    model = graph.add_model(
        Model.create("gpt-5", provider_name="OpenAI")
    )
    framework = graph.add_framework(
        Framework.create("OpenAI SDK", package="openai")
    )
    deployment = graph.add_deployment(
        Deployment.create(
            endpoint="https://api.openai.com/v1",
            endpoint_type="OPENAI_API",
            deployment_type="REMOTE_API",
        )
    )
    component = graph.add_component(
        AIComponent.create(
            "OpenAI SDK / API",
            component_type="MODEL_PROVIDER",
        )
    )

    assert provider.provider_id
    assert model.model_id
    assert framework.framework_id
    assert deployment.deployment_id
    assert component.component_id