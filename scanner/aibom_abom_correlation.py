"""
R-SecOpsX V11
AI-BOM <-> ABOM correlation layer.

Purpose:
    Correlate already-detected AI-BOM and ABOM assets.

This module does NOT perform:
    - AI asset discovery
    - ABOM discovery
    - SAST
    - LLM security detection
    - vulnerability scoring

It only creates deterministic, evidence-backed relationships.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


REL_USES = "USES"
REL_PROVIDED_BY = "PROVIDED_BY"

BOM_AI = "AI-BOM"
BOM_ABOM = "ABOM"


def _stable_relationship_id(
    source_id: str,
    relationship_type: str,
    target_id: str,
) -> str:
    """Create a deterministic relationship identifier."""
    material = f"{source_id}|{relationship_type}|{target_id}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"REL-{digest.upper()}"


def _is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _is_model(item: dict[str, Any]) -> bool:
    """
    Identify an AI-BOM model entity.

    Model identity must be explicit. We deliberately do not infer a
    model merely because an arbitrary finding contains model-like text.
    """
    return bool(
        item.get("model_id")
        and (
            item.get("entity_type") == "MODEL"
            or item.get("asset_type") == "MODEL"
            or item.get("model_name") is not None
        )
    )


def _is_provider(item: dict[str, Any]) -> bool:
    """Identify an AI-BOM provider entity."""
    return bool(
        item.get("provider_id")
        and (
            item.get("entity_type") == "PROVIDER"
            or item.get("asset_type") == "PROVIDER"
            or item.get("provider_name") is not None
        )
    )


def _is_agent(item: dict[str, Any]) -> bool:
    """
    Identify an ABOM agent.

    ABOM component identity is expected to be represented by component_id.
    """
    if not item.get("component_id"):
        return False

    entity_type = str(
        item.get("entity_type")
        or item.get("asset_type")
        or item.get("component_type")
        or ""
    ).upper()

    component = str(item.get("component") or "").lower()

    return (
        entity_type == "AGENT"
        or "agent" in component
        or item.get("abom_type") == "AGENT"
    )


def _evidence_values(*items: dict[str, Any]) -> list[Any]:
    """
    Preserve evidence from both sides without inventing evidence.
    """
    result: list[Any] = []

    for item in items:
        for key in ("evidence", "evidence_type", "provenance"):
            value = item.get(key)

            if value is None:
                continue

            if isinstance(value, list):
                result.extend(value)
            else:
                result.append(value)

    return result


def _confidence(*items: dict[str, Any]) -> str:
    """
    Derive relationship confidence conservatively.

    HIGH is retained only when the contributing entities explicitly
    contain HIGH confidence. Otherwise the relationship is MEDIUM.
    """
    values: list[str] = []

    for item in items:
        for key in ("confidence", "confidence_level"):
            value = item.get(key)
            if value:
                values.append(str(value).upper())

    if values and all(value == "HIGH" for value in values):
        return "HIGH"

    if "LOW" in values:
        return "LOW"

    return "MEDIUM"


def _relationship(
    *,
    source_id: str,
    source_type: str,
    relationship_type: str,
    target_id: str,
    target_type: str,
    source: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    """Build the canonical relationship object."""

    return {
        "relationship_id": _stable_relationship_id(
            source_id,
            relationship_type,
            target_id,
        ),
        "source_id": source_id,
        "source_type": source_type,
        "relationship_type": relationship_type,
        "target_id": target_id,
        "target_type": target_type,
        "evidence": _evidence_values(source, target),
        "evidence_type": list(
            dict.fromkeys(
                [
                    *(
                        source.get("evidence_type", [])
                        if isinstance(source.get("evidence_type"), list)
                        else [source.get("evidence_type")]
                        if source.get("evidence_type")
                        else []
                    ),
                    *(
                        target.get("evidence_type", [])
                        if isinstance(target.get("evidence_type"), list)
                        else [target.get("evidence_type")]
                        if target.get("evidence_type")
                        else []
                    ),
                ]
            )
        ),
        "confidence": _confidence(source, target),
        "provenance": {
            "source_bom": source_type,
            "target_bom": target_type,
        },
    }


def _deduplicate(
    relationships: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove duplicate relationships deterministically."""
    unique: dict[str, dict[str, Any]] = {}

    for relationship in relationships:
        key = (
            relationship.get("source_id"),
            relationship.get("relationship_type"),
            relationship.get("target_id"),
        )

        if key not in unique:
            unique[key] = relationship

    return sorted(
        unique.values(),
        key=lambda x: (
            str(x.get("source_id") or ""),
            str(x.get("relationship_type") or ""),
            str(x.get("target_id") or ""),
        ),
    )


def _normalise_identity(value: Any) -> str:
    """Case-fold, trim and collapse whitespace for identity comparison."""
    return " ".join(str(value).strip().casefold().split())


def _agent_declared_model_reference(
    agent: dict[str, Any],
) -> tuple[str, str] | None:
    """
    Return the model identity the ABOM agent itself declares, if any.

    This is the evidence that gates cross-BOM association. Only the identity
    fields ABOM/AI-BOM producers actually emit are read (`model_id`, then
    `model_name`) -- never free text -- so the correlation still does not
    infer an Agent -> Model relationship from textual proximity.

    Returns ``("model_id", value)`` or ``("model_name", value)``, else
    ``None`` when the agent declares no model identity.
    """
    for key in ("model_id", "model_name"):
        value = agent.get(key)
        if value is not None and str(value).strip():
            return (key, str(value).strip())

    return None


def _model_satisfies_reference(
    model: dict[str, Any],
    reference: tuple[str, str],
) -> bool:
    """Whether this model is the one the agent declared."""
    kind, value = reference

    if kind == "model_id":
        candidate = model.get("model_id")
    else:
        candidate = model.get("model_name")

    if candidate is None or not str(candidate).strip():
        return False

    return _normalise_identity(candidate) == _normalise_identity(value)


def correlate(
    *,
    abom: list[dict[str, Any]] | None = None,
    aibom: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Correlate AI-BOM and ABOM entities.

    Current P1 relationships:

        ABOM AGENT --USES--> AI-BOM MODEL
        AI-BOM MODEL --PROVIDED_BY--> AI-BOM PROVIDER

    Important:
        This function does not infer an Agent -> Model relationship from
        textual proximity. Only structured identity fields are read.

        An agent is linked ONLY to the model it declares, via `model_id`
        (preferred) or `model_name`, compared case-insensitively. An agent
        that declares neither is boundary-associated with the models
        supplied to this call. `model_resolution` never creates nor
        suppresses a relationship.
    """

    abom = [
        item for item in (abom or [])
        if _is_mapping(item)
    ]

    aibom = [
        item for item in (aibom or [])
        if _is_mapping(item)
    ]

    relationships: list[dict[str, Any]] = []

    models = [
        item for item in aibom
        if _is_model(item)
    ]

    providers = {
        str(item["provider_id"]): item
        for item in aibom
        if _is_provider(item)
    }

    agents = [
        item for item in abom
        if _is_agent(item)
    ]

    # ---------------------------------------------------------------
    # MODEL -> PROVIDER
    # ---------------------------------------------------------------
    for model in models:
        provider_id = model.get("provider_id")

        if not provider_id:
            continue

        provider = providers.get(str(provider_id))

        if provider is None:
            # Never manufacture a provider entity.
            continue

        relationships.append(
            _relationship(
                source_id=str(model["model_id"]),
                source_type=BOM_AI,
                relationship_type=REL_PROVIDED_BY,
                target_id=str(provider["provider_id"]),
                target_type=BOM_AI,
                source=model,
                target=provider,
            )
        )

    # ---------------------------------------------------------------
    # AGENT -> MODEL
    # ---------------------------------------------------------------
    #
    # Identity-gated contract (action item 5h):
    #
    #   An agent is associated ONLY with the model it explicitly declares
    #   (`model_id`, or failing that `model_name`). Without that evidence the
    #   agent is boundary-associated with the models supplied to this call,
    #   which is the documented P1 fallback.
    #
    #   This is what stops a `GPT-5` agent from being reported as using an
    #   unrelated `Claude` model: the agent named a model, so the declaration
    #   is honoured rather than overridden by whatever else is in scope.
    #
    # model_resolution describes identity-resolution confidence; it must not
    # suppress an already identified AI-BOM model, so UNKNOWN/UNRESOLVED
    # models may still participate. Conservative confidence is carried by the
    # existing confidence logic instead.
    #
    for agent in agents:
        declared_reference = _agent_declared_model_reference(agent)

        for model in models:
            # Stable model identity is the minimum requirement for
            # cross-BOM correlation.
            if not model.get("model_id"):
                continue

            if (
                declared_reference is not None
                and not _model_satisfies_reference(model, declared_reference)
            ):
                continue

            relationships.append(
                _relationship(
                    source_id=str(agent["component_id"]),
                    source_type=BOM_ABOM,
                    relationship_type=REL_USES,
                    target_id=str(model["model_id"]),
                    target_type=BOM_AI,
                    source=agent,
                    target=model,
                )
            )

    return _deduplicate(relationships)


def to_json(
    relationships: list[dict[str, Any]],
) -> str:
    """Serialize relationships deterministically."""
    return json.dumps(
        relationships,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


__all__ = [
    "REL_USES",
    "REL_PROVIDED_BY",
    "correlate",
    "to_json",
]

