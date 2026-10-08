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
    """Return a conservative normalized identity token."""
    if value is None:
        return ""
    return " ".join(str(value).strip().casefold().split())


def _resolution_allowed(model: dict[str, Any]) -> bool:
    """Reject explicitly unresolved AI-BOM models."""
    resolution = str(
        model.get("model_resolution")
        or model.get("resolution")
        or ""
    ).strip().upper()
    return resolution not in {"UNKNOWN", "UNRESOLVED", "AMBIGUOUS"}


def _explicit_model_id(agent: dict[str, Any]) -> str:
    """Extract an explicitly supplied model identifier from an ABOM agent."""
    for key in (
        "model_id",
        "resolved_model_id",
        "ai_model_id",
        "model_reference_id",
    ):
        value = agent.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _explicit_model_reference(agent: dict[str, Any]) -> str:
    """Extract an explicit model reference/name supplied by an ABOM agent."""
    for key in (
        "model_reference",
        "model_ref",
        "model_name",
        "resolved_model_name",
        "ai_model_name",
    ):
        value = agent.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _model_matches_reference(model: dict[str, Any], reference: str) -> bool:
    """Match an explicit reference against model identity fields."""
    token = _normalise_identity(reference)
    if not token:
        return False

    candidates = (
        model.get("model_id"),
        model.get("model_name"),
        model.get("name"),
        model.get("qualified_name"),
    )
    return any(_normalise_identity(value) == token for value in candidates)


def _resolve_agent_model_links(
    agent: dict[str, Any],
    models: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], str, str]]:
    """
    Resolve Agent -> Model relationships without Cartesian linking.

    Precedence:
      1. explicit model_id
      2. explicit model reference/name, only when unique
      3. unique model identity exposed by the agent
      4. unresolved/ambiguous => no relationship

    The resolver intentionally does not use textual proximity or the mere
    presence of a resolved model in the AI-BOM.
    """
    usable = [m for m in models if m.get("model_id") and _resolution_allowed(m)]
    if not usable:
        return []

    # Highest precedence: an explicit stable model identifier.
    explicit_id = _explicit_model_id(agent)
    if explicit_id:
        matches = [
            model for model in usable
            if _normalise_identity(model.get("model_id")) ==
               _normalise_identity(explicit_id)
        ]
        if len(matches) == 1:
            return [(matches[0], "EXPLICIT_MODEL_ID", "HIGH")]
        # An explicit but unknown/ambiguous ID must not fall through to a
        # weaker heuristic and accidentally create a different relationship.
        return []

    # Second precedence: explicit model reference/name.  It must resolve
    # uniquely, otherwise the safe result is no relationship.
    reference = _explicit_model_reference(agent)
    if reference:
        matches = [
            model for model in usable
            if _model_matches_reference(model, reference)
        ]
        if len(matches) == 1:
            return [(matches[0], "EXPLICIT_MODEL_REFERENCE", "HIGH")]
        return []

    # Third precedence: a structured model identity object may be supplied
    # by an ABOM producer without using one of the conventional flat keys.
    identity = agent.get("model_identity")
    if isinstance(identity, dict):
        name = identity.get("model_name") or identity.get("name")
        provider_id = identity.get("provider_id")
        provider_name = identity.get("provider_name")

        candidates = [
            model for model in usable
            if name
            and _normalise_identity(model.get("model_name")) ==
               _normalise_identity(name)
        ]

        if provider_id is not None:
            candidates = [
                model for model in candidates
                if _normalise_identity(model.get("provider_id")) ==
                   _normalise_identity(provider_id)
            ]
        elif provider_name is not None:
            candidates = [
                model for model in candidates
                if _normalise_identity(model.get("provider_name")) ==
                   _normalise_identity(provider_name)
            ]

        if len(candidates) == 1:
            return [(candidates[0], "UNIQUE_MODEL_IDENTITY", "MEDIUM")]

    return []


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
        textual proximity. The current P1 contract accepts an explicit
        model relationship when the ABOM/AI-BOM records expose compatible
        identity/context.

    For the initial contract, an ABOM agent is associated with resolved
    AI-BOM models supplied to the correlation boundary.
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
    # Semantic hardening:
    # Never create an Agent -> Model edge merely because both entities
    # exist.  Resolution must be evidence-backed and deterministic.
    #
    for agent in agents:
        resolved_links = _resolve_agent_model_links(agent, models)

        for model, link_method, link_confidence in resolved_links:
            relationship = _relationship(
                source_id=str(agent["component_id"]),
                source_type=BOM_ABOM,
                relationship_type=REL_USES,
                target_id=str(model["model_id"]),
                target_type=BOM_AI,
                source=agent,
                target=model,
            )
            relationship["link_method"] = link_method
            relationship["link_confidence"] = link_confidence
            relationships.append(relationship)

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
