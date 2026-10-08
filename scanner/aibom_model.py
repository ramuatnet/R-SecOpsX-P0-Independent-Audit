"""
R-SecOpsX V11
AI-BOM P1.1 — Canonical AI Asset Graph Contract

This module defines the canonical AI-BOM entities and relationships.

Design principles:
- deterministic semantic IDs
- explicit provenance
- deterministic serialization
- duplicate suppression
- no detection logic
- compatible with existing P0.5 model-resolution output
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import re
from typing import Any


CONTRACT_VERSION = "AI-BOM-P1.1"


def _normalize(value: Any) -> str:
    """Normalize a semantic identifier component deterministically."""
    text = "" if value is None else str(value)
    text = text.strip().lower()
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"[^a-z0-9._:@/+%-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text.strip("-")


def _stable_hash(value: Any) -> str:
    """Return a deterministic short SHA-256 identifier."""
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Provenance:
    source: str | None = None
    evidence_type: tuple[str, ...] = ()
    file: str | None = None
    line: int | None = None
    column: int | None = None
    detector: str | None = None
    confidence: float | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Provider:
    provider_id: str
    provider_name: str
    provider_type: str | None = None
    evidence: list[Any] = field(default_factory=list)
    confidence: float | None = None

    @classmethod
    def create(
        cls,
        provider_name: str,
        provider_type: str | None = None,
        evidence: list[Any] | None = None,
        confidence: float | None = None,
    ) -> "Provider":
        normalized = _normalize(provider_name)
        return cls(
            provider_id=f"provider:{normalized}",
            provider_name=provider_name,
            provider_type=provider_type,
            evidence=list(evidence or []),
            confidence=confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Model:
    model_id: str
    model_name: str
    version: str | None = None
    revision: str | None = None
    model_type: str | None = None
    usage_type: str | None = None
    resolution: str | None = None
    provenance: list[Provenance] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        model_name: str,
        version: str | None = None,
        revision: str | None = None,
        model_type: str | None = None,
        usage_type: str | None = None,
        resolution: str | None = None,
        provenance: list[Provenance] | None = None,
        provider_name: str | None = None,
    ) -> "Model":
        parts = [
            _normalize(provider_name) if provider_name else None,
            _normalize(model_name),
            _normalize(version) if version else None,
            _normalize(revision) if revision else None,
        ]
        semantic = ":".join(x for x in parts if x)
        return cls(
            model_id=f"model:{semantic}",
            model_name=model_name,
            version=version,
            revision=revision,
            model_type=model_type,
            usage_type=usage_type,
            resolution=resolution,
            provenance=list(provenance or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Framework:
    framework_id: str
    framework: str
    version: str | None = None
    package: str | None = None

    @classmethod
    def create(
        cls,
        framework: str,
        version: str | None = None,
        package: str | None = None,
    ) -> "Framework":
        package_value = package or framework
        semantic = ":".join(
            x for x in (
                _normalize(package_value),
                _normalize(version) if version else None,
            )
            if x
        )
        return cls(
            framework_id=f"framework:{semantic}",
            framework=framework,
            version=version,
            package=package,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Deployment:
    deployment_id: str
    endpoint: str | None = None
    endpoint_type: str | None = None
    deployment_type: str | None = None

    @classmethod
    def create(
        cls,
        endpoint: str | None = None,
        endpoint_type: str | None = None,
        deployment_type: str | None = None,
    ) -> "Deployment":
        identity = {
            "endpoint": endpoint or "",
            "endpoint_type": endpoint_type or "",
            "deployment_type": deployment_type or "",
        }
        return cls(
            deployment_id=f"deployment:{_stable_hash(identity)}",
            endpoint=endpoint,
            endpoint_type=endpoint_type,
            deployment_type=deployment_type,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AIComponent:
    component_id: str
    component_name: str
    component_type: str | None = None
    evidence: list[Any] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        component_name: str,
        component_type: str | None = None,
        evidence: list[Any] | None = None,
        provenance: list[Provenance] | None = None,
    ) -> "AIComponent":
        return cls(
            component_id=f"ai-component:{_normalize(component_name)}",
            component_name=component_name,
            component_type=component_type,
            evidence=list(evidence or []),
            provenance=list(provenance or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Relationship:
    relationship_id: str
    source_id: str
    relationship_type: str
    target_id: str
    evidence: tuple[Any, ...] = ()
    confidence: float | None = None

    @classmethod
    def create(
        cls,
        source_id: str,
        relationship_type: str,
        target_id: str,
        evidence: list[Any] | None = None,
        confidence: float | None = None,
    ) -> "Relationship":
        identity = {
            "source_id": source_id,
            "relationship_type": relationship_type,
            "target_id": target_id,
        }
        return cls(
            relationship_id=f"relationship:{_stable_hash(identity)}",
            source_id=source_id,
            relationship_type=relationship_type,
            target_id=target_id,
            evidence=tuple(evidence or []),
            confidence=confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AIBOMGraph:
    contract_version: str = CONTRACT_VERSION
    providers: list[Provider] = field(default_factory=list)
    models: list[Model] = field(default_factory=list)
    frameworks: list[Framework] = field(default_factory=list)
    deployments: list[Deployment] = field(default_factory=list)
    components: list[AIComponent] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)

    def add_provider(self, provider: Provider) -> Provider:
        for existing in self.providers:
            if existing.provider_id == provider.provider_id:
                return existing
        self.providers.append(provider)
        return provider

    def add_model(self, model: Model) -> Model:
        for existing in self.models:
            if existing.model_id == model.model_id:
                return existing
        self.models.append(model)
        return model

    def add_framework(self, framework: Framework) -> Framework:
        for existing in self.frameworks:
            if existing.framework_id == framework.framework_id:
                return existing
        self.frameworks.append(framework)
        return framework

    def add_deployment(self, deployment: Deployment) -> Deployment:
        for existing in self.deployments:
            if existing.deployment_id == deployment.deployment_id:
                return existing
        self.deployments.append(deployment)
        return deployment

    def add_component(self, component: AIComponent) -> AIComponent:
        for existing in self.components:
            if existing.component_id == component.component_id:
                return existing
        self.components.append(component)
        return component

    def add_relationship(self, relationship: Relationship) -> Relationship:
        for existing in self.relationships:
            if existing.relationship_id == relationship.relationship_id:
                return existing
        self.relationships.append(relationship)
        return relationship

    def sort_deterministically(self) -> None:
        self.providers.sort(key=lambda x: x.provider_id)
        self.models.sort(key=lambda x: x.model_id)
        self.frameworks.sort(key=lambda x: x.framework_id)
        self.deployments.sort(key=lambda x: x.deployment_id)
        self.components.sort(key=lambda x: x.component_id)
        self.relationships.sort(key=lambda x: x.relationship_id)

    def to_dict(self) -> dict[str, Any]:
        self.sort_deterministically()
        return {
            "contract_version": self.contract_version,
            "providers": [x.to_dict() for x in self.providers],
            "models": [x.to_dict() for x in self.models],
            "frameworks": [x.to_dict() for x in self.frameworks],
            "deployments": [x.to_dict() for x in self.deployments],
            "components": [x.to_dict() for x in self.components],
            "relationships": [x.to_dict() for x in self.relationships],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )