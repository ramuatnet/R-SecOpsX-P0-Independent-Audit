from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import UUID, uuid4


class EvidenceValidationError(ValueError):
    """Raised when Evidence violates the V11 canonical contract."""


class EvidenceConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class EvidenceType(str, Enum):
    PATTERN = "pattern"
    TAINT = "taint"
    SINK = "sink"
    STATIC = "static"
    DYNAMIC = "dynamic"
    DEPENDENCY = "dependency"
    SECRET = "secret"
    GRAPH = "graph"
    CONTEXT = "context"
    OTHER = "other"


class VerificationStatus(str, Enum):
    """T-4.2 dynamic-verification outcome for one finding's PoC.

    UNTESTED      -- PoC generated; no capture has been attempted.
    REPRODUCED    -- capture ran and the stated expectation matched.
    REFUTED       -- capture ran and the stated expectation failed.
    INCONCLUSIVE  -- capture ran but carried no expectation to judge.
    BLOCKED       -- the sandbox could not bring the target up (runtime
                     missing, launch failed, ready timeout).
    """

    UNTESTED = "UNTESTED"
    REPRODUCED = "REPRODUCED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class EvidenceSource:
    engine: str
    component: str
    tool: str | None = None

    def validate(self) -> None:
        _required(self.engine, "source.engine")
        _required(self.component, "source.component")


@dataclass(frozen=True)
class EvidenceProvenance:
    source: str
    observed_at: str
    engine: str
    component: str
    tool: str | None = None
    decision_consumer: str | None = None

    def validate(self) -> None:
        _required(self.source, "provenance.source")
        _required(self.observed_at, "provenance.observed_at")
        _required(self.engine, "provenance.engine")
        _required(self.component, "provenance.component")
        validate_iso8601(self.observed_at)


@dataclass(frozen=True)
class EvidenceTimestamp:
    value: str

    def validate(self) -> None:
        validate_iso8601(self.value)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: EvidenceSource
    timestamp: EvidenceTimestamp
    provenance: EvidenceProvenance
    type: EvidenceType
    content_or_context: Any
    confidence: EvidenceConfidence
    related_finding_id: str | None = None
    # T-4.2: defaults keep every pre-T-4 constructor and mapping round-trip
    # byte-compatible; only the repro bundler writes anything else.
    verification_status: VerificationStatus = VerificationStatus.UNTESTED

    @classmethod
    def create(
        cls,
        *,
        source: EvidenceSource,
        provenance: EvidenceProvenance,
        evidence_type: EvidenceType,
        content_or_context: Any,
        confidence: EvidenceConfidence = EvidenceConfidence.UNKNOWN,
        related_finding_id: str | None = None,
        evidence_id: str | None = None,
        timestamp: str | None = None,
        verification_status: VerificationStatus = VerificationStatus.UNTESTED,
    ) -> "Evidence":
        obj = cls(
            evidence_id=evidence_id or str(uuid4()),
            source=source,
            timestamp=EvidenceTimestamp(timestamp or utc_now_iso8601()),
            provenance=provenance,
            type=evidence_type,
            content_or_context=content_or_context,
            confidence=confidence,
            related_finding_id=related_finding_id,
            verification_status=verification_status,
        )
        obj.validate()
        return obj

    def validate(self) -> None:
        validate_uuid(self.evidence_id)
        self.source.validate()
        self.timestamp.validate()
        self.provenance.validate()
        if not isinstance(self.type, EvidenceType):
            raise EvidenceValidationError("type must be EvidenceType")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise EvidenceValidationError("confidence must be EvidenceConfidence")
        if not isinstance(self.verification_status, VerificationStatus):
            raise EvidenceValidationError(
                "verification_status must be VerificationStatus")
        if self.content_or_context is None:
            raise EvidenceValidationError("content_or_context is required")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "evidence_id": self.evidence_id,
            "source": asdict(self.source),
            "timestamp": self.timestamp.value,
            "provenance": asdict(self.provenance),
            "type": self.type.value,
            "content_or_context": self.content_or_context,
            "confidence": self.confidence.value,
            "related_finding_id": self.related_finding_id,
            "verification_status": self.verification_status.value,
        }


@dataclass(frozen=True)
class QualifiedEvidence:
    evidence: Evidence
    qualified: bool
    qualification_reason: str
    qualified_at: str

    def validate(self) -> None:
        self.evidence.validate()
        validate_iso8601(self.qualified_at)
        _required(self.qualification_reason, "qualification_reason")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "evidence": self.evidence.to_dict(),
            "qualified": self.qualified,
            "qualification_reason": self.qualification_reason,
            "qualified_at": self.qualified_at,
        }


def utc_now_iso8601() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_uuid(value: str) -> str:
    _required(value, "evidence_id")
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise EvidenceValidationError(f"Invalid UUID: {value!r}") from exc


def validate_iso8601(value: str) -> str:
    _required(value, "timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise EvidenceValidationError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    return value


def qualify_evidence(
    evidence: Evidence,
    *,
    qualified: bool,
    reason: str,
    qualified_at: str | None = None,
) -> QualifiedEvidence:
    result = QualifiedEvidence(
        evidence=evidence,
        qualified=bool(qualified),
        qualification_reason=reason,
        qualified_at=qualified_at or utc_now_iso8601(),
    )
    result.validate()
    return result


def evidence_from_mapping(data: Mapping[str, Any]) -> Evidence:
    if not isinstance(data, Mapping):
        raise EvidenceValidationError("Evidence input must be a mapping")

    source_data = data.get("source")
    provenance_data = data.get("provenance")
    if not isinstance(source_data, Mapping):
        raise EvidenceValidationError("source must be a mapping")
    if not isinstance(provenance_data, Mapping):
        raise EvidenceValidationError("provenance must be a mapping")

    try:
        etype = EvidenceType(str(data["type"]).lower())
        confidence = EvidenceConfidence(str(data["confidence"]).upper())
    except (KeyError, ValueError) as exc:
        raise EvidenceValidationError("Invalid type or confidence") from exc

    evidence = Evidence(
        evidence_id=str(data.get("evidence_id") or ""),
        source=EvidenceSource(
            engine=str(source_data.get("engine") or ""),
            component=str(source_data.get("component") or ""),
            tool=source_data.get("tool"),
        ),
        timestamp=EvidenceTimestamp(str(data.get("timestamp") or "")),
        provenance=EvidenceProvenance(
            source=str(provenance_data.get("source") or ""),
            observed_at=str(provenance_data.get("observed_at") or ""),
            engine=str(provenance_data.get("engine") or ""),
            component=str(provenance_data.get("component") or ""),
            tool=provenance_data.get("tool"),
            decision_consumer=provenance_data.get("decision_consumer"),
        ),
        type=etype,
        content_or_context=data.get("content_or_context"),
        confidence=confidence,
        related_finding_id=data.get("related_finding_id"),
        verification_status=_verification_status(data.get(
            "verification_status")),
    )
    evidence.validate()
    return evidence


def _verification_status(value: Any) -> VerificationStatus:
    if value is None or value == "":
        return VerificationStatus.UNTESTED
    try:
        return VerificationStatus(str(value))
    except ValueError as exc:
        raise EvidenceValidationError(
            f"Invalid verification_status: {value!r}") from exc


def _required(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceValidationError(f"{field_name} is required")
