from __future__ import annotations

from typing import Any, Mapping

from .evidence_schema import (
    Evidence,
    EvidenceConfidence,
    EvidenceProvenance,
    EvidenceSource,
    EvidenceType,
    EvidenceValidationError,
    qualify_evidence,
    utc_now_iso8601,
)


_EVIDENCE_TYPE_MAP = {
    "taint": EvidenceType.TAINT,
    "taint-confirmed": EvidenceType.TAINT,
    "taint_validated": EvidenceType.TAINT,
    "sink": EvidenceType.SINK,
    "static": EvidenceType.STATIC,
    "pattern": EvidenceType.PATTERN,
    "dependency": EvidenceType.DEPENDENCY,
    "secret": EvidenceType.SECRET,
    "graph": EvidenceType.GRAPH,
    "context": EvidenceType.CONTEXT,
    "dynamic": EvidenceType.DYNAMIC,
}


def normalize_finding_evidence(
    finding: Mapping[str, Any],
    *,
    engine: str = "R-SecOpsX",
    component: str = "finding-normalization",
    tool: str | None = None,
    decision_consumer: str | None = None,
    observed_at: str | None = None,
) -> Evidence:
    """Convert an existing V11 finding into canonical Evidence.

    This adapter is deliberately non-mutating. Existing V11 fields remain
    authoritative for the finding contract.

    Important boundary:
    finding metadata (rule/file/line/vulnerability type) is context, not
    evidence by itself. At least one concrete evidence value must exist.
    """
    if not isinstance(finding, Mapping):
        raise EvidenceValidationError("finding must be a mapping")

    evidence_values = _extract_evidence_values(finding)
    if not evidence_values:
        raise EvidenceValidationError(
            "No concrete evidence could be established from finding"
        )

    content = _build_content_context(finding, evidence_values)

    evidence_type = _resolve_evidence_type(finding)
    confidence = _resolve_confidence(finding)

    observed = observed_at or _first_nonempty(
        finding.get("detected_at"),
        finding.get("observed_at"),
        finding.get("timestamp"),
    ) or utc_now_iso8601()

    provenance_source = _first_nonempty(
        finding.get("provenance"),
        finding.get("evidence_source"),
        finding.get("detection"),
        "R-SecOpsX finding normalization",
    )

    provenance = EvidenceProvenance(
        source=str(provenance_source),
        observed_at=str(observed),
        engine=str(engine),
        component=str(component),
        tool=tool,
        decision_consumer=decision_consumer,
    )

    source = EvidenceSource(
        engine=str(engine),
        component=str(component),
        tool=tool,
    )

    return Evidence.create(
        evidence_id=_stable_or_generated_id(finding),
        source=source,
        provenance=provenance,
        evidence_type=evidence_type,
        content_or_context=content,
        confidence=confidence,
        related_finding_id=_first_nonempty(
            finding.get("finding_id"),
            finding.get("id"),
            finding.get("fingerprint"),
        ),
        timestamp=str(observed),
    )


def qualify_finding_evidence(
    finding: Mapping[str, Any],
    *,
    engine: str = "R-SecOpsX",
    component: str = "finding-normalization",
    tool: str | None = None,
    decision_consumer: str | None = None,
) -> Any:
    """Return canonical Evidence plus the existing V11 qualification result.

    Existing evidence_valid remains authoritative. This adapter does not
    reinterpret the V11 evidence gate.
    """
    evidence = normalize_finding_evidence(
        finding,
        engine=engine,
        component=component,
        tool=tool,
        decision_consumer=decision_consumer,
    )

    valid = finding.get("evidence_valid")
    if valid is None:
        detail = finding.get("evidence_validation_detail")
        if isinstance(detail, Mapping) and "valid" in detail:
            valid = detail.get("valid")

    if valid is None:
        raise EvidenceValidationError(
            "Existing V11 evidence_valid/evidence_validation_detail.valid is absent; "
            "adapter refuses to guess qualification"
        )

    detail = finding.get("evidence_validation_detail")
    detail_reason = (
        detail.get("reason")
        if isinstance(detail, Mapping)
        else None
    )
    reason = _first_nonempty(
        finding.get("evidence_reason"),
        finding.get("evidence_validation"),
        detail_reason,
        "Existing V11 evidence validation result",
    )

    return qualify_evidence(
        evidence,
        qualified=bool(valid),
        reason=str(reason),
    )


def _extract_evidence_values(finding: Mapping[str, Any]) -> list[Any]:
    values: list[Any] = []

    direct = finding.get("evidence")
    if isinstance(direct, (list, tuple)):
        values.extend(x for x in direct if x not in (None, ""))
    elif direct not in (None, ""):
        values.append(direct)

    detail = finding.get("evidence_validation_detail")
    if isinstance(detail, Mapping):
        detail_evidence = detail.get("evidence")
        if isinstance(detail_evidence, (list, tuple)):
            values.extend(x for x in detail_evidence if x not in (None, ""))
        elif detail_evidence not in (None, ""):
            values.append(detail_evidence)

    # These are concrete observations, not merely finding metadata.
    for key in (
        "snippet",
        "taint_path",
        "source_expr",
        "sink_call",
        "sink_category",
        "description",
        "evidence_reason",
    ):
        value = finding.get(key)
        if value not in (None, ""):
            values.append(value)

    return values


def _build_content_context(
    finding: Mapping[str, Any], evidence_values: list[Any]
) -> dict[str, Any]:
    content: dict[str, Any] = {"evidence": evidence_values}

    for key in (
        "vuln_type",
        "rule_id",
        "file",
        "full_path",
        "filepath",
        "line",
        "snippet",
        "taint_path",
        "source_var",
        "source_expr",
        "sink_category",
        "sink_call",
        "detection",
        "evidence_score",
        "evidence_quality",
        "evidence_valid",
        "evidence_state",
        "evidence_confidence",
        "confidence_score",
        "confidence_label",
        "finding_class",
    ):
        if key in finding and finding[key] is not None:
            content[key] = finding[key]

    return content


def _resolve_evidence_type(finding: Mapping[str, Any]) -> EvidenceType:
    for value in (
        finding.get("evidence_type"),
        finding.get("detection"),
        finding.get("vuln_type"),
    ):
        if value:
            text = str(value).strip().lower()
            for token, mapped in _EVIDENCE_TYPE_MAP.items():
                if token in text:
                    return mapped

    detail = finding.get("evidence_validation_detail")
    if isinstance(detail, Mapping):
        if detail.get("taint_validated"):
            return EvidenceType.TAINT
        if detail.get("sink_valid"):
            return EvidenceType.SINK

    return EvidenceType.STATIC


def _resolve_confidence(finding: Mapping[str, Any]) -> EvidenceConfidence:
    for value in (
        finding.get("evidence_confidence"),
        finding.get("confidence"),
        finding.get("confidence_label"),
    ):
        if value:
            text = str(value).strip().upper()
            if text in EvidenceConfidence.__members__:
                return EvidenceConfidence[text]

    score = finding.get("confidence_score")
    try:
        score_value = float(score)
    except (TypeError, ValueError):
        score_value = None

    if score_value is not None:
        if score_value >= 75:
            return EvidenceConfidence.HIGH
        if score_value >= 55:
            return EvidenceConfidence.MEDIUM
        if score_value > 0:
            return EvidenceConfidence.LOW

    return EvidenceConfidence.UNKNOWN


def _stable_or_generated_id(finding: Mapping[str, Any]) -> str | None:
    candidate = finding.get("evidence_id")
    if candidate:
        return str(candidate)
    return None


def _first_nonempty(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None
