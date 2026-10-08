from datetime import datetime, timezone
from uuid import uuid4

import pytest

from core.evidence_adapter import (
    normalize_finding_evidence,
    qualify_finding_evidence,
)
from core.evidence_schema import EvidenceValidationError, EvidenceConfidence, EvidenceType


def observed():
    return datetime.now(timezone.utc).isoformat()


def base_finding(**extra):
    data = {
        "finding_id": str(uuid4()),
        "vuln_type": "ssrf",
        "rule_id": "SAST-SSRF-001",
        "file": "app.py",
        "line": 42,
        "snippet": "requests.get(url)",
        "detection": "AST Taint Analysis",
        "evidence": ["source -> requests.get"],
        "evidence_valid": True,
        "evidence_score": 90,
        "evidence_confidence": "HIGH",
        "confidence_score": 90,
        "confidence_label": "HIGH",
        "detected_at": observed(),
    }
    data.update(extra)
    return data


def test_adapter_does_not_mutate_finding():
    f = base_finding()
    before = dict(f)
    normalize_finding_evidence(f)
    assert f == before


def test_maps_taint_evidence():
    e = normalize_finding_evidence(base_finding())
    assert e.type is EvidenceType.TAINT


def test_maps_high_confidence():
    e = normalize_finding_evidence(base_finding())
    assert e.confidence is EvidenceConfidence.HIGH


def test_preserves_finding_identity_as_related_id():
    f = base_finding()
    e = normalize_finding_evidence(f)
    assert e.related_finding_id == f["finding_id"]


def test_uses_existing_detected_at():
    f = base_finding()
    e = normalize_finding_evidence(f)
    assert e.timestamp.value == f["detected_at"]


def test_missing_evidence_rejected():
    f = base_finding()
    for key in (
        "evidence",
        "snippet",
        "taint_path",
        "source_expr",
        "sink_call",
        "sink_category",
        "description",
        "evidence_reason",
    ):
        f.pop(key, None)

    with pytest.raises(EvidenceValidationError):
        normalize_finding_evidence(f)


def test_missing_qualification_rejected():
    with pytest.raises(EvidenceValidationError):
        qualify_finding_evidence(
            base_finding(
                evidence_valid=None,
                evidence_validation_detail=None,
            )
        )


def test_false_existing_gate_is_preserved():
    q = qualify_finding_evidence(
        base_finding(
            evidence_valid=False,
            evidence_reason="Evidence rejected by existing V11 validator",
        )
    )
    assert q.qualified is False


def test_existing_detail_valid_is_supported():
    f = base_finding()
    f.pop("evidence_valid")
    f["evidence_validation_detail"] = {
        "valid": True,
        "reason": "Validated",
        "evidence": ["source -> sink"],
        "taint_validated": True,
    }
    q = qualify_finding_evidence(f)
    assert q.qualified is True


def test_existing_confidence_score_fallback():
    f = base_finding()
    f.pop("evidence_confidence")
    f["confidence_label"] = ""
    f["confidence_score"] = 75

    e = normalize_finding_evidence(f)

    assert e.confidence is EvidenceConfidence.HIGH
