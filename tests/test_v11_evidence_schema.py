from datetime import datetime, timezone
from uuid import uuid4
import pytest
from core.evidence_schema import *

def make_evidence():
    observed = datetime.now(timezone.utc).isoformat()
    return Evidence.create(
        source=EvidenceSource("scanner.sast", "scanner/sast.py", "R-SecOpsX"),
        provenance=EvidenceProvenance("static-analysis", observed, "scanner.sast", "scanner/sast.py", "R-SecOpsX"),
        evidence_type=EvidenceType.STATIC,
        content_or_context={"rule_id": "TEST-001", "line": 10},
        confidence=EvidenceConfidence.MEDIUM,
    )

def test_01_uuid_generated(): validate_uuid(make_evidence().evidence_id)
def test_02_timestamp_valid(): validate_iso8601(make_evidence().timestamp.value)
def test_03_provenance_required(): make_evidence().provenance.validate()
def test_04_source_required():
    with pytest.raises(EvidenceValidationError):
        Evidence.create(source=EvidenceSource("", "x"), provenance=EvidenceProvenance("s", datetime.now(timezone.utc).isoformat(), "e", "c"), evidence_type=EvidenceType.STATIC, content_or_context={})
def test_05_confidence_controlled(): assert make_evidence().confidence is EvidenceConfidence.MEDIUM
def test_06_type_controlled(): assert make_evidence().type is EvidenceType.STATIC
def test_07_content_required():
    with pytest.raises(EvidenceValidationError):
        Evidence.create(source=EvidenceSource("e","c"), provenance=EvidenceProvenance("s", datetime.now(timezone.utc).isoformat(), "e", "c"), evidence_type=EvidenceType.STATIC, content_or_context=None)
def test_08_qualification_preserves_id():
    e=make_evidence(); q=qualify_evidence(e, qualified=True, reason="source and sink evidence present"); assert q.evidence.evidence_id==e.evidence_id
def test_09_bad_uuid():
    with pytest.raises(EvidenceValidationError): validate_uuid("bad")
def test_10_bad_timestamp():
    with pytest.raises(EvidenceValidationError): validate_iso8601("bad")
def test_11_missing_provenance():
    with pytest.raises(EvidenceValidationError):
        evidence_from_mapping({"evidence_id":str(uuid4()),"source":{"engine":"e","component":"c"},"timestamp":datetime.now(timezone.utc).isoformat(),"type":"static","content_or_context":{},"confidence":"HIGH"})
def test_12_round_trip():
    e=make_evidence(); assert evidence_from_mapping(e.to_dict()).to_dict()==e.to_dict()
