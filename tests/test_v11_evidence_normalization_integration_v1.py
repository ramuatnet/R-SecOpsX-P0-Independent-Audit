from core.finding_model import normalize_finding


def base_finding():
    return {
        "finding_id": "11111111-1111-4111-8111-111111111111",
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
        "detected_at": "2026-10-02T00:00:00+00:00",
    }


def test_normalization_attaches_canonical_evidence():
    f = normalize_finding(base_finding())
    evidence = f["canonical_evidence"]

    assert evidence["evidence_id"]
    assert evidence["type"] == "taint"
    assert evidence["confidence"] == "HIGH"
    assert evidence["related_finding_id"] == f["finding_id"]
    assert evidence["timestamp"] == f["detected_at"]
    assert evidence["source"]["engine"] == "R-SecOpsX"
    assert evidence["provenance"]["engine"] == "R-SecOpsX"


def test_normalization_attaches_uid_preferred_evidence():
    """B3-ID Phase B Wave 2 (R-6 §4.4 Test 2): uid-preferred linkage case.

    Strengthening-only addition (contract §4.4): a uid-bearing finding gets
    related_finding_id == finding_uid; the pre-existing uuid5 case in
    test_normalization_attaches_canonical_evidence is retained unchanged as
    the historical-compatibility case.
    """
    f_in = base_finding()
    f_in["finding_uid"] = "b3id1-" + "cd"*16
    f = normalize_finding(f_in)
    assert f["finding_uid"] == "b3id1-" + "cd"*16  # incoming uid preserved
    evidence = f["canonical_evidence"]
    assert evidence["related_finding_id"] == "b3id1-" + "cd"*16
    # dual-ID coexistence: the uuid5 finding_id is still on the finding (§2.5)
    assert f["finding_id"] == "11111111-1111-4111-8111-111111111111"


def test_normalization_attaches_qualified_evidence():
    f = normalize_finding(base_finding())
    q = f["canonical_qualified_evidence"]

    assert q["qualified"] is True
    assert q["evidence"]["evidence_id"] == f["canonical_evidence"]["evidence_id"]
    assert f["canonical_evidence_state"] == "qualified"


def test_legacy_evidence_fields_are_preserved():
    original = base_finding()
    f = normalize_finding(original)

    for key in (
        "evidence",
        "evidence_valid",
        "evidence_score",
        "evidence_confidence",
        "confidence_score",
        "confidence_label",
        "classification",
        "evidence_state",
    ):
        if key in original:
            assert f[key] == normalize_finding(dict(original))[key]


def test_invalid_legacy_evidence_does_not_become_qualified():
    f0 = base_finding()
    f0["evidence_valid"] = False
    f = normalize_finding(f0)

    assert f["evidence_valid"] is False
    assert f["canonical_evidence_state"] == "not_qualified"
    assert f["canonical_qualified_evidence"]["qualified"] is False
    assert f["classification"] == "informational"


def test_successful_canonical_evidence_clears_stale_error():
    f0 = base_finding()
    f0["canonical_evidence_error"] = "stale error from earlier normalization attempt"

    f = normalize_finding(f0)

    assert f["canonical_evidence_state"] == "qualified"
    assert f["canonical_qualified_evidence"]["qualified"] is True
    assert "canonical_evidence_error" not in f

def test_missing_concrete_evidence_is_explicitly_surfaced():
    f0 = base_finding()
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
        f0.pop(key, None)

    f = normalize_finding(f0)

    assert "canonical_evidence" not in f
    assert f["canonical_evidence_state"] == "unavailable"
    assert f["canonical_evidence_error"]

