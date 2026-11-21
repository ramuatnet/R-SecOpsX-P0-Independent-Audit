"""E1 (SAST overnight): SARIF codeFlows for supported taint paths.

Contract (plan E1): emit ``codeFlows``/``threadFlowLocations`` for
supported taint paths; keep file URI, region, rule ID, fingerprint and
identity stable; validate structure; NEVER invent intermediate locations.

The engine's ``taint_chain`` entries are EXPRESSIONS (``req.body``,
``UserModel.findOne``) -- the chain has no per-step file:line rows -- so
every thread-flow location carries the step expression as its message,
and a physicalLocation appears ONLY on the sink step, which is the
finding's own (real) location. A finding without a taint chain emits no
``codeFlows`` key at all.
"""
from __future__ import annotations

import pytest

from reporting.sarif_export import build_sarif


def _finding(**over):
    f = {
        "rule_id": "TAINT_DEMO", "title": "Tainted flow", "severity": "high",
        "file": "src/app.py", "line": 10,
        "taint_path": "req.body -> UserModel.findOne",
        "taint_chain": ["req.body", "UserModel.findOne"],
    }
    f.update(over)
    return f


def test_codeflows_emitted_from_real_taint_chain():
    sarif = build_sarif({"findings": [_finding()]})
    res = sarif["runs"][0]["results"][0]
    flows = res["codeFlows"]
    assert len(flows) == 1
    locs = flows[0]["threadFlows"][0]["locations"]
    assert [l["location"]["message"]["text"] for l in locs] == [
        "req.body", "UserModel.findOne"]
    # Never invent intermediate locations: only the SINK step carries the
    # finding's own physicalLocation.
    assert "physicalLocation" not in locs[0]["location"]
    sink = locs[1]["location"]["physicalLocation"]
    assert sink["artifactLocation"]["uri"] == "src/app.py"
    assert sink["region"]["startLine"] == 10


def test_no_codeflows_without_taint_chain():
    sarif = build_sarif({"findings": [_finding(taint_chain=[], taint_path="")]})
    res = sarif["runs"][0]["results"][0]
    assert "codeFlows" not in res


def test_no_codeflows_for_single_step_chain():
    # A "chain" of one expression is not a flow; emitting one would imply
    # a source-to-sink path the engine did not report.
    sarif = build_sarif({"findings": [_finding(taint_chain=["req.body"])]})
    res = sarif["runs"][0]["results"][0]
    assert "codeFlows" not in res


def test_identity_and_fingerprint_stable_with_codeflows():
    f = _finding()
    base = build_sarif({"findings": [dict(f, taint_chain=[], taint_path="")]})
    with_flows = build_sarif({"findings": [f]})
    r0, r1 = base["runs"][0]["results"][0], with_flows["runs"][0]["results"][0]
    assert r0["ruleId"] == r1["ruleId"] == "TAINT_DEMO"
    assert r0["partialFingerprints"] == r1["partialFingerprints"]
    assert r0["locations"] == r1["locations"]
    assert r0["level"] == r1["level"]


def test_codeflow_structure_is_sarif_2_1_0_shaped():
    # Offline structural validation: the official SARIF 2.1.0 schema is
    # NOT vendored and network fetches are prohibited, so this encodes
    # the 2.1.0 structural requirements for the codeFlows subtree:
    # codeFlows[].threadFlows[].locations[].location{message{text}
    # [, physicalLocation{artifactLocation{uri}, region{startLine}}]}.
    sarif = build_sarif({"findings": [_finding(taint_chain=["a", "b", "c"])]})
    res = sarif["runs"][0]["results"][0]
    for flow in res["codeFlows"]:
        assert isinstance(flow.get("threadFlows"), list) and flow["threadFlows"]
        for tf in flow["threadFlows"]:
            assert tf["locations"]
            for tfl in tf["locations"]:
                loc = tfl["location"]
                assert isinstance(loc.get("message", {}).get("text"), str)
                if "physicalLocation" in loc:
                    pl = loc["physicalLocation"]
                    assert pl["artifactLocation"]["uri"]
                    assert pl["region"]["startLine"] >= 1


# ---------------------------------------------------------------------------
# Phase B Wave 1 -- additive uid key (contract §7). The tests below are
# ADDITIVE. Correction note (F-W1-1, corrective closure): the initial
# Wave-1 edit inadvertently re-nested the legacy structural test's inner
# loop (only the last threadFlow was validated); it has been restored
# byte-identically to its 0da0d80 form, so the legacy assertions above are
# byte-unchanged again. test_multi_threadflow_codeflow_fully_validated
# pins the every-threadFlow validation semantics.
# ---------------------------------------------------------------------------

_UID = "b3id1-09bde52221c281601387248b7b1d325e"


def test_uid_key_present_and_equal_to_json_uid():
    f = _finding(finding_uid=_UID)
    sarif = build_sarif({"findings": [f]})
    res = sarif["runs"][0]["results"][0]
    assert res["partialFingerprints"]["rsecopsxFindingUid/v1"] == _UID
    assert res["partialFingerprints"]["primaryLocationLineHash"] == \
        "src/app.py:10:TAINT_DEMO"


def test_uid_key_absent_for_legacy_findings_never_fabricated():
    sarif = build_sarif({"findings": [_finding()]})
    res = sarif["runs"][0]["results"][0]
    assert "rsecopsxFindingUid/v1" not in res["partialFingerprints"]


def test_uid_key_stable_across_builds_with_codeflows():
    f = _finding(finding_uid=_UID)
    base = build_sarif({"findings": [dict(f, taint_chain=[], taint_path="")]})
    with_flows = build_sarif({"findings": [f]})
    r0, r1 = base["runs"][0]["results"][0], with_flows["runs"][0]["results"][0]
    assert r0["partialFingerprints"] == r1["partialFingerprints"]
    assert r0["partialFingerprints"]["rsecopsxFindingUid/v1"] == _UID


def test_multi_threadflow_codeflow_fully_validated(monkeypatch):
    """F-W1-1 focused regression (corrective closure): the legacy structural
    test must validate EVERY threadFlow of a codeFlow, not only the last.

    The initial Wave-1 edit demoted the legacy ``for tfl`` loop out of
    ``for tf`` (gate finding F-W1-1); under that defective nesting a defect
    planted in the FIRST threadFlow escapes validation. This test patches
    the code-flow producer with a TWO-threadFlow fixture carrying
    distinguishable locations -- the first structurally invalid -- and
    requires the legacy structural test to REJECT it. It therefore fails
    against the defective (demoted) validation and passes against the
    corrected (nested) one."""
    import reporting.sarif_export as se

    def _two_threadflows(finding):
        return [{"threadFlows": [
            {"locations": [{"location": {
                "message": {"text": "flow1-step"},                # distinguishable marker
                "physicalLocation": {"artifactLocation": {"uri": ""},
                                     "region": {"startLine": 0}},  # INVALID: empty uri, zero line
            }}]},
            {"locations": [{"location": {
                "message": {"text": "flow2-step"},                # distinguishable marker
                "physicalLocation": {"artifactLocation": {"uri": "src/flow2.py"},
                                     "region": {"startLine": 2}},  # valid
            }}]},
        ]}]

    monkeypatch.setattr(se, "_code_flows", _two_threadflows)
    # Corrected (nested) validation: the flow-1 defect MUST be rejected.
    with pytest.raises(AssertionError):
        test_codeflow_structure_is_sarif_2_1_0_shaped()
