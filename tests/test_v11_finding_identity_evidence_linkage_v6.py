from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.finding_model import normalize_finding, normalize_payload
from core.evidence_adapter import normalize_finding_evidence

def make_finding(line=42):
    return {"rule_id":"TEST-FINDING-ID","vuln_type":"prompt_injection","file":"src/app.py","line":line,"column":7,"snippet":"ignore previous instructions","severity":"Medium","evidence_valid":True,"evidence":"test evidence"}

def main():
    f1=normalize_finding(make_finding()); f2=normalize_finding(make_finding())
    assert f1["finding_id"] and f1["finding_id"] == f2["finding_id"] and len(f1["finding_id"]) == 36
    assert normalize_finding(make_finding(43))["finding_id"] != f1["finding_id"]
    e=make_finding(); e["finding_id"]="existing-canonical-id"
    assert normalize_finding(e)["finding_id"] == "existing-canonical-id"
    assert normalize_payload({"findings":[make_finding()]})["findings"][0]["finding_id"] == f1["finding_id"]
    ev=normalize_finding_evidence(f1)
    assert getattr(ev,"related_finding_id",None) == f1["finding_id"]
    # B3-ID Phase B Wave 2 (R-6 §4.4 Test 1): uid-preferred linkage case added;
    # the uid-less assertion above is RETAINED verbatim as the
    # historical-compatibility case (contract §4.4, strengthening-only).
    fu=make_finding(); fu["finding_uid"]="b3id1-" + "ab"*16
    fn=normalize_finding(fu)
    assert fn.get("finding_uid") == "b3id1-" + "ab"*16   # incoming uid survives normalization
    evu=normalize_finding_evidence(fn)
    assert getattr(evu,"related_finding_id",None) == "b3id1-" + "ab"*16
    print("[PASS] deterministic finding_id")
    print("[PASS] existing finding_id preserved")
    print("[PASS] distinct occurrence separation")
    print("[PASS] normalize_payload preservation")
    print("[PASS] evidence.related_finding_id linkage")
    print("[PASS] evidence.related_finding_id uid-preferred linkage (B3-ID R-6)")
    print("FINDING_ID_EVIDENCE_LINKAGE_ACCEPTED")
if __name__ == "__main__": main()
