from __future__ import annotations
import ast, shutil, subprocess, sys, uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
BACKUP = ROOT / "backup"
TESTS = ROOT / "tests"
FINDING = ROOT / "core" / "finding_model.py"
EVIDENCE = ROOT / "core" / "evidence_adapter.py"
SCHEMA = ROOT / "core" / "evidence_schema.py"
BACKUP.mkdir(parents=True, exist_ok=True); TESTS.mkdir(parents=True, exist_ok=True)
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
finding_backup = BACKUP / f"finding_model.py.before_finding_identity_v6_{stamp}.py"
evidence_backup = BACKUP / f"evidence_adapter.py.before_finding_identity_v6_{stamp}.py"
test_file = TESTS / "test_v11_finding_identity_evidence_linkage_v6.py"
finding_original = FINDING.read_bytes(); evidence_original = EVIDENCE.read_bytes()

def restore():
    FINDING.write_bytes(finding_original); EVIDENCE.write_bytes(evidence_original)

TEST = '''from pathlib import Path\nimport sys\nROOT = Path(__file__).resolve().parents[1]\nsys.path.insert(0, str(ROOT))\nfrom core.finding_model import normalize_finding, normalize_payload\nfrom core.evidence_adapter import normalize_finding_evidence\n\ndef make_finding(line=42):\n    return {"rule_id":"TEST-FINDING-ID","vuln_type":"prompt_injection","file":"src/app.py","line":line,"column":7,"snippet":"ignore previous instructions","severity":"Medium","evidence_valid":True,"evidence":"test evidence"}\n\ndef main():\n    f1=normalize_finding(make_finding()); f2=normalize_finding(make_finding())\n    assert f1["finding_id"] and f1["finding_id"] == f2["finding_id"] and len(f1["finding_id"]) == 36\n    assert normalize_finding(make_finding(43))["finding_id"] != f1["finding_id"]\n    e=make_finding(); e["finding_id"]="existing-canonical-id"\n    assert normalize_finding(e)["finding_id"] == "existing-canonical-id"\n    assert normalize_payload({"findings":[make_finding()]})["findings"][0]["finding_id"] == f1["finding_id"]\n    ev=normalize_finding_evidence(f1)\n    assert getattr(ev,"related_finding_id",None) == f1["finding_id"]\n    print("[PASS] deterministic finding_id")\n    print("[PASS] existing finding_id preserved")\n    print("[PASS] distinct occurrence separation")\n    print("[PASS] normalize_payload preservation")\n    print("[PASS] evidence.related_finding_id linkage")\n    print("FINDING_ID_EVIDENCE_LINKAGE_ACCEPTED")\nif __name__ == "__main__": main()\n'''

try:
    for p in (FINDING,EVIDENCE,SCHEMA):
        if not p.is_file(): raise RuntimeError(f"Required production file does not exist: {p}")
        print(f"[PASS] Production path exists: {p}")
    shutil.copy2(FINDING,finding_backup); shutil.copy2(EVIDENCE,evidence_backup)
    print(f"[PASS] Finding-model backup: {finding_backup}")
    print(f"[PASS] Evidence-adapter backup: {evidence_backup}")
    finding=FINDING.read_text(encoding="utf-8-sig"); evidence=EVIDENCE.read_text(encoding="utf-8-sig"); schema=SCHEMA.read_text(encoding="utf-8-sig")
    print("[PASS] Production source decoded with utf-8-sig")
    if "related_finding_id" not in schema: raise RuntimeError("Evidence schema does not expose related_finding_id")
    print("[PASS] Evidence schema exposes related_finding_id")
    tree=ast.parse(finding,filename=str(FINDING)); funcs=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
    classify=next((n for n in funcs if n.name=="classify_finding"),None); normalize=next((n for n in funcs if n.name=="normalize_finding"),None)
    if classify is None or normalize is None: raise RuntimeError("Actual classify_finding()/normalize_finding() structure not found")
    print(f"[PASS] Located classify_finding() at line {classify.lineno}"); print(f"[PASS] Located normalize_finding() at line {normalize.lineno}")
    if 'related_finding_id=_first_nonempty(\n            finding.get("finding_id"),' not in evidence:
        raise RuntimeError("Current evidence_adapter.py does not contain the established finding_id -> related_finding_id linkage.")
    print("[PASS] Existing evidence adapter consumes canonical finding_id")
    if not any(isinstance(n,ast.Import) and any(a.name=="uuid" for a in n.names) for n in tree.body):
        lines=finding.splitlines(keepends=True); imports=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))]; nl="\r\n" if "\r\n" in finding else "\n"
        if imports: lines.insert(max(n.end_lineno for n in imports),"import uuid"+nl)
        else: lines.insert(0,"import uuid"+nl)
        finding="".join(lines); print("[PASS] Added uuid import at discovered import boundary")
    else: print("[PASS] uuid import already present")
    marker="_RSECOPSX_CANONICAL_FINDING_ID_V1"
    if marker not in finding:
        tree=ast.parse(finding,filename=str(FINDING)); classify=next(n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="classify_finding"); nl="\r\n" if "\r\n" in finding else "\n"
        helper=(marker+' = "rsecopsx-v11:finding:"'+nl+nl+"def _canonical_finding_id(f: dict) -> str:"+nl+"    existing = str(f.get('finding_id') or '').strip()"+nl+"    if existing:"+nl+"        return existing"+nl+nl+"    parts = ("+nl+"        str(f.get('rule_id') or '').strip(),"+nl+"        str(f.get('vuln_type') or '').strip(),"+nl+"        str(f.get('file') or f.get('path') or '').replace('\\\\', '/').strip(),"+nl+"        str(f.get('line') if f.get('line') is not None else '').strip(),"+nl+"        str(f.get('column') if f.get('column') is not None else '').strip(),"+nl+"        str(f.get('sink_category') or '').strip(),"+nl+"        str(f.get('source') or '').strip(),"+nl+"        str(f.get('snippet') or '')[:1000].strip(),"+nl+"    )"+nl+"    seed = '|'.join(parts)"+nl+"    return str(uuid.uuid5(uuid.NAMESPACE_URL, "+marker+" + seed))"+nl+nl)
        lines=finding.splitlines(keepends=True); lines.insert(classify.lineno-1,helper); finding="".join(lines); print("[PASS] Installed canonical finding identity helper")
    else: print("[PASS] Canonical finding identity helper already present")
    tree=ast.parse(finding,filename=str(FINDING)); normalize=next(n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="normalize_finding"); assignment="    f['finding_id'] = _canonical_finding_id(f)"
    if assignment not in finding:
        lines=finding.splitlines(keepends=True); anchor=None
        for node in normalize.body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=="f" and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=="dict": anchor=node.end_lineno; break
        if anchor is None: raise RuntimeError("Actual normalize_finding() has no f = dict(f) anchor")
        nl="\r\n" if "\r\n" in finding else "\n"; lines.insert(anchor,assignment+nl); finding="".join(lines); print("[PASS] Installed finding_id assignment before canonical evidence")
    else: print("[PASS] finding_id assignment already present")
    final=ast.parse(finding,filename=str(FINDING)); hc=sum(1 for n in ast.walk(final) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="_canonical_finding_id")
    if hc!=1: raise RuntimeError(f"Expected one canonical helper, found {hc}")
    nf=next(n for n in ast.walk(final) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="normalize_finding"); ac=sum(1 for n in ast.walk(nf) if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=="f['finding_id']")
    if ac!=1: raise RuntimeError(f"Expected one finding_id assignment, found {ac}")
    seg=ast.get_source_segment(finding,nf) or ""
    if seg.find("f['finding_id'] = _canonical_finding_id(f)") > seg.find("return _attach_canonical_evidence(f)"): raise RuntimeError("finding_id assignment occurs after canonical evidence attachment")
    FINDING.write_text(finding,encoding="utf-8"); print("[PASS] Finding model written after structural validation")
    print("[PASS] Evidence adapter left unchanged; existing linkage is sufficient")
    test_file.write_text(TEST,encoding="utf-8"); print(f"[PASS] Persistent acceptance test: {test_file}")
    for target in (FINDING,EVIDENCE,test_file):
        r=subprocess.run([sys.executable,"-m","py_compile",str(target)],cwd=str(ROOT),capture_output=True,text=True)
        if r.returncode: raise RuntimeError(f"Compilation failed for {target}: {r.stderr.strip()}")
    print("[PASS] Production/test compilation")
    r=subprocess.run([sys.executable,str(test_file)],cwd=str(ROOT),capture_output=True,text=True); print(r.stdout,end="")
    if r.returncode: raise RuntimeError("Acceptance test failed:\n"+(r.stderr or r.stdout))
    print("="*60); print("R-SecOpsX V11 - FINDING IDENTITY / EVIDENCE LINKAGE v6 ACCEPTED"); print("="*60)
    print("[PASS] BOM-safe source handling"); print("[PASS] Canonical deterministic finding_id"); print("[PASS] Existing finding_id preserved"); print("[PASS] Distinct occurrence separation"); print("[PASS] Existing evidence adapter linkage validated"); print("[PASS] Persistent acceptance test"); print(f"[PASS] Backup: {finding_backup}")
except Exception:
    print("[FAIL] Patch/acceptance failed; restoring production files."); restore(); print("[PASS] Production source restored from original bytes."); raise
