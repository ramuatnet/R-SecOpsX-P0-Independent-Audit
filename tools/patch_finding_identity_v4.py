from pathlib import Path
import ast
import re
import shutil
import subprocess
import sys
from datetime import datetime

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
BACKUP = ROOT / "backup"
TESTS = ROOT / "tests"
FINDING = ROOT / "core" / "finding_model.py"
EVIDENCE = ROOT / "core" / "evidence_adapter.py"
SCHEMA = ROOT / "core" / "evidence_schema.py"
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
finding_backup = BACKUP / f"finding_model.py.before_finding_identity_v4_{stamp}.py"
evidence_backup = BACKUP / f"evidence_adapter.py.before_finding_identity_v4_{stamp}.py"
test_file = TESTS / "test_v11_finding_identity_evidence_linkage_v4.py"
BACKUP.mkdir(parents=True, exist_ok=True)
TESTS.mkdir(parents=True, exist_ok=True)
original_finding = FINDING.read_text(encoding="utf-8")
original_evidence = EVIDENCE.read_text(encoding="utf-8")
shutil.copy2(FINDING, finding_backup)
shutil.copy2(EVIDENCE, evidence_backup)
print(f"[PASS] Finding-model backup: {finding_backup}")
print(f"[PASS] Evidence-adapter backup: {evidence_backup}")

try:
    schema = SCHEMA.read_text(encoding="utf-8")
    if not re.search(r"(?m)^\s*related_finding_id\s*:", schema):
        raise RuntimeError("Evidence schema does not expose related_finding_id")
    print("[PASS] Evidence schema exposes related_finding_id")
    nl = "\r\n" if "\r\n" in original_finding else "\n"
    source = original_finding
    tree = ast.parse(source, filename=str(FINDING))
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    classify = next((n for n in funcs if n.name == "classify_finding"), None)
    normalize = next((n for n in funcs if n.name == "normalize_finding"), None)
    if classify is None: raise RuntimeError("Actual classify_finding() function was not found")
    if normalize is None: raise RuntimeError("Actual normalize_finding() function was not found")
    print(f"[PASS] Located classify_finding() at line {classify.lineno}")
    print(f"[PASS] Located normalize_finding() at line {normalize.lineno}")

    if not re.search(r"(?m)^(?:import\s+uuid\b|from\s+uuid\s+import\b)", source):
        lines2 = source.splitlines(keepends=True)
        imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        if imports:
            lines2.insert(max(n.end_lineno for n in imports), "import uuid" + nl)
        else:
            lines2.insert(0, "import uuid" + nl)
        source = "".join(lines2)
        print("[PASS] Added uuid import using discovered import boundary")
    else:
        print("[PASS] uuid import already present")

    marker = "_RSECOPSX_CANONICAL_FINDING_ID_V1"
    if marker not in source:
        tree = ast.parse(source, filename=str(FINDING))
        classify = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "classify_finding")
        helper = (
            marker + ' = "rsecopsx-v11:finding:"' + nl + nl
            + "def _canonical_finding_id(f: dict) -> str:" + nl
            + '    """Return a deterministic identity for one finding occurrence."""' + nl
            + '    existing = str(f.get("finding_id") or "").strip()' + nl
            + "    if existing:" + nl
            + "        return existing" + nl + nl
            + "    parts = (" + nl
            + '        str(f.get("rule_id") or "").strip(),' + nl
            + '        str(f.get("vuln_type") or "").strip(),' + nl
            + '        str(f.get("file") or f.get("path") or "").replace("\\\\", "/").strip(),' + nl
            + '        str(f.get("line") if f.get("line") is not None else "").strip(),' + nl
            + '        str(f.get("column") if f.get("column") is not None else "").strip(),' + nl
            + '        str(f.get("sink_category") or "").strip(),' + nl
            + '        str(f.get("source") or "").strip(),' + nl
            + '        str(f.get("snippet") or "")[:1000].strip(),' + nl
            + "    )" + nl
            + '    seed = "|".join(parts)' + nl
            + '    return str(uuid.uuid5(uuid.NAMESPACE_URL, _RSECOPSX_CANONICAL_FINDING_ID_V1 + seed))' + nl + nl
        )
        lines2 = source.splitlines(keepends=True)
        lines2.insert(classify.lineno - 1, helper)
        source = "".join(lines2)
        print("[PASS] Installed canonical finding identity helper")
    else:
        print("[PASS] Canonical finding identity helper already present")

    tree = ast.parse(source, filename=str(FINDING))
    normalize = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "normalize_finding")
    assignment = "f['finding_id'] = _canonical_finding_id(f)"
    if assignment not in source:
        copy_node = next((n for n in normalize.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "f" for t in n.targets) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id == "dict"), None)
        if copy_node is None: raise RuntimeError("Actual normalize_finding() has no discoverable f = dict(...) anchor")
        lines2 = source.splitlines(keepends=True)
        lines2.insert(copy_node.end_lineno, "    " + assignment + nl)
        source = "".join(lines2)
        print("[PASS] Installed finding_id assignment")
    else:
        print("[PASS] finding_id assignment already present")

    evidence = original_evidence
    linkage = 'related_finding_id=finding.get("finding_id")'
    if linkage not in evidence:
        m = re.search(r"(?m)^([ \\t]*)evidence_id\\s*=\\s*_stable_or_generated_id\\(finding\\),\\s*$", evidence)
        if not m: raise RuntimeError("Actual evidence adapter has no discoverable evidence_id assignment")
        indent = m.group(1)
        evnl = "\r\n" if "\r\n" in evidence else "\n"
        evidence = evidence[:m.end()] + evnl + indent + linkage + evidence[m.end():]
        print("[PASS] Installed related_finding_id evidence linkage")
    else:
        print("[PASS] related_finding_id evidence linkage already present")

    final_tree = ast.parse(source, filename=str(FINDING))
    helper_count = sum(1 for n in ast.walk(final_tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_canonical_finding_id")
    if helper_count != 1: raise RuntimeError(f"Expected one canonical helper, found {helper_count}")
    normalize_final = next(n for n in ast.walk(final_tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "normalize_finding")
    assignment_count = sum(1 for n in ast.walk(normalize_final) if isinstance(n, ast.Assign) and "finding_id" in ast.unparse(n.targets[0]))
    if assignment_count != 1: raise RuntimeError(f"Expected one finding_id assignment, found {assignment_count}")
    if evidence.count(linkage) != 1: raise RuntimeError("Expected exactly one related_finding_id linkage")
    FINDING.write_text(source, encoding="utf-8")
    EVIDENCE.write_text(evidence, encoding="utf-8")
    print("[PASS] Production files written after structural validation")

    test_file.write_text('from pathlib import Path\nimport sys\nROOT = Path(__file__).resolve().parents[1]\nsys.path.insert(0, str(ROOT))\nfrom core.finding_model import normalize_finding, normalize_payload\nfrom core.evidence_adapter import finding_to_evidence\ndef finding(line=42):\n    return {"rule_id":"TEST-FINDING-ID","vuln_type":"prompt_injection","file":"src/app.py","line":line,"column":7,"snippet":"ignore previous instructions","severity":"Medium","evidence_valid":True}\ndef main():\n    a = normalize_finding(finding())\n    b = normalize_finding(finding())\n    assert a["finding_id"] and a["finding_id"] == b["finding_id"] and len(a["finding_id"]) == 36\n    existing = finding(); existing["finding_id"] = "existing-canonical-id"\n    assert normalize_finding(existing)["finding_id"] == "existing-canonical-id"\n    assert normalize_finding(finding(43))["finding_id"] != a["finding_id"]\n    assert normalize_payload({"findings":[finding()]})["findings"][0]["finding_id"] == a["finding_id"]\n    ev = finding_to_evidence(a)\n    assert ev is not None and getattr(ev,"related_finding_id",None) == a["finding_id"]\n    print("[PASS] deterministic finding_id")\n    print("[PASS] existing finding_id preserved")\n    print("[PASS] distinct occurrence separation")\n    print("[PASS] normalize_payload preservation")\n    print("[PASS] evidence.related_finding_id linkage")\n    print("FINDING_ID_EVIDENCE_LINKAGE_ACCEPTED")\nif __name__ == "__main__": main()\n', encoding="utf-8")
    print(f"[PASS] Persistent acceptance test: {test_file}")
    for target in (FINDING, EVIDENCE):
        r = subprocess.run([sys.executable, "-m", "py_compile", str(target)], capture_output=True, text=True)
        if r.returncode: raise RuntimeError(f"Compilation failed for {target.name}: {r.stderr.strip()}")
    print("[PASS] Production compilation")
    r = subprocess.run([sys.executable, str(test_file)], cwd=str(ROOT), capture_output=True, text=True)
    print(r.stdout, end="")
    if r.returncode: raise RuntimeError("Acceptance test failed:\n" + (r.stderr or r.stdout))
    print("=" * 60)
    print("R-SecOpsX V11 - FINDING IDENTITY / EVIDENCE LINKAGE ACCEPTED")
    print("=" * 60)
    print("[PASS] AST/source-structure discovery")
    print("[PASS] Canonical deterministic finding_id")
    print("[PASS] Existing finding_id preserved")
    print("[PASS] Distinct occurrence separation")
    print("[PASS] Evidence.related_finding_id linkage")
    print("[PASS] Persistent acceptance test")
    print(f"[PASS] Backups: {finding_backup} ; {evidence_backup}")
except Exception:
    print("[FAIL] Patch/acceptance failed; restoring production files.")
    FINDING.write_text(original_finding, encoding="utf-8")
    EVIDENCE.write_text(original_evidence, encoding="utf-8")
    print("[PASS] Production source restored from original content.")
    raise
