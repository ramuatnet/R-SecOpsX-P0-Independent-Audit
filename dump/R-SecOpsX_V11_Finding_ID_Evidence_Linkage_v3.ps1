# R-SecOpsX V11 - Canonical Finding ID + Evidence Linkage v3
$ErrorActionPreference = "Stop"
$Root = "D:\Data\Code test\R-SecOpsX_V11"
$BackupDir = Join-Path $Root "backup"
$TestsDir = Join-Path $Root "tests"
$FindingModel = Join-Path $Root "core\finding_model.py"
$EvidenceAdapter = Join-Path $Root "core\evidence_adapter.py"
$EvidenceSchema = Join-Path $Root "core\evidence_schema.py"
$Worker = Join-Path $TestsDir "_patch_finding_identity_v3_worker.py"
$TestFile = Join-Path $TestsDir "test_v11_finding_identity_evidence_linkage_v3.py"
New-Item -ItemType Directory -Force -Path $BackupDir,$TestsDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$FindingBackup = Join-Path $BackupDir "finding_model.py.before_finding_identity_v3_$stamp.py"
$EvidenceBackup = Join-Path $BackupDir "evidence_adapter.py.before_finding_identity_v3_$stamp.py"

$worker = @'

from pathlib import Path
import ast, re, sys

finding_path = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
finding = finding_path.read_text(encoding="utf-8")
evidence = evidence_path.read_text(encoding="utf-8")
nl = "\r\n" if "\r\n" in finding else "\n"

tree = ast.parse(finding, filename=str(finding_path))
funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
classify = next((n for n in funcs if n.name == "classify_finding"), None)
normalize = next((n for n in funcs if n.name == "normalize_finding"), None)
if classify is None:
    raise RuntimeError("Structural anchor missing: classify_finding()")
if normalize is None:
    raise RuntimeError("Structural anchor missing: normalize_finding()")

# Add import uuid without assuming the project's typing/import layout.
if not re.search(r'(?m)^\s*(?:import\s+uuid\b|from\s+uuid\s+import\b)', finding):
    lines = finding.splitlines(keepends=True)
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    if imports:
        pos = max(n.end_lineno for n in imports)
        lines.insert(pos, "import uuid" + nl)
    elif tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(getattr(tree.body[0], "value", None), ast.Constant) and isinstance(tree.body[0].value.value, str):
        lines.insert(tree.body[0].end_lineno, "import uuid" + nl)
    else:
        lines.insert(0, "import uuid" + nl)
    finding = "".join(lines)

tree = ast.parse(finding, filename=str(finding_path))
funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
classify = next(n for n in funcs if n.name == "classify_finding")
normalize = next(n for n in funcs if n.name == "normalize_finding")

marker = "_RSECOPSX_CANONICAL_FINDING_ID_V1"
if marker not in finding:
    helper = (
        marker + ' = "rsecopsx-v11:finding:"' + nl + nl +
        "def _canonical_finding_id(f: dict) -> str:" + nl +
        '    """Return deterministic identity for a finding occurrence."""' + nl +
        '    existing = str(f.get("finding_id") or "").strip()' + nl +
        "    if existing:" + nl +
        "        return existing" + nl + nl +
        "    parts = (" + nl +
        '        str(f.get("rule_id") or "").strip(),' + nl +
        '        str(f.get("vuln_type") or "").strip(),' + nl +
        '        str(f.get("file") or f.get("path") or "").replace("\\\\", "/").strip(),' + nl +
        '        str(f.get("line") if f.get("line") is not None else "").strip(),' + nl +
        '        str(f.get("column") if f.get("column") is not None else "").strip(),' + nl +
        '        str(f.get("sink_category") or "").strip(),' + nl +
        '        str(f.get("source") or "").strip(),' + nl +
        '        str(f.get("snippet") or "")[:1000].strip(),' + nl +
        "    )" + nl +
        '    seed = "|".join(parts)' + nl +
        '    return str(uuid.uuid5(uuid.NAMESPACE_URL, _RSECOPSX_CANONICAL_FINDING_ID_V1 + seed))' + nl + nl
    )
    lines = finding.splitlines(keepends=True)
    lines.insert(classify.lineno - 1, helper)
    finding = "".join(lines)

tree = ast.parse(finding, filename=str(finding_path))
normalize = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "normalize_finding")

if "f['finding_id'] = _canonical_finding_id(f)" not in finding:
    copy_node = next(
        (n for n in normalize.body
         if isinstance(n, ast.Assign)
         and any(isinstance(t, ast.Name) and t.id == "f" for t in n.targets)
         and isinstance(n.value, ast.Call)
         and isinstance(n.value.func, ast.Name)
         and n.value.func.id == "dict"),
        None
    )
    if copy_node is None:
        raise RuntimeError("Structural anchor missing: dict copy in normalize_finding()")
    lines = finding.splitlines(keepends=True)
    lines.insert(copy_node.end_lineno, "    f['finding_id'] = _canonical_finding_id(f)" + nl)
    finding = "".join(lines)

# Evidence adapter: locate the actual evidence_id assignment.
if 'related_finding_id=finding.get("finding_id")' not in evidence:
    m = re.search(r'(?m)^([ \t]*)evidence_id\s*=\s*_stable_or_generated_id\(finding\),\s*$', evidence)
    if not m:
        raise RuntimeError("Structural anchor missing: evidence_id=_stable_or_generated_id(finding)")
    indent = m.group(1)
    replacement = m.group(0) + nl + indent + 'related_finding_id=finding.get("finding_id"),'
    evidence = evidence[:m.start()] + replacement + evidence[m.end():]

# Final AST/source invariants.
tree = ast.parse(finding, filename=str(finding_path))
helper_count = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_canonical_finding_id")
if helper_count != 1:
    raise RuntimeError(f"_canonical_finding_id count={helper_count}, expected 1")
normalize = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "normalize_finding")
if sum(1 for n in ast.walk(normalize) if isinstance(n, ast.Assign) and "finding_id" in ast.unparse(n.targets[0])) != 1:
    raise RuntimeError("finding_id assignment invariant failed")
if evidence.count('related_finding_id=finding.get("finding_id")') != 1:
    raise RuntimeError("evidence linkage invariant failed")

finding_path.write_text(finding, encoding="utf-8")
evidence_path.write_text(evidence, encoding="utf-8")
print("[PASS] AST-guided source transformation completed")
print("[PASS] Actual imports/functions discovered")
print("[PASS] Canonical finding_id installed")
print("[PASS] Evidence linkage installed")

'@
[IO.File]::WriteAllText($Worker,$worker,(New-Object Text.UTF8Encoding($false)))

$findingOriginal = $null
$evidenceOriginal = $null
$changed = $false

try {
    foreach ($p in @($FindingModel,$EvidenceAdapter,$EvidenceSchema)) {
        if (-not (Test-Path $p -PathType Leaf)) { throw "Required source file missing: $p" }
    }

    $findingOriginal = [IO.File]::ReadAllText($FindingModel)
    $evidenceOriginal = [IO.File]::ReadAllText($EvidenceAdapter)
    $schema = [IO.File]::ReadAllText($EvidenceSchema)

    Copy-Item $FindingModel $FindingBackup -Force
    Copy-Item $EvidenceAdapter $EvidenceBackup -Force
    Write-Host "[PASS] Finding-model backup: $FindingBackup"
    Write-Host "[PASS] Evidence-adapter backup: $EvidenceBackup"

    if ($schema -notmatch '(?m)^\s*related_finding_id\s*:') {
        throw "Evidence schema does not expose related_finding_id. No production source written."
    }
    Write-Host "[PASS] Evidence schema exposes related_finding_id"

    python $Worker $FindingModel $EvidenceAdapter
    if ($LASTEXITCODE -ne 0) { throw "AST-guided source transformation failed." }
    $changed = $true

    python -m py_compile $FindingModel
    if ($LASTEXITCODE -ne 0) { throw "finding_model.py compilation failed." }
    python -m py_compile $EvidenceAdapter
    if ($LASTEXITCODE -ne 0) { throw "evidence_adapter.py compilation failed." }
    Write-Host "[PASS] Production compilation"

    $test = @'
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.finding_model import normalize_finding, normalize_payload
from core.evidence_adapter import finding_to_evidence

def make_finding(line=42):
    return {
        "rule_id": "TEST-FINDING-ID",
        "vuln_type": "prompt_injection",
        "file": "src/app.py",
        "line": line,
        "column": 7,
        "snippet": "ignore previous instructions",
        "severity": "Medium",
        "evidence_valid": True,
    }

def main():
    f = make_finding()
    n1 = normalize_finding(f)
    n2 = normalize_finding(f)
    assert n1["finding_id"]
    assert n1["finding_id"] == n2["finding_id"]
    assert len(n1["finding_id"]) == 36

    supplied = make_finding()
    supplied["finding_id"] = "existing-canonical-id"
    assert normalize_finding(supplied)["finding_id"] == "existing-canonical-id"

    n3 = normalize_finding(make_finding(43))
    assert n3["finding_id"] != n1["finding_id"]

    payload = normalize_payload({"findings": [f]})
    assert payload["findings"][0]["finding_id"] == n1["finding_id"]

    ev = finding_to_evidence(n1)
    assert ev is not None
    assert getattr(ev, "related_finding_id", None) == n1["finding_id"]

    print("[PASS] deterministic finding_id")
    print("[PASS] existing finding_id preserved")
    print("[PASS] distinct occurrence separation")
    print("[PASS] normalize_payload preserves finding_id")
    print("[PASS] evidence.related_finding_id linkage")
    print("FINDING_ID_EVIDENCE_LINKAGE_ACCEPTED")

if __name__ == "__main__":
    main()
'@
    [IO.File]::WriteAllText($TestFile,$test,(New-Object Text.UTF8Encoding($false)))
    Write-Host "[PASS] Persistent acceptance test created: $TestFile"

    python $TestFile
    if ($LASTEXITCODE -ne 0) { throw "Finding identity/evidence acceptance failed." }

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "R-SecOpsX V11 - FINDING IDENTITY / EVIDENCE LINKAGE ACCEPTED"
    Write-Host "============================================================"
    Write-Host "[PASS] AST-guided source discovery"
    Write-Host "[PASS] Canonical deterministic finding_id"
    Write-Host "[PASS] Existing finding_id preserved"
    Write-Host "[PASS] Distinct finding occurrences remain distinct"
    Write-Host "[PASS] Evidence.related_finding_id linkage"
    Write-Host "[PASS] Persistent acceptance test"
    Write-Host "[PASS] Backups retained under backup\"
}
catch {
    Write-Host ""
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    if ($changed) {
        [IO.File]::WriteAllText($FindingModel,$findingOriginal,(New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText($EvidenceAdapter,$evidenceOriginal,(New-Object Text.UTF8Encoding($false)))
        Write-Host "[PASS] Production source restored from backups." -ForegroundColor Yellow
    } else {
        Write-Host "[PASS] Production source was not written." -ForegroundColor Yellow
    }
    throw
}
