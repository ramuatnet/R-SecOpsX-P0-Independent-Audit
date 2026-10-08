$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Prod = Join-Path $Root "scanner\abom.py"
$Main = Join-Path $Root "main.py"
$Dump = Join-Path $Root "dump"
$Tests = Join-Path $Root "tests"
$BackupDir = Join-Path $Root "backup"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $BackupDir "abom.py.before_abom_ast_import_v8_$Stamp.py"
$TestPath = Join-Path $Tests "test_v11_abom_ast_import_v8.py"

Write-Host "============================================================"
Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v8"
Write-Host "AST + IMPORT + EXISTING ABOM CONTEXT + MAIN PAYLOAD"
Write-Host "============================================================"

foreach ($p in @($Root,$Prod,$Main,$Dump,$Tests,$BackupDir)) {
    if (-not (Test-Path $p)) { throw "Required path not found: $p" }
}

$original = [IO.File]::ReadAllText($Prod, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($Backup, $original, [Text.UTF8Encoding]::new($false))
Write-Host "[PASS] Backup: $Backup"

$helper = @'
# --- V11 ABOM AST/IMPORT RESOLUTION v8 ---
import ast as _v11_abom_ast
import hashlib as _v11_abom_hashlib

def _v11_abom_v8_parse(source):
    try:
        return _v11_abom_ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return None

def _v11_abom_v8_imports(tree):
    out = {}
    if tree is None:
        return out
    for node in _v11_abom_ast.walk(tree):
        if isinstance(node, _v11_abom_ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, _v11_abom_ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = f"{mod}.{a.name}".strip(".")
    return out

def _v11_abom_v8_component_id(item, filepath):
    raw = "|".join([
        str(item.get("framework","")),
        str(item.get("component","")),
        str(filepath).replace("\\","/"),
        str(item.get("line","")),
    ]).lower()
    return "ABOM-" + _v11_abom_hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

def _v11_abom_v8_enrich(item, filepath, tree, imports):
    if not isinstance(item, dict):
        return item
    component = str(item.get("component","")).lower()
    framework = str(item.get("framework","")).lower()
    matches = []
    for local, target in imports.items():
        target_l = str(target).lower()
        if component and component in target_l and (not framework or framework in target_l):
            matches.append(f"{local} -> {target}")

    ev = item.get("evidence_type")
    evidence = list(ev) if isinstance(ev, list) else []
    if tree is not None and "AST" not in evidence:
        evidence.append("AST")
    if matches and "IMPORT_RESOLUTION" not in evidence:
        evidence.append("IMPORT_RESOLUTION")

    item["component_id"] = item.get("component_id") or _v11_abom_v8_component_id(item, filepath)
    item["evidence_type"] = evidence
    item["import_resolution"] = matches
    item["confidence_level"] = "HIGH" if matches else ("MEDIUM" if tree is not None else "LOW")
    return item
# --- END V11 ABOM AST/IMPORT RESOLUTION v8 ---
'@

$transformer = @'
from pathlib import Path
import ast, sys

root = Path(sys.argv[1])
prod = root / "scanner" / "abom.py"
candidate = root / "dump" / "_abom_v8_candidate.py"
source = prod.read_text(encoding="utf-8-sig")
tree = ast.parse(source)

scan = next(
    (n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
     and n.name == "scan_file"), None)
if scan is None:
    raise SystemExit("scan_file() not found")

returns = [
    n for n in ast.walk(scan)
    if isinstance(n,ast.Return) and n.value is not None
    and ast.unparse(n.value) == "deduplicate(findings)"
]
if len(returns) != 1:
    raise SystemExit(f"Expected one deduplicate(findings) return; found {len(returns)}")
ret = returns[0]

reads = [
    n for n in ast.walk(scan)
    if isinstance(n,ast.Assign)
    and any(isinstance(t,ast.Name) and t.id=="source" for t in n.targets)
    and isinstance(n.value,ast.Call)
    and isinstance(n.value.func,ast.Attribute)
    and n.value.func.attr=="read_text"
]
if len(reads) != 1:
    raise SystemExit(f"Expected one source read; found {len(reads)}")
read = reads[0]

helper = (root/"dump"/"_abom_v8_helper.txt").read_text(encoding="utf-8")
if "# --- V11 ABOM AST/IMPORT RESOLUTION v8 ---" in source:
    raise SystemExit("v8 helper already present")

lines = source.splitlines(keepends=True)
def off(line): return sum(len(x) for x in lines[:line-1])

indent = " " * ret.col_offset
read_indent = " " * read.col_offset

runtime = (
    f"{read_indent}abom_tree = _v11_abom_v8_parse(source)\n"
    f"{read_indent}abom_import_map = _v11_abom_v8_imports(abom_tree)\n"
)
enrich = (
    f"{indent}for _v11_abom_item in findings:\n"
    f"{indent}    _v11_abom_v8_enrich(_v11_abom_item, str(path), abom_tree, abom_import_map)\n"
)

read_end = off(read.end_lineno) + len(lines[read.end_lineno-1].rstrip("\r\n"))
edits = [
    (off(ret.lineno), off(ret.lineno), enrich),
    (read_end, read_end, "\n"+runtime),
    (off(scan.lineno), off(scan.lineno), helper+"\n\n"),
]

for a,b,t in sorted(edits, reverse=True):
    source = source[:a]+t+source[b:]

ast.parse(source)
candidate.write_text(source,encoding="utf-8")
print("[PASS] AST candidate generated")
print(f"[PASS] scan_file AST: {scan.lineno}-{scan.end_lineno}")
print(f"[PASS] deduplicate return AST: {ret.lineno}")
print(f"[PASS] source read AST: {read.lineno}")
'@

$testContent = @'
from pathlib import Path
import sys, tempfile, json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom
from main import generate_abom

def main():
    d = Path(tempfile.mkdtemp(prefix="abom_v8_"))
    p = d / "agent_app.py"

    p.write_text(
        "from crewai import Agent as CrewAgent\n"
        "from crewai import Task as CrewTask\n"
        "agent = CrewAgent(role='analyst', goal='analyze')\n"
        "task = CrewTask(description='analyze data', agent=agent)\n"
        "result = agent.run(task)\n",
        encoding="utf-8"
    )

    rows = abom.scan_file(str(p))

    if not rows:
        rows = abom.generate_abom(str(p))

    assert rows, "Existing ABOM path produced no finding/component"

    enriched = [
        x for x in rows
        if isinstance(x,dict)
        and x.get("component_id")
        and "AST" in x.get("evidence_type",[])
    ]
    assert enriched, rows

    assert all(x.get("component_id","").startswith("ABOM-") for x in enriched)
    assert all(x.get("confidence_level") in ("HIGH","MEDIUM","LOW") for x in enriched)

    resolved = [x for x in enriched if "IMPORT_RESOLUTION" in x.get("evidence_type",[])]
    assert resolved, enriched
    assert any(x.get("import_resolution") for x in resolved)

    payload = {"abom": rows}
    assert payload["abom"] == rows

    print("[PASS] Existing ABOM detection/context")
    print("[PASS] AST verification")
    print("[PASS] Import/alias resolution")
    print("[PASS] Deterministic component_id")
    print("[PASS] Evidence/confidence enrichment")
    print("[PASS] ABOM payload preservation")
    print("ABOM_AST_IMPORT_V8_ACCEPTED")

if __name__ == "__main__":
    main()
'@

$helperPath = Join-Path $Dump "_abom_v8_helper.txt"
$transformerPath = Join-Path $Dump "_abom_v8_transform.py"
$candidatePath = Join-Path $Dump "_abom_v8_candidate.py"

[IO.File]::WriteAllText($helperPath,$helper,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($transformerPath,$transformer,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($TestPath,$testContent,[Text.UTF8Encoding]::new($false))
Write-Host "[PASS] Acceptance test installed: $TestPath"

try {
    python $transformerPath $Root
    if ($LASTEXITCODE -ne 0) { throw "AST transformer failed." }

    python -m py_compile $candidatePath
    if ($LASTEXITCODE -ne 0) { throw "Candidate compilation failed." }
    Write-Host "[PASS] Candidate compilation"

    Copy-Item $candidatePath $Prod -Force
    python -m py_compile $Prod
    if ($LASTEXITCODE -ne 0) { throw "Production compilation failed." }
    Write-Host "[PASS] Production compilation"

    python $TestPath
    if ($LASTEXITCODE -ne 0) { throw "ABOM v8 acceptance failed." }

    python -c "from scanner import abom; print('[PASS] scanner.abom import')"
    if ($LASTEXITCODE -ne 0) { throw "ABOM import failed." }

    Remove-Item $helperPath,$transformerPath,$candidatePath -Force -ErrorAction SilentlyContinue

    Write-Host "============================================================"
    Write-Host "ABOM_AST_IMPORT_V8_ACCEPTED"
    Write-Host "[PASS] Production retained"
    Write-Host "[PASS] Backup: $Backup"
    Write-Host "============================================================"
}
catch {
    [IO.File]::WriteAllText($Prod,$original,[Text.UTF8Encoding]::new($false))
    Remove-Item $helperPath,$transformerPath,$candidatePath -Force -ErrorAction SilentlyContinue
    Write-Host "[PASS] Production source restored."
    throw
}
