$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Prod = Join-Path $Root "scanner\abom.py"
$Dump = Join-Path $Root "dump"
$Tests = Join-Path $Root "tests"
$BackupDir = Join-Path $Root "backup"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $BackupDir "abom.py.before_abom_ast_import_v6_$Stamp.py"
$Test = Join-Path $Tests "test_v11_abom_ast_import_v6.py"

Write-Host "============================================================"
Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v6"
Write-Host "PURE AST STRUCTURAL PATCH"
Write-Host "============================================================"

foreach ($path in @($Root,$Prod,$Dump,$Tests,$BackupDir)) {
    if (-not (Test-Path $path)) { throw "Required path not found: $path" }
}

$original = [IO.File]::ReadAllText($Prod, [Text.UTF8Encoding]::new($false))
[IO.Directory]::CreateDirectory($BackupDir) | Out-Null

# Back up first; production is restored automatically on any failure.
[IO.File]::WriteAllText($Backup, $original, [Text.UTF8Encoding]::new($false))
Write-Host "[PASS] Backup: $Backup"

$helper = @'
# --- V11 ABOM AST/IMPORT RESOLUTION v6 ---
import ast as _v11_abom_ast
import hashlib as _v11_abom_hashlib

def _v11_abom_parse_ast(source):
    try:
        return _v11_abom_ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return None

def _v11_abom_import_map(tree):
    result = {}
    if tree is None:
        return result
    for node in _v11_abom_ast.walk(tree):
        if isinstance(node, _v11_abom_ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, _v11_abom_ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
    return result

def _v11_abom_component_id(item, filepath):
    key = "|".join([
        str(item.get("framework", "")),
        str(item.get("component", "")),
        str(filepath).replace("\\", "/"),
        str(item.get("line", "")),
    ]).lower()
    return "ABOM-" + _v11_abom_hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]

def _v11_abom_import_evidence(item, import_map):
    framework = str(item.get("framework", "")).lower()
    component = str(item.get("component", "")).lower()
    if not component:
        return []
    matches = []
    for local, target in import_map.items():
        t = str(target).lower()
        if component in t and (not framework or framework in t):
            matches.append(f"{local} -> {target}")
    return matches

def _v11_abom_enrich_item(item, filepath, tree, import_map):
    if not isinstance(item, dict):
        return item
    matches = _v11_abom_import_evidence(item, import_map)
    existing = item.get("evidence_type")
    evidence_types = list(existing) if isinstance(existing, list) else []
    if tree is not None and "AST" not in evidence_types:
        evidence_types.append("AST")
    if matches and "IMPORT_RESOLUTION" not in evidence_types:
        evidence_types.append("IMPORT_RESOLUTION")
    item["component_id"] = item.get("component_id") or _v11_abom_component_id(item, filepath)
    item["evidence_type"] = evidence_types
    item["import_resolution"] = matches
    item["confidence_level"] = "HIGH" if matches else ("MEDIUM" if tree is not None else "LOW")
    return item
# --- END V11 ABOM AST/IMPORT RESOLUTION v6 ---
'@

# Write a Python transformer. It uses AST locations to identify scan_file and its
# return statement, while preserving the original source text. It never guesses
# indentation or searches for a textual return pattern.
$transformer = @'
from pathlib import Path
import ast
import sys

root = Path(sys.argv[1])
prod = root / "scanner" / "abom.py"
candidate = root / "dump" / "_abom_v6_candidate.py"

source = prod.read_text(encoding="utf-8-sig")
tree = ast.parse(source)

scan = next(
    (n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
     and n.name == "scan_file"),
    None,
)
if scan is None:
    raise SystemExit("scan_file() not found at module scope")

returns = [
    n for n in ast.walk(scan)
    if isinstance(n, ast.Return)
    and n.value is not None
    and ast.unparse(n.value) == "deduplicate(findings)"
]
if len(returns) != 1:
    raise SystemExit(f"Expected exactly one return deduplicate(findings), found {len(returns)}")

ret = returns[0]

# Find the source-read assignment in scan_file. The actual implementation uses
# source = path.read_text(...). AST is used to identify it independent of spacing.
reads = [
    n for n in ast.walk(scan)
    if isinstance(n, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == "source" for t in n.targets)
    and isinstance(n.value, ast.Call)
    and isinstance(n.value.func, ast.Attribute)
    and n.value.func.attr == "read_text"
]
if len(reads) != 1:
    raise SystemExit(f"Expected exactly one source read assignment, found {len(reads)}")

read = reads[0]

helper = Path(root / "dump" / "_abom_v6_helper.txt").read_text(encoding="utf-8")
marker = "# --- V11 ABOM AST/IMPORT RESOLUTION v6 ---"
if marker in source:
    raise SystemExit("v6 helper marker already present")

# Insert runtime AST/import preparation immediately after source-read assignment.
# Insert enrichment immediately before the exact return node. Offsets are AST-derived.
lines = source.splitlines(keepends=True)

def line_offset(line_no):
    return sum(len(x) for x in lines[:line_no - 1])

# Determine indentation from the actual AST column offset.
indent = " " * ret.col_offset
read_indent = " " * read.col_offset

runtime = (
    f"{read_indent}abom_tree = _v11_abom_parse_ast(source)\n"
    f"{read_indent}abom_import_map = _v11_abom_import_map(abom_tree)\n"
)

enrichment = (
    f"{indent}for _v11_abom_item in findings:\n"
    f"{indent}    _v11_abom_enrich_item(_v11_abom_item, str(path), abom_tree, abom_import_map)\n"
)

# The helper goes before scan_file. Apply edits from bottom to top.
edits = [
    (line_offset(ret.lineno), line_offset(ret.lineno), enrichment),
    (line_offset(read.end_lineno) + len(lines[read.end_lineno - 1].rstrip("\r\n")),
     line_offset(read.end_lineno) + len(lines[read.end_lineno - 1].rstrip("\r\n")),
     "\n" + runtime),
    (line_offset(scan.lineno), line_offset(scan.lineno), helper + "\n\n"),
]

for start, end, text in sorted(edits, reverse=True):
    source = source[:start] + text + source[end:]

ast.parse(source)
candidate.write_text(source, encoding="utf-8")
print("[PASS] AST transformer generated syntactically valid candidate")
print(f"[PASS] scan_file() line: {scan.lineno}-{scan.end_lineno}")
print(f"[PASS] return deduplicate(findings): line {ret.lineno}")
print(f"[PASS] source read assignment: line {read.lineno}")
'@

$helperPath = Join-Path $Dump "_abom_v6_helper.txt"
$transformerPath = Join-Path $Dump "_abom_v6_transform.py"
[IO.File]::WriteAllText($helperPath, $helper, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($transformerPath, $transformer, [Text.UTF8Encoding]::new($false))

try {
    python $transformerPath $Root
    if ($LASTEXITCODE -ne 0) { throw "AST transformer failed." }

    $candidate = Join-Path $Dump "_abom_v6_candidate.py"
    python -m py_compile $candidate
    if ($LASTEXITCODE -ne 0) { throw "Candidate compilation failed." }
    Write-Host "[PASS] Candidate compilation"

    Copy-Item $candidate $Prod -Force
    Write-Host "[PASS] Production candidate installed: $Prod"

    python -m py_compile $Prod
    if ($LASTEXITCODE -ne 0) { throw "Production compilation failed." }
    Write-Host "[PASS] Production compilation"

    $test = @'
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner import abom

def main():
    d = Path(tempfile.mkdtemp(prefix="abom_v6_"))
    p = d / "case.py"
    p.write_text(
        "from crewai import Agent as CrewAgent\n"
        "agent = CrewAgent(role='analyst')\n",
        encoding="utf-8",
    )
    rows = abom.scan_file(str(p))
    assert rows, "ABOM produced no finding"
    row = next(
        (x for x in rows if str(x.get("component","")).lower() == "agent"),
        rows[0],
    )
    assert row.get("component_id","").startswith("ABOM-"), row
    assert "AST" in row.get("evidence_type", []), row
    assert "IMPORT_RESOLUTION" in row.get("evidence_type", []), row
    assert row.get("confidence_level") == "HIGH", row
    assert row.get("import_resolution"), row
    print("[PASS] Existing ABOM detection")
    print("[PASS] AST verification")
    print("[PASS] Import/alias resolution")
    print("[PASS] Deterministic component_id")
    print("[PASS] Evidence/confidence enrichment")
    print("ABOM_AST_IMPORT_V6_ACCEPTED")

if __name__ == "__main__":
    main()
'@
    [IO.File]::WriteAllText($Test, $test, [Text.UTF8Encoding]::new($false))
    Write-Host "[PASS] Acceptance test installed: $Test"

    python $Test
    if ($LASTEXITCODE -ne 0) { throw "Acceptance test failed." }

    python -c "from scanner import abom; print('ABOM_IMPORT_OK')"
    if ($LASTEXITCODE -ne 0) { throw "ABOM import smoke test failed." }

    Remove-Item $candidate,$helperPath,$transformerPath -Force -ErrorAction SilentlyContinue

    Write-Host "============================================================"
    Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v6 ACCEPTED"
    Write-Host "============================================================"
    Write-Host "[PASS] Pure AST structural patch"
    Write-Host "[PASS] AST verification"
    Write-Host "[PASS] Import/alias resolution"
    Write-Host "[PASS] Deterministic component_id"
    Write-Host "[PASS] Evidence/confidence enrichment"
    Write-Host "[PASS] Acceptance test"
    Write-Host "[PASS] Backup: $Backup"
}
catch {
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    Remove-Item (Join-Path $Dump "_abom_v6_candidate.py"),$helperPath,$transformerPath -Force -ErrorAction SilentlyContinue
    Write-Host "[PASS] Production source restored from original content."
    throw
}
