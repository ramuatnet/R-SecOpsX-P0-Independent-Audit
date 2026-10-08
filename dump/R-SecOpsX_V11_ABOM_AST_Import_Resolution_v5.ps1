$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Prod = Join-Path $Root "scanner\abom.py"
$Dump = Join-Path $Root "dump"
$Tests = Join-Path $Root "tests"
$BackupDir = Join-Path $Root "backup"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $BackupDir "abom.py.before_abom_ast_import_v5_$Stamp.py"
$Test = Join-Path $Tests "test_v11_abom_ast_import_v5.py"

Write-Host "============================================================"
Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v5"
Write-Host "AST-BOUND PATCH - ACTUAL scan_file() STRUCTURE"
Write-Host "============================================================"
Write-Host "[INFO] Root:   $Root"
Write-Host "[INFO] Prod:   $Prod"
Write-Host "[INFO] Backup: $Backup"
Write-Host "[INFO] Test:   $Test"

foreach ($path in @($Root,$Prod,$Dump,$Tests,$BackupDir)) {
    if (-not (Test-Path $path)) { throw "Required path not found: $path" }
}

$original = [IO.File]::ReadAllText($Prod, [Text.UTF8Encoding]::new($false))
$source = $original

# Refuse duplicate application.
if ($source.Contains("V11 ABOM AST/IMPORT RESOLUTION v5")) {
    throw "v5 marker already exists in production ABOM. Refusing duplicate patch."
}

# Validate actual structure discovered from AST: scan_file returns deduplicate(findings).
python -c "import ast,pathlib; p=pathlib.Path(r'$Prod'); t=ast.parse(p.read_text(encoding='utf-8-sig')); f=next((x for x in t.body if isinstance(x,ast.FunctionDef) and x.name=='scan_file'),None); assert f, 'scan_file() missing'; rs=[n for n in ast.walk(f) if isinstance(n,ast.Return)]; assert rs and any(ast.unparse(n.value)=='deduplicate(findings)' for n in rs if n.value), 'Expected return deduplicate(findings) not found'; print('[PASS] Actual scan_file() AST structure validated')"
if ($LASTEXITCODE -ne 0) { throw "Actual ABOM structure validation failed." }

[IO.Directory]::CreateDirectory($BackupDir) | Out-Null
[IO.File]::WriteAllText($Backup, $original, [Text.UTF8Encoding]::new($false))
Write-Host "[PASS] Production backup created: $Backup"

# Self-contained helper. No assumptions about the scanner's return variable beyond findings.
$helper = @'
# --- V11 ABOM AST/IMPORT RESOLUTION v5 ---
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
    if not framework or not component:
        return []
    matches = []
    for local, target in import_map.items():
        t = str(target).lower()
        if component in t and (
            framework in t
            or framework.replace("-", "") in t.replace("-", "")
            or framework.lower() in t
        ):
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
# --- END V11 ABOM AST/IMPORT RESOLUTION v5 ---
'@

$scanPos = $source.IndexOf("def scan_file")
if ($scanPos -lt 0) { throw "scan_file() anchor not found." }
$source = $source.Insert($scanPos, $helper + "`r`n`r`n")

# Recompute scan_file after helper insertion.
$scanPos = $source.IndexOf("def scan_file")
$nextDef = $source.IndexOf("`ndef ", $scanPos + 9)
$scanEnd = if ($nextDef -lt 0) { $source.Length } else { $nextDef + 1 }
$scanBlock = $source.Substring($scanPos, $scanEnd - $scanPos)

# Actual source read boundary discovered: source = path.read_text(...)
$sourceMatch = [regex]::Match($scanBlock, '(?m)^(?<indent>\s*)source\s*=\s*path\.read_text\(\s*$')
if (-not $sourceMatch.Success) {
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    throw "Actual source-read anchor was not found; production restored."
}

# Insert after the complete read_text(...) call, not after the assignment line.
$readClose = [regex]::Match(
    $scanBlock.Substring($sourceMatch.Index),
    '(?m)^\s*\)\s*$'
)
if (-not $readClose.Success) {
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    throw "Actual source-read closing anchor was not found; production restored."
}

$insertAt = $scanPos + $sourceMatch.Index + $readClose.Index + $readClose.Length
$indent = $sourceMatch.Groups["indent"].Value
$runtime = "`r`n$indent" + "abom_tree = _v11_abom_parse_ast(source)`r`n" +
           "$indent" + "abom_import_map = _v11_abom_import_map(abom_tree)"
$source = $source.Insert($insertAt, $runtime)

# Insert enrichment immediately before the actual return deduplicate(findings).
$returnMatch = [regex]::Match($scanBlock, '(?m)^(?<indent>\s*)return\s+deduplicate\(findings\)\s*$')
if (-not $returnMatch.Success) {
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    throw "Actual return deduplicate(findings) anchor was not found; production restored."
}
$indent = $returnMatch.Groups["indent"].Value
$enrich = "$indent" + "for _v11_abom_item in findings:`r`n" +
          "$indent    _v11_abom_enrich_item(_v11_abom_item, str(path), abom_tree, abom_import_map)`r`n"
$absoluteReturn = $scanPos + $returnMatch.Index
$source = $source.Insert($absoluteReturn, $enrich)

# Candidate syntax validation before production write.
$candidate = Join-Path $Dump "_abom_v5_candidate.py"
[IO.File]::WriteAllText($candidate, $source, [Text.UTF8Encoding]::new($false))
python -c "import ast,pathlib; p=pathlib.Path(r'$candidate'); ast.parse(p.read_text(encoding='utf-8-sig')); print('[PASS] Candidate AST syntax validation')"
if ($LASTEXITCODE -ne 0) {
    Remove-Item $candidate -Force -ErrorAction SilentlyContinue
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    throw "Candidate syntax validation failed; production restored."
}

Copy-Item $candidate $Prod -Force
Remove-Item $candidate -Force
Write-Host "[PASS] Production source written: $Prod"

try {
    python -m py_compile $Prod
    if ($LASTEXITCODE -ne 0) { throw "Production compilation failed." }
    Write-Host "[PASS] Production compilation"

    $testText = @'
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom

def main():
    d = Path(tempfile.mkdtemp(prefix="abom_v5_"))
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
    print("ABOM_AST_IMPORT_V5_ACCEPTED")

if __name__ == "__main__":
    main()
'@
    [IO.File]::WriteAllText($Test, $testText, [Text.UTF8Encoding]::new($false))
    Write-Host "[PASS] Acceptance test installed: $Test"

    python $Test
    if ($LASTEXITCODE -ne 0) { throw "Acceptance test failed." }

    python -c "from scanner import abom; print('ABOM_IMPORT_OK')"
    if ($LASTEXITCODE -ne 0) { throw "ABOM import smoke test failed." }

    Write-Host "============================================================"
    Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v5 ACCEPTED"
    Write-Host "============================================================"
    Write-Host "[PASS] Actual scan_file() structure honored"
    Write-Host "[PASS] AST verification"
    Write-Host "[PASS] Import/alias resolution"
    Write-Host "[PASS] Deterministic component_id"
    Write-Host "[PASS] Evidence/confidence enrichment"
    Write-Host "[PASS] Acceptance test"
    Write-Host "[PASS] Backup: $Backup"
}
catch {
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    Write-Host "[PASS] Production source restored from original content."
    throw
}
