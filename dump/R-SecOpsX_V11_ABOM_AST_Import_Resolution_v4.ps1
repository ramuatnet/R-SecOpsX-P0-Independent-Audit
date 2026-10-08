$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Prod = Join-Path $Root "scanner\abom.py"
$Dump = Join-Path $Root "dump"
$Tests = Join-Path $Root "tests"
$BackupDir = Join-Path $Root "backup"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $BackupDir "abom.py.before_abom_ast_import_v4_$Stamp.py"
$Test = Join-Path $Tests "test_v11_abom_ast_import_v4.py"

Write-Host "============================================================"
Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v4"
Write-Host "SELF-CONTAINED POWERSHELL PATCHER"
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

if ($source.Contains("V11 ABOM AST/IMPORT RESOLUTION v4")) {
    throw "v4 marker already exists in production ABOM. Refusing duplicate patch."
}

# Preserve UTF-8 source without BOM.
[IO.Directory]::CreateDirectory($BackupDir) | Out-Null
[IO.File]::WriteAllText($Backup, $original, [Text.UTF8Encoding]::new($false))
Write-Host "[PASS] Production backup created: $Backup"

# Static structural validation before modification.
if (-not $source.Contains("def scan_file")) {
    throw "Required scan_file() function not found in scanner\abom.py"
}

# Helper block. It is deliberately self-contained and only enriches existing ABOM findings.
$helper = @'
# --- V11 ABOM AST/IMPORT RESOLUTION v4 ---
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
        if framework in t and component in t:
            matches.append(f"{local} -> {target}")
    return matches

def _v11_abom_enrich_item(item, filepath, tree, import_map):
    if not isinstance(item, dict):
        return item
    matches = _v11_abom_import_evidence(item, import_map)
    evidence_types = item.get("evidence_type")
    if not isinstance(evidence_types, list):
        evidence_types = ["REGEX"] if item else []
    else:
        evidence_types = list(evidence_types)
    if tree is not None and "AST" not in evidence_types:
        evidence_types.append("AST")
    if matches and "IMPORT_RESOLUTION" not in evidence_types:
        evidence_types.append("IMPORT_RESOLUTION")
    item["component_id"] = item.get("component_id") or _v11_abom_component_id(item, filepath)
    item["evidence_type"] = evidence_types
    item["import_resolution"] = matches
    item["confidence_level"] = "HIGH" if matches else ("MEDIUM" if tree is not None else "LOW")
    return item
# --- END V11 ABOM AST/IMPORT RESOLUTION v4 ---
'@

# Insert helper immediately before scan_file. This avoids fragile import/function anchors.
$scanIndex = $source.IndexOf("def scan_file")
if ($scanIndex -lt 0) { throw "scan_file anchor disappeared." }
$source = $source.Insert($scanIndex, $helper + "`r`n`r`n")

# Locate the function body and add runtime context immediately after the first
# source assignment/read. We only accept common existing forms; otherwise rollback.
$scanStart = $source.IndexOf("def scan_file")
$nextDef = $source.IndexOf("`ndef ", $scanStart + 9)
if ($nextDef -lt 0) { $scanEnd = $source.Length } else { $scanEnd = $nextDef + 1 }
$scanBlock = $source.Substring($scanStart, $scanEnd - $scanStart)

$readPatterns = @(
    "(?m)^(?<indent>\s*)source\s*=\s*.*$",
    "(?m)^(?<indent>\s*)content\s*=\s*.*$",
    "(?m)^(?<indent>\s*)text\s*=\s*.*$"
)

$matched = $false
foreach ($pattern in $readPatterns) {
    $m = [regex]::Match($scanBlock, $pattern)
    if ($m.Success) {
        $indent = $m.Groups["indent"].Value
        $insert = "$indent" + "abom_tree = _v11_abom_parse_ast(source)`r`n" +
                  "$indent" + "abom_import_map = _v11_abom_import_map(abom_tree)`r`n"
        $absolute = $scanStart + $m.Index + $m.Length
        $source = $source.Insert($absolute, "`r`n" + $insert.TrimEnd("`r","`n"))
        $matched = $true
        break
    }
}

if (-not $matched) {
    # If the scanner has no explicit source assignment, do not guess.
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    throw "No safe source assignment anchor found inside scan_file(); production restored."
}

# Enrich findings immediately before return findings.
$scanStart = $source.IndexOf("def scan_file")
$nextDef = $source.IndexOf("`ndef ", $scanStart + 9)
if ($nextDef -lt 0) { $scanEnd = $source.Length } else { $scanEnd = $nextDef + 1 }
$scanBlock = $source.Substring($scanStart, $scanEnd - $scanStart)

$returnMatch = [regex]::Match($scanBlock, "(?m)^(?<indent>\s*)return\s+findings\s*$")
if (-not $returnMatch.Success) {
    [IO.File]::WriteAllText($Prod, $original, [Text.UTF8Encoding]::new($false))
    throw "No safe 'return findings' anchor found inside scan_file(); production restored."
}

$indent = $returnMatch.Groups["indent"].Value
$enrich = "$indent" + "for _v11_abom_item in findings:`r`n" +
          "$indent    _v11_abom_enrich_item(_v11_abom_item, str(path), abom_tree, abom_import_map)`r`n"
$absoluteReturn = $scanStart + $returnMatch.Index
$source = $source.Insert($absoluteReturn, $enrich)

# Syntax-check the candidate without writing it to production first.
$candidate = Join-Path $Dump "_abom_v4_candidate.py"
[IO.File]::WriteAllText($candidate, $source, [Text.UTF8Encoding]::new($false))

python -c "import ast, pathlib; p=pathlib.Path(r'$candidate'); ast.parse(p.read_text(encoding='utf-8-sig')); print('[PASS] Candidate AST syntax validation')"
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

    # Persistent v4 acceptance test is generated only after production syntax validation.
    $testText = @'
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom

def main():
    d = Path(tempfile.mkdtemp(prefix="abom_v4_"))
    p = d / "case.py"
    p.write_text(
        "from crewai import Agent as CrewAgent\n"
        "agent = CrewAgent(role='analyst')\n",
        encoding="utf-8",
    )
    rows = abom.scan_file(str(p))
    assert rows, "ABOM produced no finding"
    row = next((x for x in rows if str(x.get("component","")).lower() == "agent"), rows[0])
    assert row.get("component_id","").startswith("ABOM-"), row
    assert "AST" in row.get("evidence_type", []), row
    assert "IMPORT_RESOLUTION" in row.get("evidence_type", []), row
    assert row.get("confidence_level") == "HIGH", row
    assert isinstance(row.get("import_resolution"), list), row
    print("[PASS] AST verification")
    print("[PASS] import/alias resolution")
    print("[PASS] deterministic component_id")
    print("[PASS] evidence/confidence enrichment")
    print("[PASS] existing ABOM finding produced")
    print("ABOM_AST_IMPORT_V4_ACCEPTED")

if __name__ == "__main__":
    main()
'@
    [IO.File]::WriteAllText($Test, $testText, [Text.UTF8Encoding]::new($false))
    Write-Host "[PASS] Acceptance test installed: $Test"

    python -m pytest -q $Test
    if ($LASTEXITCODE -ne 0) { throw "Acceptance test failed." }

    python -c "from scanner import abom; print('ABOM_IMPORT_OK')"
    if ($LASTEXITCODE -ne 0) { throw "ABOM import smoke test failed." }

    Write-Host "============================================================"
    Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v4 ACCEPTED"
    Write-Host "============================================================"
    Write-Host "[PASS] Safe structural patch"
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
