$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Prod = Join-Path $Root "scanner\abom.py"
$BackupDir = Join-Path $Root "backup"

New-Item -ItemType Directory -Force $BackupDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $BackupDir "abom.py.before_component_id_v1_$stamp.py"

Copy-Item $Prod $Backup -Force
Write-Host "[PASS] Backup: $Backup"

$source = Get-Content $Prod -Raw -Encoding UTF8

# Add deterministic component_id immediately before each ABOM result
# is appended, without changing existing ABOM fields.
$old = @'
        findings.append(
            {
'@

if (-not $source.Contains($old)) {
    throw "Expected findings.append({...}) anchor was not found. Production not modified."
}

$new = @'
        findings.append(
            {
                "component_id": f"ABOM-{Path(file_path).stem}-{lineno}",
'@

$patched = $source.Replace($old, $new)

if ($patched -eq $source) {
    throw "No production change was generated."
}

# Validate before installation.
$tmp = Join-Path $env:TEMP "abom_component_id_candidate_$stamp.py"
Set-Content $tmp $patched -Encoding UTF8

python -c "import ast,pathlib; ast.parse(pathlib.Path(r'$tmp').read_text(encoding='utf-8-sig')); print('[PASS] Candidate AST')"
if ($LASTEXITCODE -ne 0) {
    Remove-Item $tmp -Force
    throw "Candidate syntax validation failed."
}

Copy-Item $tmp $Prod -Force
Remove-Item $tmp -Force

python -m py_compile $Prod
if ($LASTEXITCODE -ne 0) {
    Copy-Item $Backup $Prod -Force
    throw "Production compilation failed; original restored."
}

Write-Host "[PASS] Production compilation"

python ".\tests\test_v11_abom_clean_v1.py"
if ($LASTEXITCODE -ne 0) {
    Copy-Item $Backup $Prod -Force
    throw "ABOM clean acceptance failed; production restored."
}

Write-Host "============================================================"
Write-Host "ABOM_COMPONENT_ID_V1_ACCEPTED"
Write-Host "============================================================"