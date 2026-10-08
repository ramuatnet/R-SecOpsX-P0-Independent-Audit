$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Dump = Join-Path $Root "dump"
$Tests = Join-Path $Root "tests"

$Patcher = Join-Path $Dump "patch_abom_ast_import_v3.py"
$Test = Join-Path $Tests "test_v11_abom_ast_import_v3.py"

Write-Host "============================================================"
Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v3"
Write-Host "============================================================"
Write-Host "[INFO] Root:    $Root"
Write-Host "[INFO] Patcher: $Patcher"
Write-Host "[INFO] Test:    $Test"

if (-not (Test-Path $Root)) { throw "V11 root not found: $Root" }
if (-not (Test-Path (Join-Path $Root "scanner\abom.py"))) { throw "Production ABOM not found." }
if (-not (Test-Path $Patcher)) { throw "v3 patcher not found: $Patcher" }
if (-not (Test-Path $Test)) { throw "v3 acceptance test not found: $Test" }

$actual = (Resolve-Path $Patcher).Path
if ($actual -ne $Patcher) { throw "Unexpected patcher path: $actual" }

Write-Host "[PASS] Exact v3 patcher located"
Write-Host "[PASS] Exact v3 acceptance test located"

Push-Location $Root
try {
    python $Patcher
    if ($LASTEXITCODE -ne 0) { throw "ABOM AST/import v3 patcher failed." }
}
finally {
    Pop-Location
}
