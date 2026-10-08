$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Patcher = Join-Path $Root "dump\patch_abom_ast_import_v1.py"

Write-Host "============================================================"
Write-Host "R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v1"
Write-Host "============================================================"
Write-Host "[INFO] Root: $Root"
Write-Host "[INFO] Patcher: $Patcher"

if (-not (Test-Path $Root)) {
    throw "V11 root not found: $Root"
}

if (-not (Test-Path (Join-Path $Root "scanner\abom.py"))) {
    throw "Production ABOM not found."
}

if (-not (Test-Path $Patcher)) {
    throw "Patcher not found: $Patcher"
}

python $Patcher

if ($LASTEXITCODE -ne 0) {
    throw "ABOM AST/import v1 patcher failed."
}
