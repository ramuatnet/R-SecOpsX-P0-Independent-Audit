# R-SecOpsX V11 - Finding Identity / Evidence Linkage v5
$ErrorActionPreference = "Stop"
$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Patcher = Join-Path $Root "tests\patch_finding_identity_v5.py"

Write-Host "[INFO] V11 root: $Root"
Write-Host "[INFO] Patcher:  $Patcher"

if (-not (Test-Path $Root -PathType Container)) {
    throw "V11 root does not exist: $Root"
}
if (-not (Test-Path $Patcher -PathType Leaf)) {
    throw "Missing patcher: $Patcher"
}

$Finding = Join-Path $Root "core\finding_model.py"
$Evidence = Join-Path $Root "core\evidence_adapter.py"
$Schema = Join-Path $Root "core\evidence_schema.py"

foreach ($p in @($Finding,$Evidence,$Schema)) {
    if (-not (Test-Path $p -PathType Leaf)) {
        throw "Required production file does not exist: $p"
    }
    Write-Host "[PASS] Production path exists: $p"
}

python $Patcher
if ($LASTEXITCODE -ne 0) {
    throw "Finding identity v5 patcher failed."
}
