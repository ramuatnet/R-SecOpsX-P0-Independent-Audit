# R-SecOpsX V11 - Finding Identity / Evidence Linkage v4
$ErrorActionPreference = "Stop"
$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Patcher = Join-Path $Root "tests\patch_finding_identity_v4.py"

if (-not (Test-Path $Patcher -PathType Leaf)) {
    throw "Missing patcher: $Patcher"
}

python $Patcher
if ($LASTEXITCODE -ne 0) {
    throw "Finding identity v4 patcher failed."
}
