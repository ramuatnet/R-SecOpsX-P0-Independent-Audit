$ErrorActionPreference = "Stop"
$Root = "D:\data\Code test\R-SecOpsX_V11"
$Test = Join-Path $Root "tests\test_v11_evidence_normalization_integration_v1.py"
$FindingModel = Join-Path $Root "core\finding_model.py"

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - EVIDENCE NORMALIZATION INTEGRATION v1 GATE"
Write-Host " PRODUCTION NORMALIZATION BOUNDARY"
Write-Host "============================================================"

python -m py_compile $FindingModel
if ($LASTEXITCODE -ne 0) {
    Write-Host "PRODUCTION INTEGRATION GATE: FAIL - compile"
    exit 1
}

python -m pytest $Test -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "PRODUCTION INTEGRATION GATE: FAIL - integration tests"
    exit 1
}

Write-Host "PRODUCTION INTEGRATION GATE: PASS"
