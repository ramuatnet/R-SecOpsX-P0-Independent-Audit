$ErrorActionPreference = "Stop"
$Root = "D:\data\Code test\r-SecOpsX_V11"
$Test = Join-Path $Root "tests\test_v11_evidence_adapter.py"

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - EVIDENCE ADAPTER v1 GATE"
Write-Host " READ-ONLY ADAPTER TESTS"
Write-Host "============================================================"

if (-not (Test-Path $Test -PathType Leaf)) {
    Write-Host "[BLOCKED] Test file missing: $Test"
    exit 2
}

python -m pytest $Test -q
$code = $LASTEXITCODE

if ($code -eq 0) {
    Write-Host "EVIDENCE ADAPTER v1 GATE: PASS"
} else {
    Write-Host "EVIDENCE ADAPTER v1 GATE: FAIL"
}

exit $code
