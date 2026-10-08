$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - CANONICAL EVIDENCE ERROR CLEANUP v1 GATE"
Write-Host "============================================================"

$FindingModel = Join-Path $Root "core\finding_model.py"
$TestFile = Join-Path $Root "tests\test_v11_evidence_normalization_integration_v1.py"

if (-not (Test-Path $FindingModel -PathType Leaf)) {
    throw "Missing: $FindingModel"
}
if (-not (Test-Path $TestFile -PathType Leaf)) {
    throw "Missing: $TestFile"
}

$source = Get-Content $FindingModel -Raw

$expected = @(
    "canonical_evidence_state",
    "canonical_evidence_error",
    "f.pop('canonical_evidence_error', None)"
)

foreach ($needle in $expected) {
    if (-not $source.Contains($needle)) {
        throw "Production cleanup marker missing: $needle"
    }
}

Write-Host "[PASS] Production stale-error cleanup marker present"

python -m pytest $TestFile -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "CANONICAL EVIDENCE ERROR CLEANUP GATE: FAIL"
    exit $LASTEXITCODE
}

python -m py_compile $FindingModel
if ($LASTEXITCODE -ne 0) {
    Write-Host "CANONICAL EVIDENCE ERROR CLEANUP GATE: FAIL"
    exit $LASTEXITCODE
}

Write-Host "[PASS] finding_model.py compilation"
Write-Host "CANONICAL EVIDENCE ERROR CLEANUP GATE: PASS"
