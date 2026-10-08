$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$FindingModel = Join-Path $Root "core\finding_model.py"
$TestFile = Join-Path $Root "tests\test_v11_evidence_normalization_integration_v1.py"
$BackupDir = Join-Path $Root "backup"

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - CANONICAL EVIDENCE ERROR CLEANUP v1"
Write-Host " CONTROLLED PRODUCTION PATCH"
Write-Host "============================================================"

foreach ($p in @($FindingModel, $TestFile)) {
    if (-not (Test-Path $p -PathType Leaf)) {
        throw "Required file not found: $p"
    }
}

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

$fmBackup = Join-Path $BackupDir ("finding_model.py.before_evidence_error_cleanup_" + $stamp + ".py")
$testBackup = Join-Path $BackupDir ("test_v11_evidence_normalization_integration_v1.py.before_evidence_error_cleanup_" + $stamp + ".py")

Copy-Item $FindingModel $fmBackup -Force
Copy-Item $TestFile $testBackup -Force

$code = Get-Content $FindingModel -Raw

$old = @'
        f['canonical_evidence_state'] = (
            'qualified' if qualified.qualified else 'not_qualified'
        )
'@

$new = @'
        f['canonical_evidence_state'] = (
            'qualified' if qualified.qualified else 'not_qualified'
        )
        # A prior normalization attempt may have recorded a transient
        # canonical_evidence_error. Once qualification succeeds and the
        # canonical Evidence state is established, that stale error must
        # not remain in the final finding payload.
        f.pop('canonical_evidence_error', None)
'@

if ($code.Contains($new)) {
    Write-Host "[INFO] Production cleanup already present; no production replacement needed."
}
elseif ($code.Contains($old)) {
    $code = $code.Replace($old, $new)
    Set-Content -Path $FindingModel -Value $code -Encoding UTF8
    Write-Host "[PASS] Production cleanup applied:"
    Write-Host "       $FindingModel"
}
else {
    throw "Expected canonical evidence state block was not found. Refusing modification."
}

$test = Get-Content $TestFile -Raw

$testBlock = @'

def test_successful_canonical_evidence_clears_stale_error():
    f0 = base_finding()
    f0["canonical_evidence_error"] = "stale error from earlier normalization attempt"

    f = normalize_finding(f0)

    assert f["canonical_evidence_state"] == "qualified"
    assert f["canonical_qualified_evidence"]["qualified"] is True
    assert f["canonical_evidence_error"] if False else "canonical_evidence_error" not in f
'@

# Replace the deliberately awkward assertion with a plain assertion after
# embedding, so the resulting Python remains simple and readable.
$testBlock = @'

def test_successful_canonical_evidence_clears_stale_error():
    f0 = base_finding()
    f0["canonical_evidence_error"] = "stale error from earlier normalization attempt"

    f = normalize_finding(f0)

    assert f["canonical_evidence_state"] == "qualified"
    assert f["canonical_qualified_evidence"]["qualified"] is True
    assert "canonical_evidence_error" not in f
'@

if ($test.Contains("def test_successful_canonical_evidence_clears_stale_error():")) {
    Write-Host "[INFO] Regression test already present; no test replacement needed."
}
else {
    $anchor = "def test_missing_concrete_evidence_is_explicitly_surfaced():"
    if (-not $test.Contains($anchor)) {
        throw "Expected test insertion anchor not found. Refusing modification."
    }

    $test = $test.Replace($anchor, ($testBlock.TrimStart() + "`r`n`r`n" + $anchor))
    Set-Content -Path $TestFile -Value $test -Encoding UTF8
    Write-Host "[PASS] Regression test added:"
    Write-Host "       $TestFile"
}

Write-Host "[PASS] Backups:"
Write-Host "       $fmBackup"
Write-Host "       $testBackup"

python -m py_compile $FindingModel
if ($LASTEXITCODE -ne 0) {
    throw "finding_model.py compilation failed after patch."
}

python -m py_compile $TestFile
if ($LASTEXITCODE -ne 0) {
    throw "integration test compilation failed after patch."
}

Write-Host "[PASS] Python compilation"
Write-Host ""
Write-Host "Patch complete. Run the supplied gate next."
