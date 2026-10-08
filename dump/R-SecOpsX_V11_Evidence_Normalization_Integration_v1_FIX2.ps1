$ErrorActionPreference = "Stop"

$Root = "D:\data\Code test\R-SecOpsX_V11"
$FindingModel = Join-Path $Root "core\finding_model.py"
$BackupDir = Join-Path $Root "backup"

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - EVIDENCE NORMALIZATION INTEGRATION v1 FIX2"
Write-Host " CANONICAL EVIDENCE IDENTITY CORRECTION"
Write-Host "============================================================"

if (-not (Test-Path $FindingModel -PathType Leaf)) {
    throw "Production target not found: $FindingModel"
}

$code = Get-Content $FindingModel -Raw

$old = @'
def _attach_canonical_evidence(f: dict[str, Any]) -> dict[str, Any]:
    """Attach canonical V11 Evidence without changing legacy finding semantics."""
    try:
        from core.evidence_adapter import (
            normalize_finding_evidence,
            qualify_finding_evidence,
        )

        evidence = normalize_finding_evidence(f)
        f['canonical_evidence'] = evidence.to_dict()

        try:
            qualified = qualify_finding_evidence(f)
            f['canonical_qualified_evidence'] = qualified.to_dict()
            f['canonical_evidence_state'] = (
                'qualified' if qualified.qualified else 'not_qualified'
            )
        except Exception as exc:
            # Canonical Evidence exists, but qualification could not be
            # established. Do not reinterpret or overwrite legacy evidence.
            f['canonical_evidence_state'] = 'qualification_error'
            f['canonical_evidence_error'] = str(exc)

    except Exception as exc:
        # Preserve the established V11 finding contract. Canonical evidence
        # failure is explicitly surfaced rather than silently inferred.
        f['canonical_evidence_state'] = 'unavailable'
        f['canonical_evidence_error'] = str(exc)

    return f
'@

$new = @'
def _attach_canonical_evidence(f: dict[str, Any]) -> dict[str, Any]:
    """Attach one canonical Evidence object and qualify that same object."""
    try:
        from core.evidence_adapter import (
            normalize_finding_evidence,
            qualify_finding_evidence,
        )

        # Qualification is the single construction path. Calling the
        # adapter twice would generate two independent evidence IDs.
        qualified = qualify_finding_evidence(f)
        qdict = qualified.to_dict()

        canonical = qdict.get('evidence')
        if canonical is None:
            # Preserve explicit failure if the adapter did not return evidence.
            raise ValueError(
                'QualifiedEvidence did not contain its canonical evidence object'
            )

        f['canonical_evidence'] = canonical
        f['canonical_qualified_evidence'] = qdict
        f['canonical_evidence_state'] = (
            'qualified' if qualified.qualified else 'not_qualified'
        )

    except Exception as exc:
        # Preserve the established V11 finding contract. Canonical evidence
        # failure is explicitly surfaced rather than silently inferred.
        f.pop('canonical_evidence', None)
        f.pop('canonical_qualified_evidence', None)
        f['canonical_evidence_state'] = 'unavailable'
        f['canonical_evidence_error'] = str(exc)

    return f
'@

if (-not $code.Contains($old)) {
    throw "Expected FIX1 integration block not found. Refusing modification."
}

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $BackupDir ("finding_model.py.before_evidence_identity_fix2_" + $stamp + ".py")
Copy-Item $FindingModel $backup -Force

$code = $code.Replace($old, $new)
Set-Content -Path $FindingModel -Value $code -Encoding UTF8

Write-Host "[PASS] Backup created:"
Write-Host "       $backup"
Write-Host "[PASS] Canonical evidence identity integration corrected."
Write-Host "       $FindingModel"
Write-Host ""
Write-Host "The adapter is now invoked once for canonical Evidence + QualifiedEvidence."
