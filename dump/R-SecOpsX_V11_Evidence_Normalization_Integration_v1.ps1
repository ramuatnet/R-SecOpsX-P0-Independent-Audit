$ErrorActionPreference = "Stop"

$Root = "D:\data\Code test\r-SecOpsX_V11"
$FindingModel = Join-Path $Root "core\finding_model.py"
$BackupDir = Join-Path $Root "backup"
$DumpDir = Join-Path $Root "dump"

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - EVIDENCE NORMALIZATION INTEGRATION v1"
Write-Host " CONTROLLED PRODUCTION PATCH"
Write-Host "============================================================"

if (-not (Test-Path $Root -PathType Container)) {
    throw "V11 root not found: $Root"
}
if (-not (Test-Path $FindingModel -PathType Leaf)) {
    throw "Production target not found: $FindingModel"
}
if (-not (Test-Path (Join-Path $Root "core\evidence_adapter.py") -PathType Leaf)) {
    throw "Evidence adapter missing. Run Evidence Adapter v1 gate first."
}
if (-not (Test-Path (Join-Path $Root "core\evidence_schema.py") -PathType Leaf)) {
    throw "Evidence schema missing. Run Evidence Schema v1 gate first."
}

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
New-Item -ItemType Directory -Force -Path $DumpDir | Out-Null

$code = Get-Content $FindingModel -Raw

if ($code.Contains("_attach_canonical_evidence")) {
    throw "Target already contains _attach_canonical_evidence. Refusing duplicate patch."
}

$anchor = @'
def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:
    f = dict(f)
    f['classification'] = classify_finding(f)
    ev = f.get('evidence_valid')
'@

$replacement = @'
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


def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:
    f = dict(f)
    f['classification'] = classify_finding(f)
    ev = f.get('evidence_valid')
'@

if (-not $code.Contains($anchor)) {
    throw "Exact normalize_finding anchor not found. No source modification made."
}

$code = $code.Replace($anchor, $replacement)

$oldTail = @'
    f.setdefault('evidence_state', 'validated' if ev is not False else 'invalid')
    return f
'@

$newTail = @'
    f.setdefault('evidence_state', 'validated' if ev is not False else 'invalid')
    return _attach_canonical_evidence(f)
'@

if (-not $code.Contains($oldTail)) {
    throw "Exact normalize_finding return anchor not found. No source modification made."
}

$code = $code.Replace($oldTail, $newTail)

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $BackupDir ("finding_model.py.before_evidence_integration_" + $stamp + ".py")
Copy-Item $FindingModel $backup -Force

Set-Content -Path $FindingModel -Value $code -Encoding UTF8

Write-Host ""
Write-Host "[PASS] Backup created:"
Write-Host "       $backup"
Write-Host "[PASS] Production integration applied:"
Write-Host "       $FindingModel"
Write-Host ""
Write-Host "No other production source file was modified."
