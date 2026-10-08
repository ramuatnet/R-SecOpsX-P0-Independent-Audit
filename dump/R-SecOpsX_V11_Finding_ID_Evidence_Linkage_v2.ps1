# R-SecOpsX V11 - Canonical Finding ID + Evidence Linkage v2
# Source-anchored against the current finding_model.py structure.
$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$BackupDir = Join-Path $Root "backup"
$TestsDir = Join-Path $Root "tests"

$FindingModel = Join-Path $Root "core\finding_model.py"
$EvidenceAdapter = Join-Path $Root "core\evidence_adapter.py"
$EvidenceSchema = Join-Path $Root "core\evidence_schema.py"
$TestFile = Join-Path $TestsDir "test_v11_finding_identity_evidence_linkage_v2.py"

New-Item -ItemType Directory -Force -Path $BackupDir,$TestsDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$FindingBackup = Join-Path $BackupDir "finding_model.py.before_finding_identity_v2_$stamp.py"
$EvidenceBackup = Join-Path $BackupDir "evidence_adapter.py.before_finding_identity_v2_$stamp.py"

$findingOriginal = $null
$evidenceOriginal = $null
$productionChanged = $false

function Replace-Once {
    param(
        [string]$Text,
        [string]$Old,
        [string]$New,
        [string]$Name
    )
    $idx = $Text.IndexOf($Old, [System.StringComparison]::Ordinal)
    if ($idx -lt 0) {
        throw "Required source anchor not found: $Name"
    }
    return $Text.Substring(0,$idx) + $New + $Text.Substring($idx + $Old.Length)
}

function Restore-Backups {
    if ($null -ne $findingOriginal) {
        [IO.File]::WriteAllText(
            $FindingModel,
            $findingOriginal,
            (New-Object Text.UTF8Encoding($false))
        )
    }
    if ($null -ne $evidenceOriginal) {
        [IO.File]::WriteAllText(
            $EvidenceAdapter,
            $evidenceOriginal,
            (New-Object Text.UTF8Encoding($false))
        )
    }
}

try {
    foreach ($p in @($FindingModel,$EvidenceAdapter,$EvidenceSchema)) {
        if (-not (Test-Path $p -PathType Leaf)) {
            throw "Required source file missing: $p"
        }
    }

    $findingOriginal = [IO.File]::ReadAllText($FindingModel)
    $evidenceOriginal = [IO.File]::ReadAllText($EvidenceAdapter)
    $schemaText = [IO.File]::ReadAllText($EvidenceSchema)

    Copy-Item $FindingModel $FindingBackup -Force
    Copy-Item $EvidenceAdapter $EvidenceBackup -Force

    Write-Host "[PASS] Finding-model backup: $FindingBackup"
    Write-Host "[PASS] Evidence-adapter backup: $EvidenceBackup"

    if ($schemaText -notmatch '(?m)^\s*related_finding_id\s*:') {
        throw "Evidence schema does not expose related_finding_id. No production source written."
    }
    Write-Host "[PASS] Evidence schema exposes related_finding_id"

    # ------------------------------------------------------------
    # finding_model.py
    # ------------------------------------------------------------
    $py = $findingOriginal
    $nl = if ($py.Contains("`r`n")) { "`r`n" } else { "`n" }

    # Current source has: from typing import Any
    $typingAnchor = "from typing import Any" + $nl
    if ($py -notmatch '(?m)^from uuid import .*NAMESPACE_URL.*uuid5') {
        if ($py.IndexOf($typingAnchor,[StringComparison]::Ordinal) -lt 0) {
            throw "Required source anchor not found: typing import"
        }
        $py = Replace-Once `
            $py `
            $typingAnchor `
            ($typingAnchor + "from uuid import NAMESPACE_URL, uuid5" + $nl) `
            "UUID imports"
    }
    Write-Host "[PASS] Installed deterministic UUID dependency"

    # Insert immediately before classify_finding(), an anchor that is present
    # in the supplied current V11 file.
    $classifyAnchor = "def classify_finding(f: dict[str, Any]) -> str:" + $nl

    $helper = @"
_FINDING_ID_NAMESPACE = NAMESPACE_URL
_FINDING_ID_PREFIX = 'rsecopsx-v11:finding:'

def _canonical_finding_id(f: dict[str, Any]) -> str:
    """Return a deterministic UUID for the same finding occurrence."""
    existing = str(f.get('finding_id') or '').strip()
    if existing:
        return existing

    # Stable occurrence identity. Do not use timestamps, scan order or
    # random UUIDs. Include the semantic/source location and a bounded
    # snippet so distinct findings at the same line remain distinguishable.
    parts = (
        str(f.get('rule_id') or '').strip(),
        str(f.get('vuln_type') or '').strip(),
        str(f.get('file') or f.get('path') or '').replace('\\', '/').strip(),
        str(f.get('line') if f.get('line') is not None else '').strip(),
        str(f.get('column') if f.get('column') is not None else '').strip(),
        str(f.get('sink_category') or '').strip(),
        str(f.get('source') or '').strip(),
        str(f.get('snippet') or '')[:1000].strip(),
    )
    seed = '|'.join(parts)
    return str(uuid5(_FINDING_ID_NAMESPACE, _FINDING_ID_PREFIX + seed))


"@

    if ([regex]::Matches($py, 'def _canonical_finding_id\(').Count -eq 0) {
        $py = Replace-Once $py $classifyAnchor ($helper + $classifyAnchor) "classify_finding insertion boundary"
        Write-Host "[PASS] Installed canonical finding identity helper"
    } elseif ([regex]::Matches($py, 'def _canonical_finding_id\(').Count -eq 1) {
        Write-Host "[PASS] Canonical finding identity helper already present"
    } else {
        throw "Post-source invariant failed: duplicate _canonical_finding_id definitions."
    }

    # Insert assignment immediately after the existing "f = dict(f)" line.
    $normalizeAnchor = "def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:" + $nl +
                       "    f = dict(f)" + $nl
    $normalizeNew = $normalizeAnchor + "    f['finding_id'] = _canonical_finding_id(f)" + $nl

    $normalizeCount = [regex]::Matches($py, 'f\[\x27finding_id\x27\]\s*=\s*_canonical_finding_id\(f\)').Count
    if ($normalizeCount -eq 0) {
        $py = Replace-Once $py $normalizeAnchor $normalizeNew "normalize_finding identity assignment boundary"
        Write-Host "[PASS] Installed finding_id assignment in normalize_finding"
    } elseif ($normalizeCount -eq 1) {
        Write-Host "[PASS] finding_id assignment already present"
    } else {
        throw "Post-source invariant failed: duplicate finding_id assignments."
    }

    if ([regex]::Matches($py, 'def _canonical_finding_id\(').Count -ne 1) {
        throw "Post-patch invariant failed: helper count != 1."
    }
    if ([regex]::Matches($py, 'f\[\x27finding_id\x27\x5d\s*=\s*_canonical_finding_id\(f\)').Count -ne 1) {
        throw "Post-patch invariant failed: assignment count != 1."
    }

    [IO.File]::WriteAllText($FindingModel,$py,(New-Object Text.UTF8Encoding($false)))
    $productionChanged = $true
    Write-Host "[PASS] Canonical finding_id lifecycle written"

    # ------------------------------------------------------------
    # evidence_adapter.py
    # ------------------------------------------------------------
    $ea = $evidenceOriginal
    $evidenceAnchor = "        evidence_id=_stable_or_generated_id(finding),"
    if ($ea -notmatch 'related_finding_id\s*=\s*finding\.get\("finding_id"\)') {
        $ea = Replace-Once `
            $ea `
            $evidenceAnchor `
            ($evidenceAnchor + $nl + '        related_finding_id=finding.get("finding_id"),') `
            "evidence constructor linkage"
        Write-Host "[PASS] Installed evidence.related_finding_id linkage"
    } else {
        Write-Host "[PASS] Evidence.related_finding_id linkage already present"
    }

    if ($ea -notmatch 'related_finding_id\s*=\s*finding\.get\("finding_id"\)') {
        throw "Post-patch invariant failed: evidence linkage missing."
    }

    [IO.File]::WriteAllText($EvidenceAdapter,$ea,(New-Object Text.UTF8Encoding($false)))

    # ------------------------------------------------------------
    # Persistent acceptance test
    # ------------------------------------------------------------
    $test = @'
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.finding_model import normalize_finding, normalize_payload
from core.evidence_adapter import finding_to_evidence

def make_finding(line=42):
    return {
        "rule_id": "TEST-FINDING-ID",
        "vuln_type": "prompt_injection",
        "file": "src/app.py",
        "line": line,
        "column": 7,
        "snippet": "ignore previous instructions",
        "severity": "Medium",
        "evidence_valid": True,
    }

def main():
    f = make_finding()

    n1 = normalize_finding(f)
    n2 = normalize_finding(f)

    assert n1["finding_id"], "finding_id missing"
    assert n1["finding_id"] == n2["finding_id"], "finding_id is not deterministic"
    assert len(n1["finding_id"]) == 36, "finding_id is not UUID-shaped"

    # Existing IDs must be preserved.
    supplied = make_finding()
    supplied["finding_id"] = "existing-canonical-id"
    assert normalize_finding(supplied)["finding_id"] == "existing-canonical-id"

    # Different source occurrence must not collapse.
    n3 = normalize_finding(make_finding(43))
    assert n3["finding_id"] != n1["finding_id"]

    # normalize_payload must preserve the generated identity.
    payload = normalize_payload({"findings": [f]})
    assert payload["findings"][0]["finding_id"] == n1["finding_id"]

    # Evidence must link to the finding identity, not replace it.
    ev = finding_to_evidence(n1)
    assert ev is not None, "finding_to_evidence returned None"
    assert getattr(ev, "related_finding_id", None) == n1["finding_id"]

    print("[PASS] deterministic finding_id")
    print("[PASS] existing finding_id preserved")
    print("[PASS] distinct occurrence separation")
    print("[PASS] normalize_payload preserves finding_id")
    print("[PASS] evidence.related_finding_id linkage")
    print("FINDING_ID_EVIDENCE_LINKAGE_ACCEPTED")

if __name__ == "__main__":
    main()
'@
    [IO.File]::WriteAllText($TestFile,$test,(New-Object Text.UTF8Encoding($false)))
    Write-Host "[PASS] Acceptance test created: $TestFile"

    python -m py_compile $FindingModel
    if ($LASTEXITCODE -ne 0) { throw "finding_model.py compilation failed." }

    python -m py_compile $EvidenceAdapter
    if ($LASTEXITCODE -ne 0) { throw "evidence_adapter.py compilation failed." }
    Write-Host "[PASS] Production compilation"

    python $TestFile
    if ($LASTEXITCODE -ne 0) { throw "Finding identity/evidence acceptance failed." }

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "R-SecOpsX V11 - FINDING IDENTITY / EVIDENCE LINKAGE ACCEPTED"
    Write-Host "============================================================"
    Write-Host "[PASS] Canonical deterministic finding_id"
    Write-Host "[PASS] Existing finding_id preserved"
    Write-Host "[PASS] Distinct finding occurrences remain distinct"
    Write-Host "[PASS] Evidence.related_finding_id linkage"
    Write-Host "[PASS] Persistent acceptance test"
    Write-Host "[PASS] Backups retained under backup\"
}
catch {
    Write-Host ""
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    if ($productionChanged) {
        Restore-Backups
        Write-Host "[PASS] Production source restored from backups." -ForegroundColor Yellow
    } else {
        Write-Host "[PASS] Production source was not written." -ForegroundColor Yellow
    }
    throw
}
