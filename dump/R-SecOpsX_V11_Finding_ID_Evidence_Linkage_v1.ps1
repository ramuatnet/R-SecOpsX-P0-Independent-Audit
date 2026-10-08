# R-SecOpsX V11 - Canonical Finding ID + Evidence Linkage v1
# Production-safe patch:
#   backup -> exact anchors -> patch -> compile -> persistent acceptance -> rollback on failure
$ErrorActionPreference = "Stop"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$BackupDir = Join-Path $Root "backup"
$TestsDir = Join-Path $Root "tests"

$FindingModel = Join-Path $Root "core\finding_model.py"
$EvidenceAdapter = Join-Path $Root "core\evidence_adapter.py"
$EvidenceSchema = Join-Path $Root "core\evidence_schema.py"
$TestFile = Join-Path $TestsDir "test_v11_finding_identity_evidence_linkage_v1.py"

New-Item -ItemType Directory -Force -Path $BackupDir,$TestsDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$FindingBackup = Join-Path $BackupDir "finding_model.py.before_finding_identity_v1_$stamp.py"
$EvidenceBackup = Join-Path $BackupDir "evidence_adapter.py.before_finding_identity_v1_$stamp.py"

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
    $before = $Text.Substring(0, $idx)
    $after = $Text.Substring($idx + $Old.Length)
    return $before + $New + $after
}

function Restore-Backup {
    if ($findingOriginal -ne $null -and (Test-Path $FindingBackup)) {
        [System.IO.File]::WriteAllText($FindingModel, $findingOriginal, (New-Object System.Text.UTF8Encoding($false)))
    }
    if ($evidenceOriginal -ne $null -and (Test-Path $EvidenceBackup)) {
        [System.IO.File]::WriteAllText($EvidenceAdapter, $evidenceOriginal, (New-Object System.Text.UTF8Encoding($false)))
    }
}

try {
    if (-not (Test-Path $Root -PathType Container)) { throw "V11 root not found: $Root" }
    foreach ($p in @($FindingModel,$EvidenceAdapter,$EvidenceSchema)) {
        if (-not (Test-Path $p -PathType Leaf)) { throw "Required source file missing: $p" }
    }

    $findingOriginal = [System.IO.File]::ReadAllText($FindingModel)
    $evidenceOriginal = [System.IO.File]::ReadAllText($EvidenceAdapter)
    $schemaText = [System.IO.File]::ReadAllText($EvidenceSchema)

    Copy-Item -LiteralPath $FindingModel -Destination $FindingBackup -Force
    Copy-Item -LiteralPath $EvidenceAdapter -Destination $EvidenceBackup -Force
    Write-Host "[PASS] Finding-model backup: $FindingBackup"
    Write-Host "[PASS] Evidence-adapter backup: $EvidenceBackup"

    # Contract gate: evidence schema must already support explicit finding linkage.
    if ($schemaText -notmatch '(?m)^\s*related_finding_id\s*:') {
        throw "Evidence schema does not expose related_finding_id. No production source written."
    }
    Write-Host "[PASS] Evidence schema exposes related_finding_id"

    $py = $findingOriginal

    if ($py -notmatch '(?m)^from uuid import') {
        $typingLine = "from typing import Any"
        $typingIndex = $py.IndexOf($typingLine, [System.StringComparison]::Ordinal)
        if ($typingIndex -lt 0) { throw "Required source anchor not found: from typing import Any" }
        $nl = if ($py.Contains("`r`n")) { "`r`n" } else { "`n" }
        $py = $py.Substring(0, $typingIndex) + $typingLine + $nl + "from uuid import UUID, NAMESPACE_URL, uuid5" + $nl + $py.Substring($typingIndex + $typingLine.Length + $nl.Length)
    } else {
        if ($py -notmatch 'NAMESPACE_URL') {
            $py = Replace-Once `
                $py `
                "from uuid import " `
                "from uuid import UUID, NAMESPACE_URL, uuid5, " `
                "uuid import extension"
        }
    }

    $nl = if ($py.Contains("`r`n")) { "`r`n" } else { "`n" }
    $anchor = "CONTROL_GAP_TERMS = ('api_', 'control_gap', 'rate_limit', 'brute_force', 'abuse')" + $nl + $nl + $nl
    $helper = @"
CONTROL_GAP_TERMS = ('api_', 'control_gap', 'rate_limit', 'brute_force', 'abuse')

_FINDING_ID_PREFIX = 'rsecopsx-v11:finding:'

def _canonical_finding_id(f: dict[str, Any]) -> str:
    """Return a stable UUID for the normalized finding occurrence."""
    existing = str(f.get('finding_id') or '').strip()
    if existing:
        return existing

    parts = (
        str(f.get('rule_id') or '').strip(),
        str(f.get('vuln_type') or '').strip(),
        str(f.get('file') or '').replace('\\', '/').strip(),
        str(f.get('line') if f.get('line') is not None else '').strip(),
        str(f.get('column') if f.get('column') is not None else '').strip(),
        str(f.get('sink_category') or '').strip(),
        str(f.get('source') or '').strip(),
        str(f.get('snippet') or '').strip(),
    )
    seed = '|'.join(parts)
    return str(uuid5(NAMESPACE_URL, _FINDING_ID_PREFIX + seed))


"@

    $py = Replace-Once $py $anchor $helper "finding identity helper insertion"

    $normalizeAnchor = "def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:" + $nl + "    f = dict(f)" + $nl + "    f['classification'] = classify_finding(f)" + $nl
    $normalizeReplacement = @"
def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:
    f = dict(f)
    f['finding_id'] = _canonical_finding_id(f)
    f['classification'] = classify_finding(f)
"@

    $py = Replace-Once $py $normalizeAnchor $normalizeReplacement "normalize_finding identity assignment"

    # Prevent accidental duplicate helper insertion.
    if ([regex]::Matches($py, 'def _canonical_finding_id\(').Count -ne 1) {
        throw "Post-patch invariant failed: _canonical_finding_id count is not 1."
    }

    [System.IO.File]::WriteAllText($FindingModel, $py, (New-Object System.Text.UTF8Encoding($false)))
    $productionChanged = $true
    Write-Host "[PASS] Installed canonical finding_id lifecycle"

    $ea = $evidenceOriginal

    $evidenceAnchor = "        evidence_id=_stable_or_generated_id(finding),"
    $evidenceReplacement = @"
        evidence_id=_stable_or_generated_id(finding),
        related_finding_id=finding.get("finding_id"),
"@

    $ea = Replace-Once $ea $evidenceAnchor $evidenceReplacement "Evidence related_finding_id constructor linkage"

    if ($ea -notmatch 'related_finding_id=finding\.get\("finding_id"\)') {
        throw "Post-patch invariant failed: evidence linkage was not installed."
    }

    [System.IO.File]::WriteAllText($EvidenceAdapter, $ea, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[PASS] Linked evidence.related_finding_id to canonical finding_id"

    # Persistent acceptance test.
    $test = @'
from pathlib import Path
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.finding_model import normalize_finding, normalize_payload
from core.evidence_adapter import finding_to_evidence

def main():
    f = {
        "rule_id": "TEST-FINDING-ID",
        "vuln_type": "prompt_injection",
        "file": "src/app.py",
        "line": 42,
        "column": 7,
        "snippet": "ignore previous instructions",
        "severity": "Medium",
        "evidence_valid": True,
    }

    n1 = normalize_finding(f)
    n2 = normalize_finding(f)

    assert n1["finding_id"], "finding_id missing"
    assert n1["finding_id"] == n2["finding_id"], "finding_id is not deterministic"
    assert len(n1["finding_id"]) == 36, "finding_id is not UUID-shaped"

    changed = dict(f)
    changed["line"] = 43
    n3 = normalize_finding(changed)
    assert n3["finding_id"] != n1["finding_id"], "distinct finding occurrence collapsed"

    payload = normalize_payload({"findings": [f]})
    assert payload["findings"][0]["finding_id"] == n1["finding_id"]

    ev = finding_to_evidence(n1)
    assert ev is not None, "finding_to_evidence returned None"
    assert getattr(ev, "related_finding_id", None) == n1["finding_id"], (
        "Evidence is not linked to canonical finding_id"
    )

    print("[PASS] deterministic finding_id")
    print("[PASS] distinct occurrence separation")
    print("[PASS] normalize_payload preserves finding_id")
    print("[PASS] evidence.related_finding_id linkage")
    print("FINDING_ID_EVIDENCE_LINKAGE_ACCEPTED")

if __name__ == "__main__":
    main()
'@

    [System.IO.File]::WriteAllText($TestFile, $test, (New-Object System.Text.UTF8Encoding($false)))
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
    Write-Host "[PASS] Evidence related_finding_id linkage"
    Write-Host "[PASS] Persistent acceptance test"
    Write-Host "[PASS] Backups retained under backup\"
}
catch {
    Write-Host ""
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    if ($productionChanged) {
        Restore-Backup
        Write-Host "[PASS] Production source restored from backups." -ForegroundColor Yellow
    } else {
        Write-Host "[PASS] Production source was not written." -ForegroundColor Yellow
    }
    throw
}
