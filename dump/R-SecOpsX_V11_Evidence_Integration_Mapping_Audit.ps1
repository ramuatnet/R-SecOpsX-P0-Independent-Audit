# R-SecOpsX V11 - Evidence Integration Mapping Audit
# READ-ONLY. No production source is modified.
$ErrorActionPreference = "Continue"

$Root = "D:\data\Code test\r-SecOpsX_V11"
$OutDir = Join-Path $Root "Working folder\Evidence_Integration_Audit"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Report = Join-Path $OutDir "V11_Evidence_Integration_Mapping_$Stamp.txt"
$Csv = Join-Path $OutDir "V11_Evidence_Integration_Mapping_$Stamp.csv"

$Rows = @()

function Add-Row {
    param(
        [string]$Area,
        [string]$Path,
        [string]$Symbol,
        [string]$Evidence
    )
    $script:Rows += [PSCustomObject]@{
        Area = $Area
        Path = $Path
        Symbol = $Symbol
        Evidence = $Evidence
    }
}

function Scan-Pattern {
    param(
        [string]$Area,
        [string]$Path,
        [string[]]$Patterns
    )

    if (-not (Test-Path $Path -PathType Leaf)) {
        Add-Row $Area $Path "FILE_MISSING" "Target file not present"
        return
    }

    foreach ($Pattern in $Patterns) {
        $matches = Select-String -Path $Path -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue
        foreach ($m in $matches) {
            Add-Row $Area $Path $Pattern ("Line " + $m.LineNumber + ": " + $m.Line.Trim())
        }
    }
}

Start-Transcript -Path $Report -Force | Out-Null

Write-Host ""
Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - EVIDENCE INTEGRATION MAPPING AUDIT"
Write-Host " READ-ONLY"
Write-Host "============================================================"
Write-Host ""

if (-not (Test-Path $Root -PathType Container)) {
    Write-Host "[BLOCKED] V11 root not found: $Root"
    Stop-Transcript | Out-Null
    exit 2
}

$FindingModel = Join-Path $Root "core\finding_model.py"
$Analyzer = Join-Path $Root "core\analyzer.py"
$Main = Join-Path $Root "main.py"
$EvidenceSchema = Join-Path $Root "core\evidence_schema.py"

Write-Host "--- 1. Canonical Evidence Schema ---"
Scan-Pattern "CanonicalSchema" $EvidenceSchema @(
    "class Evidence",
    "class QualifiedEvidence",
    "evidence_id",
    "timestamp",
    "provenance",
    "confidence",
    "related_finding_id"
)

Write-Host "--- 2. Finding normalization boundary ---"
Scan-Pattern "FindingNormalization" $FindingModel @(
    "def classify_finding",
    "def normalize_finding",
    "def normalize_payload",
    "evidence_valid",
    "evidence_state",
    "evidence_confidence",
    "confidence",
    "confidence_score",
    "confidence_label",
    "evidence_validation_detail",
    "evidence_validation",
    "evidence_quality",
    "evidence_reason",
    "detected_at",
    "provenance"
)

Write-Host "--- 3. Finding production / grouping ---"
Scan-Pattern "FindingProduction" $Analyzer @(
    "evidence_valid",
    "evidence_state",
    "evidence_confidence",
    "confidence",
    "confidence_score",
    "confidence_label",
    "evidence_validation_detail",
    "evidence_validation",
    "evidence_quality",
    "detected_at",
    "provenance",
    "normalize_finding"
)

Write-Host "--- 4. Production entry point ---"
Scan-Pattern "ProductionEntry" $Main @(
    "finding_model",
    "normalize_finding",
    "normalize_payload",
    "analyze",
    "scan_directory",
    "sast",
    "taint"
)

Write-Host "--- 5. Evidence producers across scanner/core/analysis ---"

$SourceFiles = Get-ChildItem -Path $Root -Recurse -File -Include *.py -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notlike ($Root + "\backup\*") -and
        $_.FullName -notlike ($Root + "\Working folder\*") -and
        $_.FullName -notlike "*\__pycache__\*" -and
        $_.FullName -notlike "*\.git\*"
    }

$ProducerPatterns = @(
    "evidence_valid",
    "evidence_confidence",
    "evidence_validation_detail",
    "evidence_score",
    "evidence_quality",
    "evidence_reason",
    "confidence_basis",
    "context_confidence",
    "runtime_validation_status",
    "detected_at",
    "provenance"
)

foreach ($File in $SourceFiles) {
    foreach ($Pattern in $ProducerPatterns) {
        $matches = Select-String -Path $File.FullName -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue
        foreach ($m in ($matches | Select-Object -First 5)) {
            Add-Row "EvidenceProducer" $File.FullName $Pattern ("Line " + $m.LineNumber + ": " + $m.Line.Trim())
        }
    }
}

Write-Host "--- 6. Potential existing evidence object/model references ---"

foreach ($File in $SourceFiles) {
    $matches = Select-String -Path $File.FullName `
        -Pattern "Evidence|QualifiedEvidence|evidence_id|provenance" `
        -SimpleMatch -ErrorAction SilentlyContinue

    foreach ($m in ($matches | Select-Object -First 5)) {
        Add-Row "EvidenceModelReference" $File.FullName "Evidence-related symbol" ("Line " + $m.LineNumber + ": " + $m.Line.Trim())
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host " MAPPING SUMMARY"
Write-Host "============================================================"

$SchemaCount = @($Rows | Where-Object Area -eq "CanonicalSchema").Count
$FindingCount = @($Rows | Where-Object Area -eq "FindingNormalization").Count
$ProductionCount = @($Rows | Where-Object Area -eq "EvidenceProducer").Count
$EntryCount = @($Rows | Where-Object Area -eq "ProductionEntry").Count

Write-Host ("Canonical schema evidence      : " + $SchemaCount)
Write-Host ("Finding normalization evidence : " + $FindingCount)
Write-Host ("Evidence producer references   : " + $ProductionCount)
Write-Host ("Production entry references    : " + $EntryCount)
Write-Host ("Total mapping rows             : " + $Rows.Count)

$Rows | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Report: $Report"
Write-Host "CSV   : $Csv"
Write-Host ""
Write-Host "IMPORTANT:"
Write-Host "This audit is read-only."
Write-Host "No production source was modified."
Write-Host "Do not patch finding_model.py until this mapping is reviewed."

Stop-Transcript | Out-Null
exit 0
