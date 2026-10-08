$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not (Test-Path (Join-Path $Root "main.py"))) {
    Write-Host "[FAIL] Repository root sanity check failed: $Root"
    exit 2
}

$OutDir = Join-Path $Root "Working folder\OWASP_LLM01_Targeted_Audit"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$txt = Join-Path $OutDir "V11_LLM01_Targeted_Audit_$stamp.txt"
$csv = Join-Path $OutDir "V11_LLM01_Targeted_Audit_$stamp.csv"

$rows = @()

function Add-Row {
    param(
        [string]$Area,
        [string]$Status,
        [string]$Evidence,
        [string]$Assessment
    )
    $script:rows += [PSCustomObject]@{
        Area = $Area
        Status = $Status
        Evidence = $Evidence
        Assessment = $Assessment
    }
}

function Read-TextSafe {
    param([string]$Path)
    if (Test-Path $Path) { return (Get-Content $Path -Raw) }
    return ""
}

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - LLM01 TARGETED IMPLEMENTATION AUDIT"
Write-Host " READ-ONLY / NO PRODUCTION MODIFICATION"
Write-Host "============================================================"
Write-Host ""

$mainPath = Join-Path $Root "main.py"
$llmPath = Join-Path $Root "scanner\llm_security.py"
$fmPath = Join-Path $Root "core\finding_model.py"
$adapterPath = Join-Path $Root "core\evidence_adapter.py"

$main = Read-TextSafe $mainPath
$llm = Read-TextSafe $llmPath
$fm = Read-TextSafe $fmPath
$adapter = Read-TextSafe $adapterPath

# 1. Baseline engine / rule
if ($llm -match "LLM01_PROMPT_INJECTION") {
    Add-Row "LLM01 rule" "PASS" "scanner\llm_security.py contains LLM01_PROMPT_INJECTION" "Existing rule confirmed"
} else {
    Add-Row "LLM01 rule" "FAIL" "Rule symbol not found" "LLM01 rule requires implementation"
}

# 2. Production call path
$prodSignals = @(
    "llm_security",
    "scan_llm",
    "LLM01_PROMPT_INJECTION",
    "prompt_injection"
)
$prodHits = @($prodSignals | Where-Object { $main -match [regex]::Escape($_) })
if ($prodHits.Count -gt 0) {
    Add-Row "Production LLM path" "PASS" ("main.py contains: " + ($prodHits -join ", ")) "Production reference exists; exact runtime path should be confirmed from source"
} else {
    Add-Row "Production LLM path" "REVIEW_REQUIRED" "No expected LLM security signal found in main.py" "Need source-level call-chain inspection"
}

# 3. Payload splitting: distinguish generic split/join handling from actual detection.
$splitPatterns = @(
    "payload.?split",
    "split.?payload",
    "fragment",
    "fragmented",
    "multi.?part",
    "concatenat",
    "reassembl",
    "chunk"
)
$splitHits = @($splitPatterns | Where-Object { $llm -match $_ })
if ($splitHits.Count -gt 0) {
    Add-Row "Payload splitting" "REVIEW_REQUIRED" ("Indicators: " + ($splitHits -join ", ")) "Potential implementation exists; inspect whether it detects malicious instructions distributed across fragments"
} else {
    Add-Row "Payload splitting" "GAP" "No payload-splitting indicators in LLM security engine" "Add focused detection/test coverage if the V11 threat model includes fragmented prompts"
}

# 4. Multilingual / obfuscation
$obfPatterns = @(
    "unicode",
    "homoglyph",
    "obfuscat",
    "zero.?width",
    "normaliz",
    "base64",
    "encoding",
    "translat",
    "multilingual",
    "language"
)
$obfHits = @($obfPatterns | Where-Object { $llm -match $_ })
if ($obfHits.Count -gt 0) {
    Add-Row "Multilingual / obfuscation" "REVIEW_REQUIRED" ("Indicators: " + ($obfHits -join ", ")) "Potential handling exists; verify security semantics rather than symbol presence alone"
} else {
    Add-Row "Multilingual / obfuscation" "GAP" "No explicit multilingual/obfuscation indicators in LLM security engine" "Add normalization/obfuscation-resilient tests and implementation where justified"
}

# 5. Multimodal applicability
$multiPatterns = @(
    "multimodal",
    "image",
    "ocr",
    "vision",
    "audio",
    "transcript",
    "document"
)
$multiHits = @($main, $llm | ForEach-Object {
    foreach ($p in $multiPatterns) {
        if ($_ -match $p) { $p }
    }
} | Sort-Object -Unique)

if ($multiHits.Count -gt 0) {
    Add-Row "Multimodal injection" "REVIEW_REQUIRED" ("Indicators: " + ($multiHits -join ", ")) "Architecture shows multimodal-related terms; determine whether V11 actually ingests multimodal input before implementing"
} else {
    Add-Row "Multimodal injection" "N/A_CANDIDATE" "No multimodal ingestion indicators found in main.py or llm_security.py" "Do not add artificial multimodal detection unless the product scope requires it"
}

# 6. Tests
$testFiles = @(Get-ChildItem (Join-Path $Root "tests") -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -eq ".py" })

$llmTests = @($testFiles | Where-Object {
    $t = Get-Content $_.FullName -Raw
    $t -match "LLM01|prompt.?injection"
})

if ($llmTests.Count -gt 0) {
    Add-Row "LLM01 tests" "PASS" (($llmTests.FullName | ForEach-Object { Split-Path $_ -Leaf }) -join ", ") "Dedicated LLM01/prompt-injection test evidence exists"
} else {
    Add-Row "LLM01 tests" "GAP" "No LLM01/prompt-injection test file found" "Add focused regression tests"
}

# 7. Canonical evidence linkage
$evidenceSignals = @(
    "canonical_evidence",
    "canonical_qualified_evidence",
    "normalize_finding",
    "evidence_adapter"
)
$fmHits = @($evidenceSignals | Where-Object { $fm -match [regex]::Escape($_) })
$adapterHits = @($evidenceSignals | Where-Object { $adapter -match [regex]::Escape($_) })

if ($fmHits.Count -gt 0 -and $adapterHits.Count -gt 0) {
    Add-Row "Canonical evidence infrastructure" "PASS" ("finding_model: " + ($fmHits -join ", ") + "; adapter: " + ($adapterHits -join ", ")) "Canonical evidence infrastructure exists; LLM01-specific production attachment still requires call-path proof"
} else {
    Add-Row "Canonical evidence infrastructure" "REVIEW_REQUIRED" "Expected canonical evidence symbols not all found" "Do not patch until the existing evidence architecture is reviewed"
}

# 8. LLM01-specific evidence attachment
$llmEvidenceHits = @($llm -match "canonical_evidence|canonical_qualified_evidence|evidence_adapter|normalize_finding")
if ($llmEvidenceHits -contains $true) {
    Add-Row "LLM01 -> canonical evidence direct linkage" "PASS" "LLM security engine contains canonical evidence references" "Direct source linkage appears present"
} else {
    Add-Row "LLM01 -> canonical evidence direct linkage" "REVIEW_REQUIRED" "No direct canonical evidence symbol found in llm_security.py" "This does not prove a defect if normalization occurs at a later production boundary"
}

# 9. Mapping
$mappingFiles = @(Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in ".py",".yaml",".yml",".json" -and $_.FullName -notmatch "\\Working folder\\|\\__pycache__\\|\\.git\\" })

$mappingHits = @()
foreach ($f in $mappingFiles) {
    try {
        $t = Get-Content $f.FullName -Raw
        if ($t -match "LLM01_PROMPT_INJECTION" -or $t -match "LLM01") {
            $mappingHits += $f.FullName
        }
    } catch {}
}
if ($mappingHits.Count -gt 0) {
    Add-Row "OWASP LLM01 mapping" "PASS" (($mappingHits | ForEach-Object { $_.Substring($Root.Length).TrimStart("\") }) -join "; ") "Mapping evidence exists"
} else {
    Add-Row "OWASP LLM01 mapping" "GAP" "No LLM01 mapping found" "Add verified OWASP mapping only after taxonomy is confirmed"
}

# Console summary
$rows | ForEach-Object {
    $tag = if ($_.Status -eq "PASS") { "PASS" } elseif ($_.Status -eq "GAP" -or $_.Status -eq "FAIL") { "GAP" } else { "REVIEW_REQUIRED" }
    Write-Host ("[{0}] {1} - {2}" -f $tag, $_.Area, $_.Evidence)
}

$rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
$lines = @(
    "R-SecOpsX V11 - LLM01 TARGETED IMPLEMENTATION AUDIT",
    "Timestamp: $stamp",
    "Repository: $Root",
    "",
    "READ-ONLY. No production source modified.",
    ""
)
foreach ($r in $rows) {
    $lines += "[{0}] {1}" -f $r.Status, $r.Area
    $lines += "Evidence: $($r.Evidence)"
    $lines += "Assessment: $($r.Assessment)"
    $lines += ""
}
$lines | Set-Content $txt -Encoding UTF8

$pass = @($rows | Where-Object Status -eq "PASS").Count
$gap = @($rows | Where-Object Status -eq "GAP").Count
$review = @($rows | Where-Object Status -eq "REVIEW_REQUIRED").Count
$na = @($rows | Where-Object Status -eq "N/A_CANDIDATE").Count

Write-Host ""
Write-Host "============================================================"
Write-Host " TARGETED LLM01 AUDIT SUMMARY"
Write-Host "============================================================"
Write-Host "PASS             : $pass"
Write-Host "GAP              : $gap"
Write-Host "REVIEW_REQUIRED  : $review"
Write-Host "N/A_CANDIDATE    : $na"
Write-Host "TXT              : $txt"
Write-Host "CSV              : $csv"
Write-Host ""
Write-Host "TARGETED LLM01 AUDIT: COMPLETE"
