# R-SecOpsX V11 - OWASP LLM01 Coverage Gate
# READ-ONLY VALIDATION - no production files are modified
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutDir = Join-Path $Root "Working folder\OWASP_LLM01_Gate"

# Root sanity: this gate must execute against the R-SecOpsX V11 repository,
# not its parent directory.
if (-not (Test-Path (Join-Path $Root "main.py"))) {
    Write-Host "[FAIL] Gate root sanity - main.py not found under resolved repository root: $Root"
    exit 2
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Results = New-Object System.Collections.Generic.List[object]

function Add-Result([string]$Area, [string]$Status, [string]$Evidence, [string]$Detail) {
    $Results.Add([PSCustomObject]@{
        Area = $Area
        Status = $Status
        Evidence = $Evidence
        Detail = $Detail
    })
}

function Read-Text($Path) {
    if (Test-Path $Path) { return Get-Content $Path -Raw -ErrorAction Stop }
    return ""
}

function Has-Any($Text, [string[]]$Patterns) {
    foreach ($p in $Patterns) {
        if ($Text -match $p) { return $true }
    }
    return $false
}

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - OWASP LLM01 COVERAGE GATE v2"
Write-Host " READ-ONLY / OFFICIAL OWASP LLM01:2025 BASELINE"
Write-Host "============================================================"
Write-Host ""

$llm = Join-Path $Root "scanner\llm_security.py"
$main = Join-Path $Root "main.py"
$mappingCandidates = @(
    (Join-Path $Root "core\owasp_mappings.py"),
    (Join-Path $Root "scanner\llm_security.py"),
    (Join-Path $Root "framework_mappings.yaml"),
    (Join-Path $Root "framework_mappings.py")
)

$llmText = Read-Text $llm
$mainText = Read-Text $main

# 1. Core rule
if (Test-Path $llm) {
    if ($llmText -match "LLM01_PROMPT_INJECTION") {
        Add-Result "LLM01 rule" "PASS" $llm "LLM01_PROMPT_INJECTION present"
    } else {
        Add-Result "LLM01 rule" "REVIEW_REQUIRED" $llm "LLM01 rule file exists but rule identifier was not found"
    }
} else {
    Add-Result "LLM01 rule" "FAIL" "scanner\llm_security.py" "LLM security engine not found"
}

# 2. Production invocation
if ($mainText -match "llm_security" -and
    ($mainText -match "scan_llm" -or $mainText -match "llm_security")) {
    Add-Result "Production LLM integration" "PASS" $main "main.py contains LLM security integration references"
} else {
    Add-Result "Production LLM integration" "REVIEW_REQUIRED" $main "Static inspection did not establish a production LLM invocation"
}

# 3. Direct injection
if (Has-Any $llmText @(
    "ignore\\s+previous\\s+instructions",
    "ignore\\s+all\\s+previous",
    "system\\s+prompt",
    "jailbreak"
)) {
    Add-Result "Direct prompt injection" "PASS" $llm "Direct-injection/jailbreak patterns found"
} else {
    Add-Result "Direct prompt injection" "REVIEW_REQUIRED" $llm "No direct-injection pattern established"
}

# 4. Indirect injection / external content
if (Has-Any $llmText @(
    "indirect",
    "external.*content",
    "retriev",
    "RAG",
    "document.*instruction",
    "web.*instruction"
)) {
    Add-Result "Indirect prompt injection" "PASS" $llm "Indirect/external-content/RAG indicators found"
} else {
    Add-Result "Indirect prompt injection" "REVIEW_REQUIRED" $llm "No explicit indirect-injection evidence established"
}

# 5. Payload splitting
if (Has-Any $llmText @("payload.*split", "split.*payload", "fragment.*prompt", "multi[-_ ]step.*prompt")) {
    Add-Result "Payload splitting" "PASS" $llm "Payload-splitting indicator found"
} else {
    Add-Result "Payload splitting" "REVIEW_REQUIRED" $llm "No explicit payload-splitting implementation evidence"
}

# 6. Multimodal injection
if (Has-Any $llmText @("multimodal", "image.*prompt", "audio.*prompt", "video.*prompt", "vision.*prompt")) {
    Add-Result "Multimodal injection" "PASS" $llm "Multimodal injection indicator found"
} else {
    Add-Result "Multimodal injection" "REVIEW_REQUIRED" $llm "No explicit multimodal prompt-injection implementation evidence"
}

# 7. Adversarial suffix
if (Has-Any $llmText @("adversarial.*suffix", "suffix.*attack", "adversarial")) {
    Add-Result "Adversarial suffix" "PASS" $llm "Adversarial/suffix indicator found"
} else {
    Add-Result "Adversarial suffix" "REVIEW_REQUIRED" $llm "No explicit adversarial-suffix implementation evidence"
}

# 8. Multilingual / obfuscated attacks
if (Has-Any $llmText @(
    "Base64", "base64", "unicode", "obfuscat", "emoji", "multilingual", "encoding"
)) {
    Add-Result "Multilingual/obfuscated injection" "PASS" $llm "Encoding/obfuscation/multilingual indicator found"
} else {
    Add-Result "Multilingual/obfuscated injection" "REVIEW_REQUIRED" $llm "No explicit multilingual/obfuscation evidence"
}

# 9. Tool/MCP injection surface
if (Has-Any $llmText @("MCP", "tool", "function", "plugin", "agent")) {
    Add-Result "Tool/MCP injection surface" "PASS" $llm "Tool/plugin/agent/MCP indicators found"
} else {
    Add-Result "Tool/MCP injection surface" "REVIEW_REQUIRED" $llm "No explicit tool/MCP surface evidence"
}

# 10. Memory propagation
if (Has-Any $llmText @("memory", "context.*poison", "persistent.*context", "session")) {
    Add-Result "Memory/session propagation" "PASS" $llm "Memory/session indicators found"
} else {
    Add-Result "Memory/session propagation" "REVIEW_REQUIRED" $llm "No explicit memory/session propagation evidence"
}

# 11. Evidence normalization
if (($mainText -match "normalize_payload") -and
    ($mainText -match "normalize_finding") -and
    ($mainText -match "canonical_evidence")) {
    Add-Result "Canonical evidence integration" "PASS" $main "Canonical normalization/evidence markers present"
} else {
    Add-Result "Canonical evidence integration" "REVIEW_REQUIRED" $main "Production canonical evidence path not established by this gate"
}

# 12. Tests
$tests = Get-ChildItem -Path (Join-Path $Root "tests") -Recurse -File -Include *.py -ErrorAction SilentlyContinue
$llmTests = $tests | Where-Object {
    $t = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    $t -match "LLM01|prompt.injection|prompt_injection"
}
if ($llmTests.Count -gt 0) {
    Add-Result "LLM01 test evidence" "PASS" (($llmTests.FullName) -join "; ") "$($llmTests.Count) test file(s) contain LLM01/prompt-injection coverage"
} else {
    Add-Result "LLM01 test evidence" "REVIEW_REQUIRED" "tests\" "No LLM01-specific test file found by static search"
}

# 13. Mapping namespace
$mappingText = ""
foreach ($p in $mappingCandidates) {
    if (Test-Path $p) { $mappingText += "`n" + (Get-Content $p -Raw -ErrorAction SilentlyContinue) }
}
if ($mappingText -match "LLM01") {
    Add-Result "OWASP LLM01 mapping" "PASS" "OWASP mapping candidates" "LLM01 mapping identifier exists"
} else {
    Add-Result "OWASP LLM01 mapping" "REVIEW_REQUIRED" "OWASP mapping candidates" "LLM01 mapping identifier not found"
}

# 14. Do not claim unsupported 2026 namespace
if ($mappingText -match "LLM01:2026") {
    Add-Result "OWASP namespace integrity" "REVIEW_REQUIRED" "OWASP mapping candidates" "LLM01:2026 was found; verify against the project's authoritative OWASP source before accepting it"
} else {
    Add-Result "OWASP namespace integrity" "PASS" "OWASP mapping candidates" "No unsupported LLM01:2026 identifier detected"
}

$csv = Join-Path $OutDir "V11_LLM01_Coverage_$Stamp.csv"
$txt = Join-Path $OutDir "V11_LLM01_Coverage_$Stamp.txt"
$Results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv

$pass = @($Results | Where-Object Status -eq "PASS").Count
$review = @($Results | Where-Object Status -eq "REVIEW_REQUIRED").Count
$fail = @($Results | Where-Object Status -eq "FAIL").Count

@(
"============================================================"
" R-SecOpsX V11 - OWASP LLM01 COVERAGE GATE v2"
"============================================================"
"Timestamp       : $Stamp"
"Root            : $Root"
"PASS            : $pass"
"REVIEW_REQUIRED : $review"
"FAIL            : $fail"
""
"STATUS RULE:"
"PASS requires source evidence only; it does not prove runtime efficacy."
"REVIEW_REQUIRED means implementation or validation evidence is incomplete."
"FAIL means the expected core capability is absent."
""
"DETAILED RESULTS"
"------------------------------------------------------------"
) | Set-Content -Encoding UTF8 $txt

$Results | ForEach-Object {
    "[{0}] {1} - {2} - {3}" -f $_.Status, $_.Area, $_.Evidence, $_.Detail
} | Add-Content -Encoding UTF8 $txt

Write-Host ""
$Results | ForEach-Object {
    Write-Host ("[{0}] {1} - {2}" -f $_.Status, $_.Area, $_.Detail)
}

Write-Host ""
Write-Host "============================================================"
Write-Host " LLM01 COVERAGE GATE SUMMARY"
Write-Host "============================================================"
Write-Host "PASS            : $pass"
Write-Host "REVIEW_REQUIRED : $review"
Write-Host "FAIL            : $fail"
Write-Host "TXT             : $txt"
Write-Host "CSV             : $csv"
Write-Host ""

if ($fail -gt 0) {
    Write-Host "LLM01 COVERAGE GATE: FAIL"
    exit 2
}
elseif ($review -gt 0) {
    Write-Host "LLM01 COVERAGE GATE: REVIEW_REQUIRED"
    exit 1
}
else {
    Write-Host "LLM01 COVERAGE GATE: PASS"
    exit 0
}
