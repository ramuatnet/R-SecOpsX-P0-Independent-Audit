Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Set-Location "D:\data\Code test\R-SecOpsX_V11"

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = ".\Working folder\D02_PII_Coverage_Gate"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$txt = Join-Path $outDir "V11_D02_Coverage_$stamp.txt"
$csv = Join-Path $outDir "V11_D02_Coverage_$stamp.csv"

$rows = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [string]$Id,
        [string]$Requirement,
        [ValidateSet("PASS","PARTIAL","GAP","REVIEW_REQUIRED")]
        [string]$Status,
        [string]$Evidence
    )

    $rows.Add([pscustomobject]@{
        ID = $Id
        Requirement = $Requirement
        Status = $Status
        Evidence = $Evidence
    })
}

$engine = ".\analysis\privacy_data_exposure_engine.py"
$testFiles = Get-ChildItem ".\tests" -Recurse -File -Filter "*.py" -ErrorAction SilentlyContinue
$engineText = ""
if (Test-Path $engine) {
    $engineText = Get-Content $engine -Raw
}

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - D-02 PII COVERAGE GATE"
Write-Host " READ-ONLY / NO PRODUCTION MODIFICATION"
Write-Host "============================================================"
Write-Host ""

if (Test-Path $engine) {
    Add-Check "D02-00" "Privacy/PII engine exists" "PASS" $engine
}
else {
    Add-Check "D02-00" "Privacy/PII engine exists" "GAP" $engine
}

$checks = @(
    @{
        Id="D02-01"; Req="Email PII detection";
        Patterns=@("email", "EMAIL")
    },
    @{
        Id="D02-02"; Req="Phone PII detection";
        Patterns=@("phone", "PHONE", "MSISDN", "telephone")
    },
    @{
        Id="D02-03"; Req="SSN PII detection";
        Patterns=@("SSN", "social.?security", "3.*2.*4")
    },
    @{
        Id="D02-04"; Req="Credit/payment-card PII detection";
        Patterns=@("credit.?card", "payment.?card", "card[_ -]?(number|num)", "CVV", "CVC")
    },
    @{
        Id="D02-05"; Req="IPv4/IPv6 PII detection";
        Patterns=@("IP_ADDRESS", "IPv4", "IPv6", "ip.?address")
    },
    @{
        Id="D02-06"; Req="Semantic/context-aware qualification";
        Patterns=@("bounded semantic context", "semantic evidence", "_privacy_pii_hits_fast")
    },
    @{
        Id="D02-07"; Req="Production/non-production context controls";
        Patterns=@("_is_non_production_text", "fixtures", "documentation", "localization")
    },
    @{
        Id="D02-08"; Req="Privacy evidence state";
        Patterns=@("OBSERVED_ONLY", "EXPOSED", "privacy_evidence_state")
    },
    @{
        Id="D02-09"; Req="Source-to-sink exposure classification";
        Patterns=@("_classify_exposure", "source-to-sink", "exposure sink")
    },
    @{
        Id="D02-10"; Req="Redaction implementation";
        Patterns=@("def redact", "redact\(", "redaction", "mask")
    },
    @{
        Id="D02-11"; Req="Batch PII scanning/statistics";
        Patterns=@("scan_batch", "batch", "per-type", "counts")
    },
    @{
        Id="D02-12"; Req="Configurable PII type selection";
        Patterns=@("pii_types", "enabled_pii", "patterns =", "configurable")
    },
    @{
        Id="D02-13"; Req="NER extension";
        Patterns=@("spaCy", "spacy", "NamedEntity", "NER")
    }
)

foreach ($c in $checks) {
    $hits = @()
    foreach ($p in $c.Patterns) {
        if ($engineText -match $p) {
            $hits += $p
        }
    }

    if ($hits.Count -gt 0) {
        $status = "PASS"
        if ($c.Id -eq "D02-05" -and
            ($hits -notcontains "IPv4") -and
            ($hits -notcontains "IPv6") -and
            ($hits -notcontains "IP_ADDRESS")) {
            $status = "REVIEW_REQUIRED"
        }
        if ($c.Id -eq "D02-10" -and
            ($hits -contains "mask") -and
            ($hits -notcontains "def redact") -and
            ($hits -notcontains "redact\(")) {
            $status = "REVIEW_REQUIRED"
        }
        if ($c.Id -eq "D02-11" -and
            ($hits -contains "batch") -and
            ($hits -notcontains "scan_batch")) {
            $status = "REVIEW_REQUIRED"
        }
        Add-Check $c.Id $c.Req $status ("Engine matches: " + ($hits -join ", "))
    }
    else {
        Add-Check $c.Id $c.Req "GAP" "No matching implementation evidence in privacy_data_exposure_engine.py"
    }
}

$redactionTests = @($testFiles | Select-String -Pattern "redact|mask|PII|privacy" -CaseSensitive:$false)
if ($redactionTests.Count -gt 0) {
    Add-Check "D02-14" "Privacy/redaction test evidence" "PASS" ("Test matches: " + $redactionTests.Count)
}
else {
    Add-Check "D02-14" "Privacy/redaction test evidence" "GAP" "No privacy/redaction test evidence found"
}

$ipTests = @($testFiles | Select-String -Pattern "IPv4|IPv6|IP_ADDRESS|ip.?address" -CaseSensitive:$false)
if ($ipTests.Count -gt 0) {
    Add-Check "D02-15" "IP-address validation tests" "PASS" ("Test matches: " + $ipTests.Count)
}
else {
    Add-Check "D02-15" "IP-address validation tests" "GAP" "No explicit IPv4/IPv6 test evidence found"
}

$actualRedactTests = @($testFiles | Select-String -Pattern "def\s+redact|redact\(|redacted|mask" -CaseSensitive:$false)
if ($actualRedactTests.Count -gt 0) {
    Add-Check "D02-16" "Actual redaction behavior tests" "PASS" ("Redaction test matches: " + $actualRedactTests.Count)
}
else {
    Add-Check "D02-16" "Actual redaction behavior tests" "GAP" "No actual redaction behavior test found"
}

$summary = $rows | Group-Object Status | Sort-Object Name
$rows | Format-Table -AutoSize | Out-String -Width 240 | Tee-Object -FilePath $txt | Write-Host
$rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

$pass = @($rows | Where-Object Status -eq "PASS").Count
$partial = @($rows | Where-Object Status -eq "PARTIAL").Count
$gap = @($rows | Where-Object Status -eq "GAP").Count
$review = @($rows | Where-Object Status -eq "REVIEW_REQUIRED").Count

Write-Host ""
Write-Host "============================================================"
Write-Host " D-02 SUMMARY"
Write-Host " PASS             : $pass"
Write-Host " PARTIAL          : $partial"
Write-Host " GAP              : $gap"
Write-Host " REVIEW_REQUIRED  : $review"
Write-Host " TXT              : $txt"
Write-Host " CSV              : $csv"
Write-Host "============================================================"

if ($gap -eq 0 -and $review -eq 0) {
    Write-Host "D-02 COVERAGE GATE: PASS"
}
else {
    Write-Host "D-02 COVERAGE GATE: NOT CLOSED"
}

Write-Host ""
Write-Host "[NOTE] This gate is read-only. It does not modify production source."

