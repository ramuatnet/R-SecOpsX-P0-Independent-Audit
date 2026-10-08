# R-SecOpsX V11 — Baseline Integrity Gate (READ-ONLY)
# Purpose: establish the migrated V11 baseline before any patching.
# Run from PowerShell. This script does NOT modify production source files.
#
# Expected project root:
# D:\Data\Code test\R-SecOpsX_V11
#
# Validation artifacts:
# D:\Data\Code test\R-SecOpsX_V11\Working folder\Baseline_Gate

$ErrorActionPreference = "Continue"

$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Working = Join-Path $Root "Working folder"
$GateDir = Join-Path $Working "Baseline_Gate"

New-Item -ItemType Directory -Force -Path $GateDir | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Log = Join-Path $GateDir "V11_Baseline_Gate_$Stamp.txt"

Start-Transcript -Path $Log -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Evidence
    )
    $results.Add([pscustomobject]@{
        Check    = $Check
        Status   = $Status
        Evidence = $Evidence
    })
    Write-Host ("[{0}] {1} - {2}" -f $Status, $Check, $Evidence)
}

Write-Host ""
Write-Host "============================================================"
Write-Host " R-SecOpsX V11 — BASELINE INTEGRITY GATE"
Write-Host " READ-ONLY PRE-IMPLEMENTATION VALIDATION"
Write-Host "============================================================"
Write-Host ""

# 1. Project path
if (Test-Path $Root) {
    Add-Result "V11 source path" "PASS" $Root
} else {
    Add-Result "V11 source path" "BLOCKED" "Path not found: $Root"
    Write-Host ""
    Write-Host "STOP: V11 project path is unavailable on this machine."
    Stop-Transcript | Out-Null
    exit 2
}

# 2. Required directories
$requiredDirs = @(
    $Root,
    (Join-Path $Root "backup"),
    (Join-Path $Root "dump"),
    (Join-Path $Root "dump\validation"),
    $Working
)

foreach ($d in $requiredDirs) {
    if (Test-Path $d -PathType Container) {
        Add-Result "Directory: $d" "PASS" "Present"
    } else {
        Add-Result "Directory: $d" "REVIEW_REQUIRED" "Missing; create only if required by project layout"
    }
}

# 3. Python version
$py = Get-Command python -ErrorAction SilentlyContinue
if ($null -ne $py) {
    $pyVersion = (& python --version 2>&1 | Out-String).Trim()
    Add-Result "Python availability" "PASS" $pyVersion
} else {
    Add-Result "Python availability" "BLOCKED" "python executable not found on PATH"
}

# 4. Key production files
$keyFiles = @(
    "main.py",
    "scanner\sast.py",
    "scanner\taint_engine.py",
    "scanner\secret_intelligence.py",
    "core\analyzer.py",
    "reporting\pdf_report.py"
)

foreach ($rel in $keyFiles) {
    $p = Join-Path $Root $rel
    if (Test-Path $p -PathType Leaf) {
        Add-Result "Required source: $rel" "PASS" "Present"
    } else {
        Add-Result "Required source: $rel" "FAIL" "Missing"
    }
}

# 5. Read-only compile validation
if ($null -ne $py) {
    Write-Host ""
    Write-Host "Compiling production Python tree (read-only validation)..."

    $excludeParts = @(
        "\backup\",
        "\Working folder\",
        "\__pycache__\",
        "\.git\"
    )

    $pyFiles = Get-ChildItem -Path $Root -Recurse -File -Filter *.py |
        Where-Object {
            $full = $_.FullName
            -not ($excludeParts | Where-Object { $full -like "*$_*" })
        }

    $compileFailures = @()

    foreach ($f in $pyFiles) {
        & python -m py_compile $f.FullName 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $compileFailures += $f.FullName
        }
    }

    if ($compileFailures.Count -eq 0) {
        Add-Result "Python compile" "PASS" "$($pyFiles.Count) source files compiled"
    } else {
        Add-Result "Python compile" "FAIL" "$($compileFailures.Count) files failed; see transcript"
        $compileFailures | ForEach-Object { Write-Host "  COMPILE_FAIL: $_" }
    }
}

# 6. Production call-chain source evidence
$main = Join-Path $Root "main.py"
$sast = Join-Path $Root "scanner\sast.py"
$taint = Join-Path $Root "scanner\taint_engine.py"

if ((Test-Path $main) -and (Test-Path $sast) -and (Test-Path $taint)) {
    $mainText = Get-Content $main -Raw
    $sastText = Get-Content $sast -Raw
    $taintText = Get-Content $taint -Raw

    $mainHasSast = $mainText -match "scan_directory"
    $sastHasTaint = $sastText -match "taint_engine" -and $sastText -match "analyze_file"
    $taintHasAnalyze = $taintText -match "def\s+analyze_file\s*\("

    if ($mainHasSast -and $sastHasTaint -and $taintHasAnalyze) {
        Add-Result 'Production call-chain source evidence' 'PASS' 'main.py -> scanner.sast -> taint_engine.analyze_file is represented in source'
    } else {
        Add-Result 'Production call-chain source evidence' 'REVIEW_REQUIRED' 'One or more source links were not established by static inspection'
    }
}

# 7. Secret Intelligence closure evidence
$secret = Join-Path $Root "scanner\secret_intelligence.py"
if (Test-Path $secret) {
    $secretText = Get-Content $secret -Raw
    $api = $secretText -match "scan_secret_intelligence"
    $enrich = $secretText -match "enrich_secret_intelligence"
    if ($api -and $enrich) {
        Add-Result "Secret Intelligence source presence" "PASS" "Expected public/enrichment functions found"
    } else {
        Add-Result "Secret Intelligence source presence" "REVIEW_REQUIRED" "Expected API/enrichment symbols not both found"
    }
} else {
    Add-Result "Secret Intelligence source presence" "BLOCKED" "secret_intelligence.py missing"
}

# 8. Search for prior closure/validation evidence
$validationRoots = @(
    (Join-Path $Root "dump\validation"),
    (Join-Path $Root "Working folder")
)

$closureMatches = @()
foreach ($vr in $validationRoots) {
    if (Test-Path $vr) {
        $closureMatches += Get-ChildItem $vr -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match "(secret|closure|regression|pdf|e2e|baseline|validation)" -or
                $_.Extension -in ".log",".txt",".md",".json",".html"
            }
    }
}

if ($closureMatches.Count -gt 0) {
    Add-Result "Existing validation evidence discovery" "PASS" "$($closureMatches.Count) candidate evidence/artifact files found"
    $closureMatches | Select-Object -First 50 FullName | ForEach-Object { Write-Host "  EVIDENCE: $($_.FullName)" }
} else {
    Add-Result "Existing validation evidence discovery" "REVIEW_REQUIRED" "No candidate validation evidence found in preferred V11 working locations"
}

# 9. PDF semantic source inspection
$pdf = Join-Path $Root "reporting\pdf_report.py"
if (Test-Path $pdf) {
    $pdfText = Get-Content $pdf -Raw
    $hasReleaseDecision = $pdfText -match "release_decision"
    $hasRemediation = $pdfText -match "REMEDIATE_BEFORE_RELEASE"
    $hasBlocking = $pdfText -match "DO_NOT_RELEASE"

    if ($hasReleaseDecision -and $hasRemediation -and $hasBlocking) {
        Add-Result "PDF release semantic source inspection" "PASS" "Release/remediation/blocking decision terms present"
    } else {
        Add-Result "PDF release semantic source inspection" "REVIEW_REQUIRED" "Expected decision terms were not all found"
    }
}

# 10. Canonical JSON -> PDF smoke generation
# Deliberately DO NOT guess or invoke a reporting command here.
# Existing project-specific command must be identified from V11 artifacts.
$smokeCandidates = Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match "(pdf.*e2e|e2e.*pdf|pdf.*smoke|smoke.*pdf|generate.*pdf|report.*test)" -and
        $_.Extension -in ".py",".ps1",".bat",".cmd"
    }

if ($smokeCandidates.Count -gt 0) {
    Add-Result "Canonical JSON -> PDF smoke command discovery" "PASS" "$($smokeCandidates.Count) candidate scripts found; NOT executed by this read-only gate"
    $smokeCandidates | Select-Object -First 30 FullName | ForEach-Object { Write-Host "  SMOKE_CANDIDATE: $($_.FullName)" }
} else {
    Add-Result "Canonical JSON -> PDF smoke command discovery" "REVIEW_REQUIRED" "No unambiguous existing smoke script discovered; no command guessed"
}

# 11. Backup policy inspection
$backup = Join-Path $Root "backup"
$sourceSideBackups = Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match "\.bak($|\.)|backup" -and
        $_.FullName -notlike "$backup\*"
    }

if ($sourceSideBackups.Count -eq 0) {
    Add-Result 'Backup location policy' 'PASS' 'No source-side backup candidates detected outside backup\'
} else {
    Add-Result 'Backup location policy' 'REVIEW_REQUIRED' "$($sourceSideBackups.Count) possible backup files detected outside backup\"
    $sourceSideBackups | Select-Object -First 50 FullName | ForEach-Object { Write-Host "  BACKUP_CANDIDATE: $($_.FullName)" }
}

# 12. Final summary
Write-Host ""
Write-Host "============================================================"
Write-Host " V11 BASELINE GATE SUMMARY"
Write-Host "============================================================"

$results | Format-Table -AutoSize

$summaryCsv = Join-Path $GateDir "V11_Baseline_Gate_$Stamp.csv"
$results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsv

$failed = @($results | Where-Object { $_.Status -eq "FAIL" -or $_.Status -eq "BLOCKED" })
$review = @($results | Where-Object { $_.Status -eq "REVIEW_REQUIRED" })
$passed = @($results | Where-Object { $_.Status -eq "PASS" })

Write-Host ""
Write-Host ("PASS            : {0}" -f $passed.Count)
Write-Host ("REVIEW_REQUIRED : {0}" -f $review.Count)
Write-Host ("FAIL/BLOCKED    : {0}" -f $failed.Count)
Write-Host ""
Write-Host "Transcript: $Log"
Write-Host "Summary CSV: $summaryCsv"
Write-Host ""

if ($failed.Count -gt 0) {
    Write-Host "BASELINE GATE STATUS: BLOCKED"
    Write-Host "Do not patch or begin V11 implementation."
    Stop-Transcript | Out-Null
    exit 2
}

if ($review.Count -gt 0) {
    Write-Host "BASELINE GATE STATUS: REVIEW_REQUIRED"
    Write-Host "No source patches were made. Resolve/record the review items before freezing the baseline."
    Stop-Transcript | Out-Null
    exit 1
}

Write-Host "BASELINE GATE STATUS: PASS"
Write-Host "V11 baseline may be frozen before Evidence Schema implementation.""
Stop-Transcript | Out-Null
exit 0
