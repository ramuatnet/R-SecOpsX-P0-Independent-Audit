# R-SecOpsX V11 - Baseline Integrity Gate
# READ-ONLY validation. No production source files are modified.
# Expected root: D:\data\Code test\r-SecOpsX_V11

$ErrorActionPreference = 'Continue'

$Root = 'D:\data\Code test\r-SecOpsX_V11'
$Dump = Join-Path $Root 'dump'
$Working = Join-Path $Root 'Working folder'
$GateDir = Join-Path $Working 'Baseline_Gate'

New-Item -ItemType Directory -Force -Path $GateDir | Out-Null

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile = Join-Path $GateDir ('V11_Baseline_Gate_' + $Stamp + '.txt')
$CsvFile = Join-Path $GateDir ('V11_Baseline_Gate_' + $Stamp + '.csv')

$Results = @()

function Add-Result {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Evidence
    )

    $script:Results += [PSCustomObject]@{
        Check = $Check
        Status = $Status
        Evidence = $Evidence
    }

    Write-Host ('[{0}] {1} - {2}' -f $Status, $Check, $Evidence)
}

Start-Transcript -Path $LogFile -Force | Out-Null

Write-Host ''
Write-Host '============================================================'
Write-Host ' R-SecOpsX V11 - BASELINE INTEGRITY GATE'
Write-Host ' READ-ONLY VALIDATION'
Write-Host '============================================================'
Write-Host ''

# 1. Root
if (Test-Path $Root -PathType Container) {
    Add-Result 'V11 project root' 'PASS' $Root
} else {
    Add-Result 'V11 project root' 'BLOCKED' ('Missing: ' + $Root)
}

# 2. Required directories
$Directories = @(
    $Root,
    (Join-Path $Root 'backup'),
    (Join-Path $Root 'dump'),
    (Join-Path $Root 'dump\validation'),
    $Working
)

foreach ($Directory in $Directories) {
    if (Test-Path $Directory -PathType Container) {
        Add-Result ('Directory: ' + $Directory) 'PASS' 'Present'
    } else {
        Add-Result ('Directory: ' + $Directory) 'REVIEW_REQUIRED' 'Missing'
    }
}

# 3. Python
$Python = Get-Command python -ErrorAction SilentlyContinue

if ($null -ne $Python) {
    $Version = (& python --version 2>&1 | Out-String).Trim()
    Add-Result 'Python availability' 'PASS' $Version
} else {
    Add-Result 'Python availability' 'BLOCKED' 'python not found on PATH'
}

# 4. Required source files
$RequiredFiles = @(
    'main.py',
    'scanner\sast.py',
    'scanner\taint_engine.py',
    'scanner\secret_intelligence.py',
    'core\analyzer.py',
    'reporting\pdf_report.py'
)

foreach ($RelativeFile in $RequiredFiles) {
    $FullFile = Join-Path $Root $RelativeFile

    if (Test-Path $FullFile -PathType Leaf) {
        Add-Result ('Source: ' + $RelativeFile) 'PASS' 'Present'
    } else {
        Add-Result ('Source: ' + $RelativeFile) 'FAIL' 'Missing'
    }
}

# 5. Python compile
if ($null -ne $Python) {
    $PythonFiles = Get-ChildItem -Path $Root -Recurse -File -Filter '*.py' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notlike ($Root + '\backup\*') -and
            $_.FullName -notlike ($Root + '\Working folder\*') -and
            $_.FullName -notlike '*\__pycache__\*' -and
            $_.FullName -notlike '*\.git\*'
        }

    $CompileFailures = @()

    foreach ($PythonFile in $PythonFiles) {
        & python -m py_compile $PythonFile.FullName 2>&1 | Out-Null

        if ($LASTEXITCODE -ne 0) {
            $CompileFailures += $PythonFile.FullName
        }
    }

    if ($CompileFailures.Count -eq 0) {
        Add-Result 'Python compilation' 'PASS' ($PythonFiles.Count.ToString() + ' files compiled')
    } else {
        Add-Result 'Python compilation' 'FAIL' ($CompileFailures.Count.ToString() + ' files failed')
        foreach ($Failure in $CompileFailures) {
            Write-Host ('COMPILE_FAIL: ' + $Failure)
        }
    }
}

# 6. Production source-chain inspection
$MainFile = Join-Path $Root 'main.py'
$SastFile = Join-Path $Root 'scanner\sast.py'
$TaintFile = Join-Path $Root 'scanner\taint_engine.py'

if ((Test-Path $MainFile) -and (Test-Path $SastFile) -and (Test-Path $TaintFile)) {
    $MainText = Get-Content $MainFile -Raw
    $SastText = Get-Content $SastFile -Raw
    $TaintText = Get-Content $TaintFile -Raw

    $MainHasScan = $MainText.Contains('scan_directory')
    $SastHasTaint = $SastText.Contains('taint_engine')
    $SastHasAnalyze = $SastText.Contains('analyze_file')
    $TaintHasAnalyze = $TaintText.Contains('def analyze_file')

    if ($MainHasScan -and $SastHasTaint -and $SastHasAnalyze -and $TaintHasAnalyze) {
        Add-Result 'Production call-chain source evidence' 'PASS' 'Expected main -> SAST -> taint source symbols present'
    } else {
        Add-Result 'Production call-chain source evidence' 'REVIEW_REQUIRED' 'Expected source-chain symbols were not all found'
    }
}

# 7. Secret Intelligence source inspection
$SecretFile = Join-Path $Root 'scanner\secret_intelligence.py'

if (Test-Path $SecretFile) {
    $SecretText = Get-Content $SecretFile -Raw

    $HasScan = $SecretText.Contains('scan_secret_intelligence')
    $HasEnrich = $SecretText.Contains('enrich_secret_intelligence')

    if ($HasScan -and $HasEnrich) {
        Add-Result 'Secret Intelligence source presence' 'PASS' 'Expected scan and enrichment symbols present'
    } else {
        Add-Result 'Secret Intelligence source presence' 'REVIEW_REQUIRED' 'Expected symbols not both found'
    }
}

# 8. PDF semantic source inspection
$PdfFile = Join-Path $Root 'reporting\pdf_report.py'

if (Test-Path $PdfFile) {
    $PdfText = Get-Content $PdfFile -Raw

    $HasDecision = $PdfText.Contains('release_decision')
    $HasRemediation = $PdfText.Contains('REMEDIATE_BEFORE_RELEASE')
    $HasBlocking = $PdfText.Contains('DO_NOT_RELEASE')

    if ($HasDecision -and $HasRemediation -and $HasBlocking) {
        Add-Result 'PDF release semantic source inspection' 'PASS' 'Expected release decision semantics present'
    } else {
        Add-Result 'PDF release semantic source inspection' 'REVIEW_REQUIRED' 'Expected decision semantics not all found'
    }
}

# 9. Existing validation evidence discovery
$EvidenceFiles = @()

foreach ($SearchRoot in @($Dump, $Working)) {
    if (Test-Path $SearchRoot) {
        $EvidenceFiles += Get-ChildItem $SearchRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -in @('.txt', '.log', '.json', '.csv', '.md', '.html') -or
                $_.Name -match 'validation|regression|closure|baseline|e2e'
            }
    }
}

if ($EvidenceFiles.Count -gt 0) {
    Add-Result 'Existing validation evidence discovery' 'PASS' ($EvidenceFiles.Count.ToString() + ' candidate evidence files found')
} else {
    Add-Result 'Existing validation evidence discovery' 'REVIEW_REQUIRED' 'No candidate evidence files found'
}

# 10. Smoke-test command discovery only; do not guess or execute
$SmokeScripts = @()

if (Test-Path $Root) {
    $SmokeScripts = Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match 'pdf.*(smoke|e2e)|(?:smoke|e2e).*pdf|generate.*pdf|report.*test' -and
            $_.Extension -in @('.py', '.ps1', '.bat', '.cmd')
        }
}

if ($SmokeScripts.Count -gt 0) {
    Add-Result 'PDF smoke command discovery' 'PASS' ($SmokeScripts.Count.ToString() + ' candidate scripts found; not executed by this gate')
} else {
    Add-Result 'PDF smoke command discovery' 'REVIEW_REQUIRED' 'No unambiguous smoke script found; no command guessed'
}

# 11. Backup policy
$BackupDir = Join-Path $Root 'backup'

$BackupCandidates = Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notlike ($BackupDir + '\*') -and
        $_.Name -match '\.bak($|\.)|backup'
    }

if ($BackupCandidates.Count -eq 0) {
    Add-Result 'Backup location policy' 'PASS' 'No backup candidates outside backup directory'
} else {
    Add-Result 'Backup location policy' 'REVIEW_REQUIRED' ($BackupCandidates.Count.ToString() + ' possible backup files outside backup directory')
}

# 12. Save results
$Results | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8

$PassCount = @($Results | Where-Object Status -eq 'PASS').Count
$ReviewCount = @($Results | Where-Object Status -eq 'REVIEW_REQUIRED').Count
$FailCount = @($Results | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'BLOCKED' }).Count

Write-Host ''
Write-Host '============================================================'
Write-Host ' V11 BASELINE GATE SUMMARY'
Write-Host '============================================================'
Write-Host ('PASS            : ' + $PassCount)
Write-Host ('REVIEW_REQUIRED : ' + $ReviewCount)
Write-Host ('FAIL/BLOCKED    : ' + $FailCount)
Write-Host ('Transcript      : ' + $LogFile)
Write-Host ('CSV             : ' + $CsvFile)
Write-Host ''

if ($FailCount -gt 0) {
    Write-Host 'BASELINE GATE STATUS: BLOCKED'
    Stop-Transcript | Out-Null
    exit 2
}

if ($ReviewCount -gt 0) {
    Write-Host 'BASELINE GATE STATUS: REVIEW_REQUIRED'
    Stop-Transcript | Out-Null
    exit 1
}

Write-Host 'BASELINE GATE STATUS: PASS'
Stop-Transcript | Out-Null
exit 0
