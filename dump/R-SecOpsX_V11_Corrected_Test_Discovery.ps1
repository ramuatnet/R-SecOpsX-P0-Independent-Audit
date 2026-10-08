# R-SecOpsX V11 - Corrected Configuration/Test Discovery
# READ-ONLY. No production source is modified.
# Corrects the previous Select-String -Recurse defect by enumerating files first.
#
# Root:
# D:\data\Code test\r-SecOpsX_V11
#
# Output:
# D:\data\Code test\r-SecOpsX_V11\Working folder\Evidence_Schema_Discovery

$ErrorActionPreference = 'Continue'

$Root = 'D:\data\Code test\r-SecOpsX_V11'
$OutputDir = Join-Path $Root 'Working folder\Evidence_Schema_Discovery'

if (-not (Test-Path $Root -PathType Container)) {
    Write-Host ('BLOCKED: V11 root not found: ' + $Root)
    exit 2
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Report = Join-Path $OutputDir ('V11_Corrected_Test_Discovery_' + $Stamp + '.txt')
$Csv = Join-Path $OutputDir ('V11_Corrected_Test_Discovery_' + $Stamp + '.csv')

$Rows = @()

function Add-Row {
    param(
        [string]$Category,
        [string]$Path,
        [string]$Finding,
        [string]$Evidence
    )

    $script:Rows += [PSCustomObject]@{
        Category = $Category
        Path = $Path
        Finding = $Finding
        Evidence = $Evidence
    }
}

Start-Transcript -Path $Report -Force | Out-Null

Write-Host ''
Write-Host '============================================================'
Write-Host ' R-SecOpsX V11 - CORRECTED TEST / CONFIGURATION DISCOVERY'
Write-Host ' READ-ONLY'
Write-Host '============================================================'
Write-Host ''

$AllFiles = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notlike ($Root + '\backup\*') -and
        $_.FullName -notlike ($Root + '\Working folder\Evidence_Schema_Discovery\*') -and
        $_.FullName -notlike '*\__pycache__\*' -and
        $_.FullName -notlike '*\.git\*'
    }

Write-Host ('Files enumerated: ' + $AllFiles.Count)

# 1. Candidate test/config files
$Candidates = $AllFiles |
    Where-Object {
        $_.Name -match '(?i)test|validation|regression|config|configuration|gate' -or
        $_.Extension -in @('.yaml', '.yml', '.toml', '.json')
    }

Write-Host ''
Write-Host '--- Candidate test / validation / configuration files ---'

foreach ($File in $Candidates) {
    Write-Host $File.FullName
    Add-Row 'CandidateFile' $File.FullName 'Candidate test/config/validation file' ''
}

# 2. Search for exact 12-test evidence and likely test-count expressions
$TextFiles = $AllFiles |
    Where-Object {
        $_.Extension -in @('.py', '.ps1', '.psm1', '.bat', '.cmd', '.json', '.yaml', '.yml', '.toml', '.txt', '.md', '.log', '.csv')
    }

$CountPatterns = @(
    '12/12',
    '12 of 12',
    '12 passed',
    '12 PASS',
    '12 tests',
    'twelve tests',
    'configuration tests',
    'configuration validation',
    'config tests',
    'test_configuration'
)

Write-Host ''
Write-Host '--- Exact / near-exact 12-test evidence ---'

foreach ($Pattern in $CountPatterns) {
    foreach ($File in $TextFiles) {
        $Matches = Select-String -Path $File.FullName -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue

        foreach ($Match in $Matches) {
            Write-Host ('[' + $Pattern + '] ' + $Match.Path + ':' + $Match.LineNumber + ' | ' + $Match.Line.Trim())
            Add-Row 'TestCountEvidence' $Match.Path $Pattern ('Line ' + $Match.LineNumber + ': ' + $Match.Line.Trim())
        }
    }
}

# 3. Discover test functions/classes and assertions in Python
$PythonTestFiles = $AllFiles |
    Where-Object {
        $_.Extension -eq '.py' -and (
            $_.Name -match '(?i)^test_' -or
            $_.Name -match '(?i)_test\.py$' -or
            $_.FullName -match '(?i)\\tests?\\'
        )
    }

Write-Host ''
Write-Host '--- Python test files ---'

foreach ($File in $PythonTestFiles) {
    Write-Host $File.FullName
    Add-Row 'PythonTestFile' $File.FullName 'Python test file' ''

    $Matches = Select-String -Path $File.FullName -Pattern 'def test_|class Test|assert ' -ErrorAction SilentlyContinue

    foreach ($Match in $Matches) {
        Write-Host ('  ' + $Match.LineNumber + ' | ' + $Match.Line.Trim())
        Add-Row 'PythonTestSymbol' $File.FullName 'Test/assertion' ('Line ' + $Match.LineNumber + ': ' + $Match.Line.Trim())
    }
}

# 4. Discover evidence contract fields in tests/config
$EvidencePatterns = @(
    'evidence_id',
    'provenance',
    'timestamp',
    'confidence',
    'UUID',
    'uuid',
    'ISO-8601',
    'isoformat',
    'Evidence',
    'QualifiedEvidence',
    'EvidenceProvenance'
)

Write-Host ''
Write-Host '--- Evidence contract references in test/config files ---'

foreach ($Pattern in $EvidencePatterns) {
    foreach ($File in $TextFiles) {
        $Matches = Select-String -Path $File.FullName -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue

        foreach ($Match in ($Matches | Select-Object -First 15)) {
            if (
                $File.FullName -match '(?i)test|validation|config|schema|gate' -or
                $File.Extension -in @('.yaml', '.yml', '.json', '.toml')
            ) {
                Write-Host ('[' + $Pattern + '] ' + $Match.Path + ':' + $Match.LineNumber + ' | ' + $Match.Line.Trim())
                Add-Row 'EvidenceContractReference' $Match.Path $Pattern ('Line ' + $Match.LineNumber + ': ' + $Match.Line.Trim())
            }
        }
    }
}

# 5. Discover graph / Agent / MCP / RAG test references
$GraphPatterns = @(
    'AGENT_GRAPH',
    'MCP_GRAPH',
    'RAG_GRAPH',
    'agent graph',
    'mcp graph',
    'rag graph',
    'tool poisoning',
    'tool-poisoning',
    'ASI02',
    'ASI04'
)

Write-Host ''
Write-Host '--- Graph / agent / MCP / RAG test references ---'

foreach ($Pattern in $GraphPatterns) {
    foreach ($File in $TextFiles) {
        $Matches = Select-String -Path $File.FullName -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue

        foreach ($Match in ($Matches | Select-Object -First 20)) {
            if ($File.FullName -match '(?i)test|validation|config|schema|gate|analysis') {
                Write-Host ('[' + $Pattern + '] ' + $Match.Path + ':' + $Match.LineNumber + ' | ' + $Match.Line.Trim())
                Add-Row 'GraphReference' $Match.Path $Pattern ('Line ' + $Match.LineNumber + ': ' + $Match.Line.Trim())
            }
        }
    }
}

# 6. Existing schema/model files
$ModelCandidates = $AllFiles |
    Where-Object {
        $_.Extension -eq '.py' -and
        $_.Name -match '(?i)model|schema|evidence|finding|graph|provenance|decision'
    }

Write-Host ''
Write-Host '--- Existing model/schema/evidence candidates ---'

foreach ($File in $ModelCandidates) {
    Write-Host $File.FullName
    Add-Row 'ModelCandidate' $File.FullName 'Existing model/schema/evidence candidate' ''
}

# 7. Summarize unique likely baseline test files
$LikelyBaselineFiles = $Rows |
    Where-Object {
        $_.Category -in @('TestCountEvidence', 'PythonTestFile', 'EvidenceContractReference', 'GraphReference')
    } |
    Select-Object -ExpandProperty Path -Unique

Write-Host ''
Write-Host '============================================================'
Write-Host ' DISCOVERY SUMMARY'
Write-Host '============================================================'
Write-Host ('All files                    : ' + $AllFiles.Count)
Write-Host ('Candidate test/config files  : ' + $Candidates.Count)
Write-Host ('Python test files            : ' + $PythonTestFiles.Count)
Write-Host ('Model/schema candidates      : ' + $ModelCandidates.Count)
Write-Host ('Evidence rows                : ' + $Rows.Count)
Write-Host ('Likely baseline files        : ' + $LikelyBaselineFiles.Count)
Write-Host ('Report                       : ' + $Report)
Write-Host ('CSV                          : ' + $Csv)
Write-Host ''

$Rows | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8

if ($LikelyBaselineFiles.Count -eq 0) {
    Write-Host 'STATUS: REVIEW_REQUIRED - no baseline test file was confidently identified'
} else {
    Write-Host 'STATUS: DISCOVERY_COMPLETE - candidate baseline files identified'
}

Write-Host 'No production source files were modified.'

Stop-Transcript | Out-Null
exit 0
