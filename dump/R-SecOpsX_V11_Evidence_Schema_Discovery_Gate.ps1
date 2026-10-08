# R-SecOpsX V11 - Evidence Schema Discovery Gate
# READ-ONLY. This script inventories the current V11 tree before schema implementation.
# It does NOT create, modify, move, or delete production source files.
#
# Root:
# D:\data\Code test\R-SecOpsX_V11
#
# Output:
# D:\data\Code test\R-SecOpsX_V11\Working folder\Evidence_Schema_Discovery

$ErrorActionPreference = 'Continue'

$Root = 'D:\data\Code test\R-SecOpsX_V11'
$OutputDir = Join-Path $Root 'Working folder\Evidence_Schema_Discovery'

if (-not (Test-Path $Root -PathType Container)) {
    Write-Host "BLOCKED: V11 root not found: $Root"
    exit 2
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Report = Join-Path $OutputDir ('V11_Evidence_Schema_Discovery_' + $Stamp + '.txt')
$Csv = Join-Path $OutputDir ('V11_Evidence_Schema_Discovery_' + $Stamp + '.csv')

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
Write-Host ' R-SecOpsX V11 - EVIDENCE SCHEMA DISCOVERY GATE'
Write-Host ' READ-ONLY INVENTORY'
Write-Host '============================================================'
Write-Host ''

# Production Python files
$PythonFiles = Get-ChildItem -Path $Root -Recurse -File -Filter '*.py' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notlike ($Root + '\backup\*') -and
        $_.FullName -notlike ($Root + '\Working folder\*') -and
        $_.FullName -notlike '*\__pycache__\*' -and
        $_.FullName -notlike '*\.git\*'
    }

Write-Host ('Production Python files discovered: ' + $PythonFiles.Count)
Add-Row 'Inventory' '' 'Python files' $PythonFiles.Count

# Candidate evidence-related source files
$EvidenceFiles = $PythonFiles |
    Where-Object {
        $_.Name -match 'evidence|schema|graph|attack|provenance|confidence|finding|risk|decision|rcmsp'
    }

Write-Host ''
Write-Host '--- Evidence/schema/graph candidate source files ---'

foreach ($File in $EvidenceFiles) {
    Write-Host $File.FullName
    Add-Row 'EvidenceCandidate' $File.FullName 'Candidate source file' ''
}

# Candidate test files
$TestFiles = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notlike ($Root + '\backup\*') -and
        $_.FullName -notlike ($Root + '\Working folder\*') -and
        (
            $_.Name -match '^test_' -or
            $_.Name -match '_test\.' -or
            $_.Name -match 'test' -and $_.Extension -in @('.py', '.ps1', '.json', '.yaml', '.yml', '.txt', '.md')
        )
    }

Write-Host ''
Write-Host '--- Candidate test/configuration files ---'

foreach ($File in $TestFiles) {
    Write-Host $File.FullName
    Add-Row 'TestCandidate' $File.FullName 'Candidate test/config file' ''
}

# Structured schema/config files
$ConfigFiles = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notlike ($Root + '\backup\*') -and
        $_.FullName -notlike ($Root + '\Working folder\*') -and
        $_.Extension -in @('.json', '.yaml', '.yml', '.toml')
    }

Write-Host ''
Write-Host '--- Structured configuration/schema files ---'

foreach ($File in $ConfigFiles) {
    Write-Host $File.FullName
    Add-Row 'ConfigCandidate' $File.FullName 'Structured configuration/schema candidate' ''
}

# Search source/test/configuration content for established V11 evidence vocabulary.
$Patterns = @(
    'evidence_id',
    'provenance',
    'timestamp',
    'confidence',
    'QualifiedEvidence',
    'EvidenceSource',
    'EvidenceProvenance',
    'EvidenceTimestamp',
    'EvidenceConfidence',
    'UUID',
    'uuid',
    'ISO-8601',
    'schema',
    'configuration',
    'AGENT_GRAPH',
    'MCP_GRAPH',
    'RAG_GRAPH',
    'tool.*poison',
    'ASI02',
    'ASI04'
)

Write-Host ''
Write-Host '--- Vocabulary/content discovery ---'

foreach ($Pattern in $Patterns) {
    $Matches = Select-String -Path $PythonFiles.FullName -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue

    if ($Matches) {
        Write-Host ''
        Write-Host ('PATTERN: ' + $Pattern)

        foreach ($Match in ($Matches | Select-Object -First 20)) {
            Write-Host ('  ' + $Match.Path + ':' + $Match.LineNumber + ' | ' + $Match.Line.Trim())
            Add-Row 'Vocabulary' $Match.Path $Pattern ('Line ' + $Match.LineNumber + ': ' + $Match.Line.Trim())
        }
    }
}

# Look for likely 12-test baseline markers.
$TestMarkerPatterns = @(
    '12/12',
    '12 passed',
    '12 PASS',
    'configuration tests',
    'config tests',
    'configuration validation',
    'test_configuration'
)

Write-Host ''
Write-Host '--- Original configuration-test evidence discovery ---'

foreach ($Pattern in $TestMarkerPatterns) {
    $Matches = Select-String -Path $Root\* -Pattern $Pattern -SimpleMatch -Recurse -ErrorAction SilentlyContinue

    foreach ($Match in ($Matches | Select-Object -First 20)) {
        Write-Host ('  ' + $Match.Path + ':' + $Match.LineNumber + ' | ' + $Match.Line.Trim())
        Add-Row 'OriginalConfigTestEvidence' $Match.Path $Pattern ('Line ' + $Match.LineNumber + ': ' + $Match.Line.Trim())
    }
}

# Existing evidence-engine style outputs
$JsonFiles = Get-ChildItem -Path $Root -Recurse -File -Filter '*.json' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notlike ($Root + '\backup\*') -and
        $_.FullName -notlike ($Root + '\Working folder\*')
    }

Write-Host ''
Write-Host '--- JSON evidence-field inspection ---'

foreach ($JsonFile in $JsonFiles) {
    $Text = Get-Content $JsonFile.FullName -Raw -ErrorAction SilentlyContinue

    if ($null -ne $Text -and (
        $Text.Contains('evidence_id') -or
        $Text.Contains('provenance') -or
        $Text.Contains('confidence') -or
        $Text.Contains('timestamp')
    )) {
        Write-Host ('  EVIDENCE JSON: ' + $JsonFile.FullName)
        Add-Row 'EvidenceJson' $JsonFile.FullName 'Evidence-related JSON artifact/config' ''
    }
}

# Summary
$Rows | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host '============================================================'
Write-Host ' DISCOVERY SUMMARY'
Write-Host '============================================================'
Write-Host ('Python files              : ' + $PythonFiles.Count)
Write-Host ('Evidence candidates       : ' + $EvidenceFiles.Count)
Write-Host ('Test/config candidates    : ' + $TestFiles.Count)
Write-Host ('Structured config files   : ' + $ConfigFiles.Count)
Write-Host ('Discovery rows             : ' + $Rows.Count)
Write-Host ('Report                     : ' + $Report)
Write-Host ('CSV                        : ' + $Csv)
Write-Host ''
Write-Host 'DISCOVERY STATUS: COMPLETE'
Write-Host 'No production source files were modified.'

Stop-Transcript | Out-Null
exit 0
