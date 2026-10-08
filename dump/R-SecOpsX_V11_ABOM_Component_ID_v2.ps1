$ErrorActionPreference = "Stop"

$Root   = "D:\Data\Code test\R-SecOpsX_V11"
$Prod   = Join-Path $Root "scanner\abom.py"
$BackupDir = Join-Path $Root "backup"

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $BackupDir "abom.py.before_component_id_v2_$Stamp.py"

Copy-Item $Prod $Backup -Force
Write-Host "[PASS] Backup: $Backup"

$source = Get-Content $Prod -Raw -Encoding UTF8

$old = @'
    item = {
        "bom_type":"ABOM",
        "framework":rule["framework"],
        "component":rule["component"],
        "category":rule["category"],
        "file":filepath,
        "line":line,
        "evidence":evidence.strip(),
        "tools_detected":tools,
        "memory_detected":memory,
        "human_approval_detected":human_approval,
        "asset_scope":asset_scope,
        "validation_only":asset_scope == "validation",
        "risk":rule["risk"],
        "recommendation":"Review agent permissions, tool execution boundaries, memory usage, and human approval controls.",
        "detection_mode":detection_mode,
        "confidence":confidence,
    }
'@

$new = @'
    framework = str(rule.get("framework", ""))
    component = str(rule.get("component", ""))
    category = str(rule.get("category", ""))
    normalized_evidence = str(evidence or "").strip()

    # Stable deterministic component identity.
    # Includes enough context to distinguish multiple ABOM observations
    # without changing the legacy ABOM contract.
    import hashlib

    component_seed = "|".join([
        framework.lower(),
        component.lower(),
        str(filepath),
        str(line),
        normalized_evidence,
    ])

    component_id = "ABOM-" + hashlib.sha256(
        component_seed.encode("utf-8", errors="replace")
    ).hexdigest()[:16].upper()

    evidence_types = []

    mode_upper = str(detection_mode or "").upper()

    if "AST" in mode_upper:
        evidence_types.append("AST")

    if "IMPORT_RESOLUTION" in mode_upper:
        evidence_types.append("IMPORT_RESOLUTION")

    if "REGEX" in mode_upper:
        evidence_types.append("REGEX")

    if not evidence_types:
        evidence_types.append("REGEX")

    confidence_level = str(confidence or "MEDIUM").upper()

    item = {
        # Legacy ABOM contract
        "bom_type":"ABOM",
        "framework":framework,
        "component":component,
        "category":category,
        "file":filepath,
        "line":line,
        "evidence":normalized_evidence,
        "tools_detected":tools,
        "memory_detected":memory,
        "human_approval_detected":human_approval,
        "asset_scope":asset_scope,
        "validation_only":asset_scope == "validation",
        "risk":rule["risk"],
        "recommendation":"Review agent permissions, tool execution boundaries, memory usage, and human approval controls.",
        "detection_mode":detection_mode,
        "confidence":confidence,

        # V11 structured evidence contract
        "component_id":component_id,
        "evidence_type":evidence_types,
        "confidence_level":confidence_level,
    }
'@

if (-not $source.Contains($old)) {
    Write-Host "[FAIL] Exact _make_item() contract block was not found."
    Write-Host "[INFO] Production source NOT modified."
    exit 1
}

$source = $source.Replace($old, $new)

# Validate candidate before installation.
$candidate = Join-Path $Root "dump\_abom_component_id_v2_candidate.py"
Set-Content $candidate $source -Encoding UTF8

python -c "import ast; from pathlib import Path; p=Path(r'$candidate'); ast.parse(p.read_text(encoding='utf-8-sig')); print('[PASS] Candidate AST syntax')"
if ($LASTEXITCODE -ne 0) {
    Copy-Item $Backup $Prod -Force
    Remove-Item $candidate -Force -ErrorAction SilentlyContinue
    throw "Candidate syntax validation failed. Production restored."
}

Copy-Item $candidate $Prod -Force
Remove-Item $candidate -Force -ErrorAction SilentlyContinue

python -m py_compile $Prod
if ($LASTEXITCODE -ne 0) {
    Copy-Item $Backup $Prod -Force
    throw "Production compilation failed. Production restored."
}

Write-Host "[PASS] Production compilation"

# Run the existing acceptance contract.
$Test = Join-Path $Root "tests\test_v11_abom_clean_v1.py"

python $Test
if ($LASTEXITCODE -ne 0) {
    Copy-Item $Backup $Prod -Force
    Write-Host "[FAIL] Acceptance failed. Production restored."
    exit 1
}

Write-Host "[PASS] ABOM component_id contract"
Write-Host "============================================================"
Write-Host "ABOM_COMPONENT_ID_V2_ACCEPTED"
Write-Host "============================================================"