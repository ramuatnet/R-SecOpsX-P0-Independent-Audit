$ErrorActionPreference = "Stop"

$Root   = "D:\Data\Code test\R-SecOpsX_V11"
$Prod   = Join-Path $Root "scanner\abom.py"
$Backup = Join-Path $Root "backup"
$Tests  = Join-Path $Root "tests"

New-Item -ItemType Directory -Force -Path $Backup | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupFile = Join-Path $Backup "abom.py.before_component_contract_v3_$stamp.py"

Copy-Item $Prod $backupFile -Force
Write-Host "[PASS] Backup: $backupFile"

$source = Get-Content $Prod -Raw -Encoding UTF8

# ------------------------------------------------------------
# 1. Add hashlib import
# ------------------------------------------------------------

if ($source -notmatch '(?m)^import hashlib\s*$') {
    $source = $source -replace '(?m)^import re\s*$', "import re`r`nimport hashlib"
}

# ------------------------------------------------------------
# 2. Replace _make_item completely
# ------------------------------------------------------------

$pattern = '(?s)def _make_item\(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope,\s*detection_mode="REGEX", import_resolution=None, confidence="MEDIUM"\):.*?(?=\r?\ndef )'

$replacement = @'
def _make_item(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope,
               detection_mode="REGEX", import_resolution=None, confidence="MEDIUM"):
    """
    Canonical ABOM finding constructor.

    Guarantees:
      - legacy ABOM fields
      - deterministic component_id
      - evidence_type
      - confidence_level
      - compatibility with AST/import/regex detection
    """

    framework = str(rule.get("framework", ""))
    component = str(rule.get("component", ""))
    category = str(rule.get("category", ""))
    filepath = str(filepath)
    evidence = str(evidence or "").strip()

    mode = str(detection_mode or "REGEX").upper()

    evidence_type = []

    if "AST" in mode:
        evidence_type.append("AST")

    if "IMPORT_RESOLUTION" in mode:
        evidence_type.append("IMPORT_RESOLUTION")

    if "REGEX" in mode:
        evidence_type.append("REGEX")

    if not evidence_type:
        evidence_type.append("REGEX")

    # Deterministic component identity.
    identity = "|".join([
        framework.lower(),
        component.lower(),
        filepath.replace("\\", "/").lower(),
        str(line),
    ])

    component_id = "ABOM-" + hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:16].upper()

    item = {
        "bom_type": "ABOM",
        "component_id": component_id,

        "framework": framework,
        "component": component,
        "category": category,

        "file": filepath,
        "line": line,
        "evidence": evidence,

        "evidence_type": evidence_type,
        "detection_mode": mode,

        "confidence": confidence,
        "confidence_level": confidence,

        "tools_detected": list(tools or []),
        "memory_detected": list(memory or []),
        "human_approval_detected": bool(human_approval),

        "asset_scope": asset_scope,
        "validation_only": asset_scope == "validation",

        "risk": rule.get("risk", "MEDIUM"),

        "recommendation": (
            "Review agent permissions, tool execution boundaries, "
            "memory usage, and human approval controls."
        ),
    }

    if import_resolution:
        item["import_resolution"] = import_resolution

    return item

'@

if ($source -notmatch 'def _make_item\(') {
    throw "Could not locate _make_item(). Production not modified."
}

$source2 = [regex]::Replace(
    $source,
    $pattern,
    $replacement,
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)

if ($source2 -eq $source) {
    throw "_make_item replacement failed. Production not modified."
}

# ------------------------------------------------------------
# 3. Write candidate
# ------------------------------------------------------------

$candidate = Join-Path $Root "dump\_abom_component_contract_v3_candidate.py"

[IO.File]::WriteAllText(
    $candidate,
    $source2,
    [Text.UTF8Encoding]::new($false)
)

# ------------------------------------------------------------
# 4. Syntax validation
# ------------------------------------------------------------

python -c "import ast; from pathlib import Path; ast.parse(Path(r'$candidate').read_text(encoding='utf-8')); print('[PASS] Candidate AST syntax')"

if ($LASTEXITCODE -ne 0) {
    Copy-Item $backupFile $Prod -Force
    throw "Candidate syntax validation failed. Production restored."
}

# ------------------------------------------------------------
# 5. Install candidate
# ------------------------------------------------------------

Copy-Item $candidate $Prod -Force

python -m py_compile $Prod

if ($LASTEXITCODE -ne 0) {
    Copy-Item $backupFile $Prod -Force
    throw "Production compilation failed. Production restored."
}

Write-Host "[PASS] Production compilation"

# ------------------------------------------------------------
# 6. Verify contract directly
# ------------------------------------------------------------

$verify = @'
from scanner import abom
import tempfile
from pathlib import Path

root = Path(tempfile.mkdtemp(prefix="abom_contract_v3_"))
src = root / "crew.py"

src.write_text(
    "from crewai import Agent as CrewAgent\n"
    "import crewai\n"
    "a = CrewAgent(role='analyst', goal='analyze')\n"
    "b = crewai.Agent(role='writer', goal='write')\n",
    encoding="utf-8",
)

rows = abom.scan_file(str(src))

assert rows, "No ABOM findings"

for row in rows:
    assert row.get("component_id", "").startswith("ABOM-"), row
    assert row.get("evidence_type"), row
    assert isinstance(row["evidence_type"], list), row
    assert row.get("confidence_level"), row
    assert row.get("detection_mode"), row

assert any("AST" in x["evidence_type"] for x in rows), rows
assert any(
    "IMPORT_RESOLUTION" in x["evidence_type"]
    for x in rows
), rows

ids = [x["component_id"] for x in rows]
assert len(ids) == len(set(ids)), rows

print("ABOM_COMPONENT_CONTRACT_V3_ACCEPTED")
'@

$verifyFile = Join-Path $Tests "test_v11_abom_component_contract_v3.py"

[IO.File]::WriteAllText(
    $verifyFile,
    $verify,
    [Text.UTF8Encoding]::new($false)
)

python $verifyFile

if ($LASTEXITCODE -ne 0) {
    Copy-Item $backupFile $Prod -Force
    throw "ABOM component contract acceptance failed. Production restored."
}

Write-Host "[PASS] ABOM component contract acceptance"
Write-Host "[PASS] component_id"
Write-Host "[PASS] evidence_type"
Write-Host "[PASS] confidence_level"
Write-Host "[PASS] AST evidence"
Write-Host "[PASS] import-resolution evidence"
Write-Host "[PASS] deterministic dedup identity"
Write-Host "============================================================"
Write-Host "ABOM_COMPONENT_CONTRACT_V3_ACCEPTED"
Write-Host "============================================================"

