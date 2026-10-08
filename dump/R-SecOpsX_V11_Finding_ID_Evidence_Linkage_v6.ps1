$ErrorActionPreference = "Stop"
$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Patcher = Join-Path $Root "tests\patch_finding_identity_v6.py"
Write-Host "[INFO] V11 root: $Root"
Write-Host "[INFO] Patcher:  $Patcher"
if (-not (Test-Path $Root -PathType Container)) { throw "V11 root does not exist: $Root" }
if (-not (Test-Path $Patcher -PathType Leaf)) { throw "Missing patcher: $Patcher" }
foreach ($p in @((Join-Path $Root "core\finding_model.py"),(Join-Path $Root "core\evidence_adapter.py"),(Join-Path $Root "core\evidence_schema.py"))) {
  if (-not (Test-Path $p -PathType Leaf)) { throw "Required production file does not exist: $p" }
  Write-Host "[PASS] Production path exists: $p"
}
python $Patcher
if ($LASTEXITCODE -ne 0) { throw "Finding identity v6 patcher failed." }
