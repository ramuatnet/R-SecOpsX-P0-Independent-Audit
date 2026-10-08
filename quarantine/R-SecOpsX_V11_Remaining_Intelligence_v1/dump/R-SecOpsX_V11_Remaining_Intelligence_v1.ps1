$ErrorActionPreference = "Stop"
$Root = (Resolve-Path ".").Path
$backup = Join-Path $Root "backup"
New-Item -ItemType Directory -Force -Path $backup | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$main = Join-Path $Root "main.py"

Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - REMAINING INTELLIGENCE v1"
Write-Host " CONTROLLED GRAPH / DECISION IMPLEMENTATION"
Write-Host "============================================================"

# Copy supplied new modules/tests from the package root into the project.
$pkg = Join-Path $Root "R-SecOpsX_V11_Remaining_Intelligence_v1"
foreach ($rel in @("core\graph_schema.py","core\ai_graphs.py","core\owasp_mappings.py","core\attack_graph.py","core\rcmsp.py","core\v11_intelligence.py","tests\test_v11_intelligence_remaining.py")) {
    $src=Join-Path $pkg $rel; $dst=Join-Path $Root $rel
    if (!(Test-Path $src)) { throw "Package file missing: $src" }
    Copy-Item $src $dst -Force
}

$mainText = Get-Content $main -Raw
$marker = 'payload = normalize_payload(payload)'
$insert = @'
payload = normalize_payload(payload)
try:
    from core.v11_intelligence import enrich_payload as _enrich_v11_intelligence
    payload = _enrich_v11_intelligence(payload)
except Exception as _v11_intelligence_error:
    payload.setdefault("v11_intelligence", {})["status"] = "REVIEW_REQUIRED"
    payload["v11_intelligence"]["error"] = str(_v11_intelligence_error)
'@

# Integrate only at the final normalization occurrence before compliance enrichment.
$idx = $mainText.LastIndexOf($marker)
if ($idx -lt 0) { throw "Final normalize_payload anchor not found; no production patch applied." }

$before = $mainText.Substring(0,$idx)
$after = $mainText.Substring($idx + $marker.Length)
if ($before -match 'core\.v11_intelligence') {
    Write-Host "[REVIEW] V11 intelligence import already present; main.py not changed."
} else {
    Copy-Item $main (Join-Path $backup "main.py.before_remaining_intelligence_$stamp.py") -Force
    $mainText = $before + $insert.TrimEnd() + $after
    Set-Content -Path $main -Value $mainText -Encoding UTF8
    Write-Host "[PASS] Production integration applied: $main"
    Write-Host "[PASS] Backup: $(Join-Path $backup "main.py.before_remaining_intelligence_$stamp.py")"
}

& python -m py_compile (Join-Path $Root "core\graph_schema.py")
& python -m py_compile (Join-Path $Root "core\ai_graphs.py")
& python -m py_compile (Join-Path $Root "core\owasp_mappings.py")
& python -m py_compile (Join-Path $Root "core\attack_graph.py")
& python -m py_compile (Join-Path $Root "core\rcmsp.py")
& python -m py_compile (Join-Path $Root "core\v11_intelligence.py")
& python -m py_compile $main
if ($LASTEXITCODE -ne 0) { throw "Python compilation failed." }

Write-Host "[PASS] Production compilation"
Write-Host "Patch complete. Run the supplied gate next."
