$ErrorActionPreference = "Stop"
$Root=(Resolve-Path ".").Path
Write-Host "============================================================"
Write-Host " R-SecOpsX V11 - REMAINING INTELLIGENCE v1 GATE"
Write-Host " GRAPH / OWASP / RCMSP CONTRACT VALIDATION"
Write-Host "============================================================"

$required=@(
"core\graph_schema.py","core\ai_graphs.py","core\owasp_mappings.py",
"core\attack_graph.py","core\rcmsp.py","core\v11_intelligence.py",
"tests\test_v11_intelligence_remaining.py"
)
foreach($r in $required){ if(!(Test-Path (Join-Path $Root $r))){throw "Missing: $r"} }

python -m pytest .\tests\test_v11_intelligence_remaining.py -q
if($LASTEXITCODE -ne 0){throw "Remaining intelligence tests failed."}

python -m py_compile .\main.py
if($LASTEXITCODE -ne 0){throw "main.py compilation failed."}

$main=Get-Content .\main.py -Raw
if($main -notmatch 'core\.v11_intelligence'){throw "Production integration marker missing."}
if($main -notmatch '_enrich_v11_intelligence'){throw "Production enrichment call missing."}

Write-Host "[PASS] Graph/decision tests"
Write-Host "[PASS] main.py compilation"
Write-Host "[PASS] Production integration marker"
Write-Host "REMAINING INTELLIGENCE v1 GATE: PASS"
