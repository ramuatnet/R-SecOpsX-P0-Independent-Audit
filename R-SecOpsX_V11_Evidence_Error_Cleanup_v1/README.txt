R-SecOpsX V11 - Canonical Evidence Error Cleanup v1

Purpose:
Clear a stale canonical_evidence_error after canonical evidence qualification
has subsequently succeeded.

Production file:
  core\finding_model.py

Regression test:
  tests\test_v11_evidence_normalization_integration_v1.py

Backups:
  Created automatically under:
  <V11 root>\backup

Usage from the V11 project root:
  Set-ExecutionPolicy -Scope Process Bypass
  .\dump\R-SecOpsX_V11_Evidence_Error_Cleanup_v1.ps1
  .\dump\R-SecOpsX_V11_Evidence_Error_Cleanup_v1_Gate.ps1

Expected gate:
  CANONICAL EVIDENCE ERROR CLEANUP GATE: PASS

After this gate passes, rerun:
  python -m pytest .\tests -q
  Then rerun the controlled evidence smoke scan and inspect the new JSON/PDF.
