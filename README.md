# R-SecOpsX V11 — Evidence Normalization Integration v1

Purpose:
Integrate the already-gated Evidence Adapter v1 at the existing
`core/finding_model.py::normalize_finding()` normalization boundary.

Design:
- Preserve existing finding classification and legacy evidence fields.
- Attach `canonical_evidence`.
- Attach `canonical_qualified_evidence` when the existing V11 qualification result is available.
- Do not reinterpret `evidence_valid`.
- Do not modify scanner producers.
- Backup `finding_model.py` under `D:\data\Code test\R-SecOpsX_V11\backup`.
- Refuse duplicate patching or patching when the expected source anchors are absent.

Validation:
1. Apply `dump/R-SecOpsX_V11_Evidence_Normalization_Integration_v1.ps1`.
2. Run `dump/R-SecOpsX_V11_Evidence_Normalization_Integration_v1_Gate.ps1`.
3. Then rerun the Evidence Schema v1 gate and Evidence Adapter v1 gate.
4. Only after all pass should the full V11 regression/production call-path validation be executed.

This package intentionally does not patch analyzer.py, scanner modules, or reporting modules.
