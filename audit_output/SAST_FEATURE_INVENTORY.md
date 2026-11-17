# SAST_FEATURE_INVENTORY.md — SAST-only reconciliation of pending_features.md + cltask.md against HEAD `6a07066`

**Date:** 2026-11-17 (SAST overnight control window, T0.2) · **Repo:** `D:\Data\Code test\R-SecOpsX_P0_AUDIT` · branch `feature/r2-multiecosystem-graph` @ `6a07066eafb9efa116872ed47963110cc58cdc36` (matches the plan's expected HEAD; verified full hash)
**Canonical row table:** `audit_output/SAST_GAP_MATRIX.csv` (55 rows, the 11 required columns; post-execution dispositions refreshed — see §1bis below). This document is the narrative inventory + summary; the CSV is authoritative for row-level status.
**Method:** no status was trusted from either source document. Every row was re-measured at HEAD by direct inspection (three parallel read-only exploration passes with file:line evidence) plus targeted test execution (collection run, 8 baseline-failure diagnoses, v02-normalizer module run). Filenames were never treated as proof — call paths and tests were inspected.
**Scope guard applied:** SCA, SBOM, IaC, DAST, Cloud, ASM, IAM, Rust engine, tenancy/deployment items → recorded as `OUT_OF_SCOPE` rows, not dropped.

## 1. Status counts (55 reconciled rows, as captured at the T0.3 checkpoint)

| Status | Count |
|---|---|
| IMPLEMENTED_VERIFIED | 12 |
| IMPLEMENTED_UNVERIFIED | 2 |
| PARTIAL | 17 |
| MISSING | 7 |
| OUT_OF_SCOPE | 3 (+ deferred rows) |

## 1bis. Post-execution dispositions (final CSV counts after the overnight's 9 commits)

| Status | Count | Tonight's upgrades |
|---|---|---|
| IMPLEMENTED_VERIFIED | 25 | +13: G0-A1-001/002 (collection config, pymupdf), G0-A2-001/002/003/004/006 (markers, audit scope, gitignored fixtures, self-sbom), SAST-T06-001 (PHP YAML migration), B6-SCORE-001 (scoring wire), B8-AUD-001 (audit gate SAST invariants), E1-SARIF-001 (codeFlows), B5-REC-001 (recall invariants) |
| PARTIAL | 18 | remaining enhancement surfaces (D-series probes, E2/E4/E6, C2/C4/C5, A-1, flag registry, abs paths) |
| MISSING | 7 | tier.py, insights.py, incremental cache, Windows script rules, API Security Matrix, + spec-name-delta rows documented |
| IMPLEMENTED_UNVERIFIED | 2 | T-0.4 depth cap (verified in tonight's regression), ACC mapping |
| NOT_STARTED / OUT_OF_SCOPE | 3 | D1/D3 probes (P2), SCA-class drift |

## 2. Where the source documents are WRONG at HEAD (reconciliation deltas)

Both documents pre-date the current tip (`34b07ed`-era and `76beba9`-era). The material corrections:

1. **cltask §0.4 "report integrity is 0% implemented" — FALSE at HEAD.** `core/report_aggregates.py`, `core/value_state.py`, `payload["aggregates"]`, `tools/report_audit.py`, and renderer migration are implemented and tested (B1/B2 verified). `total_findings` survives only as documented fallback/legacy echo.
2. **pending_features "VRD ❌ core/verdict.py missing" — the CAPABILITY exists under different names.** Verdict arbitration is implemented as two deliberate layers: `analysis/ufib_brain.py` (disposition writer, closed `RELEASE_DISPOSITIONS` vocabulary, gates G1–G8) and `accuracy/layer.py` (`_decide`: user suppression outranks everything; TRUE_POSITIVE capped to NEEDS_REVIEW without a complete source→sink path — exactly the static-evidence-gated arbitration cltask G1.5 specifies). `final_state` never existed as a key; `disposition`/`accuracy.verdict` are the real writers. → spec-name delta, not a gap.
3. **pending_features "RND ❌ reporting/cell.py missing" — the contract exists** as `core/value_state.py::cell()` consumed by PDF/XLSX (`tests/test_no_renderer_literal_defaults.py` enforces the render invariant). → spec-name delta.
4. **pending_features "REC ❌" — the matcher exists** (`analysis/juice_shop_ground_truth.py`, 3 tiers, both denominators, `challenge_recall`), but the versioned oracle/mapping contract and the matched+missed==denominator assertions are real gaps (PARTIAL).
5. **pending_features "CNT-13 dedupe ❌ / root cause ❌" — layered verdicts cover dedupe** (`DUPLICATE` verdict + `DUPLICATE` disposition); root cause exists as authored register DATA (Phase-3 `reports/gap_register.json`) backing the g035/AIBOM conformance tests; the named modules remain absent (spec-name deltas, documented).
6. **pending_features R3 (measurability 0.569) — RESOLVED at HEAD** (34/34 pass this run).
7. **"SAST platform largely built" (cltask H2) — CONFIRMED** at HEAD: taint 2.0 + cross-file interproc (Python), ReDoS budget (thread_time + S2 v4), span layer (native-core-dependent), file index, filter trace, corpus replay/variant hunter, C/C++ — all present with tests.
8. **The 27-failure baseline is now fully root-caused** (10 Rust-dependent, 10 missing-gitignored-artifacts, 3 dead-code-audit scope, 1 self-sbom drift, 3 SCA-class out-of-scope) — see §4.

## 3. Architecture reuse contract (no parallel implementations)

`audit_output/SAST_ARCHITECTURE_REUSE.md` records the binding extend-don't-duplicate map established this run: every new slice MUST extend the listed existing modules (rule loader, value_state, aggregates, ufib/accuracy arbitration, suppressions, taint engine/interproc, sarif_export, telemetry, report_audit) — the plan's boundary 14.

## 4. Baseline decomposition (27 failures at `6a07066` — the starting regression truth)

| Class | Count | Tests | Root cause (verified this run) |
|---|---|---|---|
| Rust-native-dependent | 10 | test_t14_span_layer ×4, test_t111_fuzz_targets ×6 | `rsecopsx_core` pyo3 extension not built (parked, cltask Appendix A); span `grammar=True` requires it; the fuzz harness itself prints "Rust engine extension not built" |
| Missing gitignored artifacts | 11 | test_v11_g035_framework_taint ×4 + test_v11_p0_owasp_aibom_conformance ×5 (`reports/gap_register.json` absent), test_v11_dead_code_guard ×2 (`quarantine/MANIFEST.txt` absent) | artifacts are gitignored (`.gitignore:7,14`); exist in the V11 reference tree; never restored in this worktree |
| Incomplete gitignored fixture | 1 | test_privacy_single_engine::test_backup_copies_are_excluded | worktree `backup/` holds 1 legacy copy; V11 reference holds the full legacy set the test was authored against |
| Audit-scope defect | 2 | test_t1402_dead_code_ci, test_v11_dead_code_guard (dead-population half) | `analysis/audit_dead_code.py` counts 97 "dead" modules — ALL under untracked `audit_output/` evidence trees (not production code) |
| Tracked-artifact drift | 1 | test_t118_self_sbom::test_check_passes_fresh | committed `supplychain/rsecopsx_sbom.json` predates the audit-era repo growth; `tools/emit_self_sbom.py` regeneration owed |
| SCA-class (out of SAST scope) | 3 | test_supply_chain_trust_signals ×2, test_corpus_replay::test_emitter_check (2-byte stale) | advisory/corpus data strategy — SCA workstream decides refresh-vs-relabel (cltask G0.3-1) |

**SAST-scope in-scope failures: 24** (10 + 11 + 1 + 2). The P0 slice (workstream A) targets all 24; the 3 SCA-class failures remain in the baseline, reported separately per plan boundary 7.

## 5. Positive/negative-fixture and test-safety inventory

- Existing enforcement: `test_rule_format_v1.py` (every rule id from YAML ∪ pack), `test_report_parity.py` (computed, never pinned parity), `test_no_renderer_literal_defaults.py`, conformance `t15` pins. No absolute rule count pinned (by design).
- Gaps recorded in the matrix: per-rule positive/negative fixtures (C1/C2 slices add them), full-audit CHECKS test (B8 slice), stable-ID regression tests (B3), SARIF schema validation (E1 slice).

## 6. Items intentionally NOT re-implemented (boundary 14 evidence)

- No new scoring model (the existing `analysis/scoring/score.py` + the distinct `core/risk_scorer` pipeline contract are preserved).
- No second suppression system (accuracy/suppressions.py extended only).
- No parallel taint/graph/identity implementation (taint_interproc + file_index extended only).
- No IaC/SBOM producers touched (OUT_OF_SCOPE rows).
