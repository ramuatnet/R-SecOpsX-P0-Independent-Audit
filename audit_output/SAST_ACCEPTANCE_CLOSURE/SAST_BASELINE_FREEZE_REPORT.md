# SAST_BASELINE_FREEZE_REPORT.md — Phase E (acceptance closure)

**Date:** 2026-11-18 · **Frozen at:** `b42316c8fc94773e34f70081a64b42b3448a2881` (branch `feature/r2-multiecosystem-graph`)
**Nature:** a reproducible, evidence-backed SAST baseline statement — NOT a completion claim. The SAST programme is **not complete** (remaining queue below).

## 1. Accepted campaign HEAD and chain

| Pin | Hash | Role |
|---|---|---|
| Campaign start | `6a07066eafb9efa116872ed47963110cc58cdc36` | verified ancestor |
| Implementation end | `2603e5873dee4e78c7dd5a001cdfefbed60c737d` | 11 implementation commits (`3ff8c20`…`2603e58`), 0 merges |
| Acceptance closure | `b42316c8fc94773e34f70081a64b42b3448a2881` | 6 deliverables (docs-only) — the current HEAD |

Acceptance verdict: `ACCEPT_WITH_REVISIONS` (`audit_output/SAST_ACCEPTANCE_REVIEW/`); the three closure requirements are addressed by this closure task (erratum + ledger complete; fixture decision = `OWNER_DECISION_REQUIRED`). The frozen chain carries **22 new test functions** over the campaign start (corrected count per `SAST_CAMPAIGN_ERRATUM.md` E-3).

## 2. Verified implementation slices (acceptance audit E1–E9, all ✓)

E1 collection health (unscoped exit 0, 5,204 collected) · E2 Rust-conditional marker policy (enforcement + mandatory reasons + conditional execution) · E3 dead-code gate (evidence-tree exclusion, 0 dead live tree, detection preserved) · E4 PHP YAML migration (9/9 pattern parity, kill switch preserved, sink categories declarative) · E5 SARIF codeFlows (no invented locations; identity stable) · E6 scoring wire (`payload["scoring"]` + `--explain-score`, verbatim rows, deterministic) · E7 recall invariants (named windows, fail-loud accounting, NOT_MEASURED disclosure) · E8 SAST audit gate (AUD-S01/AUD-S02 fail-closed, validated on 17 real artifacts) · E9 self-scan exclusion (both unions agree; guard functional).

## 3. Regression baseline (frozen)

| Metric | Value |
|---|---|
| Command | `python -m pytest tests/ -q --tb=no -rf` |
| Result | **3 failed / 5,127 passed / 74 skipped** (5,204 collected), 28:19, exit 1 |
| Failure identities | exactly the 3 SCA-class OUT_OF_SCOPE items: `test_corpus_replay.py::test_emitter_check_passes_on_committed_artifacts`, `test_supply_chain_trust_signals.py::test_package_release_date_still_counts_as_freshness`, `test_supply_chain_trust_signals.py::test_looks_recent_ignores_missing_and_advisory_dates` |
| Prior baseline | 27 failed / 5,089 passed / 66 skipped (5,182) — 24 resolved by the campaign (10 Rust relocations + 14 recoveries) |
| New failures | **0** |
| Identity accounting | identity-level (`SAST_SKIP_SET_LEDGER.csv` + `ff_failure_ids_norm.txt` + both logs), not aggregate counts |
| Known flake context | the redos S3/R-FR3-2 risk remains OPEN from the prior campaign (disclosure recommendation outstanding); no flake event occurred in the frozen run |

## 4. Skip-set ledger (frozen)

`SAST_SKIP_SET_LEDGER.csv` — identity-level: 10 Rust-conditional relocations (individually listed, conditional on the parked native core, run-when-built), 2 resumed tests (individually named, both passed), plus marked aggregate rows (66 → 74 arithmetic). Baseline skip inventory context (CycloneDX-era): rust 8, t1401 1, t14 11, attack 2, conf_baseline 4, report_val 1, root_cause 1, spdx 36, ssdf 2.

## 5. Feature inventory (frozen)

55 rows / 55 unique IDs / zero empty cells — **IMPLEMENTED_VERIFIED 25 / PARTIAL 18 / MISSING 7 / IMPLEMENTED_UNVERIFIED 2 / OUT_OF_SCOPE 1 / NOT_STARTED 2** (= 55). Post-execution upgrades cite the 11 campaign commits. The programme is **not complete**: 27 rows carry forward-looking work.

## 6. Remaining SAST feature queue (explicit, from `SAST_GAP_MATRIX.csv` + `SAST_ROADMAP.md`)

C2 Windows/PowerShell/Batch/VBScript rules (+ ext coverage, LANG_BY_EXT) · A-1 API Security Matrix (route registry, chain parser, correlator, gate) · E3 incremental cache (design-first) · C4 rule lifecycle states (experimental/deprecated/retired) · C5 rule-level ATT&CK mapping + CAPEC · E2 diff-scan flag + full-vs-diff equality gate · E4 suppression expiry/owner/stale audit · E6 telemetry p50/p95 + cache ratio · D-series probes (D1 taint audit document, D3 getter/setter, D5 path sensitivity, D7 correlation evidence fields, D9 secret context) · C-5 flag registry · G0-R5 absolute-path pin widening (5 files) · B3 stable-ID regression tests · DEC-09 insights · B3 tier.py (design undefined).

## 7. Known limitations (frozen, disclosed)

1. **Official SARIF 2.1.0 schema validation NOT_VERIFIED** (no vendored schema; offline constraint) — structural validation only.
2. **Native Rust execution coverage NOT_VERIFIED on this host** — the span-grammar and fuzz-determinism bodies are conditionally skipped (they run when `rsecopsx_core` is built); skip mechanics verified, bodies not.
3. **Fixture portability** — the three V11-derived gitignored fixtures are host-local; fresh-clone impact documented per test (9 fail / 2 skip / 2 conditional) — **`OWNER_DECISION_REQUIRED`** (Options A/B/C assessed; nothing implemented).
4. The 3 SCA-class failures (advisory/corpus data strategy) are OUT_OF_SCOPE for SAST and belong to the SCA workstream.
5. `data/.vuln_cache.json` remains modified (pre-existing slot, scan-driven refreshes, never committed).
6. T-115 determinism: `payload["scoring"]`'s `as_of` falls under the declared `iso_timestamp` volatile class (verified 18/18).

## 8. Freeze classification

| Dimension | Class |
|---|---|
| Technical acceptance (code, tests, gates, accounting) | **TECHNICALLY_ACCEPTED** — independently audited (ACCEPT_WITH_REVISIONS), all revisions except the fixture decision addressed and validated |
| Fixture governance | **GOVERNANCE_PENDING** — `OWNER_DECISION_REQUIRED` (Options A/B/C; nothing implemented; fixtures preserved untouched) |
| Portable validation (fresh-clone green; official SARIF schema; Rust-executed coverage) | **VALIDATION_PENDING** |

The freeze binds the baseline to `b42316c` + the identity-level ledger; any next campaign must diff against THESE identities, not counts.
