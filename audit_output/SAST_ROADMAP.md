# SAST_ROADMAP.md — prioritized execution queue (T0.3 checkpoint, SAST-only overnight)

**Checkpoint time:** 2026-11-17 ~22:50 (control window complete: snapshot, closure-commit review, D-043/V-036 authorization check, both specs reconciled at HEAD `6a07066`, 46-row gap matrix, baseline decomposition, architecture reuse map)
**HEAD/worktree at checkpoint:** `feature/r2-multiecosystem-graph` @ `6a07066eafb9efa116872ed47963110cc58cdc36`; tracked-modified = 1 (pre-existing cache); untracked = pre-existing evidence set + this campaign's new files; stash 1; no branch/ref movement.

## P0 — correctness, evidence integrity, FP/FN control, broken SAST behavior (tonight)

| # | Slice | Red-first evidence | Accept | Risk |
|---|---|---|---|---|
| P0-1 | **Collection clean unscoped** (A1): add pytest config (`testpaths=["tests"]`, `norecursedirs` incl. `audit_output`) so evidence trees are never collected | this run: unscoped `pytest --co -q` exit 2, 4 import-shadow errors | unscoped collection exit 0, 5,178 tests; `tests/` collection unchanged | config-only; no test semantics |
| P0-2 | **Registered-marker infrastructure** (A1/A2, cltask rule 2): create `conftest.py` with the five registered markers + collection-time enforcement (unregistered/reason-less skip = error) | missing conftest today (verified) | marker guard test passes; no unregistered skips | conftest is new policy layer sanctioned by cltask rule 2 |
| P0-3 | **Rust-dependent tests marked** (A2): 4 span-layer + 6 fuzz tests get `requires_rust_ext` + mandatory reason | root cause verified: `rsecopsx_core` import fails; fuzz harness prints "Rust engine extension not built" | those 10 move fail→skip (registered reason); remaining baseline byte-identical; shift disclosed in the same commit | policy-sanctioned (cltask G0.4); NOT test weakening — capability genuinely parked |
| P0-4 | **Gitignored fixture restoration** (A2): copy `reports/gap_register.json`, `quarantine/` (MANIFEST + pinned content), complete `backup/` from the protected V11 tree (READ-ONLY source) | 11 tests FileNotFoundError/absent-manifest; privacy test fixture incomplete | 11+1 tests green; no commits (gitignored paths); V11 untouched | read-only source copy; documented per file |
| P0-5 | **Dead-code audit scope fix** (A2): exclude untracked `audit_output/` evidence trees from the live-tree dead-module population | audit reports 97 dead — all under audit_output/ | 2 baseline tests (dead-population halves) green; guard intent preserved (live tree clean, >200-file sanity, no quarantine imports) | production tooling fix, SAST-scope (CI quality gate) |
| P0-6 | **Self-sbom regeneration** (A2): run `tools/emit_self_sbom.py`, commit refreshed tracked artifact | `--check` exit 1 (drift) | `--check` exit 0; commit with same-commit baseline rule | artifact refresh disclosed |

## P1 — high-value semantic/workflow slices (tonight, after P0)

| # | Slice | Red-first evidence | Accept |
|---|---|---|---|
| P1-1 | **B8 audit-gate test + SAST invariants**: test running the FULL `tools/report_audit.py` CHECKS suite on a canonical fixture; add SAST invariants (stable IDs, verdict consistency, suppression explainability, cross-format SAST count parity) | no test executes the full CHECKS suite today (verified) | full-suite audit test green on fixture; fail-closed verified |
| P1-2 | **B6/E7 scoring wire**: `payload["scoring"]` via existing `score_findings`; `--explain-score` emits real contributor rows | `payload["scoring"]` 0 hits; flag absent | additive payload key; deterministic explain test; missing-evidence → disclosed skip rows (never invented) |
| P1-3 | **C1 PHP YAML migration**: 9 pack rules → `scanner/rules/enterprise_v1.yaml` (+ schema extension only if required) | `set(pack ids) − set(YAML ids)` = 9 today | delta = 0; byte-parity on golden fixtures; positive+negative fixture per rule; kill-switch semantics preserved |
| P1-4 | **E1 SARIF codeFlows**: emit `codeFlows`/`threadFlowLocations` from existing `taint_path` property data only (no invented locations) | codeFlows 0 hits; taint_path data exists (:178-187) | schema-valid SARIF; identity/URI/region stability unchanged; paths absent → no codeFlows key games |
| P1-5 | **B5 recall assertions**: named window constants (replace magic 120/160) + `matched+missed==denominator` + `recall_all ≤ recall_code_detectable` + no-double-match tests | constants at :28-29; assertions absent | tests green reusing the existing matcher; external benchmarks stay NOT_MEASURED |

## P2 — enhancements dependent on P0/P1 (only if capacity remains)

| # | Slice | Note |
|---|---|---|
| P2-1 | C2 Windows script rules (first family: PowerShell dangerous execution) — requires SCANNABLE_EXT + LANG_BY_EXT extension + YAML rules + fixtures; never execute scripts | bounded slice only |
| P2-2 | B3 stable-ID regression tests (repeated scans; material-change identity) | reuses existing identity |
| P2-3 | G0-R5 abs-path pin widening + 5-file fix | portable fixtures, behavior unchanged |
| P2-4 | D1 taint capability audit document (assemble from existing disclosures) | documentation of evidence |
| P2-5 | E4 suppression stale-detection audit (never auto-delete) | additive |

## Deferred (explicit, with reasons)

| Item | Reason |
|---|---|
| A-1 API Security Matrix (route registry + chain parser + correlator + gate) | multi-PR feature; cltask G2.3 order requires flag registry first; exceeds overnight capacity |
| E3 incremental cache | design-first project (key material, invalidation matrix); no fixture corpus for cold/warm parity yet |
| C4 lifecycle states (experimental/deprecated/retired) | schema change + registry tool; P2 after C1 proves the YAML migration path |
| C5 rule-level ATT&CK + CAPEC | mapping design (per-rule NONE resolution) after C1/C2 |
| D2 deepening, D3/D5/D7/D9 probes | fixture-driven audits; no new engines |
| E6 telemetry percentiles/cache ratio | cache ratio depends on E3; percentiles additive but low-value without E2/E3 |
| E2 --diff-scan flag + equality gate | flag-set equality gate is the test-first prerequisite; P2 |
| DEC-09 insights.py, B3 tier.py | design undefined in both specs beyond names |
| SCA-class baseline items (3) | OUT_OF_SCOPE (boundary 7) — SCA workstream |
| CI matrix/nightly (A3) | only if locally validated AND SAST-necessary; not blocking tonight |

## Tasks safe for unattended execution tonight

P0-1..P0-6 and P1-1..P1-5 (each: red-first → minimal change → focused + regression modules → identity-diffed baseline → explicit-path commit). Parallel work limited to read-only inspections and fixture authoring; no parallel edits to shared core modules, rule registries, report schemas, or ledgers.

## Blockers

None hard. Soft dependencies: P0-2 before P0-3 (marker infra); P1-1 before E1's parity assertions (audit gate lands first); P1-3 before P2-1 (schema migration path proven).
