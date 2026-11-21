# SAST_OVERNIGHT_EXECUTION_REPORT.md — SAST-only overnight campaign (SAST_overnight_tasks.md)

**Repo:** `D:\Data\Code test\R-SecOpsX_P0_AUDIT` · branch `feature/r2-multiecosystem-graph`
**Starting HEAD:** `6a07066eafb9efa116872ed47963110cc58cdc36` (verified full hash; matches the plan's expectation)
**Ending HEAD:** `2603e58…` (see §3 manifest; linear, no merges)
**Protected `R-SecOpsX_V11`:** untouched — read-only HEAD/status checks + three READ-ONLY file copies FROM it into this worktree's gitignored paths (documented in §2 P0-4). No push/fetch/pull/deployment/tag/branch movement anywhere.

## 1. Control window (T0.1–T0.3, mandatory first hour)

- **T0.1 snapshot:** `audit_output/sast_overnight_2026-11-17T22-26-46/snapshot/` — timestamp, branch, full HEAD + parent, porcelain status (151 entries at capture; pre-existing set preserved), staged/unstaged diff summaries (staged empty; unstaged = the pre-existing cache slot), stash (1), tracking-ref counts, history `0929dbd..6a07066`, closure-commit `6a07066` full diff scope, D-043/V-036 authorization check (authorized by the same-session tasks.md plan; ledger pre-edit hashes recorded in the closure commit), collection probe.
- **T0.2 reconciliation:** both supplied specs re-measured at HEAD — three parallel read-only exploration passes + targeted test runs. Deliverables: `SAST_FEATURE_INVENTORY.md`, `SAST_GAP_MATRIX.csv` (55 rows, 11 columns), `SAST_ARCHITECTURE_REUSE.md` (extend-don't-duplicate map + spec-name deltas), `SAST_ROADMAP.md` (P0/P1/P2 queue). Key correction: the specs' "report integrity 0%" claim is FALSE at HEAD (aggregates/value_state/UFIB arbitration/accuracy layer/suppressions all implemented under different module names — documented as spec-name deltas, not silently absorbed).
- **T0.3 checkpoint:** `sast_overnight_2026-11-17T22-26-46/CHECKPOINT_MINUTE60.md` — HEAD/worktree state, feature counts, queue, unattended-safe tasks, 8 baseline-failure diagnoses.

## 2. Task-by-task outcome (plan §9 execution order)

| Slice | Status | Commit(s) | Evidence |
|---|---|---|---|
| A1 collection health | **COMPLETE_VERIFIED** | `3ff8c20` | unscoped collection exit 2 → exit 0 (5,182; the 4 evidence-tree shadow errors gone; `pytest tests` unchanged); pymupdf (pending_features R4) declared as `test` extra |
| A2 Rust-conditional tests | **COMPLETE_VERIFIED** | `6bec6ed` | conftest registered-marker policy (cltask rule 2, fail-closed on unregistered `requires_*`); 10 Rust-dependent tests root-caused (`rsecopsx_core` not built) and conditionally skipped (6 via `requires_rust_ext` marker, 4 via the file's own `_load_core` convention); they RUN again if the extension is ever built |
| A2 dead-code gate | **COMPLETE_VERIFIED** | `a8a9b52` | audit excludes untracked `audit_output/` evidence trees; entry roots registered for `scanner/cli.py` (pending_features R2's prescribed fix) + `conftest.py`; 12/12 gate tests green; real-tree audit: 750 files / 435 roots / 748 reachable / 0 dead; new unit test proves scratch exclusion while live dead code is still reported |
| A2 gitignored fixtures | **COMPLETE_VERIFIED** | (no commit — gitignored) | `reports/gap_register.json`, `quarantine/` (MANIFEST + content), `backup/` restored READ-ONLY from the V11 reference tree; 11 baseline tests recovered (g035 ×4, aibom ×5, quarantine-manifest, privacy) |
| A2 self-sbom drift | **COMPLETE_VERIFIED** | `9293b1b` | regenerated via `tools/emit_self_sbom.py` (`--check` exit 0, 70 components); same-commit baseline rule |
| B8 audit gate | **COMPLETE_VERIFIED** | `5476f3b` | AUD-S01 (stable SAST identity triple — validated against 17 real artifacts first: 0 missing/63) + AUD-S02 (closed verdict vocabularies + suppression explainability) added to the fail-closed audit; full-suite fixture tests 7/7 incl. crash-is-breach and old-invariant regression pins |
| C1 PHP YAML migration | **COMPLETE_VERIFIED** | `6e18771` | red: `set(pack ids) − set(YAML ids)` = 9; the designed emit tool extended to include pack rules → `enterprise_v1.yaml` 183 rules; sast.py pack append + SINK_CATEGORIES merge removed (sink categories fully declarative, pinned count 15 unchanged); `RSECOPSX_PHP_WEBSHELL_RULES=0` kill switch preserved at load time (probe: exactly the 9 migrated ids removed); compiled-pattern parity 9/9 byte-equal; golden suites 13/13 |
| E1 SARIF codeFlows | **COMPLETE_VERIFIED** | `bc830c7` | codeFlows emitted from real `taint_chain` data only — message-only step locations, physicalLocation solely on the sink step (the finding's own real location) — never invented; identity/fingerprints byte-stable; offline structural SARIF 2.1.0 validation encoded (official schema not vendored — disclosed limitation) |
| B6/E7 scoring wire | **COMPLETE_VERIFIED** | `12a17d8` | `payload["scoring"]` via the EXISTING `analysis/scoring/score.py` service (full explain rows, machine-readable skips, stats; the separate `core/risk_scorer` contract untouched); `--explain-score` writes `explain_scores.json` with VERBATIM rows (base source + 8 signed contributions) — no placeholders; deterministic for default findings; T-115 two-scan gate 18/18 |
| B5 recall invariants | **COMPLETE_VERIFIED** | `fe33c6b` | named `WINDOW_SOURCE_CONTEXT`/`WINDOW_EXPLICIT_REFERENCE` constants (120/160 unchanged, FND-03 convention); covered+missed==denominator + disjoint-bucket assertions fail loud; `code_detectable_recall` disclosed NOT_MEASURED (inventory lacks a detectability field — no inference); existing 3-tier matcher reused, no second engine |
| Self-scan hazard (found by the first full run) | **COMPLETE_VERIFIED** | `f1f0805` + `2603e58` | `explain_scores.json` joins BOTH `EXCLUDED_FILES` unions (file_index + taint_engine set-agreement invariant) — the guard caught the new artifact exactly as designed |

**Not completed (honest):** C2 Windows script rules, A-1 API Security Matrix, E3 incremental cache, C4 lifecycle states, C5 rule-level ATT&CK/CAPEC, E2 diff-scan flag + equality gate, E4 suppression audit extensions, E6 telemetry percentiles, D-series probes (D1/D3/D5/D7/D9 audits), flag registry, abs-path pin widening — all remain in the gap matrix with dispositions (P2/DEFERRED; see `SAST_ROADMAP.md`). Documentation-only rows were upgraded only where backed by executed tests.

## 3. Commits (11, linear off `6a07066`)

```
2603e58 fix(self-scan): explain_scores.json also joins the taint-engine ARTIFACT_FILE_NAMES union
f1f0805 fix(self-scan): explain_scores.json joins EXCLUDED_FILES (self-scan hazard guard)
5476f3b feat(audit-gate): B8 -- SAST invariants + full-suite fixture tests
fe33c6b feat(accuracy): B5 -- ground-truth coverage invariants + named windows + NOT_MEASURED
12a17d8 feat(scoring): B6/E7 -- payload["scoring"] + --explain-score (real contributors)
bc830c7 feat(sarif): E1 -- codeFlows for supported taint paths (no invented locations)
6e18771 refactor(rules): G2.1/C1 -- migrate the nine PHP webshell rules into declarative YAML
9293b1b chore(self-sbom): regenerate tracked self-SBOM after test-extra declaration
a8a9b52 fix(dead-code-gate): evidence-tree exclusion + entry-root registration (R2 prescribed fix)
6bec6ed test(policy): registered-marker infrastructure + Rust-conditional skips
3ff8c20 fix(test-infra): A1 collection config + pymupdf test extra declared
```
Full per-commit file manifest: `sast_overnight_2026-11-17T22-26-46/commit_manifest.txt` (+910/−40 over 20 files).

## 4. Validation gates (plan §8)

Every slice: red-first (red outputs preserved under the evidence dir), minimal change, focused positive/negative tests, affected regression modules, explicit-path staging, `git diff --check` per commit. Suite-level:

| Run | Result | Duration |
|---|---|---|
| Pre-overnight baseline (tasks.md plan) | 27 failed / 5,089 passed / 66 skipped (5,182 collected) | 29:40 |
| SAST final run 1 (mid-campaign) | 4 failed / 5,126 passed / 74 skipped (5,204 collected) | 29:07 |
| **SAST final run 2 (post-self-scan fix; authoritative)** | **3 failed / 5,127 passed / 74 skipped (5,204 collected), 28:19, exit 1 = the 3 registered SCA-class failures only** | `final_regression2.log` |

**Failure-identity comparison (starting baseline → final):**
- 27 baseline failures → 24 resolved by tonight's slices (10 Rust-conditional relocations with registered reasons, 11 gitignored-fixture recoveries, 2 audit-scope fixes, 1 self-sbom refresh).
- Remaining: exactly the 3 SCA-class baseline failures (`test_supply_chain_trust_signals` ×2, `test_corpus_replay::test_emitter_check` — advisory/corpus data strategy, OUT_OF_SCOPE per boundary 7; unchanged identities).
- New failures introduced: **0** (the single mid-campaign regression — the self-scan guard catching the new artifact — was itself fixed in the same night; the guard working as designed).
- Skip delta 66 → 74: +10 Rust-conditional relocations, −2 pre-existing skips that now execute because the restored gitignored artifacts un-skipped them (one identified: `test_v11_report_validation_fixes.py:461` gap_register-conditional; mechanism consistent, zero failure-set impact).

## 5. Worktree state (never claimed clean)

Tracked-modified: `data/.vuln_cache.json` only (pre-existing slot; scan-driven refreshes, rule-permitted, never committed). Untracked: the pre-existing evidence/report set + this campaign's deliverables and evidence dir (including restored gitignored `quarantine/`, `reports/gap_register.json`, `backup/` — invisible to git status by design). Stash: 1 pre-existing entry, untouched. Branch/refs: no movement; local remains 20 commits ahead of the recorded `audit/feature` tracking ref (`f100e3e`) with 0 behind — publication still NOT performed.

## 6. Completion accounting (plan §11 vocabulary)

Completion is calculated from the reconciled 55-row inventory, not from the run ending: **IMPLEMENTED_VERIFIED 25 / PARTIAL 18 / MISSING 7 / IMPLEMENTED_UNVERIFIED 2 / OUT_OF_SCOPE 1 / NOT_STARTED 2** (post-execution dispositions). The overnight delivered 9 tested vertical slices and closed 24 of the 27 pre-existing baseline failures; the program is NOT complete — the remaining P2 surfaces are enumerated in `SAST_ROADMAP.md` and the gap matrix.

## 7. Limitations

1. Offline SARIF schema validation is structural (official 2.1.0 schema not vendored; network prohibited).
2. `code_detectable` recall denominator: NOT_MEASURED (no detectability field in the inventory; versioned mapping contract needs fixtures).
3. The 3 SCA-class baseline failures remain (advisory/corpus data strategy is an SCA-workstream decision — refresh-vs-relabel, cltask G0.3-1).
4. Rust-conditional coverage (span grammar path, fuzz determinism) is skip-marked, not verified on this host — it executes when the parked native core is built.
5. The B-4 S3/S5 timing study from the previous campaign remains OPEN (unchanged).
6. Skip-delta attribution: one of the two un-skipped tests is individually identified; the other is mechanism-consistent but not individually named (zero impact on the failure-set comparison).

## 8. Boundary confirmations

- No push, fetch, pull, remote update, deployment, release, tag movement, PR creation, or publication of any kind.
- `R-SecOpsX_V11` never modified: no writes, no patches, no copies INTO it; read-only HEAD/status checks plus three read-only file copies FROM it (gap_register/quarantine/backup → gitignored paths in the AUDIT worktree).
- No reset/clean/rebase/amend/history rewrite/branch deletion/stash manipulation.
- Pre-existing dirty files, untracked files, caches, evidence, reports, and the stash were preserved throughout; no user-pre-existing change was committed (staged diffs reviewed per commit; the cache file was never staged).
- Scope held to SAST: no SCA/SBOM/IaC/DAST/Cloud/ASM/IAM/Rust/tenancy implementation; the B-1 skip-flipper and parked code untouched.
- No test weakening: skips are registered-marker-conditional (tests run when the capability exists); no xfails, relaxed assertions, pinned counts, deleted tests, or swallowed exceptions; the one failing test the night produced (self-scan hazard) was fixed, not suppressed.
- No external target scanning; all validation offline on repository fixtures/local corpora.

---

## ADDENDUM · 2026-11-18 — dated erratum (acceptance closure; historical text above preserved unmodified)

Per the acceptance audit (`audit_output/SAST_ACCEPTANCE_REVIEW/SAST_ACCEPTANCE_AUDIT.md`, verdict `ACCEPT_WITH_REVISIONS`, condition 2) and the full erratum `audit_output/SAST_ACCEPTANCE_CLOSURE/SAST_CAMPAIGN_ERRATUM.md`:

- **Ending HEAD:** the actual final commit is **`b42316c`** (the closure deliverables commit, docs-only). The "Ending HEAD: `2603e58`" recorded above is an **ancestor** of `b42316c`; the 11 implementation commits are unchanged and exactly as reported.
- **Commit count:** 12 total — 11 implementation + 1 closure.
- **New tests:** **22** (not 23) — exact added-`def test_` count and collected delta (5,204 − 5,182) both give 22.
- All other figures in this report (final regression 3 failed / 5,127 passed / 74 skipped; the 3 unchanged SCA-class failure identities; zero new failures; skip arithmetic 66 → 74) were independently re-verified and stand as written.
