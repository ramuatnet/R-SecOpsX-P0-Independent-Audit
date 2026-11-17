# PROJECT_VALIDATION_LEDGER.md

Maintained per session-context rule 4. Evidence-producing checks with command
summaries and measured results; newest last. Verbose outputs are not persisted
for read-only inspection snippets (results inline); suite runs will log to
`audit_output/logs/` when R1 implementation begins.

---

## V-001 · 2026-11-11 · Proposal-preparation evidence (baseline `dcc5146`, read-only)

| Check | Method | Result |
|---|---|---|
| CycloneDX ref vocabularies | source inspection `cyclonedx_export.py:24-31,34-64,519-530`; `npm_lock_graph_v2.py:47`; `purl.py:136-141` | bom-refs = `scanner.purl` (npm scope `%40`); graph refs = raw engine ids (raw `@`) — mismatch confirmed structurally |
| Gemfile heuristic vs real trees | `gemfile_lock.py:66`; awk indent census on `railsgoat-main/Gemfile.lock` | 197 specs at 4-indent (all stamped direct), DEPENDENCIES at line 494 unread; corpus fixture `vulnerable/Gemfile.lock`: actioncable/actionpack transitive yet direct=True |
| Provenance coverage | `sbom.py:1530-1574` | only version + license stamped |
| Corpus ground-truth collision | read both `vulnerable*/Gemfile.lock.ground_truth.json` | SCA findings only — no direct-flag assertions |

## V-002 · 2026-11-11 · R1 review evidence (baseline `dcc5146`, read-only)

| Check | Method | Result |
|---|---|---|
| NodeGoat CycloneDX ref integrity | python -I over `data/outputs/review_nodegoat_after_f3/Security_CycloneDX.json` | 1,136 components / 564 dep entries / 1,928 dependsOn / 0 dangling refs / 0 scoped components — unscoped trees coincide; mismatch fixture-demonstrable only |
| Synthetic root component | same artifact + `cyclonedx_export.py:471-488` | deliberate: `application / pkg:npm/__root__ / unknown` emitted when root edges exist; code-comment documented |
| Payload edge duplication | python -I over `clean_report.json` + filesystem check | 3,856 edges = 2 × 1,928; sources = two copies of the same `package-lock.json` (nested double-extraction); engine dedupe sound (`npm_lock_graph_v2.py:535-540`) — corpus artifact, not a defect |
| Gate bypass mechanism | `dependency_intelligence.py:104-106` | `direct is True` → "Direct" unconditional — confirms GAP-09 harm path |
| Provenance override contract | `core/value_state.py:203-233` | provenance `state` decides when present → populated fields need reason-only entries |
| Gemfile.lock membership evidence | `dependency_intelligence.py:30-45` | `"gemfile.lock"` ∈ LOCKFILES → W3 non-direct rows classify Transitive with evidence |
| Join stamp field names | `dependency_intelligence.py:404,436,450-457` | `verified_transitive`, `ambiguous_multiple_versions`, `parent_edge_fingerprint/source`, `ambiguous_multiple_parents` — echo sources for W2 verified |
| cvss_version stamping gate | `sbom.py:1603-1609` | stamped only where enrich_with_cve marked the offline table score |
| Engine endpoint id classes | `npm_lock_graph_v2.py:47-49,391,509,516` | registry, `__root__`, `pkg:npm-workspace/`, `pkg:npm-file/` — four endpoint classes for W1 |

No application source, tests, or fixtures modified in V-001/V-002. No suite
runs required (inspection + artifact measurement only); regression gates for
R1 remain defined in `R1_IMPLEMENTATION_PROPOSAL.md` §5 and
`R1_PROPOSAL_TECHNICAL_REVIEW.md` §5.

## V-003 · 2026-11-11 · R1 implementation validation (branch `fix/r1-identity-purl`)

Baseline captured BEFORE any change: full regression at `dcc5146` =
27 failed / 4,762 passed / 67 skipped (19:55); identities saved to
`logs/baseline_failure_ids_dcc5146.txt` and byte-consistent with the Task 4
record.

| Check | Result |
|---|---|
| W1 red-first | 6 red / 3 pins green -> 30 green (incl. `test_cvss_cyclonedx`) |
| W1 adjacent suites | 211 passed; 1 t118 failure = pre-existing baseline identity |
| W1 NodeGoat artifact rebuild | `dependencies[]` byte-identical to baseline artifact; components 1136->1135 (root moved); tally 7680 resolved / 32 root_mapped / 0 dropped; 0 dangling |
| W3 red-first | 4 red -> 8 green |
| W3 downstream suites | 128 passed (Ruby corpus SCA closure, phase1 SCA, gate, join, F-123, report fields) |
| W3 real-tree delta | railsgoat: 197 direct -> 52 direct / 145 transitive |
| W2 red-first | collection error (function absent) -> 15 green |
| W2 adjacent suites | 114 passed incl. value_state vocabulary guard (updated same commit) |
| Parity render (5) + full regression | see V-004 |
| Benchmarks NodeGoat + juice-shop | see V-004 |

## V-004 · 2026-11-11 · R1 final validation — ALL GATES GREEN

| Gate | Result |
|---|---|
| Parity render | 5 passed / 0 failed in 6:39 (`logs/r1_parity_render.txt`, EXIT=0) |
| Full regression | 4,794 passed / 27 failed / 67 skipped in 17:30 (`logs/r1_full_regression.txt`, EXIT=1 as at baseline) |
| Failure-identity diff | **27/27 IDENTICAL to `dcc5146` baseline, 0 new, 0 recovered** (`logs/r1_failure_ids.txt` vs `logs/baseline_failure_ids_clean.txt`) |
| Passed delta | 4,762 -> 4,794 = +32 (9 W1 + 8 W3 + 15 W2 new tests) |
| NodeGoat re-scan | EXIT=0 (`logs/r1_nodegoat_scan.txt`); components 1136->1135 (root -> metadata.component); `dependencies[]` byte-identical to baseline artifact; 0 dangling; tally 7680 resolved / 32 root_mapped / 0 dropped; join summary identical (681/277/77/28/0) |
| NodeGoat provenance | 1091/1091 rows carry dependency_type + purl provenance; parent provenance on 1,049 rows = exactly the join-touched records (681 parented + 277 multi-parent + 77 version-ambiguous + 14 root-declared) |
| juice-shop re-scan | EXIT=0 (`logs/r1_juiceshop_scan.txt`); 166 components (baseline match); 0 dependency entries (no lockfile); 0 dangling; provenance 166/166; 2 disclosed heuristic candidates (baseline match) |
| Real Gemfile classification | railsgoat 197 rows -> 52 direct / 145 transitive; corpus fixtures classified per DEPENDENCIES (W3 tests, 8/8) |
| Benchmark artifacts | `data/outputs/r1_nodegoat/`, `data/outputs/r1_juiceshop/` |

## V-005 · 2026-11-12 · Task 6 integration-readiness validation — ALL PHASES PASS

| Check | Result |
|---|---|
| Phase A ancestry | single linear chain, one parent each; inventories match scope; worktree preserved |
| Phase B invariants | 0 bad paths / 0 unpaired parents / reason-only provenance / candidates unclaimed & un-leaked (NodeGoat + juice-shop) |
| Phase C W1 | root→metadata.component both artifacts; 0 dangling; tally 7,680/32/0; workspace/file via red-first tests (no real workspace benchmark — risk #9) |
| Phase C W3 | railsgoat 52/145 exact; 38 DEPENDENCIES names → 52 direct (platform variants, Bundler-consistent); 0 unresolved; gate bases provenance-stamped |
| Phase C W2 | provenance 1,091/1,091 (dt+purl) + 1,049 parent rows = join-touched set; reason-only; renderers consume none |
| Phase D oracle | independent re-implementation: 0 wrong / 0 invented / 0 missing / 0 root mismatches / 0 unbacked join stamps (both payload runs) |
| Phase D scans | NodeGoat + juice-shop + railsgoat EXIT=0; baselines reproduced exactly (incl. 681/277/77/28 join tallies) |
| Phase E cross-format | PASS ×3 (17–18 checks each); pre-existing Excel semantics recorded D-007 |
| Phase F regression | 4,794/27/67 in 18:15; identities 27/27 identical across dcc5146 → R1 → Task 6; +32 = new R1 tests |

Artifacts: `data/outputs/task6_{nodegoat,juiceshop,railsgoat}/`;
logs `task6_*.txt`; oracle + cross-format instruments in
`audit_output/staging/` (validation-only, outside tests/ and tools/).
Deliverables: TASK6_{INTEGRATION_READINESS, COMMIT_ANCESTRY,
BENCHMARK_COMPARISON, REGRESSION_REPORT, OUTSTANDING_RISKS}.md.
Status: READY_WITH_DISCLOSED_LIMITATIONS.

## V-006 · 2026-11-12 · Controlled integration validation — ALL GATES PASS

Branch `integration/dependency-evidence-r1` @ `c350b07` (fast-forward of the
validated chain; `git diff c350b07 HEAD` = empty). Tag
`r1-validated-20261112`; source branch `fix/r1-identity-purl` untouched.

| Gate | Result | vs Task 6 baseline |
|---|---|---|
| Targeted suites (R1 + adjacent) | 123 passed / 0 failed (`logs/int_targeted.txt`) | = baseline |
| Parity render | 5 passed in 6:48 (`logs/int_parity.txt`) | = baseline |
| Full regression | 4,794 / 27 / 67 in 17:27 (`logs/int_full_regression.txt`) | identities 27/27 IDENTICAL (`logs/int_failure_ids.txt` diff = empty) |
| Smoke juice-shop | EXIT=0; 166 rows / 166 direct / 0 parent / 0 edges (`data/outputs/int_smoke_juiceshop`) | counts MATCH exactly |
| Smoke NodeGoat | EXIT=0; 1,091 rows / 681 parented / 77 version-ambiguous / 46 direct; cross-format PASS (`data/outputs/int_smoke_nodegoat`) | counts MATCH exactly |
| Worktree | dirty/untracked preserved through checkout and all runs | preserved |

## V-007 · 2026-11-12 · R2.1 implementation validation (branch `feature/r2-multiecosystem-graph`)

Commits: R2.1a `b179eb5`, R2.1b `1170ad8`, R2.1c `1394837`, R2.1d `09db252`,
R2.1e (FND-03 span fix).

| Check | Result |
|---|---|
| Red-first new tests | contract/registry/adapter 12 + join multi-ecosystem 9 + poetry 14 + uv 11 + exporter bridge 2 = 48 new, all red-first |
| Targeted set (final) | 166 green (all Task 2-4/R1 suites unchanged) |
| Poetry oracle (DVAP, real corpus) | PASS 90/90 — extractor-direct AND end-to-end scan payload; 0 wrong / 0 missing / 0 invented / 0 ambiguity mismatches |
| uv oracle (flask, real corpus) | PASS 8/8 end-to-end |
| Benchmark scans | DVAP EXIT=0, flask EXIT=0, NodeGoat EXIT=0 (`logs/r21_bench_*.txt`; artifacts `data/outputs/r21_bench_*`) |
| NodeGoat npm byte-stability | dependencies[] byte-identical to Task 6 baseline artifact; join 681/277/77/28/0; parent provenance 1,049; by_ecosystem npm tallies added |
| Cross-format checker | PASS ×3 (DVAP / flask / NodeGoat) — checker root-heuristic corrected for non-npm ecosystems |
| Join ecosystem-scoping | npm edge cannot stamp PyPI row (structural); DVAP pypi join 55 matched / 38 parented / 13 ambiguous_multiple_parents / 20 unmatched |
| CycloneDX contract-edge bridge | found by scans (dependencies[] silently empty for non-npm); fixed red-first; DVAP 31 entries / 0 dangling; flask 8 drop-and-count (project package not a component — disclosed limitation) |
| Full regression (final R2.1 state) | see V-008 |
| FND-03 span compliance | versions.py slice bounds named (WINDOW_M1/M2/1) after full-regression catch; oracles re-validated |

## V-008 · 2026-11-12 · R2.1 full regression (final state, commit `1bcd061`) — PASS

**4,839 passed / 27 failed / 67 skipped (20:25)**; failure-identity diff vs the
standing baseline: EMPTY — 27/27 identical, zero new regressions
(`logs/r21_full_regression.txt`, `logs/r21_failure_ids.txt`). +45 passed =
exactly the new R2.1 tests. First run stopped mid-run (exporter defect found
via benchmarks); second run caught FND-03 on versions.py (fixed R2.1e
`1bcd061`); final run clean.

## V-009 · 2026-11-12 · R2.2 implementation validation (Java: Maven, Gradle)

Commits: R2.2a `8977f77`, R2.2b `9cf3173`, R2.2c `97328f3`, R2.2d `2062c62`,
R2.2e `f79c202`, R2.2f `9adbefc`.

| Check | Result |
|---|---|
| Red-first new tests | Maven 14 + Gradle 12 + F-1 1 + F-2 equivalence 1 + exporter 2 = 30 |
| Maven oracle (REAL evidence) | BenchmarkJava committed tree 131/131 PASS; freshly regenerated tree byte-equivalent (reproducible); WebGoat fresh tree 166/166 PASS after the `(optional)` marker fix |
| Gradle oracle (hand-authored fixtures; CLI absent — GAP-R2-08) | PASS 3/3 VERIFIED identities; 4 direct declarations counted |
| F-1/F-2/F-3 remediations | !=-branch fixed red-first; norm_pypi consolidated + join-equivalence test; instruments promoted to tools/ and re-validated |
| Maven sandbox scan (hand-authored pom + REAL tree) | EXIT=0; 131 VERIFIED edges; join 5 matched (ecosystem-scoped); CDX 0 dangling; cross-format PASS |
| npm stability under the single-authority change | unscoped bom-refs byte-identical; scoped refs raw@ -> %40 (16 components, purl-spec-correct); dependencies[] structure identical after scoped normalization |
| Full regression (final `9adbefc`) | see V-010 |

## V-010 · 2026-11-12 · R2.2 full regression (final state, commit `9adbefc`) — PASS

**4,868 passed / 27 failed / 67 skipped (24:51)**; failure-identity diff vs
the standing baseline: EMPTY — 27/27 identical, zero new regressions
(`logs/r22_full_regression.txt`, `logs/r22_failure_ids.txt`). +29 passed =
exactly the new R2.2 tests. Two superseded runs disclosed in the delivery
report §7 (FND-03 catch on the new extractors).

## V-011 · 2026-11-13 · R2.2 final review independent re-validation — ALL GATES REPRODUCED

Instruments/outputs in `audit_output/r22_review/`; fresh scans in
`data/outputs/r22_review_{maven,nodegoat,nodegoat_prodtest}`.

| Check | Result |
|---|---|
| Oracle Maven BenchmarkJava (committed 20260911 evidence, SHA-verified vs corpus) | PASS 131/131, 0 wrong/0 missing |
| Oracle Maven WebGoat fresh tree | PASS 166/166 |
| mvn 3.9.16 offline regeneration (BenchmarkJava) | exit 0; 132 lines; byte-equivalent to committed evidence |
| Oracle Gradle fixture | PASS 3/3 VERIFIED + 4 direct |
| Oracle Poetry DVAP / uv flask (registry path) | PASS 90/90 · PASS 8/8 |
| Oracle NodeGoat (fresh same-corpus scan) | PASS 0 wrong/0 invented/0 missing/0 root/0 unbacked |
| Maven sandbox scan (fresh) | EXIT=0; 131 VERIFIED; join matched=5/parented=0/unmatched=1; payload, SBOM purls, CDX refs and dependencies[] byte-identical to delivery artifact `r22_bench_maven`; crossformat PASS |
| R2.2e exporter isolation (fresh prodtest NodeGoat vs `r21_bench_nodegoat`) | components 1,135=1,135; delta = 4 scoped identities raw@->%40 (14 occurrences); dependencies[] identical after normalization; join identical on all 9 keys; clean_report counts identical |
| Crossformat | PASS on both fresh scans |
| Targeted suites | 64 + 43 passed; parity units 26 passed |
| Full regression (independent re-run) | 4,868 passed / 27 failed / 67 skipped (26:56); failure identities 27/27 identical three-way (r21 baseline == delivery r22 == rerun) |
| Test-count reconciliation | 30 defs added, 1 removed (registry rename) -> net +29 = passing delta exactly |

## R2.3 pnpm remediation (2026-11-14, D-017)

| Check | Result |
|---|---|
| Red-first demonstration at f2345a2 | 12/33 pnpm tests failed exactly on review findings F-R3-2/3/4/8 (v5.4 zero edges; child_name="" misses; dead fallback; dead alias branch; tarball/link/tarball-parent disclosure gaps; FND-03 pnpm.py:65) |
| Commits | f3ea13a (F-R3-1 wiring+pin+dispatch tests), eb4710b (F-R3-2/3/4 core fixes + F-R3-5 33-test suite), f38b7d8 (F-R3-6 oracle) |
| pnpm fixture suite | 33/33 PASS (SYNTHETIC fixtures; v5.4/6.0/6.1/9.0; 16 mandatory scenario classes) |
| Oracle on real evidence (pnpm-import v9.0, sha256 bca6d7af) | PASS: 1365/1365 CORRECT, 0 wrong/0 missing/0 invented; UNRESOLVED 5/5 (NON_REGISTRY_PARENT); AMBIGUOUS 0/0; status variance 0 |
| Cross-format vs npm engine (NodeGoat) | A parent-absent 558; B version-divergent 50; C import-dropped 1; gates invented 0 / missed 0 |
| Oracle independence | zero shared imports/symbols with the extractor (own YAML walk + identity parsing) |
| npm byte-stability | double-run sha256-identical 682e6cae (unchanged from pre-fix) |
| Full regression | 4,927 passed / 27 failed / 67 skipped (23:27); failure identities 27/27 identical to dcc5146 baseline, 0 new, 0 gone |
| Test-count reconciliation | +35 defs +2 fixed = +37 passing (4,890 -> 4,927); exact |
| Clean checkout | temp worktree at f38b7d8: 71/71 targeted tests pass (worktree removed) |
| Yarn untouched | yarn.py / test_lock_graph_yarn.py / oracle_yarn.py unmodified since 05b4e89 |
| Gradle F-1 (n) prerequisite | still registered, unresolved (gradle.py:78 unchanged since R2.2f) |
| Evidence tier disclosure | real-evidence pnpm lockfile is TOOL-GENERATED (pnpm 11.10.0 import from NodeGoat package-lock.json, live-registry log); project-committed pnpm real-world validation NOT_ESTABLISHED |
| Verdict | R2.3 READY; all 11 acceptance gates pass; R2.4 requires separate approval |

## R2.4 Go + Rust verified dependency graphs (2026-11-14, D-018)

| Check | Result |
|---|---|
| Commits | ad93e5e (R2.4a Go), 952ab20 (R2.4b Rust) on feature/r2-multiecosystem-graph; established extractors/contract/join/npm untouched (diff f38b7d8..HEAD over those files: empty) |
| Go evidence tiers | go-mod-graph.txt = resolved instance edges (VERIFIED on identity parse; escaping decoded; /v2 and +incompatible verbatim; versionless UNRESOLVED); go.mod declarations tallied (direct/indirect/replacements/excludes), NEVER edges; go.sum membership only, NEVER edges |
| Rust evidence tiers | Cargo.lock formats 1-4 = resolved edges (exact/unique/source-hint -> VERIFIED; versionless multi-instance -> AMBIGUOUS; misses -> UNRESOLVED; source provenance registry/git/path; scope=unknown disclosed); Cargo.toml declarations tallied, NEVER edges |
| Go tests | 18 scenarios (16 mandatory classes mapped to Go reality; synthetic graph fixtures disclosed) |
| Cargo tests | 20 scenarios (16 mandatory classes mapped to Cargo reality; synthetic fixtures disclosed) |
| Go real-corpus oracle | PASS 11/11 real files: crAPI community (19/114), gateway (3/3), wrongsecrets aws/azure/gcp/sort (35,35,36,0 go.mod; 59,59,86 go.sum) |
| Cargo real-corpus oracle | PASS 6/6 real files: project rust/Cargo.lock format 4 = 125/125 VERIFIED, 0 wrong/missing/invented; corpus vulnerable format 3; argip workspace + 4 member manifests (17 workspace-inherited in collector) |
| Oracle independence | zero shared symbols with extractors (fresh parsers) |
| npm byte-stability | sha256 682e6cae identical (unchanged) |
| Targeted suites | 200 passed |
| Full regression | 4,965 passed / 27 failed / 67 skipped (23:23); failure identities 27/27 identical to baseline, 0 new, 0 gone |
| Reconciliation | +38 defs = 4,927 + 38 = 4,965 exact |
| Clean checkout | temp worktree at 952ab20: 109/109 targeted |
| Gradle (n) prerequisite | still registered, unresolved |
| pnpm real-world committed evidence | still NOT_ESTABLISHED (tool-generated import artifact only) |
| Go real go-mod-graph artifacts | NOT_GENERATABLE (no go CLI, GAP-R2-08); graph coverage fixture-based, disclosed |
| cargo metadata | NOT_GENERATABLE (no cargo CLI); dep-kinds/targets in edges need metadata evidence; scope=unknown by design |
| Verdict | R2.4 COMPLETE; R2.5 requires separate approval |

## R2.5 Ruby + .NET verified dependency graphs (2026-11-14, D-019)

| Check | Result |
|---|---|
| Commits | f4e7dca (R2.5a Ruby), fa27704 (R2.5b .NET) on feature/r2-multiecosystem-graph; registry.py the only modified existing file (+27 dispatch lines) |
| Ruby evidence tier | Gemfile.lock GEM/GIT/PATH specs blocks = resolved universe with parent-child declarations (constraint-resolvable: VERIFIED unique / AMBIGUOUS candidates / UNRESOLVED none); section provenance on edges; DEPENDENCIES tallied never edges; R1/W3 GAP-09 membership fix untouched |
| Ruby dialect (local) | pessimistic '~>' bumps second-to-last segment: 2-seg major>0 -> caret, 2-seg major 0 -> conjunction, >=3-seg -> explicit lo/hi (real corpus 4-segment '~> 3.17.0.2'); comma conjunctions clause-by-clause; versions.py untouched |
| .NET evidence tiers | packages.lock.json / project.assets.json targets = resolved restore state (exact child identities -> VERIFIED; AMBIGUOUS structurally absent like pnpm); TFM qualifiers, contentHash provenance, runtime assets counted, project refs skipped; restore types tallied never edges; packages.config membership only; Directory.Packages.props CPM tallies; csproj arbitrary-named -> membership-parser territory (disclosed) |
| Ruby tests | 21 scenarios (16 mandatory classes mapped to Ruby reality) |
| .NET tests | 16 scenarios (16 mandatory classes mapped to .NET reality) |
| Ruby real-corpus oracle | PASS 4/4: railsgoat-main (737 lines, 167 gems, 246 edges = 232 VERIFIED / 10 AMBIGUOUS / 4 UNRESOLVED, exact agreement), corpus vulnerable + rails_stack locks, railsgoat Gemfile envelope |
| .NET real-corpus oracle | PASS 3/3: CVE_Test packages.config (2), autogen CPM props (112), semantic-kernel CPM props (200) |
| Oracle independence | zero shared symbols (fresh line-walk/interval engine and fresh XML/JSON walks) |
| npm byte-stability | sha256 682e6cae identical (unchanged) |
| Targeted suites | 237 passed |
| Full regression | 5,002 passed / 27 failed / 67 skipped (23:10); identities 27/27 identical to baseline, 0 new, 0 gone |
| Reconciliation | +21 ruby +16 nuget = 4,965 + 37 = 5,002 exact |
| Clean checkout | temp worktree at fa27704: 145/145 targeted |
| Standing limitations | Gradle (n) F-1; pnpm real-world committed NOT_ESTABLISHED; Go graph artifacts NOT_GENERATABLE; cargo metadata NOT_GENERATABLE; R2.4 F-R4-A/B/C Low — all unchanged |
| NEW limitations | .NET lock tiers: zero real packages.lock.json/project.assets.json in corpus (fixture-validated, disclosed); csproj not registry-dispatchable (disclosed) |
| Verdict | R2.5 COMPLETE; R2.6 requires separate approval |

## R2.5.1 bounded Ruby remediation (2026-11-14, D-020)

| Check | Result |
|---|---|
| Branch | fix/r251-ruby-defects from fa27704 (separate per mandate; feature branch + R2.5 commits untouched); commit cc28ddb |
| Red-first | 7 regression tests failed at fa27704 exactly on F-R5-1/2/3 behaviors |
| F-R5-1 fix | PLUGIN -> source_kind=plugin (was KeyError); clean envelope, disclosed provenance |
| F-R5-2 fix | per-instance universe (version, qualifiers); resolved children disclose child_source_kind/child_source/child_revision; multi-section resolution comma-joins kinds |
| F-R5-3 fix | exact non-numeric constraints -> verbatim instance matching, NO numeric fallback (absent variant -> NO_MATCHING_VERSION); ranges stay AMBIGUOUS; versions.py untouched (local resolution policy, justified) |
| Ruby suite | 28/28 (21 preserved + 7 new) |
| NuGet + all ecosystems + join/CDX/FND-03 | 265 passed |
| npm byte-stability | 682e6cae identical |
| Real-corpus oracle post-fix | PASS 4/4; railsgoat 246 edges 232V/10A/4U UNCHANGED identity/confidence; all 232 VERIFIED edges carry child provenance |
| Full regression | 5,009 passed / 27 failed / 67 skipped; identities 27/27 identical to baseline, 0 new |
| Reconciliation | 5,002 + 7 defs = 5,009 exact |
| Acceptance criteria | all five PASS |
| Verdict | R2.5.1 delivered; R2.6 requires separate approval; no merge/push |

## R2.5.1 controlled integration (2026-11-15, D-021)

| Check | Result |
|---|---|
| Pre-integration | branch tip cc28ddb8… (full hash verified); parent = fa277047e… (direct); rev-list fa27704..branch = 1 commit (only the approved R2.5.1 commit); feature HEAD was fa277047e…; FF possible; tag r1-validated-20261112 -> c350b07 intact; dirty state preserved |
| Integration | git merge --ff-only fix/r251-ruby-defects on feature/r2-multiecosystem-graph — fast-forward, NO merge commit |
| Post-integration HEAD | cc28ddb8562563ca… == validated hash exactly |
| Tree identity | git diff between the two refs = 0 lines (trees identical; both refs at cc28ddb8) |
| Targeted suites | 265 passed (12 ecosystems + join/CycloneDX/FND-03) |
| npm byte-stability | 682e6cae identical |
| Full regression | 5,009 passed / 27 failed / 67 skipped (23:52); identities 27/27 identical to baseline, 0 new, 0 gone |
| Reconciliation | 5,009 = R2.5.1 delivery count (no test-def changes) |
| Branch state | fix/r251-ruby-defects still exists at the same commit (disposition = separate approval) |
| Verdict | integration COMPLETE and verified; R2.6 proposal delivered (D-021); no push |

## R2.6 cross-ecosystem integration validation (2026-11-15, D-022 / V-016)

| Check | Result |
|---|---|
| Repo integrity | HEAD cc28ddb8562563ca == approved baseline; tag r1-validated-20261112 intact; 0 commits/merges/pushes; pre-existing dirty preserved |
| W1 synthetic (11 formats, one walk) | 43 edges vs independent expected graph: 42 correct / 1 wrong (registered F-1, disclosed) / 0 missing / 0 invented; determinism run2==run3 (edge sets + fingerprints); 38 VERIFIED fingerprints all unique, non-VERIFIED mint none |
| W1 scenario classes | direct/transitive, multi-parent, multi-version, duplicates, AMBIGUOUS w/ candidates (3/3), UNRESOLVED disclosures, Gradle (n), provenance (cargo registry/git/path, ruby registry/path), npm root-declared + UNRESOLVED_FROM_TOPOLOGY standing semantics, maven project-root parents (matches R2.2 baseline) |
| W2 real-corpus re-scans | 21 targets, full pipeline, exit 0 all; per-benchmark summaries with input SHA-256s + commands + artifacts under r26/results/ |
| W2 baseline reconciliation | NodeGoat 681/277/77/14 + 1091 EXACT; juiceshop 166 EXACT; pnpm 1365 EXACT (probe, tool-generated); yarn sk1/sk2/oa/auto EXACT (1114/1045/2309/3794); DVAP poetry 90 EXACT (75 sbom); flask uv 8 EXACT; Maven BJ 131 / WG 166 EXACT; railsgoat 246=232V/10A/4U EXACT (sbom 197 == task6); semkernel nuget 200 EXACT (+new npm/yarn measurements); autogen 112 EXACT; rust 125/65 EXACT; corpus 1/2/3 EXACT; argip tallies EXACT (17 inherited) |
| W2 join tallies per ecosystem | recorded per benchmark (by_ecosystem) in w2_*_summary.json |
| W3 cross-format (24 payloads) | committed Task 6 checker + R2.6 additions: 0 dangling refs, 0 invented relationships, 0 duplicate components, JSON=CDX=SPDX counts exact, 0 cross-eco collisions, 0 heuristic leaks; PDF tier on 3 full-format payloads (PASS), 20 --no-pdf scans green on every non-PDF assertion |
| W4 payload capability | 10/10 capabilities on synthetic+NodeGoat+railsgoat (direct/transitive vuln classes, depth, multi-path, multi-parent, multi-version, ambiguity disclosure, reachability fields, vuln association, provenance, confidence+separation); capability only, NOT accuracy |
| W5 npm byte-stability | double-run identical; canonical-identical to stored r23_review artifact (1928 edges, 67e638d8) |
| W5 targeted suites | 258 (15 modules) + 8 Gemfile = 266 passed, 0 failures |
| W5 full regression | 5,009 passed / 27 failed / 67 skipped; failure identities 27/27 byte-identical (f62c7e25) — 0 new, 0 gone |
| Findings | F-R6-1 = reconfirmation of registered F-1 (Gradle (n) -> VERIFIED); NO new defects; instrument-only corrections disclosed |
| Limitations | all preserved verbatim (pnpm real-world NOT_ESTABLISHED; Go graph + cargo metadata NOT_GENERATABLE; .NET lock tiers fixture-only; Gradle F-1; csproj; npm v2/v3; membership-tier semantics; GAP-03 reachability) |
| Verdict | R2.6 COMPLETE — ACCEPTED as delivered evidence; R2.1-R2.6 roadmap closed; awaiting separate approval (R3 / production / branch dispositions) |

## R2.6.1 bounded Gradle (n) remediation (2026-11-15, D-023)

| Check | Result |
|---|---|
| Branch / commit | fix/r261-gradle-n-marker @ 6dc55661daa8eaf69365076ea1d9ddd7a3e8bed7 (parent cc28ddb; single commit; NOT merged) |
| Change set | gradle.py + its test module + its oracle ONLY (3 files, +275/−42); contract/join/PURL/npm/other extractors/RCMSP/fixtures untouched |
| Defect reproduced at HEAD | gd-c@3.0.0 (n) -> gd-d@4.0.0 VERIFIED + fingerprint sha256:77fe1926 (phaseA_repro_head.txt) |
| Red-first | 8 new tests; pre-fix 8 failed / 12 passed at cc28ddb (ALL new tests red; no silently-passing preservation) |
| Post-fix Gradle suite | 20/20 |
| Corrected semantics | (n)=requested-not-resolved -> UNRESOLVED GRADLE_VERSION_NOT_RESOLVED, no fingerprint, child-or-parent side, never promoted; (c)=constraint-selected -> VERIFIED + constraint_selected; missing '->' selection follows (n); tallies.not_resolved_markers |
| Oracle (independent rewrite) | comprehensive fixture: 4V+3U expected == extractor, 0 wrong/missing/invented/confidence-mismatch, exit 0; pre-fix W1 payload REJECTED exit 1 (WRONG VERIFIED 1 + MISSING (n) UNRESOLVED 1) — shared assumption gone |
| Post-fix full pipeline | synthetic re-scan: defect edge UNRESOLVED; W1 independent expected-graph comparison 43/43 correct, 0 wrong (F-1 remediated end-to-end) |
| Consumers | CDX (cyclonedx_export.py:584), SPDX (spdx_export.py:433+), join — VERIFIED-only; no fabricated relationship can reach any format |
| Extended gate batch | 354 passed (21 modules: 11 lock-graph + join + CDX-ref + FND-03 + quarantine-join + Gemfile + F123 + dep-intel-evidence + 3 CVSS render) |
| FND-03 | span suite 7 passed / 4 failed (the 4 = registered baseline identities); gradle WINDOW_ usage untouched |
| npm byte-stability | double-run identical; canonical vs stored R2.3 artifact 67e638d8 (1928 edges) |
| Determinism | gradle double-run identical; VERIFIED fingerprints unique (4/4); UNRESOLVED mint none |
| Full regression | 27 failed / 5,017 passed / 67 skipped (25:11); identities 27/27 byte-identical (f62c7e25); 5,009+8=5,017 exact |
| Real Gradle evidence | DEFERRED: no gradle CLI; wrapper (gradle-9.5.1) + JDK 21 present; wrapper download = install -> approval-gated; exact future command in R2_6_1_ORACLE_VALIDATION.md |
| Verdict | R2.6.1 ACCEPTED_WITH_DISCLOSED_LIMITATIONS; F-1/GAP-R2-08 remediation delivered on the remediation branch; integration/push/R3 require separate approval |

## R2.6.1 final independent technical review (2026-11-15)

| Check | Result |
|---|---|
| Review scope | read-only verification of fix/r261-gradle-n-marker @ 6dc5566 |
| Repo integrity | 1 authorized commit, parent cc28ddb, exactly 3 files (+275/−42); feature branch still cc28ddb; R1 tag intact; no remote refs; worktree preserved |
| Semantics | (n) treatment VERIFIED against Gradle userguide (docs.gradle.org, fetched): "cannot be resolved" — matches; (c) = "dependency constraint, NOT a dependency" → **F-R1 (Medium, latent, pre-existing since R2.2)**: (c) lines emit VERIFIED edges at the constraint version — documented NOT fixed (read-only); follow-up recommended; does NOT block integration |
| Tests | per-test pre-fix reproduction via materialized pre-fix module: 8/8 red (review_prefix_per_test.txt); post-fix 20/20 |
| Oracle | independence verified (no extractor import); postfix exit 0 PASS / pre-fix W1 payload exit 1 FAIL reproduced (review_oracle_*.txt) |
| Full pipeline | post-fix W1 comparison 43/43 correct, 0 wrong; CDX/SPDX contain ZERO gradle entries (VERIFIED-only gates); join clean — no fabricated relationships downstream |
| Regression (independent re-run at 6dc5566) | 27 failed / 5,017 passed / 67 skipped (18:02); identities 27/27 byte-identical (f62c7e25); 5,009+8=5,017 exact |
| Byte-stability / determinism | 67e638d8 unchanged; gradle deterministic; VERIFIED fingerprints unique; UNRESOLVED mint none |
| Real evidence | REAL_GRADLE_EVIDENCE_NOT_ESTABLISHED — no local distribution (~/.gradle/dists absent, not on PATH); wrapper + JDK 21 present; download approval-gated |
| Verdict | **ACCEPTED_WITH_DISCLOSED_LIMITATIONS; SAFE TO FAST-FORWARD** (integration itself approval-gated); findings F-R1 Medium-latent-preexisting (follow-up), F-R2/F-R3 Info, F-R4 evidence; deliverable R2_6_1_FINAL_REVIEW.md |

## R2.6.1 FF integration preflight (2026-11-15)

| Check | Result |
|---|---|
| Source | fix/r261-gradle-n-marker @ 6dc55661daa8eaf69365076ea1d9ddd7a3e8bed7 (reviewed: R2_6_1_FINAL_REVIEW.md ACCEPTED_WITH_DISCLOSED_LIMITATIONS / SAFE TO FF) |
| Target | feature/r2-multiecosystem-graph @ cc28ddb8562563ca (not advanced) |
| Parent | 6dc5566^ == cc28ddb (direct parent) |
| FF feasibility | merge-base == target tip; rev-list target..source = 1 -> FAST-FORWARD POSSIBLE |
| Commit inventory | exactly 3 authorized files (gradle.py 90±, test_lock_graph_gradle.py +122, oracle_gradle.py 105±; +275/−42) |
| R1 tag | r1-validated-20261112 -> c350b07 unchanged |
| Worktree | tracked diff = data/.vuln_cache.json only (pre-existing); untracked preserved (6 entries) |
| Risks | (a) (c) edges gain the constraint_selected qualifier (disclosure only; classification unchanged from R2.2; fingerprints unaffected — qualifiers not in the identity); (b) gradle (n) edges become UNRESOLVED post-integration (the intended fix; W1 comparison 43/43, downstream VERIFIED-only verified); (c) F-R1 ((c) semantics per Gradle docs) remains open — follow-up required, does not block |
| Proposed command | git checkout feature/r2-multiecosystem-graph && git merge --ff-only fix/r261-gradle-n-marker (single command sequence; NO merge commit; then verify HEAD == 6dc5566 + trees identical + post-gates) |
| Status | PREFLIGHT COMPLETE — STOPPED BEFORE EXECUTION; awaiting explicit integration approval |

## R2.6.1 fast-forward integration (2026-11-15, explicitly authorized)

| Check | Result |
|---|---|
| Revalidation | all preconditions == approved preflight (source 6dc5566, target cc28ddb, parent direct, 1 ahead, FF feasible, R1 tag c350b07, worktree preserved) |
| Execution | git checkout feature/r2-multiecosystem-graph && git merge --ff-only fix/r261-gradle-n-marker — exit 0, "Updating cc28ddb..6dc5566 / Fast-forward", NO merge commit |
| Post-FF HEAD | 6dc55661daa8eaf69365076ea1d9ddd7a3e8bed7 on feature/r2-multiecosystem-graph; rev-list cc28ddb..HEAD = 1 (linear); git diff 6dc5566 HEAD empty (trees identical) |
| Gradle targeted | 20/20 |
| Oracle | comprehensive exit 0 PASS; pre-fix W1 payload exit 1 (sensitivity preserved) |
| Downstream | gradle UNRESOLVED edge -> 0 CDX dependency entries, 0 SPDX relationships (VERIFIED-only intact) |
| npm byte-stability | 67e638d8 identical (1928 edges) |
| Full regression | 27 failed / 5,017 passed / 67 skipped (35:28); identities 27/27 byte-identical (f62c7e25); 5,009+8=5,017 exact |
| Worktree | runtime cache + 6 untracked preserved; no clean/reset/stash |
| Status | INTEGRATION COMPLETE AND VERIFIED; no push; R2.6.2/R3/production/push await separate approval; deliverable R2_6_1_FAST_FORWARD_INTEGRATION_REPORT.md |

## R2.6.2 Gradle constraint-semantics remediation (2026-11-15, authorized implementation)

| Check | Result |
|---|---|
| Branch / commit | fix/r262-gradle-constraint-semantics @ 04e4bdea6894b96f05249d49736b76b26cb31560 (parent 6dc5566; single commit; NOT merged) |
| Change set | gradle.py + its test module + its oracle ONLY (3 files, +374/−32); contract/join/PURL/npm/other extractors/RCMSP untouched |
| Red-first | 15 new tests; pre-fix 14 failed / 21 passed at 6dc5566 (14/15 red; malformed-input preservation test correctly passed pre-fix — honest accounting) |
| Post-fix Gradle suite | 35/35, including the DISCLOSED REWRITE of the R2.6.1-era (c) test that pinned the per-docs-wrong VERIFIED classification |
| Corrected semantics | (c) = constraint entry, NOT a dependency (Gradle userguide) -> UNRESOLVED GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY, no fingerprint, constraint_version/parent_constraint_version qualifiers, both sides; depth-1 (c) tallied not direct-declared; (n) precedence preserved; no tree matching |
| Oracle | independent (c) semantics + three-way expected sets + constraint confidence-mismatch + fingerprint-violation counters; TWO-DIRECTION PROOF: rejects both pre-remediation payloads (exit 1, constraint mismatch=1) and accepts remediated output (exit 0, 0 wrong/missing all classes) |
| Downstream probe | full-pipeline (c) fixture: constraint edge UNRESOLVED in payload (qualifiers retained — evidence not discarded); 0 CDX dependency entries; 0 SPDX relationships; resolved edges stay VERIFIED+serialized |
| W1 | fresh re-scan 43/43 correct, 0 wrong (fixture (c)-free, unchanged) |
| npm byte-stability | 67e638d8 identical |
| Determinism | gradle double-run identical; VERIFIED fingerprints unique; non-VERIFIED mint none |
| Full regression | 27 failed / 5,032 passed / 67 skipped (19:06); identities 27/27 byte-identical (f62c7e25); 5,017+15=5,032 exact |
| Limitations | REAL_GRADLE_EVIDENCE_NOT_ESTABLISHED; no tree matching (deferred); reason-sublines open format question; tally envelope-level (consistent design) |
| Verdict | R2.6.2 delivered ACCEPTED_WITH_DISCLOSED_LIMITATIONS on the remediation branch; integration/push/R3 await separate approval |

## R2.6.2 final independent technical review (2026-11-15)

| Check | Result |
|---|---|
| Review scope | read-only verification of fix/r262-gradle-constraint-semantics @ 04e4bde |
| Repo integrity | 1 authorized commit, parent 6dc5566, exactly 3 files (+374/−32); feature branch at 6dc5566 untouched; R1 tag c350b07; tags unchanged; worktree preserved |
| Semantics | (c) handling traced and verified (iterative strip, both sides, no promotion, no fingerprint, tally, depth-1 reclassification, (n) precedence); **F-R2 (Low)**: stale _parse_node inline docstring retains the R2.6.1-era "(c) IS in use" sentence — doc-only, non-blocking |
| Tests | per-scenario pre-fix reproduction via materialized 6dc5566 module: 14/15 red (malformed preservation correct); post-fix 35/35; all 12 scenario classes covered; old (c) test rewrite verified |
| Oracle | independence verified (no extractor import; independent semantics; explicit three-way constraint comparison + fingerprint-violation counter); TWO-DIRECTION REPRODUCED: reject pre-fix payloads exit 1 (constraint mismatch=1) / accept remediated exit 0 |
| Downstream | 0 CDX gradle entries, 0 SPDX relationships, join clean; constraint evidence retained in payload qualifiers |
| Regression | TWO independent full runs at 04e4bde: run 1 = 28/5,031/67 with ONE extra failure (test_redos_budget 5MB test — pre-existing environment-sensitive flake, passes standalone + module-standalone, unrelated to the change); run 2 = **27/5,032/67 with identities 27/27 byte-identical (f62c7e25)** — baseline reproduced; **F-R3 (Low)**: redos flake registered as test-robustness follow-up |
| Real evidence | REAL_GRADLE_EVIDENCE_NOT_ESTABLISHED re-verified (no local distribution) |
| Verdict | **ACCEPTED_WITH_DISCLOSED_LIMITATIONS; SAFE TO FAST-FORWARD** (integration approval-gated); deliverable R2_6_2_FINAL_REVIEW.md |

## R2.6.2 fast-forward integration (2026-11-15, explicitly authorized)

| Check | Result |
|---|---|
| Revalidation | all preconditions == R2_6_2_FINAL_REVIEW.md (source 04e4bde, target 6dc5566, direct parent, 1 ahead, FF feasible, R1 tag c350b07, worktree preserved) |
| Execution | git checkout feature/r2-multiecosystem-graph && git merge --ff-only fix/r262-gradle-constraint-semantics — exit 0, "Updating 6dc5566..04e4bde / Fast-forward", NO merge commit |
| Post-FF HEAD | 04e4bdea6894b96f05249d49736b76b26cb31560 on feature/r2-multiecosystem-graph; rev-list 6dc5566..HEAD = 1 (linear); git diff 04e4bde HEAD empty (trees identical) |
| Gradle targeted | 35/35 (R2.6.1 (n) tests green inside) |
| Oracle two-direction | reject pre-remediation payload exit 1 / accept remediated exit 0 (ff_oracle_*.txt) |
| Downstream | constraint disclosure edge in payload (qualifiers, no fingerprint); 0 CDX gradle entries; 0 SPDX relationships |
| W1 | 43/43 correct at this exact code state (phase6_w1_check.log) |
| npm byte-stability | 67e638d8 identical |
| Full regression | 27 failed / 5,032 passed / 67 skipped (38:42); identities 27/27 byte-identical (f62c7e25) |
| Flaky observation | test_5mb_minified redos test PASSED in the full run — no flake event; F-R3 characterization unchanged; test NOT modified |
| Findings preserved | F-R2 (Low, stale _parse_node docstring), F-R3 (Low, redos flake) — recorded, not fixed |
| Status | INTEGRATION COMPLETE AND VERIFIED; no push; R2.6.3/R3/production/push await separate approval; deliverable R2_6_2_FAST_FORWARD_INTEGRATION_REPORT.md |

## H1 hygiene — F-R2 docstring + F-R3 investigation (2026-11-15)

| Check | Result |
|---|---|
| Branch / commit | fix/h1-fr2-docstring @ 3d1ec9ce1e290f65fc40a0b9a94145d16dc33fd0 (parent 04e4bde; single commit; NOT merged) |
| F-R2 correction | _parse_node inline docstring corrected (documentation-only, +7/−3): (c) = dependency constraint, disclosed UNRESOLVED, never VERIFIED/fingerprint; (n) per R2.6.1; consistent with the module docstring; NO executable logic change |
| F-R3 root cause | the 250ms gate measures time.process_time() (core/regex_budget.py:838,842) = PROCESS-WIDE CPU incl. all threads -> not deterministic under in-process thread concurrency (module docstring's single-thread assumption) |
| F-R3 mechanism experiment | worst JS regex true CPU 46.9ms; 1 busy in-process thread -> 78.1ms (+67%); 8 threads -> 187.5ms (4.0x inflation, approaching the 250ms budget); exact historical breach environment-dependent, NOT reliably reproducible |
| F-R3 disposition | DEFERRED per mandate (no speculative fix); recommended minimal correction deferred to a separate approval: thread_time() in timed_finditer's gate path (immune to contamination; budget/telemetry/guard unchanged; production-utility scope) |
| Security assurance | ReDoS protection unchanged: static audit, prefilter, subprocess hard-guard, 250ms budget all intact; ReDoS suite 13/13 |
| Gates | Gradle 35/35; oracle reject exit 1 / accept exit 0; downstream 0 CDX/SPDX leak; W1 fresh re-scan 43/43; npm byte-stability 67e638d8; full regression 27/5,032/67 identities 27/27 identical (f62c7e25); redos test PASSED in the full run |
| Verdict | H1 delivered ACCEPTED_WITH_DISCLOSED_LIMITATIONS (F-R3 deferred); deliverable H1_HYGIENE_REPORT.md; independent review + separate integration approval awaited |

## H1 final independent review (2026-11-15)

| Check | Result |
|---|---|
| Review scope | read-only verification of fix/h1-fr2-docstring @ 3d1ec9c |
| Repo integrity | 1 docstring-only commit (+7/−3, 1 file), parent 04e4bde, feature branch untouched, R1 tag intact, worktree preserved |
| F-R2 | diff read in full — docstring lines only; all four mandated statements present; consistent with the module docstring; behavior-neutral proven by tests |
| F-R3 | root cause VERIFIED: time.process_time (core/regex_budget.py:838/842/861 + rule_finditer 1060/1072/1125) is PROCESS-WIDE CPU vs the intended per-regex measurement; mechanism demonstrated (46.9/78.1/187.5 ms monotonic in thread count, saved logs confirmed); historical incident NOT reproducible from preserved evidence (--tb=no run) — review does not claim deterministic reproduction |
| thread_time assessment | per-thread CPU of the calling thread, available (Python 3.14.3), same-thread start/end, guard independent, telemetry more accurate, budget unchanged; concealment only under a future thread-pool refactor; RISKS: three call sites incl. production rule_finditer per-line path, Windows resolution for 50ms line budgets, telemetry consumers |
| Regression (independent run at 3d1ec9c) | 27 failed / 5,032 passed / 67 skipped (20:27); identities 27/27 byte-identical (f62c7e25); redos test PASSED (no flake event) |
| Additional gates | ReDoS+Gradle 48 combined; oracle two-direction reproduced (exit 1/0); downstream/W1/byte-stability clean |
| Verdict | **H1 ACCEPTED** — F-R2 safe to integrate (YES); F-R3 adequately investigated, deferral correct (YES); thread_time deserves a separate bounded task covering all three sites (YES); integration NOT authorized by this verdict |

## H1 fast-forward integration (2026-11-15, explicitly authorized)

| Check | Result |
|---|---|
| Revalidation | all preconditions == H1_FINAL_REVIEW.md (source 3d1ec9c, target 04e4bde, direct parent, 1 ahead, FF feasible, R1 tag c350b07, worktree preserved) |
| Execution | git checkout feature/r2-multiecosystem-graph && git merge --ff-only fix/h1-fr2-docstring — exit 0, "Updating 04e4bde..3d1ec9c / Fast-forward", NO merge commit |
| Post-FF HEAD | 3d1ec9ce1e290f65fc40a0b9a94145d16dc33fd0 on feature/r2-multiecosystem-graph; rev-list 04e4bde..HEAD = 1 (linear); git diff 3d1ec9c HEAD empty (trees identical) |
| Gradle + ReDoS | 48 passed (35 gradle incl. R2.6.1 (n) + R2.6.2 (c) tests; 13 ReDoS) |
| Oracle two-direction | reject pre-remediation payload exit 1 / accept remediated exit 0 (ff_oracle_*.txt) |
| Downstream + W1 | 0 CDX gradle entries, 0 SPDX relationships (W1 + probe payloads); W1 43/43 at this code state |
| npm byte-stability | 67e638d8 identical |
| Full regression | 27 failed / 5,032 passed / 67 skipped (19:08); identities 27/27 byte-identical (f62c7e25) |
| Flaky observation | test_5mb_minified redos test PASSED — no flake event; F-R3 characterization unchanged; test NOT modified |
| Findings | F-R2 CLOSED by this integration; F-R3 OPEN deferred (thread_time proposal + risks in H1_FINAL_REVIEW.md §4) |
| Status | INTEGRATION COMPLETE AND VERIFIED; no push; F-R3 follow-up/production/push/R3 await separate approval; deliverable H1_FAST_FORWARD_INTEGRATION_REPORT.md |

## F-R3 CPU budget isolation — investigation & proposal (2026-11-15)

| Check | Result |
|---|---|
| Scope | investigation + proposal ONLY (no source/test/threshold changes); deliverable F_R3_CPU_BUDGET_REMEDIATION_PROPOSAL.md + evidence under fr3/logs/ |
| Three-site trace | timed_finditer (838/842 inline, 861 guarded branch), rule_finditer (1060/1072/1125 per-line path) — all measure process-wide CPU; enforcement is wall/child-driven at every site (cpu never gates) |
| Timing-model experiment | Python 3.14.3/win32: thread_time available, excludes sleep (0.000ms/200ms sleep), tracks CPU (140.6/141ms), fine resolution; CONTENDED (8 spinners) whole-scan: process_cpu=1218.8ms (contaminated) vs thread_cpu=78.1/109.4ms (true regex CPU) — per-thread measurement isolates |
| Blast radius | no enforcement reads cpu; filter_trace rows are wall-budget messages (untouched); collector slowest-row sort + ReDoS gate = intended corrections; npm/gradle/other extractors untouched |
| Proposal | thread_time() at all six measurement lines in core/regex_budget.py + red-first concurrency matrix (12 scenarios) in tests/test_redos_budget.py; single bounded commit on a dedicated branch; revert = rollback |
| Security preservation | 250ms budget, static audit, prefilter, subprocess hard-guard, wall telemetry, per-line limits, filter_trace integrity — all unchanged; genuine over-budget detection preserved |
| Verdict | proposal delivered; implementation requires separate explicit authorization |

---

## V-017 · 2026-11-15 · A1 F-R3 implementation validation (branch `fix/fr3-thread-cpu-budget` @ `3563a0e`, baseline parent `3d1ec9c`)

| Check | Method | Result |
|---|---|---|
| Red-first pre-fix run | `pytest tests/test_redos_budget.py -k fr3 -q` at `3d1ec9c` with the matrix materialized | 4 failed / 8 passed — S2 band (1187.5 > 1040.6), S3 decisive (9 rows over 250 ms, worst 1343.75), S5 per-row (359.4 under load), S7 structural — exactly the proposal's red expectations |
| Redos module post-fix | `pytest tests/test_redos_budget.py -q` | 25/25 (13 existing + 12 new) |
| Gradle suite | `pytest tests/test_lock_graph_gradle.py -q` | 35/35 |
| Oracle two-direction | stored pre-fix payload → oracle (exit expected 1); fresh extraction → oracle (exit expected 0) | reject exit 1 / accept exit 0 |
| W1 expected graph | fresh synthetic-tree scan + `w1_check.py` | 43/43, 0 wrong/missing/invented |
| npm byte-stability | double-run + fingerprint-dedup 1928 vs stored `r23_review/npm_edges.json`; canonical sha256 (sort_keys) with stored order+path | content identical modulo `source` path; hash `67e638d8` byte-exact |
| Downstream zero leak | W1 payload CDX/SPDX gradle-string counts; probe constraint edge | 0 entries / 0 rels; `('UNRESOLVED','GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY')` unchanged |
| Full regression | `pytest tests/ -q --tb=no -rf` (single run, 24:06) | 27 failed / 5,044 passed / 67 skipped — 5,032 + 12 new = 5,044 exact |
| Failure identities | normalized FAILED IDs sha256 vs baseline | 27/27 byte-identical, `f62c7e25` |
| Calibration evidence | `fr3/logs/phase1*.py/.txt` | single-rule windows do not reliably contaminate; multi-rule acceptance-shape windows do (8-spinner 5 MB: worst 1343.8 ms); thread_time tick 15.625 ms (64 Hz) |

---

## V-018 · 2026-11-15 · A2 real-Gradle evidence (branch `evidence/real-gradle-validation` @ `3d1ec9c`, evidence-only)

| Check | Method | Result |
|---|---|---|
| Wrapper install | `gradlew.bat --version` per project | Gradle 9.8.2 (mockito; pinned distributionSha256Sum validated by wrapper) / Gradle 9.9.1 (micrometer); JDK 21.0.11; downloads 200 OK |
| Real reports | `gradlew.bat --console=plain :mockito-core:dependencies` / `:micrometer-core:dependencies` | exit 0 both; 462 / 1710 lines; preserved verbatim |
| Extractor vs oracle (mockito-core) | `tools/oracle_gradle.py` on the real report + payload | 101 V / 5 U vs 103 expected: 0 WRONG, 2 MISSING (F-RG-1); real (c) 0 wrong/missing; fingerprints on all 101 |
| Extractor vs oracle (micrometer-core) | same | extractor `EXTRACTION_ERROR` → 0 edges (F-RG-2: `g:a -> v` no-left-version shape, 25 occurrences); oracle 517 V + 24 (c) |
| CDX/SPDX/join | payload inspection both projects | 0 gradle-derived CDX components / 0 SPDX rels (established envelope, R2.6.2 probe-consistent); join edges_seen=101, matched=0 (npm-only invariant) |
| (n) semantics | shape analysis `logs/shape_analysis.txt` | all real (n) nodes are depth-1 in unresolvable configurations → direct declarations, no edges — both implementations consistent |
| Scope discipline | git status on evidence branch | zero repo modifications; findings registered, not fixed |

---

## V-019 · 2026-11-15 · Independent review reproductions (read-only)

| Check | Method | Result |
|---|---|---|
| F-R3 red reproduction | temp worktree @ `3d1ec9c` + committed matrix (worktree removed after) | 4 failed / 8 passed — matches implementation red evidence from the committed state alone |
| F-R3 post-fix module | `pytest tests/test_redos_budget.py -q` at `3563a0e` | 24/25 — S2 flake caught live (R-FR3-1) |
| S2 margin probe | 5-pass exact-measurement instrument | 3/5 FAIL band; ratios 0.97/1.47/1.91/1.58/1.78×; worst row 218.8 ms |
| F-R3 targeted gates | review-scoped driver re-run | ALL GREEN (oracle 2-dir, W1 43/43, `67e638d8` byte-exact, zero leak) |
| F-R3 full regression | independent re-run at `3563a0e` | 27/5,044/67 (20:19); identities 27/27 byte-identical f62c7e25 |
| F-RG-1 reproduction | minimal fixture from verbatim mockito lines, baseline extractor + oracle | extractor UNRESOLVED '33.4.0-jre (*)' no-fingerprint vs oracle VERIFIED — CONFIRMED |
| F-RG-2 reproduction | direct extractor call on preserved micrometer report | EXTRACTION_ERROR → 0 edges — CONFIRMED; oracle silently skips 25 no-left-version lines (parsed=0); 54 skip-orphans |
| (n) no-promotion | exact decoration-depth analysis both reports | 0 (n) nodes at depth≥2; 0 VERIFIED edges touch depth≥2 (n) identities |
| CDX/SPDX/join | preserved payload re-inspection | 0 gradle-derived components/rels; join npm-only (invariant #3) — confirmed |

---

## V-020 · 2026-11-16 · R-FR3-1 S2 calibration validation (branch `fix/fr3-s2-test-calibration` @ `972fbe3`, parent `3563a0e`)

| Check | Method | Result |
|---|---|---|
| Distribution study | 12+12 alternating passes, pre-fix module materialized from `git show 3d1ec9c` (no repo change) | post-fix excess [−31.2,+0.0] ms vs pre-fix [+671.9,+1390.6] ms; 2.5q+150 passes 6/12 pre-fix → REJECTED; envelope ≤300 ms separates 12/12 + 12/12 |
| S2 repeated post-fix | 10 × `pytest ...::test_fr3_s2_one_spinner_thread_envelope` at `3563a0e`-state | 10/10 PASS |
| S2 repeated pre-fix | 10 × same in temp worktree @ `3d1ec9c` + committed test file | 10/10 FAIL (preservation line; pre-fix worst row 375–437 ms) |
| Other scenarios | diff scope + pre/post module runs | 3 S2-only hunks; post-fix 25/25; pre-fix 4 red (S2/S3/S5/S7) / 21 green |
| Module / gradle / gates | full module, gradle suite, targeted gates driver (fr3_s2-scoped) | 25/25; 35/35; oracle 2-dir, W1 43/43, `67e638d8`, zero leak — all green |
| Full regression | `pytest tests/ -q --tb=no -rf` (23:01, single run) | 27/5,044/67; identities 27/27 byte-identical `f62c7e25` |

---

## V-021 · 2026-11-16 · S2 v4 window-equivalence correction validation (branch `fix/fr3-s2-window-equivalence` @ `5f32431`, parent `972fbe3`)

| Check | Method | Result |
|---|---|---|
| Calibration (v4 boundaries) | 12+12 alternating passes | pre-fix excess [+515.6, +1234.4] ms (0/12 pass) vs post-fix [−15.6, +0.0] ms (12/12 pass) — deterministic separation |
| Import-window equivalence | gap tt0→first row | 0.00 ms in 24/24 calibration passes (hoist effective) |
| Red-first battery | 40 runs (temp worktrees @ `3d1ec9c`/`3563a0e`, bindings recorded per run) | standalone 10/10 pre-fix FAIL via "process-wide contamination" (clock=process_time recorded every run) + 10/10 post-fix PASS (clock=thread_time); full-module 10/10 pre-fix (4 failed/21 passed, red set S2/S3/S5/S7) + 10/10 post-fix 25 passed |
| Gates | module / gradle / oracle / W1 / byte-stability | 25/25; 35/35; two-direction; 43/43; `67e638d8` |
| Full regression | `pytest tests/ -q --tb=no -rf` (17:39) | 27/5,044/67; identities 27/27 byte-identical `f62c7e25` |
| Shared-window scenarios | §3 inspection S3/S5/S10/S11 | NO change required (only shared effect = the mandated import hoist) |

## V-022 · 2026-11-16 · S2 v4 independent review reproductions (read-only)

| Check | Method | Result |
|---|---|---|
| Window equivalence | committed code + 50 instrumented runs | gap tt0→first row ≤ 0.098 ms; post-fix excess [−31.2, +0.0] ms telescoping bound |
| Red-first reproduction | 40 battery runs, standalone + module contexts | 20/20 pre-fix FAIL via the contamination assertion (excess == sp_in_win, clock=process_time recorded) + 20/20 post-fix PASS |
| Floor assessment | n=50 incl. 10 runs under 4 competing CPU burners | global sp_in_win min 484.4 ms → margin 34.4 ms (~2.2 ticks; below the report's ≥3-tick claim — non-blocking, fail-safe; widens to 687.5–921.9 ms under load) |
| Negative control | sabotaged-spinner runs | 3/3 FAIL on the floor assertion (vacuous pass impossible) |
| Hoist side-effects | shared _Spinner/_spinners comparison | byte-identical; same module objects; rows never included import CPU |
| Gates | module / gradle / oracle / W1 / byte-stability / regression | 25/25; 35/35; two-direction; 43/43; `67e638d8`; 27/5,044/67 (19:24) identities 27/27 `f62c7e25` |

## V-023 · 2026-11-16 · F-R3 series fast-forward integration validation (explicitly authorized)

| Check | Result |
|---|---|
| Preflight | 9/9 PASS: source `5f32431` @ fix/fr3-s2-window-equivalence; target feature @ `3d1ec9c`; ancestry exactly 3 commits (`3563a0e`→`972fbe3`→`5f32431`); review verdict ACCEPTED; diffs scoped 2-file/1-file/1-file; dirty state recorded |
| Execution | git checkout feature/r2-multiecosystem-graph && git merge --ff-only fix/fr3-s2-window-equivalence — "Updating 3d1ec9c..5f32431 / Fast-forward", NO merge commit |
| Post-FF HEAD | `5f3243104aff76c4688b98db6182642dfb12f5ee`; rev-list 3d1ec9c..HEAD = 3 linear; diff vs source = empty (trees identical) |
| Post-verification | 10/10 PASS: linear history; 6× thread_time / 0× process_time; hoist + boundaries intact; dirty state byte-identical |
| Gates | ReDoS 25/25; gradle 35/35; oracle two-direction (reject exit 1 / accept exit 0); W1 43/43; npm byte-stability `67e638d8` byte-exact; zero leak |
| Full regression | 27/5,044/67 (23:48); identities 27/27 byte-identical (`f62c7e25`) |
| S2 v4 practical check | 3/3 post-fix PASS on integrated HEAD + 1 pre-fix red via the contamination assertion (temp worktree) |
| Status | INTEGRATION COMPLETE AND VERIFIED; no push; deliverable FR3_FAST_FORWARD_INTEGRATION_REPORT.md (evidence audit_output/fr3_ff/) |

## V-024 · 2026-11-16 · F-RG-2 implementation validation (branch `fix/rg2-platform-selected-version` @ `3fbc317`, parent `5f32431`)

| Check | Method | Result |
|---|---|---|
| Red-first | 14-test matrix vs pre-fix code | 11 red / 3 green exactly as designed (S1–S6, S9–S13 red; S7/S8/S14 preservation pins green) |
| Suite | tests/test_lock_graph_gradle.py | 49/49 (35 existing — 2 §5-sanctioned updates — + 14 new) |
| Oracle two-direction | stored probe pair + fresh extraction | reject exit 1 / accept exit 0 |
| mockito real report | extraction identity reconciliation + oracle | IDENTITY-IDENTICAL 106/106 vs the A2 pre-fix extraction; oracle unchanged (0 WRONG / 2 MISSING = F-RG-1) |
| micrometer real report | first-ever extraction + oracle classification | 547 edges (493 VERIFIED, 24 unique (c), invalid_nodes 9, direct 305); 0 WRONG; 23 MISSING 23/23 F-RG-1-combo-attributable, 0 unexplained (agreement MODULO F-RG-1 — disclosed) |
| Downstream | full-pipeline re-scans both projects | 0 CDX gradle-derived entries, 0 SPDX gradle-derived relationships |
| W1 / byte-stability | synthetic tree + npm double-run | 43/43; `67e638d8` byte-exact (1928 = stored 1:1) |
| Full regression | single run (21:09) | 27/5,058/67 (5,044+14 exact); identities 27/27 byte-identical `f62c7e25` |
| Disclosures | invalid_nodes 9 lines named; S11 fixture correction; §5 test updates | recorded in F_RG_2_IMPLEMENTATION_REPORT.md §7 |

## V-025 · 2026-11-16 · F-RG-2 independent review reproductions (read-only)

| Check | Method | Result |
|---|---|---|
| Scope/parent | git show --stat `3fbc317` | exactly 3 files (+451/−15); parent == `5f32431`; working tree only pre-existing dirty entries |
| Path isolation | hunk-by-hunk diff inspection | platform branch purely additive; 3-part conflict path zero diff (extractor + oracle); `(*)` stripping only in the 2-part platform branch |
| Fabrication | real-payload inspection | 0 platform edges with a requested_version qualifier; 0 empty-string requested_version qualifiers |
| Line accounting | full micrometer 1,710-line classification | 1,710/1,710 classified, zero unaccounted; 25/25 previously-skipped lines individually listed (24 depth-1 + 1 depth-2) |
| Skip-orphan | rg_verify2 None-on-skip model + extractor tallies | 54/54 reproduced and resolved; 0 orphan promoted (direct 305 == independent depth-1 count 305); 0 sentinel leakage into expectations |
| F-RG-1 attribution | module-API recomputation | expected 516 / got 493 / WRONG 0 / MISSING 23 → 23/23 combo-attributable, 0 unexplained; (c) 24=24, (n) 0=0, mockito (c) 3=3 |
| (n)-leaves | 9 named lines + leaf-removal invariance | tallied + disclosed; expectation sets byte-identical with the lines removed |
| Malformed-test updates | hunk inspection | §5-faithful (leaf → tally+disclosure; with-subtree fatal pinned by S14); strictly stronger assertions; no weakening |
| Genuine two-direction | pre-fix REAL output + partial payload | pre-fix EXTRACTION_ERROR payload rejected exit 1 naming the platform identity; partial payload rejected; post-fix accepted exit 0 |
| Gates | full reproduction suite | 49/49; gates driver 11/11; W1 43/43; `67e638d8`; full regression 27/5,058/67 (22:07) identities 27/27 `f62c7e25`; CDX/SPDX leak 0 both projects |

## V-026 · 2026-11-16 · F-RG-2 fast-forward integration validation (explicitly authorized)

| Check | Result |
|---|---|
| Authorization | user approval this session: F-RG-2 local FF integration + ledger synchronization ONLY (no push/production/F-RG-1/R3/unrelated changes) |
| Preflight | source `3fbc317dfbef917ca7205059f81bbbe33936a744` @ fix/rg2-platform-selected-version (== worktree HEAD); parent == `5f3243104aff76c4688b98db6182642dfb12f5ee` (direct); rev-list feature..source = 1 → FF possible; R1 tag r1-validated-20261112 → c350b07 intact; dirty state = pre-existing 7 entries (preflight.txt) |
| Execution | git checkout feature/r2-multiecosystem-graph && git merge --ff-only fix/rg2-platform-selected-version — "Updating 5f32431..3fbc317 / Fast-forward", NO merge commit (ff_operation.txt) |
| Post-FF HEAD | `3fbc317dfbef917ca7205059f81bbbe33936a744` on feature/r2-multiecosystem-graph; rev-list 5f32431..HEAD = 1 (linear); tree-identity diff vs `3fbc317` = 0 lines; exactly 3 files +451/−15 |
| Series intactness | 6× time.thread_time() / 0× time.process_time (core/regex_budget.py); `version_selected_by_platform` present in gradle.py (4 occurrences); oracle skip-orphan sentinel present (post_verification.txt) |
| Gradle targeted | 49/49 (gate_gradle.txt) |
| ReDoS module | 25/25 (gate_module.txt) |
| Oracle two-direction | stored pre-fix payload rejected exit 1 / fresh extraction accepted exit 0 (ff_oracle_reject.txt / ff_oracle_accept.txt) |
| W1 | 43/43, 0 wrong/missing/invented (ff_w1_check.txt) |
| npm byte-stability | double-run identical (3856); dedup 1928 == stored; fingerprint sets 1:1; content byte-identical modulo source path; canonical hash `67e638d8` byte-exact |
| Downstream zero leak | W1 payload 0 CDX gradle entries, 0 SPDX gradle relationships; probe constraint edge unchanged (UNRESOLVED / GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY) |
| Real-report oracle (integrated HEAD) | mockito identity-IDENTICAL 106/106, 0 WRONG / 2 MISSING (= F-RG-1, unchanged); micrometer 547 edges (493 VERIFIED, invalid_nodes 9, direct 305), 0 WRONG (VERIFIED), 0 (c)/(n) wrong-or-missing, 0 constraint-confidence mismatches, MISSING F-RG-1-attributable (5/5 visible tuples; 23-identity attribution per the review's module-API recomputation), exit 0 (ff_real_report_validation.txt) |
| Full regression | 27 failed / 5,058 passed / 67 skipped (24:45, exit 1 = registered baseline failures); failure identities 27/27, sha256 `f62c7e25`, byte-identical to both stored baselines (h1_ff + frg2 delivery) |
| Worktree | pre-existing dirty state preserved byte-identical through checkout and all runs; no reset/clean/stash |
| Branch state | fix/rg2-platform-selected-version residual pointer at `3fbc317` (disposition = separate approval) |
| Verdict | INTEGRATION COMPLETE AND VERIFIED; no push; deliverable F_RG_2_FAST_FORWARD_INTEGRATION_REPORT.md (evidence audit_output/frg2_ff/) |

## V-027 · 2026-11-16 · Overnight preflight baseline recheck (nov16task §1/§5) — ALL GATES REPRODUCED

Evidence `audit_output/overnight/preflight/`; state `feature/r2-multiecosystem-graph` @ `3fbc317dfbef917ca7205059f81bbbe33936a744`.

| Check | Result |
|---|---|
| Gradle suite | 49 passed (exit 0; gradle_suite.txt) |
| ReDoS suite | 25 passed (exit 0; redos_suite.txt) |
| Oracle two-direction | stored pre-fix payload rejected exit 1 / fresh extraction accepted exit 0 (oracle_reject.txt / oracle_accept.txt) |
| W1 | 43/43, 0 wrong/missing/invented (w1_check.txt) |
| npm byte-stability | double-run identical (3856); dedup 1928 == stored; fingerprints 1:1; content byte-identical modulo source path; canonical hash `67e638d8` byte-exact |
| Downstream zero leak | W1 payload 0 CDX gradle + 0 SPDX gradle; probe constraint edge unchanged (UNRESOLVED / GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY); targeted driver 13/13 PASS exit 0 |
| Real-report oracle | mockito identity-IDENTICAL 106/106, 0 WRONG / 2 MISSING (= F-RG-1, unchanged); micrometer 547 edges (493 VERIFIED, invalid_nodes 9, direct 305), 0 WRONG, 0 (c)/(n) deltas, 0 constraint-confidence mismatches, unexplained 0, exit 0 |
| Full regression | 27 failed / 5,058 passed / 67 skipped (1214.16s, 20:14; exit 1 = the registered failures); failure identities 27/27, sha256 `f62c7e25`, byte-identical to the stored baseline (failure_ids_norm.txt) |
| Preflight verdict | baseline fully reproduced at `3fbc317`; no deviations; OVERNIGHT_PREFLIGHT_REPORT.md delivered |

## V-028 · 2026-11-16 · Overnight end-state verification + independent agent fact-check

| Check | Result |
|---|---|
| End-state git | HEAD unchanged `3fbc317dfbef917ca7205059f81bbbe33936a744` on feature/r2-multiecosystem-graph; committed tree identical (diff 0 lines); tracked working-tree diff vs HEAD = exactly the pre-existing `M data/.vuln_cache.json`; dirty/untracked set = the pre-existing 7 entries |
| End-state spot gates | gradle 49 passed; redos 25 passed (state unchanged since the V-027 full battery — no code changed during the overnight run) |
| Independent agent verification | separate read-only general-purpose agent re-executed/independently inspected 20 claims (groups A-H: toolchains, sha256 hashes, corpus surveys, code lines oracle_gradle.py:253-262 / gradle.py:337-338 / test_redos_budget.py:563,616 / gemfile_lock.py sections, preflight artifacts, F-RG-1 fixture lines + absent selected-side strip at HEAD, authorization-gate consistency vs nov16task.md + decision log, git/remote containment): **CONSISTENT — 20/20 PASS, 0 FAIL, 0 discrepancy** |
| Review status | agent fact-check = completed evidence verification; substantive review of any future F-RG-1 implementation = PENDING_INDEPENDENT_REVIEW |

## V-029 · 2026-11-17 · F-RG-1 implementation validation (branch `fix/rg1-gradle-conflict-elision` @ `20542e3`, parent `3fbc317`)

| Check | Method | Result |
|---|---|---|
| Red-first | 12-test matrix run at the pre-fix state | **8 failed / 52 passed exactly as designed** — red: s8-rewritten, M1, M2, M3, M3b, M7, M9, M10; green preservation: M4, M5, M6, M8 (red_run.txt) |
| Gradle suite | tests/test_lock_graph_gradle.py post-fix | **60/60** (49 existing incl. 1 sanctioned rewrite + 11 new) |
| ReDoS module | tests/test_redos_budget.py | 25/25 |
| Oracle two-direction (unit) | m3b: byte-embedded ACTUAL pre-fix payload vs corrected oracle | pre-fix payload REJECTED exit 1 (MISSING VERIFIED names the clean guava identities) / post-fix extraction ACCEPTED exit 0 |
| Oracle two-direction (real) | full 106-edge pre-fix mockito payload (captured at red) vs corrected oracle | REJECTED exit 1, MISSING 2 (clean identities) / post-fix payload ACCEPTED exit 0 — genuine, not a strawman |
| mockito reconciliation | extract + oracle on the preserved real report | **103 VERIFIED (101 + 2 combo, clean `33.4.0-jre`) — oracle exit 0, 0 WRONG / 0 MISSING** (exact) |
| micrometer reconciliation | extract + oracle on the preserved real report | **516 VERIFIED (493 + 23 remediated) — oracle exit 0 PASS: 0 wrong/missing ALL classes, 0 constraint-confidence mismatches; unresolved 54→31 (remaining = (c)/project-parent disclosures); FIRST exact agreement — the modulo-F-RG-1 limitation is CLOSED** |
| Downstream full-pipeline | full scans of both real reports (registered filename) | mockito 106 edges (103 V): CDX gradle 0, SPDX gradle 0, join edges_seen=103 matched=0; micrometer 547 (516 V): CDX 0, SPDX 0, join matched=0 — zero-leak unchanged, npm-only join invariant intact (real_fullpipeline.txt) |
| W1 / npm byte-stability | targeted gates driver | 43/43; `67e638d8` byte-exact; driver 13/13 PASS exit 0 |
| Full regression | `pytest tests/ -q --tb=no -rf` (20:33) | 27 failed / 5,069 passed / 67 skipped (5,058+11 exact); identities 27/27, sha256 `f62c7e25`, byte-identical to the stored baseline |
| Scope/worktree | git diff + status | exactly the 3 authorized files (+447/−17); dirty state preserved byte-identical; single commit `20542e319e4c102163ecb04cc30ca258cf33bc82` |
| Verdict | — | implementation COMPLETE; review-then-integrate applies; no push |

## V-030 · 2026-11-17 · F-RG-1 independent review reproductions (read-only)

| Check | Method | Result |
|---|---|---|
| Scope/parent | git rev-parse + show --stat | HEAD `20542e3`, parent `3fbc317` exact; feature @ `3fbc317` untouched; exactly 3 files (+447/−17); `branch -r --contains HEAD` empty |
| Red-first reproduction | committed tests in temp worktree @ `3fbc317` (removed after) | **7 failed / 52 passed / 1 skipped** — exact red set (s8-rewritten, m1, m2, m3, m3b, m9, m10); M7 skipped (no corpus in worktree) — reconciles the implementation's 8 red |
| (a) strip census | grep -n re.sub both files | 3 sites per file; new sites = gradle.py:213 + oracle:133 (3-part conflict path only); 2 hunks per file in the diff, platform branches untouched |
| Pre/post delta accounting | fresh `git show 3fbc317` materialization vs post-fix on both reports | mockito +2/−2; micrometer +23/−23 (each gone = new + ` (*)`); **(c) 24=24 + 3=3 byte-identical; (n) 0=0**; all other tallies unchanged; only the 25 combo identities affected |
| Payload authenticity | embedded FRG1_PREFIX_PAYLOAD vs fresh pre-fix extraction | identity fields + qualifiers equal (sole full-JSON diff = source path form) |
| Line accounting | full walk both reports | micrometer 1,710/1,710 (48 combo, 0 unclassified; classes cross-check with the F-RG-2 review); mockito 462/462 (6 combo); 54/54 combo lines verified 4 ways, 0 mismatches |
| Real-report reconciliation | review-scoped script, exit 0 | mockito 103 VERIFIED, 0 WRONG / 0 MISSING (exit 0); micrometer 516 VERIFIED, 0 wrong/missing ALL classes, 0 constraint-confidence mismatches (exit 0 PASS) |
| Two-direction (real) | pre-fix 106-edge payload vs corrected oracle | reject exit 1 (MISSING 2 clean identities) / accept exit 0 |
| Gates | gradle / ReDoS / driver / full-pipeline | 60/60; 25/25; 13/13 (W1 43/43, npm `67e638d8`); CDX 0 + SPDX 0 both, join matched=0 |
| Full regression | independent re-run (21:10) | 27/5,069/67; identities **27/27 `f62c7e25`, byte-identical three-way** (review == implementation == baseline) |
| Tests inspection | committed file | 11 test_frg1_m* defs + s8 rewrite (no old def name); M9 disclosure guarantee intact; M7 corpus guard present |
| Verdict | — | **ACCEPTED** (findings R1–R5 all Info, non-blocking); no integration/push authorized |

## V-031 · 2026-11-17 · F-RG-1 strict FF integration + post-integration validation (explicitly authorized)

| Check | Result |
|---|---|
| Phase A preflight | 12/12 PASS: fix @ `20542e3`, parent `3fbc317` exact, feature at expected base, review verdict ACCEPTED at specified path, ledger heads D-037/V-030, 0 remote refs contain the commit, FF feasible (preflight.txt) |
| Phase B execution | `git checkout feature/r2-multiecosystem-graph` (HEAD verified 3fbc317 pre-merge) + `git merge --ff-only 20542e319e4c102163ecb04cc30ca258cf33bc82` → "Updating 3fbc317..20542e3 / Fast-forward", exit 0 (ff_operation.txt) |
| Post-FF graph | HEAD == `20542e319e4c102163ecb04cc30ca258cf33bc82`; NO merge commit (linear graph; rev-list 3fbc317..HEAD = 1); tree diff vs reviewed commit = 0 lines; metadata unchanged (author/date/subject preserved) |
| Gradle / ReDoS | 60/60 (exit 0) · 25/25 (exit 0) |
| Targeted gates | 13/13 PASS exit 0: oracle two-direction reject 1 / accept 0; W1 43/43 (0 wrong/missing/invented); npm `67e638d8` byte-exact (dedup 1928 == stored, fingerprints 1:1); downstream zero-leak both payloads; probe constraint edge unchanged |
| Mockito reconciliation | 106 edges, **103 VERIFIED, 0 WRONG / 0 MISSING** (oracle exit 0); 2 remediated combo clean; tallies unchanged except verified 101→103 / unresolved 5→3 |
| Micrometer reconciliation | 547 edges, **516 VERIFIED, 0 WRONG / 0 MISSING all classes, 0 constraint-confidence mismatches, ORACLE RESULT: PASS** (exit 0); tallies unchanged except verified 493→516 / unresolved 54→31 |
| Downstream full-pipeline | PASS: CDX gradle 0 / SPDX gradle 0 both projects; join npm-only (edges_seen 103/516, matched 0) |
| Full regression | 27 failed / 5,069 passed / 67 skipped (1233.03s, 20:33; exit 1 = registered failures) |
| Identity comparison | 27/27, sha256 **`f62c7e25`**, byte-identical **four-way** (FF == baseline artifact == implementation == review) — no new, none disappeared |
| Scope | exactly 3 authorized files (+447/−17); working tree == commit for those files; no other source changes |
| Dirty-state preservation | byte-identical to pre-integration snapshot (7 entries); evidence dirs intact; new artifacts only in frg1_ff/ |
| Remote refs | `branch -r --contains 20542e3` empty before AND after — no push, no fetch |
| Verdict | **INTEGRATION COMPLETE AND VERIFIED, NO DEVIATIONS** — deliverable F_RG_1_FAST_FORWARD_INTEGRATION_REPORT.md (evidence audit_output/frg1_ff/) |

## V-032 · 2026-11-17 · B-1 strict FF integration + post-integration validation (explicitly authorized)

| Check | Result |
|---|---|
| Phase A preflight | ALL PASS: fix/b1 @ `f100e3e`, parent `20542e3` exact, feature at target, verdict ACCEPTED_WITH_DISCLOSED_LIMITATIONS, ledgers D-038/V-031, 0 remote refs contain `f100e3e`, FF feasible (preflight.txt) |
| Phase B execution | `git checkout feature/r2-multiecosystem-graph` (HEAD verified pre-merge) + `git merge --ff-only f100e3e493719a79d0901117cf089732475badf8` → "Updating 20542e3..f100e3e / Fast-forward", exit 0 (ff_operation.txt) |
| Post-FF graph | feature HEAD == `f100e3e493719a79d0901117cf089732475badf8`; NO merge commit (linear); exactly 1 commit introduced; tree identical (0-line diff); metadata unchanged |
| B-1 diagnostic tests | **7/7** (structural pin: all 33 sites corrected + 5 exclusion slices pinned) |
| Gradle / ReDoS | 60/60 · **25/25 clean** (no S3 flake recurrence) |
| Targeted / W1 / npm | 13/13 (oracle 2-dir 1/0, zero-leak) · **43/43** · **`67e638d8` byte-exact** |
| Site/exclusion/forms | 33 corrections intact; 32 exclusions unchanged (5 numeric + 8 variable + 19 caps); all 5 display forms covered; oracles independent (0 production imports) |
| ReDoS disclosure (Phase D) | original S3 event preserved verbatim (281.25 ms / 250 ms / 8 spinners; reruns clean; never reproduced in full regression) = intermittent environment-sensitive R-FR3-2; **B-4 OPEN** |
| Real-project recon (Phase E) | mockito **103/0/0** exit 0; micrometer **516/0/0 ORACLE PASS**; CDX gradle 0 / SPDX gradle 0; join npm-only; no classification changes |
| Full regression (Phase F) | **27 failed / 5,077 passed / 66 skipped (1994.80s, 33:14)** — **DISCLOSED DEVIATION vs expected 5,076/67: one skip→pass promotion** (totals reconcile 5,170; exact flipped test not isolated this run; `-rs` follow-up recommended; not a failure regression) |
| Identity comparison | **27/27, sha256 `f62c7e25`, byte-identical SEVEN-WAY** (baseline + F-RG-1 impl/review/FF + B-1 impl/review + this run); no new/disappeared identity |
| Scope | integrated commit == 12 reviewed files exactly; 0 production files; B-2..B-7 untouched; no V11 changes; no ReDoS test/measure changes |
| Dirty-state + cache | status byte-identical `98fadb83a053b2d8`; cache content disclosed: 3c14fdda (impl start) → 4d85afbc (review gates) → **ff90f36a (this run's gates)** — scan-driven refresh only, no manual edit |
| Census erratum (R1) | corrected figures: 11 oracle files / 38 numeric / 8 variable / 65 total / 33 corrected / 32 excluded — historical claims preserved, corrected on the record |
| Verdict | **INTEGRATION SUCCESS with one disclosed validation deviation (regression counts; identities clean)** — deliverable B1_FAST_FORWARD_INTEGRATION_REPORT.md (evidence audit_output/b1_ff/) |

## V-033 · 2026-11-17 · Independent validation of CycloneDX 1.6 offline-schema remediation (read-only review of `34b07ed`, parent `f100e3e`)

Evidence classes: **[REPRODUCED]** = independently re-executed by the
review; **[PRESERVED]** = read from committed evidence artifacts;
**[RECONSTRUCTED]** = re-derived from committed states after originals
proved unpreserved; **[NOT-FRESHLY-RERUN]** = accepted on preserved
evidence per the no-expensive-reruns guidance.

| Check | Method | Result |
|---|---|---|
| Scope / parent / lineage | `git rev-parse`/`show`/`diff --name-status` | HEAD `34b07ed8dd15f4b66296636fc8943f773b96735d`, parent `f100e3e493719a79d0901117cf089732475badf8` exact; single parent (no merge); `rev-list f100e3e..34b07ed`=1; exactly 6 paths (+7,934/−2); working tree == commit for those paths; feature @ `f100e3e` untouched; V11 @ `889170a` untouched; 0 remote refs contained the commit at review time **[REPRODUCED]** |
| Schema provenance | live in-memory fetch of the 3 official URLs + upstream LICENSE (`provenance_probe.py`) | **VERIFIED**: bom-1.6 / spdx / jsf byte-identical to vendored (sha256 MATCH ×3); upstream LICENSE = Apache License 2.0 **[REPRODUCED]** |
| Schema SHA-256 | independent `sha256sum` vs pins + MANIFEST + `cyclonedx16/raw/` copies | `18f57f7482593bad…ca5b37d` / `4b345e2329f209f3…dc47b359` / `8bae002c25e723db…ecb090aae` — exact 3/3; manifest bytes/id cross-checks pass **[REPRODUCED]** |
| `$ref` completeness | independent JSON traversal (`ref_scan.py`) + behavioral probes | 303 refs, exactly 2 external (spdx.schema.json, jsf-0.82.schema.json#/definitions/signature), both resolve locally, 0 transitive, 0 URL-form; offline dereference proven by probes (spdx enum + jsf signer branches fully evaluated under network block) **[REPRODUCED]** |
| Offline behavior | fresh network-disabled harness in an isolated worktree mirror (requests.get/Session.request/Session.send blocked and counted) | **52 passed / 0 failed / 0 skipped; NETWORK_ATTEMPTS_DURING_RUN: 0** **[REPRODUCED]** |
| Loader review | source diff + explicit-failure probes (`identity_failure_probe.py`, `cwd_probe.py`) | PASS: SHA-256 before use; `$id` asserted; wrong-$id / wrong-version / hash-lie → explicit RuntimeError with exact messages; zero network in the 1.6 path; non-1.6 fetch block byte-identical (109 lines); signatures compatible; CWD-independent; stateless/concurrency-safe **[REPRODUCED]** |
| Test adequacy | committed-suite inspection | **PASS WITH GAPS**: all 8 new tests exercise the real loader; F-CDX16-R2 (test 6 assertions can't discriminate ref-resolution failure; malformed via missing required field) + F-CDX16-R3 (wrong-$id rejection untested); no network-dependent skip path remains (retained skip fires only on ImportError) **[REPRODUCED inspection]** |
| Red-first | detached worktree at exact `f100e3e` + committed tests (variants A: tests only / B: + schemas) | **RECONSTRUCTED RED-FIRST: 7 failed / 1 passed ×2**; single green = invalid-document preservation test; every red shows the genuine pre-fix dependency; original red log unpreserved (F-CDX16-R1); sequencing deviation (fix applied before red capture) stands disclosed **[RECONSTRUCTED]** |
| Semantic invariance | reconstructed 4-doc battery + 3 ref-probes, pre-fix (live path) vs post-fix (blocked) | verdicts **4/4 + 3/3 identical**; string error lists both sides; one error-wording difference (deepest-branch vs oneOf summary), verdicts unchanged; boundary: reconstructed battery, tested shapes only (originals unpreserved) **[RECONSTRUCTED]** |
| Full regression | NOT freshly executed by the review (hand-off: no expensive reruns) — preserved `cyclonedx16/logs/full_regression.log` at the committed state | **27 failed / 5,085 passed / 66 skipped** (26:11) — **[PRESERVED] historical result, not a newly executed full regression** |
| Collection count | fresh `pytest --collect-only` in the isolated mirror | **5,178** collected **[REPRODUCED]** |
| Failure identity | 27-nodeid re-execution in mirror + artifact byte-comparison | 27 nodeids re-run → **27 failed**, name set identical to baseline; `failure_ids_norm.txt` sha256 **`f62c7e25…`** byte-identical to 30+ stored artifacts; no new/disappeared identity (27/27) **[REPRODUCED + PRESERVED]** |
| Skip inventory | tally of preserved log SKIPPED lines | 66 exact (t14 11 + rust 8 + t1401 1 + attack 2 + conf_baseline 4 + report_validation 1 + root_cause 1 + spdx 36 + ssdf 2); **zero schema skips**; both schema tests execute and pass **[PRESERVED tally; schema-test pass REPRODUCED]** |
| B-1 flipper distinction | erratum verification | fetch failure → `{"valid": False}` → failed assertion, NOT a skip (skip path requires ImportError); **historical B-1 skip→pass flipper UNRESOLVED** — not attributed to this remediation **[PRESERVED erratum]** |
| Dirty-state | sha256[:16] of `git status --porcelain` + cache file, before/after (convention confirmed via recorded status hash) | status `98fadb83a053b2d8` byte-identical; cache `dab348e44c8484c1` untouched by the review; impl-report §16 "unchanged during task" claim unsupported (preflight `e67879a57573c228`) = F-CDX16-R4 (scan-driven refresh rule-permitted) **[REPRODUCED]** |
| Findings | — | F-CDX16-R1..R4 LOW; F-CDX16-R5..R9 INFORMATIONAL; none blocking technical integration |
| Verdict | — | **ACCEPTED_WITH_DISCLOSED_LIMITATIONS** — report `audit_output/CYCLONEDX16_OFFLINE_SCHEMA_INDEPENDENT_REVIEW.md`, evidence `audit_output/cyclonedx16_review/`; the complete regression suite was NOT freshly executed during the independent review; the verdict does NOT authorize integration, push, deployment, R3 or B-2..B-7 |

## V-034 · 2026-11-17 · DEV-1 independent verification (fresh-checkout line-ending remediation, `d695aa2`, parent `34b07ed`)

Evidence classes: **[REPRODUCED]** = independently re-executed in this
verification; **[PRESERVED]** = read from committed/preserved artifacts.

| Check | Method | Result |
|---|---|---|
| Preflight / state | git rev-parse, status hash, ledger hashes | branch feature @ `d695aa2732cb3ccc28991c335635a22e88ab6316`, parent `34b07ed…` exact; source branch @ `34b07ed`; D-041/V-034 absent pre-append, D-040/V-033 exactly once; status hash `98fadb83a053b2d8`, cache `dab348e44c8484c1` (== historical reference values) **[REPRODUCED]** |
| Commit integrity | `git show d695aa2` diff inspection | exactly 2 paths (`.gitattributes` +7, `tests/test_cyclonedx16_offline_schema.py` +35); single parent, 1 commit 34b07ed..d695aa2, no merge; `.gitattributes` append-only with both pre-existing rules preserved verbatim; guard test carries real byte-hash + check-attr assertions; zero schema/loader files in the commit; loader integrity/identity failure lines intact at HEAD **[REPRODUCED]** |
| Attribute resolution | `git check-attr -a`, config/filters inspection | `text: unset` for schema.json / spdx.schema.json / jsf-0.82.schema.json (and MANIFEST.json); unrelated paths `text: unspecified`; `core.autocrlf=true` (system gitconfig) unmodified; no nested attribute files or smudge filters applicable to the fixture **[REPRODUCED]** |
| Fresh-checkout method | NEW `git worktree add --detach` at `d695aa2` under host `core.autocrlf=true`; no `-c` overrides, no manual conversion, no copied files, no reused checkout, no filter bypass | checkout deterministically reproduces normal clone behavior **[REPRODUCED]** |
| Byte comparison (3 files) | independent `verify_bytes.py`: `git cat-file blob` vs fresh file, byte-for-byte + size | blob==file True ×3; sizes 262,666 / 63,418 / 8,058 equal; **CR=0 CRLF=0 ×3** (pre-remediation fresh checkout had +5,699 CR in schema.json and differing hashes on all three) **[REPRODUCED]** |
| SHA-256 results | independent hashlib vs pins vs manifest | `18f57f74…ca5b37d` / `4b345e23…dc47b359` / `8bae002c…ecb090aae` — blob == file == pin == manifest ×3 **[REPRODUCED]** |
| D1 offline-schema suite | `pytest -q tests/test_cyclonedx16_offline_schema.py` in fresh worktree | **9 passed / 0 failed / 0 skipped** (8 pre-existing + 1 new DEV-1 guard) **[REPRODUCED]** |
| D2 affected tests | `pytest -q` the two named nodeids | **2 passed / 0 failed / 0 skipped** — no network-dependent skip **[REPRODUCED]** |
| D3 offline network | established hard-block harness (patches `requests.get`/`Session.request`/`Session.send`, counts attempts — verified by source inspection to cover the module's entire network surface; loader imports contain no network library) + integrity probes + semantic battery | **53 passed / 0 failed / 0 skipped, NETWORK_ATTEMPTS = 0**; tampered hash → `schema integrity failure`, missing → `vendored schema missing`, wrong `$id`/version → `schema identity failure` (all explicit, no silent fallback/skip); external refs resolve offline (spdx enum True, jsf branches fully dereferenced); battery verdicts T/F/F/F unchanged **[REPRODUCED]** |
| D4 focused regression | `pytest -q` on test_phase4_cbom_conformance + test_phase4_cbom_purpose + test_v4_validation_modules + test_v4_real_tool_conformance in fresh worktree | **59 passed / 0 failed / 0 skipped** (94 s) — identical to the remediation run's selection and result **[REPRODUCED]** (historical figure independently reproduced, not merely preserved) |
| Guard adequacy | test-source inspection | asserts actual file bytes vs manifest pins (not config text alone) AND `check-attr text: unset`; catches rule removal (attribute half red) and byte drift (hash half red) regardless of which worktree runs it **[REPRODUCED inspection]** |
| Limitations | — | guard's attribute half skips if git unavailable; full 25–35-minute regression not rerun (focused set only, per mandate); hosts with exotic global smudge filters would be flagged by the guard rather than prevented |
| Protected state | before/after capture | dirty state `98fadb83a053b2d8` (7 entries) byte-identical; cache `dab348e44c8484c1` unchanged; `stash@{0}` (1) untouched; D-040/V-033 unchanged pre-append; V11 `889170a` untouched; 24 remote refs unchanged; no implementation/source/test/schema modification by this verification **[REPRODUCED]** |
| Verdict | — | **VERIFIED** — DEV-1 failure mode fully closed under normal checkout on this host; report `audit_output/DEV1_INDEPENDENT_VERIFICATION_REPORT.md`, evidence `audit_output/dev1_independent_verification/`; no publication or deployment authorized |

## V-035 · 2026-11-17 · F-CDX16-R2/R3 test remediation — independent review reproductions (`74c4515`, parent `d695aa2`; related decision D-042)

Evidence classes: **[REPRODUCED]** = independently re-executed in the
review worktree at `74c4515` (host config preserved); **[PRESERVED]** =
read from committed/preserved artifacts; **[ARTIFACT-VERIFIED]** =
historical artifact inspected, moment not replayable; **[NOT-EXECUTED]**
= explicitly not run.

| Check | Method | Result |
|---|---|---|
| Preflight / commit identity | git rev-parse, show --name-status | branch feature @ `74c451578b2ed8000f9ee83c11d2194358406f05`, parent `d695aa2732cb3ccc28991c335635a22e88ab6316` exact; exactly 1 changed path (`tests/test_cyclonedx16_offline_schema.py`, +148/−0); no merge; D-041/V-034 latest pre-append **[REPRODUCED]** |
| Diff scope | full diff + numstat + added-line scans | pure additions (0 deletions — no existing assertion weakened/removed); no production/schema/pin/manifest/`.gitattributes` path; no broad exception swallowing in added lines **[REPRODUCED]** |
| Python compilation | `python -I -m py_compile` | exit 0 **[REPRODUCED]** |
| Offline-schema suite | `pytest -q tests/test_cyclonedx16_offline_schema.py` | **12 passed / 0 failed / 0 skipped** (9 pre-existing + 3 new R2/R3 tests) **[REPRODUCED]** |
| Affected tests | `pytest -q` the two named nodeids | **2 passed / 0 failed / 0 skipped** **[REPRODUCED]** |
| Network-disabled harness | established hard-block harness (requests.get/Session.request/Session.send patched + counted) | **56 passed / 0 failed / 0 skipped, NETWORK_ATTEMPTS: 0** (12 + 44 CBOM) **[REPRODUCED]** |
| Guard effectiveness | live attempt under `_NetworkGuard` | ConnectionError raised AND counted (`attempts=['get']`, GUARD_EFFECTIVE=True) — zero-attempt claims not vacuous **[REPRODUCED]** |
| Focused CBOM/SBOM regression | 4 modules (cbom_conformance + cbom_purpose + v4_validation_modules + v4_real_tool_conformance) | **59 passed / 0 failed / 0 skipped** — exact parity with the recorded baseline **[REPRODUCED]** |
| R2 red-first: old-assertion gap | sabotaged loader (empty resources) vs old assertion set | old set **PASSES** on `(False, ['Unresolvable: …'])` despite zero resolution — the original weakness reproduced **[REPRODUCED]** |
| R2 red-first: failing-resolver sabotage | empty-resources loader variant, 3 R2 tests | **3 failed** (`test_external_ref_inventory_and_local_resolution`, `test_external_refs_resolve_offline`, `test_unresolved_external_ref_fails_explicitly`) **[REPRODUCED]** |
| R2 negative probe: missing resource | spdx resource removed from loader variant | inventory test **FAILED** (resource-set assertion) **[REPRODUCED]** |
| R2 negative probe: silently-skipping resolver | resolution exceptions swallowed to `valid=True` | `test_unresolved_external_ref_fails_explicitly` **FAILED** (its `valid is False` assertion catches the skip) **[REPRODUCED]** |
| R3 negative probe: accepting-loader variant | `$id` check neutralized (review copy only) | `test_wrong_schema_id_is_rejected_by_loader` **FAILED — DID NOT RAISE** (catches acceptance) **[REPRODUCED]** |
| R3 positive | real loader + tampered tmp fixture (manifest hash updated → hash gate passes → `$id` check rejects) | explicit `RuntimeError: schema identity failure` naming both identity values; public path returns `{"valid": False, errors: ["schema identity failure…"]}` with `valid` present (no skip shape) **[REPRODUCED]** |
| Restore checks | `git checkout --` after each sabotage; module rerun | **12 passed / 0 failed / 0 skipped** after every restore; review copy clean **[REPRODUCED]** |
| Whitespace / formatting | `git diff --check` | exit 0 **[REPRODUCED]** |
| Full regression | 25–35-minute suite | **[NOT-EXECUTED]** — the focused 59-test suite was independently reproduced instead (mandated policy) |
| Cache refresh disclosure | current hash vs disclosed values | current `c494b680ecd32280…` == disclosed post-refresh value; pre-value `dab348e44c8484c1…`; mechanism = scan-driven refresh during mandated gate runs (rule-permitted); **the refresh moment itself is [ARTIFACT-VERIFIED] only** — the independent review found the current state consistent with the disclosure; file left `M`, never normalized **[PRESERVED + ARTIFACT-VERIFIED]** |
| JSF / jsonschema limitations | assessment | jsf `oneOf` quirk preserved under F-CDX16-R6 (positive proof deliberately uses the URI-algorithm form); wording assertion acceptable under pinned jsonschema 4.26.0; structured-error hardening = non-mandatory future recommendation **[PRESERVED]** |
| Protected state | before/after capture | dirty set (7 entries) intact; stash (1) untouched; remotes 24 unchanged; V11 `889170a` untouched; no source/test/schema modification by review or synchronization; ledgers pre-edit hashes `c6a2c3f6…` / `a9967d43…` backed up (`d042_v035_sync_evidence/`) **[REPRODUCED]** |
| Verdict | — | **ACCEPTED** (per CYCLONEDX16_R2_R3_INDEPENDENT_REVIEW.md: F-CDX16-R2 ACCEPT, F-CDX16-R3 ACCEPT); the full regression was NOT run; no publication or deployment authorized |

## V-036 · 2026-11-17 · Overnight plan execution validation (tasks.md §11 regression + documentation-batch gates; related decision D-043)

Evidence classes: **[REPRODUCED]** = executed this run; **[PRESERVED]** =
read from committed/preserved artifacts; **[NOT-EXECUTED]** = explicitly
not run.

| Check | Method | Result |
|---|---|---|
| Safety snapshot (§0) | git rev-parse / status / stash / for-each-ref / cache hash / V11 read-only | branch feature @ `0929dbd` exact (expected HEAD match); parent `74c4515` ancestor ✓; stash 1 preserved; cache `c494b680ecd32280`; V11 `889170a` / `fix/report-integrity` untouched; snapshot file preserved **[REPRODUCED]** |
| F-CDX16-R4 preservation | byte diff pre-edit copy vs appended report | first 174 lines byte-identical; sha256 pre-edit recorded (`c514d9c75691e213`); all 3 fingerprints verified in cited sources; 8/8 path checks PASS **[REPRODUCED]** |
| F-CDX16-R5 comment-only | full diff + py_compile + pre/post suites | diff = docstring + 2 comment headers only (+12/−6); py_compile exit 0; suites 56 passed pre AND post identical; `git diff --check` clean **[REPRODUCED]** |
| F-CDX16-R9 body integrity | byte diff pre-edit copy | exactly 6 header lines changed (Last-updated + dated note + HEAD line); all body sections identical; `1bcd061` identified as the 2026-11-12 R2.1e tip; all cited refs resolve **[REPRODUCED]** |
| B-3 history integrity | git log scan + parent check | exactly 1 mangled subject across `889170a..HEAD`; zero UTF-8 `§` subjects; `3fbc317` parent `5f32431` exact; no history operation **[REPRODUCED]** |
| B-6 closure | read of cited passages | correction present at `R2_5_1_FINAL_REVIEW.md:78-84,161`; original wording intact at `R2_5_1_REMEDIATION_REPORT.md:22` **[PRESERVED]** |
| B-2 probe | synthetic fixture extraction (isolated, repo untouched) | platform+`(n)`-parent child emits `parent_requested_version: ""` (red reproduced); contrast shapes clean; real corpora 0 occurrences (mockito 106 + micrometer 547 ×2 copies) **[REPRODUCED]** |
| B-4 study | 12-rep probe replicating S3/S5 (8 spinners, thread_time rows) | S3 worst max 171.9 ms (≥1.454× budget headroom), S5 max 46.9 ms (≥5.33×); 0 over-budget / 0 out-of-band across 12 reps; min band margin 3.1 ms; environment recorded; no defaults changed **[REPRODUCED]** |
| B-5 probes | isolated fixtures through gomod/cargo extractors | non-graph → `NO_VERIFIED_EDGES` (red); empty file → `NO_VERIFIED_EDGES` (correct); valid graph → `VERIFIED_EDGES_AVAILABLE` (correct); git child lacks child-source qualifiers (red); candidates `['d@1.0.0','d@1.0.0']` duplicated (red); oracle greps: oracle_go 0 envelope refs, oracle_cargo compares candidate lists **[REPRODUCED]** |
| B-7 fixtures + suites | 6 fixtures through membership parser + graph extractor; Ruby suites | cases 1/3/5 red (GIT/PATH/PLUGIN gems skipped); case 6 anti-misclassification pinned; graph reference shows git/path source_kinds; `pytest test_gemfile_lock_classification.py test_lock_graph_rubygems.py test_g7_ruby_solidity_20261023.py` = **56 passed / 0 failed / 0 skipped** **[REPRODUCED]** |
| Full regression | documented command `python -m pytest tests/ -q --tb=no -rf` | **27 failed / 5,089 passed / 66 skipped** in 1780.87 s (29:40), exit 1 (baseline-normal); **failure identities 27/27 byte-identical (`f62c7e25`)** via normalized comparator (COMPARE_EXIT=0); count reconciliation exact: 5,085 + 1 (DEV-1 test, `d695aa2`) + 3 (R2/R3 tests, `74c4515`) = 5,089 — first full-suite run carrying the 4 new tests (previously `[NOT-EXECUTED]` per V-035) **[REPRODUCED]** |
| Regression side effects | status enumeration + cache hash | only tracked modification = `M data/.vuln_cache.json` (scan-driven refresh `c494b680ecd32280` → `56581588bc89bd5d`, rule-permitted); no test/source/schema path modified; +3 status entries = this session's own evidence dirs (no pytest scratch) **[REPRODUCED]** |
| Publication assessment | read-only git (no fetch) | feature ahead 8 / behind 0 of recorded tracking ref (`f100e3e`); tracking ref is strict ancestor (clean FF); all 8 commits scope-verified; no fetch/push/tag performed **[REPRODUCED]** |
| Protected state (final) | status / stash / V11 / remotes | tracked set unchanged (cache only); stash 1 intact; V11 `889170a` untouched; no remote operation at any point **[REPRODUCED]** |
| Exclusions honored | review of executed actions | project R3 not started; B-1 skip flipper not reopened; F-CDX16-R3 (test finding) distinct from project R3 — untouched post-acceptance **[PRESERVED]** |
| Verdict | — | **ALL OVERNIGHT GATES PASS; BASELINE-IDENTICAL REGRESSION; NO UNAUTHORIZED CHANGE.** Documentation commits `77f21f4`/`dbe1f3c`/`b8df396`/`40c0b4b` validated; B-2/B-5/B-7 implementation and B-4 disclosure note remain separately gated; publication NOT performed |
