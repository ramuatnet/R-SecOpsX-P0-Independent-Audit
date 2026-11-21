# PROJECT_DECISION_LOG.md

Maintained per session-context rule 4. One entry per decision or ruling;
newest last. Facts vs assumptions vs recommendations are labeled.

---

## D-001 · 2026-11-11 · Session policy adopted

Message-optimization and engineering-discipline policy (PART A of the
session policy message) adopted as permanent project policy; acknowledged
once and applied thereafter.

## D-002 · 2026-11-11 · R1 proposal review verdict: APPROVABLE WITH FOUR REVISIONS

**Type: recommendation (awaiting user ruling).** Full review:
`R1_PROPOSAL_TECHNICAL_REVIEW.md`. The four revisions:

1. W1 must handle four endpoint classes (registry, `__root__`,
   workspace/file, unresolvable), not only `%40` encoding.
2. W2 provenance entries for populated fields must be reason/source-only —
   `value_state.resolve()` (`core/value_state.py:203-233`) lets a provenance
   `state` override the ladder.
3. W3 scope limited to GEM-section stamping; GIT/PATH/PLUGIN specs are not
   collected today (`gemfile_lock.py:46-47`) — disclosed, registered as
   follow-up, not silently fixed.
4. NodeGoat payload edge duplication (3,856 = 2 × 1,928) is a corpus artifact
   (same `package-lock.json` present twice in the extracted tree), not an
   engine defect — corpus documentation note only.

Recommended implementation order: W1 → W3 → W2.

**Open approval points for the user:** (a) W1 root-endpoint mapping — default
keep the deliberate synthetic `pkg:npm/__root__` component, alternative map to
`metadata.component`; (b) W3 GIT/PATH follow-up registration; (c) branch
`fix/r1-identity-purl` off `dcc5146`, three commits, no merge/push.

## D-003 · 2026-11-11 · Handover/ledger files created

`PROJECT_SESSION_HANDOVER.md`, `PROJECT_DECISION_LOG.md` (this file),
`PROJECT_VALIDATION_LEDGER.md` created under rule 4; handover updated with
the R1 review milestone.

## D-004 · 2026-11-11 · R1 implemented on `fix/r1-identity-purl` (approved)

Approval received with design decisions: W1 resolve all four endpoint classes
+ root maps to `metadata.component`; W3 DEPENDENCIES-authoritative, no
indentation signal, GIT/PATH/PLUGIN registered as follow-up gap; W2 parent
provenance from existing edge fingerprints/sources, gate/join contracts
untouched, no root-to-package conflation. Controls honored: branch off
`dcc5146`, three separate commits, red-first, no merge/push.

Commits: W1 `bd14809`, W3 `320e6cd`, W2 `c350b07`.

Facts corrected during implementation (disclosed per ground rule 7):
- GAP-04's claimed `%40`-encoding mismatch does not exist at the exporter
  (it has its own raw `_purl`); GAP-04's real content is endpoint resolution.
- A reason-only provenance entry on a placeholder/absent field flips
  `resolve()` ABSENT -> UNKNOWN-with-reason (ladder step 4). No renderer
  resolves the W2 fields today (version/fixed_versions/severity only), so no
  rendered cell changes; disclosed and pinned by tests.
- The Gemfile direct delta measured: railsgoat 197 direct -> 52 direct /
  145 transitive.

## D-005 · 2026-11-11 · Follow-up gap registered: GIT/PATH/PLUGIN Gemfile sources

Per R1 approval, GIT/PATH/PLUGIN section specs are not collected by
`gemfile_lock.py` (pre-existing); declared-but-unresolved gems surface in the
parser's log disclosure. NOT implemented in R1; candidate for a later phase
(natural home: R2 extractor work).

## D-006 · 2026-11-12 · Task 6 integration-readiness validation performed

Validation-only task (no source/test changes). Phases:
- A: ancestry verified — single linear chain 889170a -> 8c7e036 -> d39b2aa ->
  dcc5146 -> bd14809 -> 320e6cd -> c350b07 (each commit exactly one parent);
  per-commit file inventories match declared scope; worktree unchanged except
  the pre-existing cache files.
- B: five-way evidence distinction holds on artifacts (no path >2 hops, no
  __root__ in any path, every parent stamp fingerprint+source-paired,
  reason-only parent provenance, candidates quarantined and unclaimed).
- C: R1 checks green (root->metadata.component, stable refs, 0 dangling,
  DEPENDENCIES classification reproduced 52/145 on railsgoat, provenance
  reason-only, renderers resolve version/fixed_versions/severity only).
- D: INDEPENDENT edge oracle (fresh resolution logic, no engine import):
  0 wrong / 0 invented / 0 missing / 0 root mismatches / 0 unbacked join
  stamps on NodeGoat.
- E: cross-format consistency PASS on NodeGoat + juice-shop (JSON/CDX/SPDX/
  Excel/PDF; HTML triage with --html-embedded); two pre-existing renderer
  behaviors DISCLOSED as not-R1 (Excel introduced_by parent cells 727 =
  681+46, identical on the dcc5146 baseline artifact; Excel full-word Type).
- F: full regression 4,794/27/67, failure identities 27/27 identical to
  baseline and to the R1 run.

## D-007 · 2026-11-12 · Pre-existing renderer semantics recorded (not defects)

Excel SBOM sheet: (1) renders full-word Type (Direct/Transitive) — the D/T
letters are the PDF's rendering; (2) Parent cell renders the definitive join
parent OR the direct row's introduced_by (file-path evidence), identical
behavior on the dcc5146 baseline artifact; (3) appends Legend/EPSS note rows
below the table. All three pre-date R1; none were changed.

## D-008 · 2026-11-12 · Controlled integration executed (approved)

Approval covered ISOLATED integration only. Execution:
- Pre-flight: `dcc5146` verified as direct ancestor of `c350b07` with exactly
  3 commits between -> fast-forward integrates the IDENTICAL validated hashes
  (no merge commit, zero conflict surface, byte-identical tree).
- `git branch integration/dependency-evidence-r1 dcc5146`; checked out;
  `git merge --ff-only c350b07` -> HEAD == c350b0711c277bf4a08f81c3081234d13f48cbae.
- Recoverable references: annotated tag `r1-validated-20261112` @ c350b07;
  source branch `fix/r1-identity-purl` untouched @ c350b07.
- Combined diff dcc5146..HEAD: +897/-65 across exactly the 10 declared files
  (7 source + 3 new test files + value_state guard).
- Dirty/untracked worktree state preserved through checkout.
- No push; no merge into any fix/* or main branch; production integration
  requires separate approval.

Rationale (recorded for audit): a --no-ff merge would have minted a new,
never-validated merge hash; fast-forward reproduces exactly the commits Task 6
validated, making the integrated state byte-identical to the validated state.

## D-009 · 2026-11-12 · R2.0 planning delivered — awaiting phase approval

R2 master prompt received; R2.0 executed as planning-only (no branch, no code,
no merge/push). Seven deliverables: R2_{ARCHITECTURE_ASSESSMENT,
ECOSYSTEM_COVERAGE_MATRIX, GRAPH_CONTRACT, TEST_BENCHMARK_STRATEGY,
GAP_REGISTER, ROADMAP, EXECUTIVE_SUMMARY}.md.

Key verified findings (facts, not assumptions):
- The join's matching mechanics are ecosystem-agnostic; only the gate and npm
  id parsing are npm-specific — R2 extends, never forks.
- main.py's discovery/merge/join/provenance flow is already generic.
- Evidence tiers established from real corpus samples: exact-resolved (pnpm,
  NuGet), constraint-resolvable (Poetry, uv, Yarn, Cargo, Ruby),
  resolved-evidence-required (Maven, Gradle, Go full graph), membership-only
  (Pipfile.lock — verified edges impossible from the format; UNSUPPORTED
  disclosure planned, never guessed).
- Real corpus present for 7 ecosystems; pnpm/Cargo/.NET/Pipenv/Gradle-lockfile
  have no real sample in-workspace (synthetic fixtures documented).
- tomllib (stdlib) + PyYAML 6.0.3 available; no new dependencies needed.

Open approval points: roadmap R2.1-R2.6 scope, contract as proposed, branch
`feature/r2-multiecosystem-graph` creation off `c350b07`.

## D-010 · 2026-11-12 · R2.0 approved; R2.1 implemented on `feature/r2-multiecosystem-graph`

Approval received for the common graph contract, the R2.1-R2.6 roadmap, and
branch creation. Architectural decisions approved: four-tier evidence model;
constraint-resolvable -> VERIFIED only on unambiguous match; AMBIGUOUS stays
explicit; membership-only formats never fabricate; npm behavior preserved;
single PURL authority and join reused; relationships separate from
reachability.

Branch `feature/r2-multiecosystem-graph` created off `c350b07`.
Commits: R2.1a `b179eb5` (contract + registry + npm adapter + multi-ecosystem
join + main.py dispatch + Pipenv disclosure), R2.1b `1170ad8` (Poetry
extractor + oracle), R2.1c `1394837` (uv extractor + oracle).

Facts established during implementation (disclosed per ground rule 7):
- The `packaging` distribution is NOT available -> the constraint matcher is
  self-contained; unparseable constraints refuse honestly (UNRESOLVED).
- Real-corpus shapes handled after oracle cross-validation: `||` unions
  (pylint->isort), LIST-alternative declarations (dill), extras-in-marker
  (uv/flask: marker = "extra == 'async'").
- Contract change approved in R2.0: the join is ecosystem-SCOPED — an npm
  edge can never stamp a PyPI record; PyPI rows with no pypi edges count as
  unmatched (previously skipped_non_npm). Task 3's join test updated to the
  approved semantics in the same commit (security property preserved
  structurally).

## D-011 · 2026-11-12 · versions.py approximation disclosed

Pre-release suffixes (`1.0.0rc1`, `3.4.0-dev0`) compare as their numeric
release prefix (disclosed in the module docstring). Resolved lockfile pins
are exact in practice; a suffix-sensitive resolution would require full PEP
440 ordering and is deferred until a corpus demands it.

## D-012 · 2026-11-12 · R2.1 final review delivered (read-only) — R2.2-ready

One consolidated review (`R2_1_FINAL_REVIEW.md`), six areas, three Low
findings, none blocking:
- F-1 (Low): versions.py exact-`!=` branch returns True for an unparseable
  version (latent only — build_edge's purl guard prevents incorrect edges);
  one-line fix recommended in R2.2's first commit.
- F-2 (Low): PEP 503 normalization duplicated x3 (poetry/uv/join);
  consolidate at R2.2 start.
- F-3 (Low, process): validation instruments half-tracked in git
  (audit_output/staging committed, rest untracked); decide promote-to-tools/
  or untrack at R2.2 scoping.

Verdict: R2.1 accepted-quality, R2.2 READY FOR APPROVAL (with tiered
acceptance per GAP-R2-02/08). Review was read-only: no source/test changes,
no commits, no branch actions.

## D-013 · 2026-11-12 · R2.2 implemented — Maven/Gradle + R2.1-review remediations

R2.2 approved and delivered on `feature/r2-multiecosystem-graph`. Commits:
R2.2a `8977f77` (F-1 versions.py !=-branch fix + F-2 norm_pypi consolidation
+ F-3 instruments promoted to tools/), R2.2b `9cf3173` (Maven extractor +
real-evidence oracle), R2.2c `97328f3` (Gradle extractor + oracle),
R2.2d `2062c62` (Maven `(optional)` marker from real WebGoat evidence),
R2.2e `f79c202` (exporter delegates purls to scanner.purl — single
authority), R2.2f (FND-03 span compliance in the new extractors).

Decisions and facts:
- F-3 decision: validation instruments are FIRST-CLASS, tracked in tools/
  (oracle_poetry/uv/nodegoat/maven/gradle, crossformat_check); audit_output/
  remains the untracked evidence area.
- Maven real evidence: mvn 3.9.16 works OFFLINE; dependency:tree generated
  for BenchmarkJava (byte-equivalent to the committed 20260911 evidence —
  reproducible) and WebGoat; WebGoat's fresh tree exposed the real
  `(optional)` marker shape (fixed red-first, oracle re-validated 166/166).
- Gradle CLI absent: fixtures hand-authored (GAP-R2-08 tier honored).
- ARCHITECTURE DEFECT fixed (R2.2e): the exporter's private purl builder
  disagreed with scanner.purl for Maven — the exporter now delegates to the
  single authority. Disclosed behavior change: npm scoped bom-refs raw @ ->
  %40 (purl-spec-correct; 16 NodeGoat components); npm unscoped refs
  byte-identical; dependencies[] structure identical after scoped
  normalization.
- Maven sandbox scan (hand-authored pom membership rows + REAL tree
  evidence): join ecosystem-scoped matching verified; 0 dangling CDX refs
  with honest drop-and-count (project parents + children outside the 6-row
  SBOM; version-exact identity refuses a 2.3.3-vs-2.3.1 mismatch).
- FND-03 applies to ALL new analysis/ code — caught the Java extractors'
  slice bounds in full regression; fixed with WINDOW_6/60/80.

## D-014 · 2026-11-12 · Registry scope expansion (R2.2, approved)

Registry names now include Java resolved-evidence files
(dependency-tree.txt, gradle-dependencies.txt) AND the manifest files
(pom.xml, build.gradle, settings.gradle, gradle.lockfile) which answer with
disclosed UNSUPPORTED envelopes — manifests structurally never produce
edges (master prompt §7).

## D-015 · 2026-11-13 · R2.2 final review (read-only, pre-R2.3) — ACCEPTED-QUALITY, R2.3 READY WITH CONDITIONS

`audit_output/R2_2_FINAL_REVIEW.md` (D-015). All eight requested areas
verified independently: 6 commits/ancestry/inventory/R1 preservation;
Maven oracles 131/131+166/166 re-run PASS with evidence provenance proven
byte-identical to the committed 20260911 corpus artifact; mvn 3.9.16
offline regeneration reproduced byte-equivalent; Gradle fixture oracle
3/3 PASS; appendOutput-style multi-root per-root parsing verified (P6);
single-PURL-authority exporter isolated to exactly 4 scoped identities /
14 occurrences raw@->%40 with dependencies[] structure identical and join
identical on all keys (same-corpus fresh scan vs r21_bench artifact); npm
oracle 0/0/0/0 PASS; 30-vs-29 test reconciliation exact (30 defs added, 1
removed by rename, net +29 = passing delta); FND-03 span compliance
verified; full regression independently re-run 4,868/27/67 with failure
identities 27/27 identical three-way (baseline/delivery/rerun).
Findings: F-1 Medium latent (Gradle `(n)` -> VERIFIED edge, no
disclosure; docstring claims otherwise — gradle.py:78) + F-2..F-8
Low/cosmetic (conflict+`(*)` ordering incl. oracle mirroring; Maven
classifier=packaging qualifier on standard lines; source_location depth
inflation; console-capture EXTRACTION_ERROR constraint; staging tests
collision; cosmetics; "16 components" wording = 4 identities/14
occurrences). Conditions for R2.3: R-1 F-1/F-2 (+Maven verbose-marker
analogue) remediated red-first BEFORE any real Gradle evidence is trusted
(gates GAP-R2-08 closure, not R2.3 itself); R-2 single-authority
vocabulary + ecosystem-scoped join + npm byte-stability standing gates;
R-3 registry exact-filename + clean-evidence constraints carried into R2.3
disclosures. No remediation implemented — read-only review.

## D-016 — R2.3 final review (2026-11-13, read-only, V-012)

Verdict NOT_READY. Yarn v1 accepted-quality (24 tests covering all 16
mandatory classes; 4/4 real-corpus oracle PASS reproduced). pnpm NOT_READY:
F-R3-1 registry wiring uncommitted (dead code at HEAD); F-R3-2 v5.4
silently zero edges; F-R3-3 sentinel ''/None mismatch killed fallback and
mangled miss edges; F-R3-4 FND-03 pnpm.py:65; F-R3-5 no pnpm tests;
F-R3-6 oracle mis-modeled non-registry parents and mis-directed
cross-format gates; F-R3-7 no delivery report/ledgers, commit messages
overclaimed; F-R3-8 tarball-parent disclosure absent; F-R3-9 pnpm evidence
tier = tool-generated (pnpm import), project-committed NOT_ESTABLISHED.
Regression 4,890/29/67 with 27/27 baseline identities + 2 R2.3-attributable
new. Gradle F-1 prerequisite preserved. Corrections of record: yarn tests
are 24 (not 48); no pnpm oracle PASS existed pre-remediation.

## D-017 — R2.3 bounded pnpm remediation authorized and delivered (2026-11-14)

User authorized remediation of F-R3-1..F-R3-7 only. Delivered on
feature/r2-multiecosystem-graph as f3ea13a / eb4710b / f38b7d8 (no
rewrites; R1/R2.1/R2.2 preserved; Yarn untouched). Red-first: 12/33 new
pnpm tests failed at f2345a2 before the fixes. All 11 acceptance gates
PASS, including full regression 4,927/27/67 with 27/27 baseline identity
parity (0 new), exact test-count reconciliation (+35 defs +2 fixed =
+37), clean-checkout reproduction (71/71), npm byte-stability, and
independent oracle PASS 1365/1365 on the tool-generated v9.0 real
evidence. Deliverable: R2_3_PNPM_REMEDIATION_REPORT.md; ledgers updated
with actual evidence. Verdict: R2.3 READY; R2.4 requires separate
approval; do not merge or push.

## D-018 — R2.4 Go + Rust verified dependency graphs delivered (2026-11-14)

User approved R2.4 after accepting R2.3 (post-remediation). Delivered on
feature/r2-multiecosystem-graph as ad93e5e (R2.4a Go) and 952ab20
(R2.4b Rust); established extractors/contract/versions/join/npm engine
untouched. Go: three evidence tiers (go mod graph resolved edges;
go.mod declarations disclosed never edges; go.sum membership only --
approved constraint honored structurally), escaped-path decoding, /v2 and
+incompatible verbatim, replacements (local vs module) as substitution
evidence. Rust: Cargo.lock formats 1-4 resolved edges with source-hint
disambiguation and AMBIGUOUS versionless entries, registry/git/path
provenance, scope=unknown (kinds/targets need cargo metadata, disclosed);
Cargo.toml declarations disclosed never edges. Real-corpus oracles: Go
11/11 files PASS (crAPI, wrongsecrets), Cargo 6/6 files PASS (project
format-4 lock 125/125 VERIFIED; argip workspace tallies). Full regression
4,965/27/67, failure identities 27/27 identical (0 new), reconciliation
exact (+38 defs). Clean-checkout 109/109. GAP-R2-08 unchanged (no go/cargo
CLIs -- graph/metadata artifacts not generatable here; disclosed).
Verdict: R2.4 COMPLETE; R2.5 requires separate approval; no merge/push.

## D-019 — R2.5 Ruby/Bundler + .NET/NuGet verified dependency graphs delivered (2026-11-14)

User approved R2.5 after accepting the R2.4 final review. Delivered on
feature/r2-multiecosystem-graph as f4e7dca (R2.5a Ruby) and fa27704
(R2.5b .NET); registry.py is the only modified existing file. Ruby:
Gemfile.lock specs blocks are the resolved universe with parent-child
declarations (GEM/GIT/PATH provenance on edges; DEPENDENCIES/PLATFORMS
tallied never edges); the R1/W3 GAP-09 membership fix was inspected and
NOT duplicated. Ruby dialect mapped locally: pessimistic '~>' bumps the
second-to-last segment (real corpus revealed multi-clause conjunctions
and 4-segment pessimistic forms — both handled and oracle-validated).
.NET: packages.lock.json/project.assets.json targets = resolved restore
state (exact identities; AMBIGUOUS structurally absent; project refs
skipped; restore types tallied); packages.config membership only;
Directory.Packages.props CPM catalog tallied; csproj arbitrary-named ->
membership-parser territory (disclosed). Real-corpus oracles: Ruby 4/4
(railsgoat 246 edges 232V/10A/4U exact), .NET 3/3 (semantic-kernel CPM
200, autogen 112, packages.config 2). Full regression 5,002/27/67,
identities 27/27 identical (0 new), reconciliation exact (+37 defs).
Clean-checkout 145/145. npm byte-stability unchanged. Survey established
0 real packages.lock.json/project.assets.json in corpus (lock tiers
fixture-disclosed). Verdict: R2.5 COMPLETE; R2.6 requires separate
approval; no merge/push.

## D-020 — R2.5.1 bounded Ruby/Bundler remediation delivered (2026-11-14)

User approved remediation of exactly F-R5-1/2/3 after conditionally
accepting the R2.5 final review. Mandated SEPARATE branch:
fix/r251-ruby-defects from fa27704 (R2.5 commits preserved on
feature/r2-multiecosystem-graph). Single commit cc28ddb; red-first (7
tests failed pre-fix). Root causes: PLUGIN missing from the provenance
dict (KeyError); version-only universe discarding per-instance section
provenance; numeric-prefix approximation applied to exact platform
constraints. Fixes: PLUGIN -> source_kind=plugin; per-instance universe
with child_source_kind/child_source/child_revision disclosure (comma-
joined for multi-section resolution); verbatim instance matching for
exact non-numeric constraints with NO fallback (absent variant ->
NO_MATCHING_VERSION). versions.py untouched (local resolution policy,
justified: platform-variant selection is Bundler identity semantics).
Oracle implements the verbatim rule independently. Validation: 28/28
ruby, 265 targeted, railsgoat oracle PASS 4/4 with 232 VERIFIED edges now
carrying child provenance and identity/confidence results unchanged,
full regression 5,009/27/67 identities 27/27 identical (0 new),
reconciliation exact (+7), npm byte-stability unchanged. All five
acceptance criteria PASS. Verdict: R2.5.1 delivered; R2.6 requires
separate approval; no merge/push.

## D-021 — R2.5.1 accepted; controlled FF integration; R2.6 proposal (2026-11-15)

R2.5.1 final review accepted (V-015). User approved integrating
fix/r251-ruby-defects into feature/r2-multiecosystem-graph. Pre-integration
verified: cc28ddb8562563ca… with direct parent fa277047e…; exactly ONE
commit on the branch; FF possible; tag intact; dirty preserved. Integrated
via git merge --ff-only (NO merge commit). Post-integration: feature HEAD
== cc28ddb8562563ca… exactly; source/destination trees identical (0-diff);
265 targeted passed; npm byte-stability unchanged (682e6cae); full
regression 5,009/27/67 with failure identities 27/27 identical to the
established baseline (0 new, 0 gone); reconciliation exact. fix/r251-
ruby-defects still points at cc28ddb (disposition = separate approval).
R2.6 PROPOSAL delivered (R2_6_PROPOSAL.md): cross-ecosystem integration
validation per the approved R2.0 roadmap §R2.6 — multi-ecosystem
synthetic tree, real-benchmark re-scans with per-ecosystem join tallies,
cross-format sweep, §10 payload-capability checks, R2.0 §9 acceptance
verbatim; validation-only by design (no extractor/contract/join changes).
No push. R2.6 implementation awaits separate approval of the proposal.

## D-022 — R2.6 cross-ecosystem integration validation delivered (2026-11-15)

User formally approved R2.6 as a validation-only phase (five workstreams
W1-W5, strict change-control: no extractor/contract/join/npm/report
changes, no new dependencies, no refactors; defects -> separate
remediation approval). Executed at HEAD cc28ddb8562563ca on
feature/r2-multiecosystem-graph with zero commits, zero merges, zero
pushes; all instruments kept outside production source and test paths
(audit_output/r26/). Deliverable: R2_6_FINAL_INTEGRATION_REPORT.md
(V-016). Results: W1 synthetic 11-format single-walk tree vs independent
hand-authored expected graph = 42/43 correct, 0 missing, 0 invented, 1
disclosed discordance = registered latent F-1 (Gradle (n) -> VERIFIED,
reconfirmed, NOT fixed under validation-only); deterministic
(run2==run3); no cross-ecosystem contamination; provenance preserved;
ambiguous candidates fully disclosed. W2: 21 real/tool-generated
benchmarks re-scanned through the FULL pipeline; every R2.1-R2.5.1
baseline reconciled EXACTLY (NodeGoat 681/277/77/14 + 1091 sbom;
pnpm 1365; Yarn 1114/1045/2309/3794; Poetry 90; uv 8; Maven 131/166;
railsgoat 246=232V/10A/4U + sbom 197; CPM 200/112; Rust 125/65; corpus
1/2/3; argip 17 inherited); every delta explained (dual-evidence join
shift on pnpm probe; per-unique-identity membership dedup on
wrongsecrets; new semkernel npm/yarn measurements have no prior
baseline). W3: 24 payloads swept with the committed Task 6 checker +
R2.6 additions; zero non-PDF failures; JSON=CDX=SPDX counts exact; PDF
tier demonstrated on the 3 full-format payloads (20 W2 scans ran
--no-pdf by disclosed instrument choice). W4: all 10 payload
capabilities demonstrated (capability, not accuracy; RCMSP untouched).
W5: targeted 258+8 green (historical 265 composition not recorded
verbatim; count pinned by the regression total); full regression
5,009/27/67 with failure identities 27/27 byte-identical to baseline;
npm byte-stability re-proven vs the stored R2.3 artifact (1928 edges,
canonical-identical, fingerprints identical). No new defects; only
instrument corrections (DVAP target, maven evidence naming, ruby
fixture bare-pin). All standing limitations preserved, none upgraded.
VERDICT: R2.6 COMPLETE, ACCEPTED as delivered evidence; R2 roadmap
R2.1-R2.6 fully closed. Stopping; R3 / production integration / branch
dispositions require separate explicit approval.

## D-023 — R2.6.1 bounded Gradle (n) remediation delivered (2026-11-15)

User adjudicated R2.6 (W1 = PASS_WITH_DISCLOSED_EXCEPTION; acceptance
wording corrected as documented-exception) and mandated the bounded
Gradle (n) remediation. Executed on SEPARATE branch
fix/r261-gradle-n-marker from cc28ddb: single commit 6dc55661daa8eaf693
65076ea1d9ddd7a3e8bed7 (3 files: analysis/lock_graph/gradle.py,
tests/test_lock_graph_gradle.py, tools/oracle_gradle.py; contract/join/
PURL/npm/other extractors/RCMSP untouched). Root cause
gradle.py:78 _parse_node stripped (n) into a resolved version; corrected
semantics: (n) = requested-not-resolved (UNRESOLVED,
GRADLE_VERSION_NOT_RESOLVED, no fingerprint, child-or-parent side, no
promotion), (c) = constraint-selected resolved (VERIFIED +
constraint_selected qualifier), missing '->' selection follows (n).
Red-first: 8 new tests ALL failed pre-fix (8 failed/12 passed at
cc28ddb); 20/20 post-fix. Oracle rewritten with independently derived
semantics: post-fix comprehensive fixture PASS (4V+3U, 0
wrong/missing/mismatch); oracle now REJECTS the pre-fix W1 payload
(exit 1) -- shared assumption proven gone. Post-fix full-pipeline W1
comparison: 43/43 correct, 0 wrong (F-1 remediated end-to-end).
Consumers verified VERIFIED-only (CDX cyclonedx_export.py:584, SPDX
spdx_export.py:433+, join) so no fabricated relationship can reach any
format. Full regression: 27 failed / 5,017 passed / 67 skipped (25:11),
failure identities 27/27 byte-identical (f62c7e25), reconciliation
exact (5,009+8=5,017). npm byte-stability unchanged (67e638d8 vs stored
artifact). FND-03: the 4 span-layer failures are the registered
baseline identities; gradle span usage untouched. Phase G: gradle CLI
absent; spring-petclinic wrapper (gradle-9.5.1) + JDK 21 present; real
evidence DEFERRED (wrapper download = install, requires approval; exact
future command recorded). Final status ACCEPTED_WITH_DISCLOSED_LIMITATIONS.
Deliverables: R2_6_1_GRADLE_REMEDIATION_REPORT.md,
R2_6_1_TEST_RECONCILIATION.md, R2_6_1_ORACLE_VALIDATION.md,
R2_6_1_REGRESSION_REPORT.md. NOT merged; integration/push/R3 require
separate approval.

---

## D-024 · 2026-11-15 · Overnight execution authorized (cztask.md)

FACTS: cztask.md (authorization addendum) authorizes A1 F-R3 implementation
(branch `fix/fr3-thread-cpu-budget`) and A2 real-Gradle evidence (branch
`evidence/real-gradle-validation`), from integrated baseline `3d1ec9c`.
Approval boundaries unchanged: no FF integration of either branch, no push,
no production, no R3, no out-of-scope changes. Persistent ledger required
(OVERNIGHT_EXECUTION_STATE.md). This entry records the AUTHORIZATION;
execution entries follow.

## D-025 · 2026-11-15 · A1 F-R3 implemented and validated (3563a0e)

FACTS: commit `3563a0eae4e50857e7e0cf547382bd4f97186d0f` on
`fix/fr3-thread-cpu-budget` (parent `3d1ec9c`, FF-able), exactly two files
(core/regex_budget.py +28/−9, tests/test_redos_budget.py +401 additive):
`time.thread_time()` at all six measurement lines; docstrings disclose
per-thread semantics (F-R3). Red-first matrix: 12 scenarios, one per approved
proposal §5 row; pre-fix red run 4 red (S2 band, S3 decisive 9 rows over
250 ms budget worst 1343.75 ms, S5 per-row, S7 structural pin) / 8 green —
matches the proposal's red expectations. Evidence-based deviations disclosed
(S9 asserts calibrated 15.625 ms GetThreadTimes tick — proposal's sub-ms
resolution claim did not reproduce on 3.14.3/win32; S2/S3/S5 use the
multi-rule acceptance-shape window because single-rule windows do not
reliably contaminate on this machine (calibration evidence); S7 upgraded to
red-capable pin; S4 rewritten v1→v2 during implementation after a
deterministic-flake observation). All gates green: redos module 25/25;
gradle 35/35; oracle two-direction (reject exit 1 / accept exit 0); W1 43/43;
npm byte-stability `67e638d8` byte-exact (content identical modulo source
path; hash reproduced with stored order+path substitution); downstream zero
leak; full regression 27/5,044/67 (5,032+12 exact, single run 24:06);
failure identities 27/27 byte-identical (f62c7e25). Deliverables:
FR3_IMPLEMENTATION_REPORT.md + fr3/REVIEW_PACKAGE.md + evidence under
audit_output/fr3/. NOT integrated; review must precede integration (cztask
§E). ASSUMPTION: none. RECOMMENDATION: independent review of 3563a0e, then
separate FF-integration approval.

## D-026 · 2026-11-15 · A2 real-Gradle evidence delivered (findings registered, not fixed)

FACTS: evidence branch `evidence/real-gradle-validation` @ `3d1ec9c` — zero
repository modifications. Real projects: mockito @ 10b31ba2 (wrapper Gradle
9.8.2, pinned distributionSha256Sum validated) and micrometer @ 9fb166aa
(wrapper Gradle 9.9.1); HikariCP/jacoco rejected (both Maven now). JDK
21.0.11. Commands `gradlew.bat --console=plain :mockito-core:dependencies` /
`:micrometer-core:dependencies`, both exit 0; raw reports preserved. Oracle:
mockito-core — extractor 101 VERIFIED / 5 UNRESOLVED vs oracle 103 expected:
0 WRONG, 2 MISSING; real (c) constraint semantics PASS (0 wrong/missing);
(n) depth-1-in-unresolvable-configuration consistency confirmed. micrometer-
core — extractor EXTRACTION_ERROR on the real no-left-version platform shape
`g:a -> v` (25 occurrences): 0 edges where the oracle reads 517 VERIFIED +
24 (c). FINDINGS (candidates, remediation needs separate approval): F-RG-1
Medium (conflict+elision `-> selected (*)` emitted UNRESOLVED with marker-
contaminated version; safe direction), F-RG-2 High (whole-file rejection on
`g:a -> v`), O-RG-1 Low (oracle tuple artifact), F-RG-3 Low (real (n)
semantics disclosure). CDX/SPDX/join: zero-leak, established-envelope
consistent (R2.6.2 probe shape), join npm-only by binding invariant.
Deliverable: REAL_GRADLE_EVIDENCE_REPORT.md + audit_output/real_gradle/.
NOT integrated; no broad coverage claims (2-project JVM-only sample).
RECOMMENDATION: independent review; F-RG-1/F-RG-2 remediation proposal as a
future R2.6.3-class task with the oracle correction paired in.

## D-027 · 2026-11-15 · Independent review verdicts: A1 + A2 ACCEPTED_WITH_DISCLOSED_LIMITATIONS

FACTS: review task executed read-only (zero source/test changes, zero commits).
FR3_INDEPENDENT_REVIEW.md — ACCEPTED_WITH_DISCLOSED_LIMITATIONS: all seven
verification points pass; NEW R-FR3-1 Medium (S2 band mis-calibrated, 3/5 probe
passes fail post-fix; calling-thread GIL-switch overhead reaches ~2.3x; the
implementation report's "≤~1.2x post-fix" claim corrected); R-FR3-2 Low. Fix
itself proven correct (six sites, no enforcement changes, identities 27/27
f62c7e25 reproduced independently). REAL_GRADLE_INDEPENDENT_REVIEW.md —
ACCEPTED_WITH_DISCLOSED_LIMITATIONS: F-RG-1/F-RG-2/O-RG-1 CONFIRMED;
real-(n) no-promotion CONFIRMED (0 (n) nodes at edge positions); CDX/SPDX/join
confirmed; precision correction recorded (oracle silently skips the 25
no-left-version lines; 54 skip-orphans misattributed as direct). Remediation
proposals delivered: F_RG_2 (priority 1) + F_RG_1 (priority 2) — NOT
implemented. RECOMMENDATION: (a) R-FR3-1 test-band correction (hygiene), (b)
FF of fix/fr3-thread-cpu-budget on review evidence (disclose R-FR3-1 until
corrected), (c) authorize F-RG-2 then F-RG-1 implementation. All
integration/push/production/R3 remain approval-gated.

## D-028 · 2026-11-16 · R-FR3-1 S2 stabilization delivered (972fbe3)

FACTS: cgptask2.md authorized the R-FR3-1 correction. Distribution study
(12+12 alternating passes) REJECTED the proposed 2.5xquiet+150 threshold
(6/12 pre-fix pass — pre-fix contamination ratio 1.96-3.53x overlaps post-fix
GIL-overhead ratio 0.90-1.73x at 1 spinner; no quiet-relative threshold can
separate). S2 redesigned v3 (disclosed rename to
test_fr3_s2_one_spinner_thread_envelope): load-adaptive envelope invariant
(recorded_total <= calling-thread thread_time delta + 300 ms; constants
calibrated from the measured distributions: post-fix excess [-31.2, +0.0] ms,
pre-fix [+671.9, +1390.6] ms) + spinner-activity floor (250 ms) + budget
preservation retained. The stale header claim "post-fix inflation <= ~1.2x"
corrected in the same commit. ALL gates green: S2 10/10 post-fix PASS, 10/10
pre-fix FAIL, module 25/25, gradle 35/35, oracle 2-direction, W1 43/43,
byte-stability 67e638d8, full regression 27/5,044/67 identities 27/27
(f62c7e25). Commit 972fbe3 on fix/fr3-s2-test-calibration (parent 3563a0e;
test file only, +101/−21). NOT merged; review-then-integrate applies.

## D-029 · 2026-11-16 · S2 v4 window-equivalence correction delivered (5f32431)

FACTS: The S2 v3 review (FR3_S2_INDEPENDENT_REVIEW.md) verdict REJECTED —
the mandatory 10/10 pre-fix-FAIL gate was not met (1/10 observed); root
cause quantified: `_run_js_rules` performed the cold
`from scanner import sast` inside the spinner/envelope window but outside
every rule row window, so GIL-lottery outcomes could hide pre-fix
contamination (excess cancels to ≈0). The authorized correction was
delivered on SEPARATE branch `fix/fr3-s2-window-equivalence` @ `5f32431`
(single commit from `972fbe3`; test file only, +110/−59):
(a) import hoisted to module scope (gap tt0→first row 0.00 ms in 24/24
calibration passes); (b) spinner CPU checkpointed in-window with floor
450 ms > 300 ms allowance (500 ms evaluated and REJECTED as flake-thin vs
the observed 500.0 ms battery minimum); (c) envelope/contamination
assertion ordered before the budget line; (d) vacuous-pass guard
(rows non-empty). Calibration 12+12: pre-fix excess [+515.6, +1234.4] ms
(0/12 pass) vs post-fix [−15.6, +0.0] ms (12/12 pass) — deterministic
separation, GIL-lottery dependence eliminated. Red-first validation 40/40
(standalone 10/10 pre-fix FAIL via the process-wide-contamination
assertion + 10/10 post-fix PASS; full-module 10/10 pre-fix — S2 red via
contamination, red set S2/S3/S5/S7 — + 10/10 post-fix 25 passed). Gates:
module 25/25, gradle 35/35, oracle two-direction, W1 43/43, byte-stability
67e638d8, full regression 27/5,044/67 (17:39) identities 27/27 (f62c7e25).
Deliverable FR3_S2_V4_CORRECTION_REPORT.md (evidence audit_output/fr3_s2_v4/).
NOT merged at delivery.

## D-030 · 2026-11-16 · S2 v4 independent review ACCEPTED

FACTS: FR3_S2_V4_INDEPENDENT_REVIEW.md — verdict **ACCEPTED** (read-only).
Window equivalence verified from committed code + runtime (gap tt0→first
row ≤ 0.098 ms over 50 instrumented runs; post-fix excess telescoping
[−31.2, +0.0] ms). Red-first reproduction 40/40 exact (20/20 pre-fix FAIL
standalone + module via the contamination assertion with clock=process_time
recorded; 20/20 post-fix PASS). Floor assessment n=50 (incl. 10 runs under
4 competing CPU burners): global in-window spinner min 484.4 ms → margin
34.4 ms (~2.2 ticks — slightly below the correction report's ≥3-tick
claim, non-blocking, fail-safe direction; margin widens under load to
687.5–921.9 ms); sabotaged-spinner negative control 3/3 FAIL on the floor
assertion (vacuous pass impossible). Hoist side-effects none (shared
_Spinner/_spinners byte-identical; rows never included import CPU). Gates
reproduced: module 25/25, gradle 35/35, oracle 2-direction, W1 43/43,
67e638d8, full regression 27/5,044/67 (19:24) identities 27/27 (f62c7e25).
Evidence audit_output/fr3_s2_v4_review/. The F-R3 line = `3563a0e` +
`972fbe3` + `5f32431`, all three commits reviewed ACCEPTED.

## D-031 · 2026-11-16 · F-R3 series FF integration executed (explicitly authorized)

FACTS: feature/r2-multiecosystem-graph fast-forwarded from `3d1ec9c` to
**`5f3243104aff76c4688b98db6182642dfb12f5ee`** (git merge --ff-only; NO
merge commit; trees identical). Preflight 9/9 PASS (refs, ancestry exactly
3 commits, review verdict ACCEPTED, diffs scoped 2-file/1-file/1-file,
dirty state recorded); post-verification 10/10 PASS (linear history,
6× thread_time / 0× process_time, hoist + boundaries intact, dirty state
byte-identical). Post-integration gates all green, NO deviations: ReDoS
25/25, gradle 35/35, oracle two-direction (exit 1/0), W1 43/43,
byte-stability 67e638d8 byte-exact, full regression 27/5,044/67 (23:48)
identities 27/27 byte-identical (f62c7e25), S2 v4 practical check 3/3
post-fix PASS + 1 pre-fix red via the contamination assertion (temp
worktree). Deliverable FR3_FAST_FORWARD_INTEGRATION_REPORT.md (evidence
audit_output/fr3_ff/). NO push. Residual pointers (dispositions = separate
approval): fix/fr3-s2-window-equivalence @ 5f32431, fix/fr3-s2-test-
calibration @ 972fbe3, fix/fr3-thread-cpu-budget @ 3563a0e.

## D-032 · 2026-11-16 · F-RG-2 implemented (3fbc317)

FACTS: F-RG-2 (Gradle platform/BOM-selected version shape) delivered per
the approved proposal F_RG_2_REMEDIATION_PROPOSAL.md on SEPARATE branch
`fix/rg2-platform-selected-version` @
`3fbc317dfbef917ca7205059f81bbbe33936a744` (single commit from integrated
baseline `5f32431`; exactly the 3 authorized files:
analysis/lock_graph/gradle.py +86/−15, tools/oracle_gradle.py +39/−15,
tests/test_lock_graph_gradle.py +341/−15). Semantics: 2-part arrow body
resolved at the selected version (VERIFIED + fingerprint +
version_selected_by_platform; requested version never invented; `(*)`
stripped on the platform path ONLY; the 3-part conflict path untouched —
F-RG-1 pinned open by test_frg2_s8_conflict_marker_semantics_untouched);
§5 hardening (unparseable leaf → invalid_nodes tally + limitation;
with-subtree → EXTRACTION_ERROR retained). Oracle paired: same platform
branch + skip-orphan sentinel (children of skipped/absent parents excluded
from `direct` — the 54-orphan defect) + two-direction proof. Red-first
11 red / 3 green (S1–S6, S9–S13 red; S7/S8/S14 preservation pins green).
Suite 49/49 (35 existing — 2 §5-sanctioned assertion updates — + 14 new).
Gates ALL green: mockito identity-IDENTICAL 106/106 with oracle side
unchanged (0 WRONG / 2 MISSING = F-RG-1); micrometer FIRST-EVER extraction
547 edges (493 VERIFIED, 24 unique (c), invalid_nodes 9, direct 305) with
oracle 0 WRONG + 23 MISSING 23/23 F-RG-1-combo-attributable, 0 unexplained
(agreement MODULO F-RG-1 — literal exit 0 unreachable without the
prohibited F-RG-1 work; disclosed); CDX/SPDX zero-leak both projects;
W1 43/43; byte-stability 67e638d8; full regression 27/5,058/67 (21:09)
identities 27/27 (f62c7e25; 5,044+14 exact). Deliverable
F_RG_2_IMPLEMENTATION_REPORT.md (evidence audit_output/frg2/). NOT
integrated at delivery; stopped for independent review.

## D-033 · 2026-11-16 · F-RG-2 independent review ACCEPTED

FACTS: FRG_2_INDEPENDENT_REVIEW.md — verdict **ACCEPTED** (read-only;
evidence audit_output/frg2_review/). All 12 requirements + special-scrutiny
items verified: scope/parent clean; platform branch purely additive
(3-part conflict path zero diff; mockito FULL payload byte-identical
pre/post); 0 fabricated requested_versions; full line accounting
1,710/1,710 (zero unaccounted); 25/25 previously-skipped platform lines
individually accounted (24 depth-1 direct + 1 depth-2 edge child); 54/54
skip-orphan model reproduced and resolved (0 orphan promoted: extractor
direct 305 == independent depth-1 count 305); 48 F-RG-1 combo lines → 23
MISSING identities 23/23 attributable (0 WRONG, 0 unexplained); (c)/(n)
exact both reports (24=24, 0=0, mockito 3=3); 9 (n)-without-arrow leaves
tallied+named with leaf-removal invariance byte-identical; the 2
malformed-test updates §5-faithful (no weakening); genuine two-direction
(pre-fix REAL output rejected naming the platform identity; partial
payload rejected; post-fix accepted); gates reproduced 49/49, W1 43/43,
67e638d8, full regression 27/5,058/67 (22:07) identities 27/27 (f62c7e25);
CDX/SPDX leak 0 both real projects. Findings (none blocking):
F-RG2-R1 Low (pre-existing oracle diagnostic [:5] truncation — counts/sets
complete, display truncated), F-RG2-R2 Low latent (empty-string
parent_requested_version for platform+not_resolved parents; 0 on real
corpora), F-RG2-R3 Info (commit-subject "§5" mangling). The review does
not authorize merge/FF/push/production/F-RG-1/R3.

## D-034 · 2026-11-16 · F-RG-2 FF integration executed (explicitly authorized)

FACTS: User authorization received (this session) for exactly two
activities: F-RG-2 local FF integration + project-ledger synchronization.
Boundaries: no push, no production, no F-RG-1, no R3, no unrelated code or
test modifications, no reset/clean/stash/rebase/cherry-pick; stop and
report on any FF or gate failure.

Preflight (revalidated immediately before execution): worktree HEAD
`3fbc317dfbef917ca7205059f81bbbe33936a744` on
fix/rg2-platform-selected-version; `3fbc317`'s parent ==
`5f3243104aff76c4688b98db6182642dfb12f5ee` (direct); rev-list feature..fix
= 1 (FF possible); R1 tag r1-validated-20261112 → c350b07 intact; dirty
state = the pre-existing 7 entries.

Execution: git checkout feature/r2-multiecosystem-graph && git merge
--ff-only fix/rg2-platform-selected-version → "Updating 5f32431..3fbc317 /
Fast-forward" (exit 0, NO merge commit). Post-FF: HEAD ==
`3fbc317dfbef917ca7205059f81bbbe33936a744` on
feature/r2-multiecosystem-graph; tree-identity diff vs `3fbc317` = 0
lines; rev-list `5f32431`..HEAD = 1 (linear; no unrelated commits); change
set exactly 3 files +451/−15; F-R3 series intact at the integrated state
(6× time.thread_time() / 0× time.process_time in core/regex_budget.py).

Post-integration gates ALL GREEN (evidence audit_output/frg2_ff/):
- gradle suite 49/49; ReDoS module 25/25.
- Targeted gates 13/13 checks PASS: oracle two-direction (stored pre-fix
  payload rejected exit 1; fresh extraction accepted exit 0); W1 43/43
  (0 wrong/missing/invented); npm double-run identical (3856), dedup 1928
  == stored, fingerprint sets 1:1, content byte-identical modulo source
  path, canonical hash `67e638d8` byte-exact; W1 payload 0 CDX gradle
  entries + 0 SPDX gradle relationships; probe constraint edge unchanged
  (UNRESOLVED / GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY).
- Real-report oracle re-run at the integrated HEAD: mockito-core
  identity-IDENTICAL 106/106 vs the A2 pre-fix extraction (oracle 0 WRONG
  / 2 MISSING = the unchanged F-RG-1 pair); micrometer-core 547 edges
  (493 VERIFIED, invalid_nodes 9, direct 305) with 0 WRONG (VERIFIED),
  0 (c)/(n) wrong-or-missing, 0 constraint-confidence mismatches, all
  MISSING F-RG-1-combo-attributable (visible tuples 5/5 attributable; the
  23-identity attribution per the review's module-API recomputation —
  code path unchanged at the integrated tree), script exit 0.
- Full regression: 27 failed / 5,058 passed / 67 skipped (24:45, exit 1 =
  the registered baseline failures); failure identities 27/27, sha256
  f62c7e25, byte-identical to both stored baselines (h1_ff and frg2
  delivery).

Worktree preserved byte-identical through checkout and all runs (the
pre-existing M data/.vuln_cache.json + 6 untracked entries; no
reset/clean/stash). fix/rg2-platform-selected-version remains a residual
pointer at `3fbc317` (disposition = separate approval). Deliverable:
F_RG_2_FAST_FORWARD_INTEGRATION_REPORT.md. NO push; NO production
movement. F-RG-1 remediation, hygiene/evidence-establishment batch,
production/push, and R3 all await separate approval.

## D-035 · 2026-11-16 · Overnight plan executed (nov16task.md): preflight + F-RG-1 preparation + hygiene triage + evidence establishment — F-RG-1 implementation gate HELD

FACTS: nov16task.md (overnight autonomous engineering plan, 2026-11-16)
authorized §1 preflight (baseline recheck), §2 F-RG-1 preparation behind
an explicit authorization gate, §3 hygiene triage/proposals, §4 evidence
establishment (read-only), §5 gates, §7 no push/production, §8 ledger
sync, §9 master report. **Gate determination (nov16task §2): NO F-RG-1
implementation authorization exists** — the task instructions phrase
implementation conditionally ("### If explicitly authorized") and the
decision ledger D-001..D-034 contains no authorizing entry (D-027
delivered proposals NOT implemented; D-033 records the review's
non-authorization; D-034's boundaries exclude F-RG-1) → preparation only;
`F_RG_1_OVERNIGHT_READINESS_REPORT.md` delivered with status
**READY_FOR_AUTHORIZATION** (proposal verified current at `3fbc317`;
verbatim mockito/micrometer fixtures preserved; 8-scenario red-first
matrix designed incl. the F-RG-2 compatibility pin; branch-name
discrepancy proposal-vs-taskfile disclosed). **Zero source/test/fixture
changes; zero commits; zero branches created** by the overnight run.
Hygiene triage delivered (OVERNIGHT_HYGIENE_EVIDENCE_TRIAGE.md +
OVERNIGHT_REMEDIATION_BACKLOG.md, backlog B-1..B-8): all eight known
items located with exact code/report evidence (oracle_gradle.py:253-262
[:5] slices; gradle.py:337-338 parent_requested_version path;
test_redos_budget.py:563/616; gomod.py envelope vocabulary + child
provenance; cargo.py candidate duplicates; R2_5_1 report wording;
scanner/manifests/gemfile_lock.py section handling; GAP-13);
classifications recorded; **zero unambiguous documentation-only
corrections qualified** (GAP-13 blocked on the protected repo;
F-R5-1R closed by the historical-record convention); nothing implemented.
Evidence establishment delivered (OVERNIGHT_EVIDENCE_ESTABLISHMENT_REPORT.md):
pnpm NOT_ESTABLISHED (CLI present 11.10.0; zero project-committed locks
in corpus); Go graph NOT_GENERATABLE (no CLI); Cargo metadata
NOT_GENERATABLE (rustup shim present, NO default toolchain — record
refined); .NET NOT_GENERATABLE/NOT_ESTABLISHED (no SDK, zero real locks);
Gradle third-project capture NOT_RUN (protected-repo write or wrapper
download required); preserved mockito/micrometer evidence hash-recorded.
Independent agent verification (read-only, separate agent): **CONSISTENT,
20/20 claims PASS** across toolchain/hash/survey/code-line/preflight/
fixture/gate/git groups. Full gates reproduced once (V-027) + end-state
spot verification (V-028). ASSUMPTIONS: none. RECOMMENDATION: authorize
F-RG-1 implementation (priority 2; proposal + readiness package
complete). NO push; NO production; NO R3.

## D-036 · 2026-11-17 · F-RG-1 implemented (20542e3) — authorized; awaiting independent review

FACTS: explicit user authorization received for F-RG-1 implementation per
the approved proposal `F_RG_1_REMEDIATION_PROPOSAL.md` (source of truth).
Branch `fix/rg1-gradle-conflict-elision` created from the verified feature
HEAD `3fbc317dfbef917ca7205059f81bbbe33936a744` (the authorization's
branch name; the proposal's `fix/rg1-conflict-elision-marker` discrepancy
disclosed and resolved in favor of the authorization). Single commit
**`20542e319e4c102163ecb04cc30ca258cf33bc82`** — exactly the 3 authorized
files (+447/−17: gradle.py 39, tools/oracle_gradle.py 21,
tests/test_lock_graph_gradle.py 404). Semantics implemented per the
proposal §2: paired selected-side marker strip (extractor: conflict
branch resolves `g:a:req -> sel (*)` at the CLEAN selected version —
VERIFIED + `conflict_resolved` + `subtree_elided` + identity-stable
fingerprint; `-> (*)` cleaned-empty = requested-but-unresolved, never
promoted; unknown trailing marker after the arrow = strict-unparseable
per §2.5 with the F-RG-2 §5 node/file policy; oracle O-RG-1 mirrored
independently — no shared code). Red-first: matrix run at the pre-fix
state = **8 failed / 52 passed exactly as designed** (red: the rewritten
s8 pin + M1/M2/M3/M3b/M7/M9/M10; green preservation: M4/M5/M6/M8).
Genuine two-direction: the ACTUAL pre-fix extractor payload (captured at
the red phase, byte-embedded in m3b; full JSON preserved under
audit_output/frg1/logs/) is REJECTED exit 1 by the corrected oracle
naming the clean guava identities, and the post-fix extraction is
ACCEPTED exit 0 — proven at unit level (m3b) AND at real-report level
(the full 106-edge pre-fix mockito payload → exit 1; post-fix → exit 0).
Gates ALL GREEN: gradle suite 60/60 (49 existing incl. the sanctioned s8
rewrite + 11 new); ReDoS 25/25; W1 43/43; npm byte-stability `67e638d8`
byte-exact; targeted gates driver 13/13; real reports — mockito-core
**103 VERIFIED (101 + 2) exact reconciliation, 0 WRONG / 0 MISSING**
(oracle exit 0) and micrometer-core **FIRST-EVER exact oracle agreement:
516 VERIFIED (493 + 23 remediated), exit 0 PASS, 0 wrong/missing ALL
classes, 0 constraint-confidence mismatches** — the standing
agreement-modulo-F-RG-1 limitation is CLOSED; downstream full-pipeline
zero-leak both projects (CDX gradle 0 / SPDX gradle 0; join npm-only:
edges_seen 103/516, matched 0); full regression 27/5,069/67 (20:33)
identities 27/27 byte-identical (`f62c7e25`; 5,058+11=5,069 exact).
Disclosures: (a) test_frg2_s8 rewritten in place + renamed
(test_frg2_s8_conflict_combo_frg1_semantics) — sanctioned, the former pin
pinned the defect state; (b) M9 behavior change on a zero-real-occurrence
shape (unknown marker after the arrow: accidental contaminated-UNRESOLVED
→ strict-unparseable leaf-tally / with-subtree fatal, per §2.5); (c) M9's
status assertion corrected during the green phase (the fixture honestly
answers NO_VERIFIED_EDGES; test-side only, disclosed); (d) commit subject
uses ASCII "section-2.5" (F-RG2-R3 mangling lesson). Worktree preserved
byte-identical through all runs; the commit contains exactly the 3
authorized files (the pre-existing data/.vuln_cache.json churn excluded).
Deliverables: F_RG_1_IMPLEMENTATION_REPORT.md + frg1/REVIEW_PACKAGE.md;
evidence audit_output/frg1/. NO integration, NO push — exact next action:
independent review of `20542e3`, then separate integration approval.

## D-037 · 2026-11-17 · F-RG-1 independent review ACCEPTED (20542e3)

FACTS: independent read-only review DELIVERED (FRG_1_INDEPENDENT_REVIEW.md;
evidence audit_output/frg1_review/): verdict **ACCEPTED**. All 18 review
requirements + special scrutiny verified: scope clean (3 files +447/−17,
parent `3fbc317`, feature untouched, never pushed); red-first reproduced
from the committed state in a temp worktree at `3fbc317` (7 red / 52 pass
/ 1 skip — reconciled with the implementation's 8 red: the eighth is the
corpus-dependent M7); `(*)`-strip census exact (one new site per file, on
the 3-part conflict path only; F-RG-2 platform branches zero diff);
oracle independence confirmed (stdlib imports only); `-> (*)`
requested-but-unresolved and unknown-marker strict-unparseable verified
without fabrication; **delta accounting exact — the ONLY identities
affected across both real reports are the 25 F-RG-1 combo identities
(2 + 23), every gone tuple = its new tuple + ` (*)`, (c) sets
byte-identical (24=24 micrometer, 3=3 mockito), (n) 0=0**; line
accounting closes 1,710/1,710 + 462/462 with 0 unclassified and 54/54
combo lines verified four ways (pre/post × extractor/oracle); mockito
103/103 exact and micrometer **first exact oracle agreement 516/516
exit 0** reproduced; genuine two-direction verified against the ACTUAL
pre-fix output (embedded payload field-identical to fresh pre-fix
extraction modulo the source-path form); downstream zero-leak + npm-only
join reproduced; full regression reproduced 27/5,069/67 (21:10) with
**three-way byte-identical identities** (review == implementation ==
baseline `f62c7e25`); 11 new tests + the sanctioned s8 rewrite inspected
(M9 correction verified not to weaken the disclosure guarantee). Findings
(all Info, non-blocking): F-R1G-R1 pipeline `constraints` counter
convention (21 unique children vs 24 unique edge-tuples — same unchanged
set), R2 M7 corpus-dependence with honest skip, R3 pre-existing
SyntaxWarning in a fixture string, R4 the M9 assertion correction
(verified safe), R5 review-prompt wording artifact (not an
implementation defect). Verdict does NOT authorize integration/push/
production/R3 — separate approvals required.

## D-038 · 2026-11-17 · F-RG-1 FF integration executed (explicitly authorized) — distinct milestone from implementation (D-036) and review (D-037)

FACTS: explicit user authorization for strict local fast-forward
integration of the accepted F-RG-1 commit. **Phase A preflight 12/12
PASS** (preflight.txt): fix branch @ `20542e319e4c102163ecb04cc30ca258cf33bc82`,
parent == `3fbc317dfbef917ca7205059f81bbbe33936a744` exact, feature at
the expected base, review report at the specified path records
**ACCEPTED**, ledger heads D-037/V-030, 0 remote refs contain the
commit, FF feasible (count 1). **Phase B: strict
`git merge --ff-only 20542e319e4c102163ecb04cc30ca258cf33bc82` →
"Updating 3fbc317..20542e3 / Fast-forward", exit 0, NO merge commit**
(graph linear; rev-list 3fbc317..HEAD = 1; HEAD == `20542e3` exact;
tree identical to the reviewed commit; commit metadata unchanged;
dirty state preserved through the switch). **Phase C all green, NO
deviations:** gradle 60/60; ReDoS 25/25; targeted driver 13/13 (oracle
two-direction reject 1 / accept 0; W1 43/43; npm `67e638d8` byte-exact;
downstream zero-leak both payloads; probe constraint edge unchanged);
real-project reconciliation — mockito 106 edges / **103 VERIFIED / 0
WRONG / 0 MISSING** (2 remediated combo @ clean `33.4.0-jre`), micrometer
547 edges / **516 VERIFIED / 0 wrong/missing ALL classes / ORACLE RESULT:
PASS**, no unexpected classification changes (only the remediated
verified/unresolved delta); full-pipeline **PASS** (CDX gradle 0, SPDX
gradle 0 both projects; join npm-only, matched 0); full regression 27
failed / 5,069 passed / 67 skipped (20:33) with **failure identities
27/27 sha256 `f62c7e25` byte-identical FOUR-WAY** (FF run == baseline
artifact == implementation run == review run; counts alone not used).
Scope: exactly the 3 authorized files (+447/−17) in the integrated
commit; working tree == commit for those files. **Phase D: dirty/
untracked state byte-identical to the pre-integration snapshot** (the
pre-existing 7 entries; evidence dirs intact; new artifacts only under
audit_output/frg1_ff/). Deliverable:
F_RG_1_FAST_FORWARD_INTEGRATION_REPORT.md (evidence frg1_ff/). Explicit
exclusions honored: NO push (0 remote refs contain the commit before
and after), NO production, NO backlog remediation, NO R3, no merge
commit, no destructive git operations, V11 untouched. One disclosed
reference-path note: the review PACKAGE lives at frg1/REVIEW_PACKAGE.md
(not frg1_review/REVIEW_PACKAGE.md as the task cited); the verdict-
bearing review report was at its exact specified path with ACCEPTED.
Assumptions: none. Next: separately authorized work only (hygiene
backlog B-1..B-7, production/push decision, R3).

## D-039 · 2026-11-17 · B-1 FF integration executed + audit erratum recorded (explicitly authorized)

FACTS: explicit authorization for strict local FF integration of the
reviewed B-1 commit `f100e3e493719a79d0901117cf089732475badf8` (review
verdict ACCEPTED_WITH_DISCLOSED_LIMITATIONS, B1_INDEPENDENT_REVIEW.md)
plus audit erratum + review-finding recording + ledger sync. **Phase A
preflight ALL PASS** (parent `20542e3` exact, feature at target, verdict
present, ledgers D-038/V-031, 0 remote refs contain the commit, FF
feasible; pre-integration cache `4d85afbc0def5ca9`, status
`98fadb83a053b2d8`). **Phase B: `git merge --ff-only f100e3e` → "Updating
20542e3..f100e3e / Fast-forward", exit 0, NO merge commit**; feature HEAD
== `f100e3e…` exact; tree identical to the reviewed commit; exactly 1
commit introduced; metadata unchanged. **Phase C focused gates ALL
GREEN:** B-1 tests 7/7; gradle 60/60; ReDoS 25/25 (clean — no flake
recurrence); targeted 13/13 (oracle two-direction 1/0, zero-leak); W1
43/43; npm `67e638d8` byte-exact; 33 corrections intact, 32 exclusions
unchanged (5 numeric + 8 variable + 19 caps), all 5 display forms
covered, oracles independent (0 production imports). **Phase D:** the
original S3 event preserved verbatim (281.25 ms / 250 ms budget /
8 spinners; reruns clean; not reproduced in any full regression) —
classified intermittent environment-sensitive R-FR3-2; **B-4 REMAINS
OPEN**. **Phase E:** mockito 103/0/0 exit 0, micrometer 516/0/0 ORACLE
PASS; CDX/SPDX gradle leak 0; join npm-only; no classification changes.
**Phase F regression: 27 failed / 5,077 passed / 66 skipped (33:14) —
ONE DISCLOSED DEVIATION vs expected 5,076/67** (exactly one
skip→pass promotion; totals reconcile at 5,170; failure identities
**27/27 sha256 `f62c7e25` byte-identical SEVEN-WAY** across baseline +
F-RG-1 impl/review/FF + B-1 impl/review + this run; exact flipped test
NOT isolated this run — 36 conditional-skip sites; candidates probed
(73/73, 0 skips); `-rs` characterization recommended as follow-up).
**R1 ERRATUM (historical claims preserved, corrected here):** 11 oracle
files (not 10), 38 numeric-slice sites (not 39), 8 variable-bound (not
7), 65 total inspected = 33 corrected + 32 excluded (4+1+8+19). **R2:**
committed behavioral tests cover 1 of 5 display forms (review verified
all 5; structural pin covers all 33). **R3 cache-refresh disclosure:**
cache content 3c14fdda → 4d85afbc (review gates) → ff90f36a (this run's
gates); status `98fadb83a053b2d8` byte-identical throughout; no manual
edit/normalization. **R4:** S3 event recorded; B-4 open. **R5:** the
regression-count deviation (above). Sample caps (19) remain by-design
exclusions. Deliverables: B1_FAST_FORWARD_INTEGRATION_REPORT.md
(evidence audit_output/b1_ff/). Boundaries: NO push (0 remote refs),
NO production, NO B-2..B-7, NO GAP-13/R3, no amend/destructive git ops,
historical reports not silently rewritten. Production readiness
UNCHANGED. Next: separately authorized work only (B-2..B-7 items, B-4
study, `-rs` characterization, production/push decision, R3).

## D-040 · 2026-11-17 · CycloneDX 1.6 offline-schema remediation — independent review disposition (documentation-only ledger synchronization)

FACTS: the independent read-only review of the CycloneDX 1.6 offline-schema
remediation is COMPLETE. Implementation: commit
`34b07ed8dd15f4b66296636fc8943f773b96735d` on
`fix/cyclonedx16-offline-schema`, exact parent
`f100e3e493719a79d0901117cf089732475badf8` (= current
feature/r2-multiecosystem-graph HEAD; NOT integrated). Independent review
verdict: **ACCEPTED_WITH_DISCLOSED_LIMITATIONS**
(CYCLONEDX16_OFFLINE_SCHEMA_INDEPENDENT_REVIEW.md; evidence
audit_output/cyclonedx16_review/). Technical integration readiness:
**YES**. Findings: **F-CDX16-R1..R4 (LOW)** — (R1) red/semantic raw run
outputs unpreserved, review-package evidence list over-promised; (R2)
test_external_refs_resolve_offline assertions cannot discriminate
$ref-resolution failure from validation failure; (R3) wrong-$id rejection
path works (review-probed) but has no committed test; (R4) implementation
report §16 "content hash unchanged during this task" unsupported
(preflight `e67879a5…` vs current `dab348e4…`, sha256[:16]; scan-driven
cache refresh is rule-permitted — wording only) — and
**F-CDX16-R5..R9 (INFORMATIONAL)** — (R5) stale docstrings/section
headers; (R6) upstream jsf-0.82 oneOf quirk preserved verbatim (identical
pre/post); (R7) MANIFEST is an unpinned trust root (standard tradeoff);
(R8) pre-existing stash@{0} (Task-3 era) outside the recorded dirty-state
inventory; (R9) handover "Repository and branch" header still cites
`1bcd061` (contradicted by later sections and git). **None currently
blocks technical integration.** **The review verdict does NOT authorize
integration** — merge/cherry-pick/fast-forward/push/deploy remain
separately gated; technical readiness must not be read as approval.
Red-first evidence classified **RECONSTRUCTED RED-FIRST**: the disclosed
sequencing deviation (production fix applied before red capture) stands;
the original red log was unpreserved; the review reproduced 7 failed / 1
passed twice from the exact committed pre-fix `f100e3e` state plus the
committed tests (the single green = the invalid-document preservation
test). Semantic comparison boundary: verdicts identical 4/4 (battery) +
3/3 (probes) pre-vs-post on a RECONSTRUCTED document set (originals
unpreserved; one error-message wording difference, verdicts unchanged) —
equivalence claims extend only to the tested shapes, not the universal
document space. Investigation erratum preserved exactly: schema fetch
failure yields `{"valid": False}` → a failed assertion, NOT a skip (the
skip path requires ImportError); the **historical B-1 skip→pass flipper
remains UNRESOLVED** — this remediation must NOT be credited with
identifying or resolving the historical promotion (it removes the network
dependency and makes the two tests deterministic; the historical
mechanism stays an open question). Outstanding remediation/documentation
considerations (each separately authorized): F-CDX16-R1..R5 hygiene
corrections; the R9 handover stale-header fix (documentation-only
handover update); B-4 OPEN; B-2..B-7 backlog; strict fast-forward
integration of `34b07ed` (a separate decision this verdict does not
grant). Separately authorized and executed earlier in this session
(outside this disposition, recorded for truth of the record):
publication of committed refs (21 branches + 2 tags) to the new `audit`
remote https://github.com/ramuatnet/R-SecOpsX-P0-Independent-Audit after
the user approved GitHub push-protection's hit on the synthetic
`sk_live_…` test fixture (commit `9561db7`,
tests/v3_targets/secrets_target/app_config.py — self-declared FAKE
pattern-valid fixtures) as a false positive; `origin` untouched; not an
integration or production action. Production readiness UNCHANGED. Next:
separately authorized work only (remediation of F-CDX16-R1..R9 if
requested, FF integration decision for `34b07ed`, B-2..B-7 items, B-4
study, production/push-to-origin decision, R3).

## D-041 · 2026-11-17 · DEV-1 fresh-checkout line-ending remediation — independently VERIFIED (documentation-only ledger synchronization)

FACTS: DEV-1 (the fresh-checkout CRLF-smudge defect discovered during the
authorized strict fast-forward integration: `core.autocrlf=true` converted
the vendored CycloneDX 1.6 schema LF blobs to CRLF on checkout so the
hash-pin loader correctly rejected them on every fresh worktree/clone
while the original worktree stayed green) is **REMEDIATED and
independently VERIFIED**. Remediation commit
`d695aa2732cb3ccc28991c335635a22e88ab6316` on
feature/r2-multiecosystem-graph, exact parent
`34b07ed8dd15f4b66296636fc8943f773b96735d`, message "fix: preserve
CycloneDX schema bytes across checkout"; scope exactly two files (+42):
`.gitattributes` += `schemas/** -text` (append-only; existing rules
`tests/replay/** text eol=lf` and `tests/fixtures/baseline/** -text`
preserved verbatim — the same FND-08 hash-pinned-fixture convention) +
one narrow regression guard `test_schema_fixture_checkout_bytes_and_
attributes` (asserts on-disk bytes == manifest SHA-256 pins AND
`git check-attr text` = unset for every fixture file). No schema content,
pin, loader or non-1.6 behavior change. Independent verification (new
fresh worktree at `d695aa2`, host `core.autocrlf=true` preserved, no
overrides, no copied files): **byte identity 3/3** — blob == fresh
checkout == pin == manifest (schema.json `18f57f74…` 262,666 B,
spdx.schema.json `4b345e23…` 63,418 B, jsf-0.82.schema.json
`8bae002c…` 8,058 B; CR=0 CRLF=0 on all three); attribute resolution
`text: unset` ×3 with unrelated paths unaffected and no smudge filters
applicable. Functional validation in the fresh worktree ALL GREEN:
offline-schema suite **9 passed / 0 failed / 0 skipped** (8 pre-existing
+ 1 new guard); both formerly network-dependent tests **2 passed**, no
skip; network-disabled harness **53 passed / 0 HTTP attempts** with
tampered/missing/wrong-`$id` probes failing explicitly and external refs
resolving offline (battery verdicts unchanged T/F/F/F); focused
CBOM/SBOM regression **59 passed / 0 failed** (independently reproduced,
not merely preserved). Verification verdict: **VERIFIED**. Evidence
`audit_output/dev1_independent_verification/` +
`DEV1_INDEPENDENT_VERIFICATION_REPORT.md`. DEV-1 is a NEW finding and
closes none of F-CDX16-R1..R9 (dispositions unchanged: R2/R3
REMEDIATE_AFTER_INTEGRATION; R4/R5/R9 DOCUMENTATION_ONLY; R1/R7 accepted
with disclosed limitations; R6/R8 NO_ACTION_REQUIRED). B-1 separation
preserved: fetch failure yields `valid=False` → assertion failure, not a
skip; skip path requires ImportError; the historical B-1 skip→pass
flipper remains **UNRESOLVED** and is not claimed resolved here. This
entry does NOT authorize remote publication or deployment. Next:
separately authorized work only (publication decision, R2/R3 hygiene
batch, R4/R5/R9 documentation, B-2..B-7, production/push-to-origin
decision, R3).

## D-042 · 2026-11-17 · F-CDX16-R2 / F-CDX16-R3 test-quality remediation — formal disposition after independent ACCEPTED review (documentation-only ledger synchronization)

FACTS: the test-only remediation of F-CDX16-R2 (offline external `$ref`
resolution test quality) and F-CDX16-R3 (wrong schema `$id` negative
regression test) — commit `74c451578b2ed8000f9ee83c11d2194358406f05` on
feature/r2-multiecosystem-graph, exact parent
`d695aa2732cb3ccc28991c335635a22e88ab6316`, message "test: strengthen
CycloneDX offline reference and identity checks", scope exactly one file
(tests/test_cyclonedx16_offline_schema.py, +148/−0) — is formally
dispositioned per the independent read-only review
(CYCLONEDX16_R2_R3_INDEPENDENT_REVIEW.md; evidence
audit_output/cyclonedx16_r2_r3_independent_review/): overall review
verdict **ACCEPTED**; **F-CDX16-R2 disposition: ACCEPT**; **F-CDX16-R3
disposition: ACCEPT**. Rationale: the committed regression tests
independently prove offline external-reference resolution (content-
derived ref inventory, resource-id mapping, positive resolution through
the real loader/validator path), explicit unresolved-reference rejection
(silent-skip catching) and incorrect schema-identity rejection (the `$id`
check as the rejecting authority behind a passing hash gate), with every
reported validation figure independently reproduced (module 12 passed /
affected 2 passed / network-disabled harness 56 passed with 0 attempts /
focused CBOM-SBOM regression 59 passed / compilation and
`git diff --check` exit 0) and all red-first claims reproduced in the
review copy (old-assertion gap under unresolved-reference sabotage; 3
R2 tests red under the failing-resolver variant; R3 test
DID-NOT-RAISE against the accepting-loader variant; restore → 12 green).
Scope: test-quality remediation only — no production loader, schema,
pin, manifest or `.gitattributes` change; DEV-1 behavior intact
(including the checkout-bytes guard); F-CDX16-R1/R6/R7/R8 dispositions
unchanged; R4/R5/R9 remain open documentation work. Review limitations
preserved: the full 25–35-minute regression was not rerun (the focused
59-test suite was independently reproduced); the jsonschema wording
assertion is acceptable under the pinned jsonschema 4.26.0 (structured-
error hardening is a non-mandatory future recommendation); the JSF
`oneOf` quirk remains under F-CDX16-R6 (the positive proof deliberately
uses the URI-algorithm form); cache content was refreshed
`dab348e44c8484c1…` → `c494b680ecd32280…` by the remediation-era mandated
gate runs (scan-driven, rule-permitted; the refresh moment is artifact-
verified only; the independent review found the current state consistent
with the disclosure). This decision does NOT authorize project R3,
B-2 through B-7, R4/R5/R9 remediation, deployment or remote publication.
Next: separately authorized work only (publication decision, R4/R5/R9
documentation batch, B-2..B-7, production/push-to-origin decision, R3).

## D-043 · 2026-11-17 · Overnight plan executed (tasks.md): F-CDX16-R4/R5/R9 + B-3 documentation batch, B-6 verified, B-2/B-4/B-5/B-7 evidence + proposals, full regression baseline-identical, publication assessment (no publication), GAP-13/B-8 blocked

FACTS: the overnight autonomous plan (tasks.md, 2026-11-17) was executed
against verified baseline `0929dbd` on feature/r2-multiecosystem-graph
(§0 safety snapshot preserved at
audit_output/overnight_nov17/snapshot/pre_work_snapshot.txt; ancestry
74c4515 verified). Delivered, in §15 order:

1. **Task 1** — `audit_output/OVERNIGHT_PENDING_WORK_INVENTORY.md`
   (read-only reconciliation against D-001..D-042 / V-001..V-035, the
   handover, the F-CDX16 disposition review and the B1_B7 assessment;
   no disposition changed; B-8 + evidence-establishment items + residual
   pointers recorded as DEFERRED; exclusions honored).
2. **Task 2 — F-CDX16-R4 IMPLEMENTED** (`77f21f4`, docs-only): dated
   ADDENDUM appended to the historical implementation report — original
   174 lines preserved byte-identical (pre-edit copy + sha256 recorded);
   the §16 "content hash unchanged during this task" claim withdrawn as
   unsupported with the full fingerprint chain
   (`e67879a57573c228` preflight → `dab348e44c8484c1` D-040 →
   `c494b680ecd32280` D-042/V-035) and the refresh moment declared
   artifact-verified only.
3. **Task 3 — F-CDX16-R5 IMPLEMENTED** (`dbe1f3c`, comment-only):
   `_attach_official_schema` docstring corrected to the committed
   offline-1.6 semantics + two stale test headers; no executable line or
   test semantics change; py_compile exit 0; suite 56 passed pre/post
   identical; `git diff --check` clean.
4. **Task 4 — F-CDX16-R9 IMPLEMENTED** (`b8df396`, docs-only): handover
   header corrected (stale R2.1-era `1bcd061` — verified to be the
   2026-11-12 R2.1e tip — replaced with the correction-time tip and a
   dated note recording the D-040..D-042 progression); body byte-identical
   (6 header lines changed); the handover file is now git-tracked
   (authorized status-shape change).
5. **Task 5 — B-3 CLOSED WITH EVIDENCE** (`40c0b4b`, docs-only):
   canonical-interpretation note for the `3fbc317` mangled subject
   ("(5)-hardening" = intended "§5-hardening", proposal-§5 leaf contract);
   history untouched; scan confirms exactly 1 mangled subject.
6. **Task 6 — B-6 VERIFIED CLOSED** (no change): the F-R5-1R correction
   stands published in `R2_5_1_FINAL_REVIEW.md:78-84,161`; original
   wording at `R2_5_1_REMEDIATION_REPORT.md:22` preserved by design.
7. **Task 7 — B-2 evidence + proposal** (no implementation — the recorded
   disposition reserves the contract design choice for authorization):
   synthetic red probe reproduced (platform+`(n)`-parent child emits
   `parent_requested_version: ""`), real corpora re-verified 0
   occurrences (653 edges ×2 copies); one-line omit-when-empty proposal
   (option a, recommended) vs document-empty-string (option b) delivered
   (audit_output/overnight_nov17/b2/).
8. **Task 8 — B-4 bounded study delivered; risk remains OPEN** (no
   runtime/default/assertion change): 12-rep controlled 8-spinner study
   replicating the S3/S5 methodology — S3 worst row max 171.9 ms (budget
   headroom ≥1.454×, min margin 78.1 ms), S5 max 46.9 ms (≥5.33×), 0
   over-budget / 0 out-of-band rows; the 2.5×+floor band is the binding
   constraint (min margin 3.1 ms); disposition = disclose-the-risk
   recommendation (test-docstring change separately authorized) or an
   S2-class 12+12 calibration study before any margin change (evidence
   audit_output/overnight_nov17/b4/).
9. **Task 9 — B-5a/b/c probes + paired-change proposal** (no
   implementation — recorded disposition requires separate per-batch
   authorization): all three reds reproduced (non-graph go-mod-graph.txt
   → NO_VERIFIED_EDGES; git-sourced cargo child lacks child_source
   disclosure; AMBIGUOUS candidates `['d@1.0.0','d@1.0.0']` duplicated)
   with preservation shapes; oracle scope resolved — oracle_go has zero
   envelope assertions (B-5a needs no pairing), oracle_cargo DOES compare
   candidate lists (B-5c must be a PAIRED extractor+oracle change);
   three-commit batch profile on a new branch delivered
   (audit_output/overnight_nov17/b5/).
10. **Task 10 — B-7 six-fixture assessment + proposal** (no
    implementation — recorded disposition DEFER PENDING EVIDENCE stands):
    membership parser collects GEM-only (GIT/PATH/PLUGIN gems skipped —
    red for cases 1/3/5), graph extractor already provenance-aware
    (`_SECTION_PROVENANCE`); six isolated fixtures + red-first
    expectations + conservatism pins (no directness inference, no
    provenance fabrication); Ruby suites 56/56 green baseline
    (audit_output/overnight_nov17/b7/).
11. **Task 11 — FULL REGRESSION EXECUTED** (documented command, 29:40,
    exit 1 = baseline-normal): **27 failed / 5,089 passed / 66 skipped,
    failure identities 27/27 byte-identical (`f62c7e25`)**; count
    reconciled exactly: 5,085 + 4 (DEV-1 `d695aa2` +1, F-CDX16-R2/R3
    `74c4515` +3 — the first full-suite run carrying them, previously
    `[NOT-EXECUTED]` per V-035) — no new failures, no identity drift;
    only documented side effect: scan-driven cache refresh
    `c494b680ecd32280` → `56581588bc89bd5d`
    (audit_output/overnight_nov17/regression/).
12. **Task 12 — publication-readiness assessed, NO publication** (read-
    only, no fetch): local feature line ahead 8 / behind 0 of the
    recorded `audit/feature/r2-multiecosystem-graph` tracking ref
    (`f100e3e`); clean fast-forward possible; all 8 commits scope-
    verified intended (CycloneDX, DEV-1, R2/R3, D-042/V-035 sync + this
    overnight's 4); verdict READY-FOR-AUTHORIZATION with prerequisites
    (explicit authorization, regression gate — now satisfied clean, live
    remote fetch confirmation) (audit_output/overnight_nov17/publication/).
13. **Task 13 — GAP-13/B-8 documented BLOCKED** (protected V11
    dependency; correction content staged on this side; no V11 write, no
    workaround) (audit_output/overnight_nov17/gap13/).
14. **Task 14 — this closure record** +
    `audit_output/OVERNIGHT_EXECUTION_REPORT.md` (consolidated status
    table, final state, status-shape explanations).

BOUNDARIES HONORED: no push/fetch/pull/deployment/tag movement; no V11
modification (read-only checks only); no history rewrite/reset/clean; no
production behavior change (R5 = comments; B-2/B-5/B-7 unimplemented);
project R3 not started; B-1 skip flipper not reopened; no test weakened
or suppressed; stash and pre-existing dirty/untracked state preserved
throughout. This decision does NOT authorize: B-2/B-5/B-7 implementation,
B-4 disclosure-note or calibration study, publication, R3.
Next: separately authorized work only.

## D-044 · 2026-11-21 · B-5a (F-R4-A) owner acceptance + conditional two-file commit authorization exercised

FACTS: B-5a (gomod zero-parseable-records envelope) was implemented 2026-11-20
against the uncommitted working tree @ `0da0d80` (no staging; 25 tracked mods
= 23 prior + the 2 B-5a files). Owner decision 2026-11-21 (this session):

1. **ACCEPTANCE** — B-5a accepted based on the controlled repeat, which
   reproduced the accepted baseline exactly (3 failed / 5,290 passed / 75
   skipped, 13:26, run_tag `b5a_repeat_20261120`, pinned offline advisory
   cache); the 3 transient timing flakes of the first contended run
   (R-FR3-2 ×2 + F-W1-2) did not recur. Both runs recorded accurately in
   V-037, including the initial 6-failure result (evidence:
   `audit_output/b3id_phase_b_waves23/b5a_full_regression.log` +
   `b5a_repeat_regression.log`; pin proofs
   `audit_output/b3id_phase_b_baseline_normalized/pin_activation_proof_b5a_{full,repeat}_20261120.json`).
2. **CONDITIONAL COMMIT AUTHORIZATION EXERCISED** — one separate commit
   containing EXACTLY `analysis/lock_graph/gomod.py` +
   `tests/test_lock_graph_gomod.py`: commit `3fe7703`
   (`3fe7703130fa93a5ec60234497ead897b24fa511`, parent `0da0d80`, 2 files,
   67+/15−). Pre-commit integrity: working-tree blob hashes equal the diff
   post-images (`fdf63d8…` / `96f39b3…`) — commit content == validated
   content. Post-commit: staged 0; remaining tracked mods 23 (all unrelated
   work preserved); stash (1) intact; no push.
3. **BOUNDARIES** — B-5b/B-5c NOT implemented (untouched); no push; no
   history operation; unrelated changes preserved. The D-044/V-037 ledger
   edits themselves are UNCOMMITTED working-tree changes by design (the
   authorized commit scope was owner-capped at the 2 code files).

Next: owner-directed work only (B-5b/B-5c and any further authorization remain open).

## D-045 · 2026-11-21 · B-5b (Cargo child-side dependency-edge provenance) implemented + owner ACCEPT — no commit/push authorization

FACTS: B-5b was implemented 2026-11-21 against the uncommitted working tree
@ `78fac3c` on feature/r2-multiecosystem-graph (4 files, +197/−17; exact
numstat in V-038). Paired change: `analysis/lock_graph/cargo.py` discloses
child-side provenance on VERIFIED edges only (`child_source_kind` /
`child_source` / `child_revision` verbatim `#`-fragment when the child's
own [[package]] source carries one; AMBIGUOUS/UNRESOLVED children carry
none — nothing fabricated), and `tools/oracle_cargo.py` independently
re-derives the same provenance contract from its own TOML walk (the
extractor is never imported) and gates PASS on it.

1. **IMPLEMENTATION + VALIDATION** — RED-first demonstrated (3 expected
   failures: `KeyError: 'child_source_kind'` ×3; 1 boundary test passing
   by design pre+post). GREEN: Cargo suite 24 passed; oracle diagnostics
   7 passed; wider lock-graph regression 258 passed; oracle battery —
   probe fixture 1/1 identity + 0 provenance mismatches (PASS), tamper
   probe FAILED rc=1 with exactly 1 provenance mismatch detected (oracle
   independence demonstrated), real corpus rust/Cargo.lock 125/125
   identities + 0 provenance mismatches (== recorded R2.4 identity
   baseline). Full evidence and exact counts: V-038.
2. **OWNER ACCEPTANCE (2026-11-21)** — Workstream B-5b: **ACCEPT**,
   explicit; owner comments: NONE. Acceptance applies to the
   implementation and the focused validation evidence presented in the
   B-5b implementation report (recorded as V-038).
3. **AUTHORIZATION BOUNDARIES** — this acceptance does NOT authorize a
   commit (B-5b remains UNCOMMITTED at HEAD `78fac3c`), a push, B-5c,
   Wave 4/VEX, or R3. Any commit requires a separate explicit Project
   Owner authorization.
4. **DISCLOSED** — pre-existing `SyntaxWarning` at
   tests/test_lock_graph_cargo.py:133 ('is' with tuple literal) untouched;
   `expected_lock` interface extended 3→4-tuple with a disclosed unpack
   adaptation in tests/test_oracle_diagnostics.py (display assertion
   unchanged — update, not weakening); provenance compared only for
   extractor-claimed identities (absent/invented edges remain identity
   failures — no double-flagging).

Next: owner-directed work only.

## D-046 · 2026-11-21 · B-5c (AMBIGUOUS candidate duplicate semantics) implemented + owner ACCEPT — no commit/push authorization

FACTS: B-5c was implemented 2026-11-21 against the uncommitted working tree
@ `78fac3c` on feature/r2-multiecosystem-graph (paired extractor+oracle
change per the authorized B-5 proposal §3 Commit 3; files: cargo.py +
oracle_cargo.py + test_lock_graph_cargo.py; test_oracle_diagnostics.py
NOT changed by B-5c).

1. **SCOPE + OUTCOME** — AMBIGUOUS candidate duplicate semantics: two
   distinct Cargo instances with identical name+version but different
   sources generated duplicate candidate disclosure strings
   (`['d@1.0.0', 'd@1.0.0']`, probe fixture_c); the extractor now
   deduplicates the disclosure strings (`sorted(set(...))`, R2.3 yarn
   convention) while distinct instances, source-hint disambiguation, the
   AMBIGUOUS decision, empty child version,
   `AMBIGUOUS_MULTIPLE_INSTANCES` and the absence of a fingerprint all
   remain unchanged; `tools/oracle_cargo.py` applies the same candidate
   normalization independently (own derivation, extractor never
   imported). Evidence and exact counts: V-039.
2. **DISCOVERED PRE-EXISTING ORACLE DEFECT CORRECTED (part of accepted
   scope)** — expected AMBIGUOUS keys were (parent, parent_version,
   child) tuples while extractor-side keys were pipe-joined strings, so
   the candidate reconciliation could never match (dead since R2.4; the
   rust corpus has AMBIGUOUS 0 and never exercised it); keys were
   aligned so the proposal's B-5c reconciliation gate functions. This
   activates a previously ineffective check — a strengthening, disclosed
   in code and in the implementation report.
3. **OWNER ACCEPTANCE (2026-11-21)** — Workstream B-5c: **ACCEPT**,
   explicit; owner comments: NONE. Acceptance applies to the
   implementation and the focused validation evidence presented in the
   B-5c implementation report (recorded as V-039).
4. **AUTHORIZATION BOUNDARIES** — this acceptance does NOT imply a
   commit (B-5c remains UNCOMMITTED at HEAD `78fac3c`, alongside the
   accepted B-5b), a push, Wave 4/VEX, R3, or any other workstream. Any
   commit requires separate explicit Project Owner authorization.

Next: owner-directed work only.

## D-047 · 2026-11-21 · G-P0-1 B3-ID prepared-commit decision EXECUTED — owner-authorized controlled commit of the verified 21-file manifest

FACTS: the G-P0-1 workstream (B3-ID Phase B Waves 1–3, register entry
G-P0-1) reached its owner decision: the Project Owner authorized staging
and then the commit of the corrected, evidence-verified 21-file manifest
(revised from the historical 23-file wording by owner-approved exclusions,
per the G-P0-1 readiness + 10-file attribution verification tasks).

1. **COMMIT EXECUTED** — `b47b85b` (`b47b85b5885d1bf74541590a074594f3cd130fc6`,
   subject `feat(p0): commit accepted B3-ID waves 1-3`, parent
   `78fac3c5caa0196cccefceffa7bb1292aeb7a2bc`): exactly the approved 21-file
   manifest (6 Wave-1 + 10 Wave-2 production + 1 Wave-3 + 4 R-6 linkage
   tests), 21 files +297/−25. Pre-commit checks: all seven passed (branch,
   HEAD, staged-set equality, 21/21 index-vs-working-tree blob hashes,
   unstaged set == the 8 protected exclusions, exclusions unstaged, stash
   intact). Post-commit: path-set equality exact (no additional or missing
   paths), zero excluded paths in the commit, staging empty, 8 protected
   modifications remain unstaged, stash intact. Full evidence: V-040.
2. **SCOPE CORRECTION (owner-approved)** — the historical register wording
   "23-file set" was revised to 21 files: `SAST_OVERNIGHT_EXECUTION_REPORT.md`
   excluded (its current content belongs to the G-P0-2 prepared commit —
   later SAST erratum) and `data/.vuln_cache.json` excluded (runtime cache,
   rule-permitted refreshes; left uncommitted). Neither was silently dropped:
   the revision was presented, evidence-verified, and owner-approved before
   staging.
3. **DISTINCTION PRESERVED** — this decision records implementation
   completion of G-P0-1 (commit executed exactly as verified). It is NOT
   the formal overall P0 acceptance (G-P0-10) and does not imply any other
   gate's disposition.
4. **AUTHORIZATION BOUNDARIES** — no push/publication performed or
   authorized; ledger updates for this commit were separately authorized
   (this D-047/V-040 pair); B-5b/B-5c remain accepted-but-uncommitted;
   G-P0-2/G-P0-3 not started; no tests/scans in the commit task.

Next: owner-directed work only (G-P0-2 SAST closure commit, G-P0-3 ledger
backfill, and the remaining decision gates).

## D-048 · 2026-11-21 · G-P0-2 SAST closure-commit decision EXECUTED — owner-authorized controlled commit of the verified seven-file manifest

FACTS: the G-P0-2 workstream (SAST campaign acceptance conditions 2+3,
register entry G-P0-2) reached its owner decision: the Project Owner
authorized staging and the commit of the seven-file prepared manifest
(`SAST_ACCEPTANCE_CLOSURE/SAST_ACCEPTANCE_CLOSURE_SUMMARY.md` §5), following
the read-only readiness verification (PASS disposition, exact 7/7 scope,
no drift).

1. **COMMIT EXECUTED** — `6edc0d3`
   (`6edc0d3a0dec08a812ee6bc49fce72d06180f3c5`, subject
   `docs(p0): commit SAST acceptance closure evidence`, parent `b47b85b`
   — the G-P0-1 commit): exactly the seven-file §5 manifest, 7 files
   +349/−0 (1 tracked +11/−0 dated addendum to
   `SAST_OVERNIGHT_EXECUTION_REPORT.md` + 6 new closure-evidence files,
   nothing overwritten). Fresh pre-staging verification: all 7 blob hashes
   matched the previously verified values; committed baseline byte-identical
   to `report_BEFORE_erratum_append.md` (`c5d8c7d1…` both); staging set
   equality exact; 7/7 index-vs-working-tree hash match; zero exclusions
   staged. Post-commit: path-set equality exact, zero excluded paths,
   staging empty, 7 protected modifications remain unstaged, stash intact.
   Full evidence: V-041.
2. **CLOSURE-VALIDATION STATUS PRESERVED** — `SAST_CLOSURE_VALIDATION.json`
   overall VERIFIED with all six sub-checks VERIFIED; its honest
   `not_verified` disclosures (offline SARIF schema validation, Rust-
   conditional bodies, full-suite re-run, V11-side fixture provenance,
   commit-authorization itself) are preserved verbatim in the committed
   evidence and NOT superseded by this decision.
3. **FIXTURE-PROVENANCE DECISION UNRESOLVED (deliberately)** — the §6
   `OWNER_DECISION_REQUIRED` item (Options A/B/C in
   `SAST_FIXTURE_PROVENANCE_ASSESSMENT.md`) remains open; no resolution is
   inferred or recorded by this decision.
4. **DISTINCTION PRESERVED** — this records implementation completion of
   G-P0-2 (closure commit executed exactly per manifest). It is NOT formal
   overall P0 acceptance (G-P0-10) and does not imply any other gate's
   disposition.
5. **AUTHORIZATION BOUNDARIES** — no push/publication performed or
   authorized; no tests/scans in the commit task; B-5b/B-5c remain
   accepted-but-uncommitted; G-P0-3 not started.

Next: owner-directed work only (fixture-provenance adjudication, G-P0-3
ledger backfill, remaining decision gates).

## D-049 · 2026-11-21 · SAST campaign era backfill — campaign executed under owner task authorization; independent audit ACCEPT_WITH_REVISIONS (historical evidence record, not a new decision)

FACTS (historical backfill; all facts source-verified, no new owner
decision created): the SAST implementation campaign was executed
2026-11-17/18 under the owner-issued task authorization
(`SAST_overnight_tasks.md`) as 12 commits `3ff8c20..b42316c`
(commit chain and per-commit scopes verified in
`SAST_ACCEPTANCE_REVIEW/SAST_COMMIT_SCOPE.csv`; subjects verified in git
history; NO push).

1. **INDEPENDENT AUDIT VERDICT (preserved verbatim)** — **ACCEPT_WITH_REVISIONS**
   (`SAST_ACCEPTANCE_REVIEW/SAST_ACCEPTANCE_AUDIT.md:100`): "the technical
   work is independently verified (commit chain, regression accounting, all
   nine feature slices, inventory totals); the deviations are disclosed and
   non-concealed but leave three conditions before the next implementation
   campaign". This verdict is NOT converted into unconditional ACCEPT.
2. **CONDITIONS STATUS** — condition 1 (fixture governance) was split to
   **G-P0-4** (Option B ratification — still PENDING owner decision;
   nothing here implies its resolution). Conditions 2+3 closure evidence was
   prepared, validated, and committed as the G-P0-2 closure commit
   **`6edc0d3`** (recorded separately as D-048/V-041). The next campaign is
   NOT authorized (requires explicit owner instruction AND the fixture
   decision, per the closure summary).
3. **BOUNDARY DEVIATIONS** — disclosed and non-concealed
   (`SAST_BOUNDARY_DEVIATIONS.md`); carried forward, not absorbed.
4. **BOUNDARY** — this entry records a historical era's documented outcomes;
   it is NOT a new owner decision, NOT overall P0 acceptance (G-P0-10), and
   does not close G-P0-4.

Cross-reference: V-042 (campaign validation evidence).

## D-050 · 2026-11-21 · C2-WIN era backfill — implementation committed `aa4e2be`; NO formal acceptance verdict located (UE-27 remains pending)

FACTS (historical backfill; no owner decision created or inferred): the
C2-WIN Windows/PowerShell slice was implemented and committed as
**`aa4e2be`** ("feat(sast): add Windows PowerShell security scanning", 12
files; NO push).

1. **VALIDATION (documented)** — core 121/121 + broader 193/193 + full-suite
   zero new failures, as recorded VERIFIED in the frozen consolidated plan
   (row 27, `bf45b2ef…`) and register UE-27; Layer C (Batch/VBScript
   detection) deferred-by-design.
2. **ACCEPTANCE VERDICT: NOT LOCATED** — explicitly recorded per register
   UE-27: "A formal acceptance verdict record for C2-WIN — none located in
   this repository". **No ACCEPT or REJECT outcome is manufactured here.**
   UE-27 remains AWAITING-DECISION (PENDING owner adjudication; row 27
   reclassifies to COMPLETED only upon an actual verdict).
3. **BOUNDARY** — implementation completion is NOT acceptance; this entry is
   NOT overall P0 acceptance (G-P0-10).

Cross-reference: V-044 (C2-WIN validation evidence).

## D-051 · 2026-11-21 · B3-ID Phase A + Phase B Waves 1–3 era backfill — session acceptance ACCEPTED WITH DOCUMENTED LIMITATIONS (historical evidence record)

FACTS (historical backfill; all verdicts preserved verbatim from their
hash-verified sources):

1. **PHASE A** — `0da0d80` ("feat(identity): B3-ID Phase A -- finding_uid
   minting + canonical sort + T1-T14 tests"), parent `aa4e2be`.
2. **PHASE B WAVE 1** — accepted with documented limitations
   (`B3_ID_PHASE_B_WAVE_1_ACCEPTANCE_RECORD.md`, `cd19a1f2…`): F-W1-1/G-W1-1
   closed, F-W1-2 retained as non-blocking, F-W1-3 Interpretation A;
   corrective closure and regate history recorded in the Wave-1
   corrective/regate reports.
3. **PHASE B WAVES 2–3** — final verdict **ACCEPTED WITH DOCUMENTED
   LIMITATIONS** (`B3_ID_PHASE_B_WAVES_1_TO_3_FINAL_ACCEPTANCE_REPORT.md`
   §12, `d103feab…`); three documentation-only reconciliation passes
   2026-11-20 (`B3_ID_PHASE_B_DOCUMENTATION_RECONCILIATION_RECORD.md`,
   `e0d63d51…`).
4. **DISTINCTION PRESERVED** — the historical session acceptance above is
   distinct from the later owner-authorized G-P0-1 implementation commit
   **`b47b85b`** (recorded separately as D-047/V-040), and both are distinct
   from overall P0 acceptance (G-P0-10). Neither is implied by this entry.
5. **BOUNDARY** — historical evidence record only; no new owner decision;
   G-P0-1's ledger record and G-P0-10 remain as they were.

Cross-reference: V-045 (B3-ID validation evidence); D-047/V-040 (the later
G-P0-1 commit records).

## D-052 · 2026-11-21 · G-P0-4 RATIFIED WITH DISCLOSED LIMITATIONS — SAST Option B portable prod-tree fixtures (`993f6b8`) are the standing fixture basis

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **RATIFY WITH DISCLOSED LIMITATIONS**.

1. **RATIFIED** — SAST Option B portable synthetic prod-tree fixtures
   (`993f6b8`) are the standing fixture basis for the SAST baseline, accepted
   WITH DISCLOSED LIMITATIONS per V-043: fresh-clone validation executed
   (portable tests **14 passed / 0 failed / 0 skipped, exit 0**) under BOTH
   the fixture-absent and the controlled-fixture-present conditions;
   per-check table VERIFIED.
2. **DISCLOSED DEVIATIONS PRESERVED** — the 7 marker-string corrections
   (`test_v11_g035_framework_taint.py` ×4, `test_v11_p0_owasp_aibom_
   conformance.py` ×3) and 2 marker-addition corrections (test_37/test_38)
   remain disclosed annotation deviations from strict §5; `conftest.py`
   hash unchanged; t118 self-SBOM drift stands as a **pre-existing
   `core.autocrlf` condition** (proven on a pristine baseline clone).
   The delivered `PASS_WITH_LIMITATIONS` classification is preserved —
   **no unconditional acceptance is claimed**.
3. **DISTINCTION PRESERVED** — the implementation/validation evidence
   (V-043) and this ratification record are distinct artifacts: this entry
   now supplies the formal ratification record the register recorded as
   MISSING; G-P0-4's documented closure criterion (dated ratification
   record) is satisfied by this entry. This does NOT close any other gate
   and is NOT overall P0 acceptance.

Cross-reference: V-043; register §G-P0-4; `993f6b8`.

## D-053 · 2026-11-21 · UE-27 C2-WIN CONDITIONAL ACCEPTANCE — Windows/PowerShell slice (`aa4e2be`) formally accepted; Layer C not accepted

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **CONDITIONAL ACCEPTANCE**.

1. **ACCEPTED SCOPE** — the implemented Windows/PowerShell detection slice
   associated with `aa4e2be` ("feat(sast): add Windows PowerShell security
   scanning", 12 files), on the documented validation evidence: core
   **121/121**, broader **193/193**, baseline full-suite regression
   **5,207 passed / 4 failed / 74 skipped** with **zero C2-WIN-attributable
   failures** (V-044; the 4 failures are the preserved pre-existing
   SCA-class identities + the R-FR3-2 environmental timing flake — historical
   outcomes and attribution preserved verbatim).
2. **NOT ACCEPTED** — Layer C (Batch/VBScript detection) remains **deferred
   by design and is not accepted as implemented**; no full Windows-scripting
   coverage is claimed. The formal verdict the register recorded as MISSING
   is supplied by this entry; per the register's own consequence rule, plan
   row 27 reclassifies to COMPLETED for the implemented scope.
3. **BOUNDARY** — conditional acceptance ≠ overall P0 acceptance (G-P0-10);
   Layer C carries forward under the G-P0-7 unsourced inventory.

Cross-reference: V-044; register UE-27; `aa4e2be`.

## D-054 · 2026-11-21 · Fixture provenance — OPTION C selected (requires_prod_tree markers; V11-derived register/quarantine/backup fixtures)

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **OPTION C selected** from the
documented Options A/B/C (`SAST_FIXTURE_PROVENANCE_ASSESSMENT.md` §4).

1. **SELECTED** — the V11-derived register/quarantine/backup fixture
   dependencies are to be governed via the registered `requires_prod_tree`
   marker policy (mandatory reasons) targeting the **nine unconditional
   fixture-dependent tests**; fresh clones must degrade honestly through
   reason-attached skips.
2. **PRESERVED DISTINCTIONS** — the V11-derived files remain **local-only**:
   nothing is fabricated, committed, or added to the P0 repository; the two
   existing conditional cases and fixture-independent behavior are not
   silently altered; the provenance deviation is recorded as
   disclosed-and-managed.
3. **NOT AUTHORIZED BY THIS ENTRY** — implementing Option C (the marker
   conversion) requires its own separate task authorization; Option B
   (authoring committed replacements) remains a possible FUTURE workstream,
   explicitly not selected.

Cross-reference: `SAST_FIXTURE_PROVENANCE_ASSESSMENT.md` §2–5; closure
summary §6 (the OWNER_DECISION_REQUIRED item this entry resolves).

## D-055 · 2026-11-21 · G-P0-5b production adjudication — DEFER; production/main-branch integration recorded NOT-READY

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **DEFER**.

1. **ADJUDICATED** — production/main-branch integration readiness is
   recorded **NOT-READY** as the standing position (`R2_FINAL_CLOSURE_AUDIT.md`
   §9/§181: production integration and push are separate approvals; `origin`
   carries no audit commit).
2. **RECONSIDERATION** — requires a separately authorized production-
   readiness review; this entry implies **no production approval and no
   production readiness**.
3. **BOUNDARY** — feed into G-P0-10; no implementation authorized.

## D-056 · 2026-11-21 · G-P0-5c B-4 (R-FR3-2) — DISCLOSURE-ONLY CLOSURE approved

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **APPROVE DISCLOSURE-ONLY CLOSURE**.

1. **EVIDENCE RECORDED (preserved)** — conservative-margin observation:
   worst observed row 218.8 ms under the one-spinner condition (≈1.15×
   headroom under heavier contention than observed); **no failure observed
   at eight spinners**; post-study margins **S3 ≥1.454× / S5 ≥5.33×** with
   **0 of 12 over-budget** observations (D-043-era study, V-036); the
   historical thread-time contamination mechanism was addressed after
   `3563a0e`.
2. **AUTHORIZED** — the disclosure disposition only (recording the
   observation in the test module documentation and ledgers as a disclosed
   conservative-margin observation). The actual documentation change is a
   separately authorized task. **Assertions and test names are preserved
   unchanged** (identity baseline); **no new performance validation is
   claimed**.

Cross-reference: V-036; D-043 (study row); `B1_B7_HYGIENE_BACKLOG_ASSESSMENT.md` §B-4.

## D-057 · 2026-11-21 · G-P0-5e residual pointer dispositions — RETAIN UNTIL PUBLICATION approved

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **APPROVE RETENTION UNTIL PUBLICATION**.

1. **DISPOSITIONED** — the 18 residual local branch pointers (content-
   verified integrated, linear history) are **retained until publication has
   successfully landed**; deletion only after publication AND fresh
   verification of the exact pointer inventory; **no history rewriting**.
2. **BOUNDARY** — no branch is deleted or modified by this entry; the
   per-pointer schedule is a hygiene record feeding G-P0-10.

Cross-reference: frozen consolidated plan structural discovery (branch
inventory); matrix row 9.

## D-058 · 2026-11-21 · G-P0-6 GAP-13/B-8 — ACCEPT AS BLOCKED (protected V11 boundary)

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **ACCEPT AS BLOCKED**.

1. **ADJUDICATED** — the GAP-13/B-8 defect (`ztask5.md` cites the
   nonexistent commit `f3b2e8c` in the protected V11 worktree) is accepted
   as a recorded **P3 documentation defect** subject to the protected V11
   boundary; the staged P0-side correction remains preserved.
2. **BOUNDARY** — the correction remains pending a separately authorized
   V11-maintenance task; **this entry does not authorize access to or
   modification of V11** in any form.

Cross-reference: register §G-P0-6; `GAP13_BLOCKER_DOCUMENTATION.md`.

## D-059 · 2026-11-21 · G-P0-7 carried backlog — ACCEPT AS UNSOURCED for P0 disclosure

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **ACCEPT AS UNSOURCED FOR P0
DISCLOSURE**.

1. **INVENTORY ACCEPTED AS UNSOURCED** — T26, T28, T44, T45, Layer C, and
   here-strings: their defining documents are **unavailable in the P0
   repository** (V11-side) and their technical definitions remain
   **unverified** — both facts explicitly preserved.
2. **BOUNDARY** — no provenance is fabricated and no technical verification
   is claimed; sourcing remains possible later via a separately authorized
   V11 read authorization; Layer C also carries the D-053 scope note.

Cross-reference: register §G-P0-7; B3-ID authorization §9 reference.

## D-060 · 2026-11-21 · G-P0-8a pnpm — evidence tier ACCEPTED: NOT_ESTABLISHED (real-world committed lock)

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling). Ruling: **ACCEPT the recorded evidence tier as final P0 disclosure**.

Label preserved: **NOT_ESTABLISHED** for real-world committed-lock evidence
(corpus availability blocker — evidence-establishment report §1). This is a
separate, individual disposition; higher-tier evidence (corpus acquisition)
requires separate authorization. No unavailable validation is claimed to
have occurred.

## D-061 · 2026-11-21 · G-P0-8b Go — evidence tier ACCEPTED: REAL_WORLD declarations/membership; NOT_GENERATABLE graph artifacts

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling). Ruling: **ACCEPT the recorded evidence tiers as final P0 disclosure**.

Labels preserved: declarations/membership **REAL_WORLD** (established R2.4);
graph artifacts **NOT_GENERATABLE** (`go` CLI absent — GAP-R2-08; evidence-
establishment report §2). Graph-edge evidence beyond fixtures remains
unverifiable here; a Go toolchain acquisition requires separate
authorization. No unavailable validation is claimed.

## D-062 · 2026-11-21 · G-P0-8c Cargo/Rust — evidence tier ACCEPTED: REAL_WORLD lockfile edges; NOT_GENERATABLE metadata

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling). Ruling: **ACCEPT the recorded evidence tiers as final P0 disclosure**.

Labels preserved: lockfile edges **REAL_WORLD** (established R2.4); metadata
**NOT_GENERATABLE** (shim present, no default toolchain — report §3).
Metadata-dependent edge semantics (kinds/targets) remain unverified; a Cargo
toolchain acquisition requires separate authorization. No unavailable
validation is claimed.

## D-063 · 2026-11-21 · G-P0-8d .NET/NuGet — evidence tier ACCEPTED: FIXTURE-only lock tiers; NOT_GENERATABLE restore validation

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling). Ruling: **ACCEPT the recorded evidence tier as final P0 disclosure**.

Labels preserved: lock tiers **FIXTURE**-only; restore validation
**NOT_GENERATABLE** (SDK absent; fixtures never real-world — report §4).
Restore-tier evidence remains fixture-only; an SDK acquisition requires
separate authorization. No unavailable validation is claimed.

## D-064 · 2026-11-21 · G-P0-8e Gradle — evidence tier ACCEPTED: two-project REAL_WORLD; third-project capture NOT_RUN

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling). Ruling: **ACCEPT the recorded evidence tiers as final P0 disclosure**.

Labels preserved: two-project evidence **REAL_WORLD** (preserved +
hash-recorded); third-project capture **NOT_RUN** (wrapper download
approval-gated — report §5). Gradle real evidence remains the two JVM
projects only; wrapper-download approval requires separate authorization.
No unavailable validation is claimed.

## D-065 · 2026-11-21 · G-P0-9 R3 disposition — DEFER (not started; planning register acknowledged)

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **DEFER**.

1. **ADJUDICATED** — R3 remains **not started**; the R2 §10 planning
   register (`R2_FINAL_CLOSURE_AUDIT.md`: R3 planning readiness READY) is
   acknowledged as the input for future R3 planning.
2. **REQUIREMENTS TO RECONSIDER** — completed P0 closure AND a separate
   R3 authorization package. R3 is not started and the P0 scope is not
   expanded by this entry.

## D-066 · 2026-11-21 · V-012–V-016 historical traceability gap — PRESERVED AS DOCUMENTED HISTORICAL ARTIFACT

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **PRESERVE THE DOCUMENTED HISTORICAL
GAP** (no reconstruction).

1. **FACTS PRESERVED** — V-012 through V-016 were never created in the
   validation ledger (G-P0-3A audit finding: 40 entries, gaps at 12–16);
   the related historical evidence exists in committed review documents
   (`R2_3_FINAL_REVIEW.md` et al.); the existing D-016, D-021, and D-022
   references remain **historically traceable through those documents**.
2. **DISPOSITION** — no reconstruction is required for this disposition;
   the append-only ledger is left as-is; **any future reconstruction
   requires separate authorization and evidence-backed append-only
   entries**. No replacement validation entries are created by this entry.

## D-067 · 2026-11-21 · B-5b/B-5c commit packaging — APPROVED as a separate controlled exact-file-set commit

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **APPROVE SEPARATE CONTROLLED COMMIT
PACKAGING**.

1. **APPROVED** — the already owner-accepted B-5b/B-5c implementation and
   test files (`analysis/lock_graph/cargo.py`, `tools/oracle_cargo.py`,
   `tests/test_lock_graph_cargo.py`, `tests/test_oracle_diagnostics.py`)
   are approved for packaging as **one separate exact-file-set commit**
   under the established controlled procedure (fresh pre-staging
   verification, explicit-path staging, set equality, hash verification,
   post-commit verification).
2. **EXPLICIT EXCLUSIONS** — the runtime vulnerability cache
   (`data/.vuln_cache.json`), all other unrelated changes, untracked
   evidence, and any file outside the four approved paths.
3. **BOUNDARY** — this entry records approval of the packaging task ONLY;
   it does **not execute staging or committing**; execution requires its
   own authorized task with a fresh §9.1 declaration.

Cross-reference: D-045/D-046 (the acceptances whose commit condition this
approval satisfies); V-038/V-039.

## D-068 · 2026-11-21 · G-P0-5a publication — DEFERRED until governance decisions and controlled commit packaging are reconciled

DECISION AUTHORITY: Project Owner (explicit endorsement of the architecture
ruling presented 2026-11-21). Ruling: **DEFER PUBLICATION**.

1. **ADJUDICATED** — publication (audit-remote push) waits until the
   governance decisions recorded in D-052…D-067 and the controlled commit
   packaging (D-067) have been reconciled.
2. **PRESERVED** — the previously established **clean fast-forward
   requirement** for the 30-commit local lead over the audit remote
   tracking ref; no push, publication, tag, or remote operation is
   performed or authorized by this entry.

Cross-reference: D-043 (publication assessment READY-FOR-AUTHORIZATION —
deferred by this decision, not contradicted); register §G-P0-5a.
