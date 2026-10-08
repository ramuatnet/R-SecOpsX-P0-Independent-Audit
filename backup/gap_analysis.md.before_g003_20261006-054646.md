# R-SecOpsX V11 — Gap Analysis

**Phase 3 deliverable — the GAP step between BENCHMARK and IMPLEMENT.**

Generated from [`reports/gap_register.json`](../reports/gap_register.json)
by `python analysis/render_gap_register.py`. The JSON is the source of
truth; this document is derived, so the two cannot disagree.

Baseline inputs: Phase 2 enterprise capability matrix, the SAST class-A
benchmark, and the SCA class-A benchmark.

---

## 1. How to read this register

Every entry answers the same ten questions — problem, mature reference
tool, how that tool does it, current behaviour, actual gap,
enterprise-essential, research-relevant, cost, regression risk, exact
implementation location — because a capability is only worth building
when all ten have a defensible answer.

Two axes matter more than priority:

- **Evidence tier** — whether a benchmark actually demonstrated the gap.
  A gap that is merely *structural* has no number attached yet, and a gap
  marked *UNMEASURED* is one the current corpora **cannot see**. The
  class-A 100% score does not clear these.
- **Root-cause class** — so that when a new miss appears, it is triaged to
  a mechanism rather than to a symptom.

### Evidence tiers

| Tier | Meaning |
|---|---|
| **MEASURED_OPEN** | benchmark reproduced it; a number exists; not yet at target |
| **MEASURED_CLOSED** | benchmark reproduced it, it was fixed, and it re-benchmarked to target |
| **UNMEASURED** | the current corpora structurally cannot expose this |
| **STRUCTURAL** | confirmed by source inspection; no benchmark built for it yet |

### Root-cause class vocabulary

Used to classify both historical and future missed findings.

| Class | Definition |
|---|---|
| `ALIAS_GAP` | Receiver, alias, or object-field resolution missing. |
| `ARCH_GAP` | Structural shortfall: required stage does not exist as an independent stage. |
| `CONTRACT_GAP` | Test expectation and implementation contract conflict. |
| `COVERAGE_GAP` | Benchmark corpus does not cover the capability class. |
| `DATA_GAP` | Intelligence is a static placeholder rather than a live feed, or the source is absent. |
| `DISCOVERY_GAP` | Package inventory inaccurate: invented or missing entries. |
| `ECOSYSTEM_GAP` | Ecosystem or lockfile format unsupported. |
| `ENUM_GAP` | Required status or type enumeration unimplemented. |
| `EVIDENCE_GAP` | Finding or value produced but dropped, unlabelled, or mislabelled downstream. |
| `FORMAT_GAP` | Required output format absent. |
| `GRANULARITY_GAP` | Analysis performed at a coarser granularity than required. |
| `IDENTIFIER_GAP` | Required identifier scheme absent. |
| `MERGE_GAP` | Advisory data overwritten instead of merged. |
| `MODEL_GAP` | Required analytical model absent. |
| `PARSER_GAP` | No parser exists for the target language or construct. |
| `RESOLUTION_GAP` | Cannot resolve a symbol or constant to its concrete value. |
| `RULE_GAP` | Detection rule absent, or rules are not declarative/versioned. |
| `SANITIZER_GAP` | Sanitizer model absent or modelled for the wrong vulnerability class. |
| `SCOPE_GAP` | Scope/frame/binding resolution wrong, or analysis scope too narrow. |
| `SINK_GAP` | Sink not modelled, or not validated as concrete. |
| `SOURCE_GAP` | Taint source not modelled. |
| `STUB_GAP` | Placeholder implementation standing in for the required pipeline. |
| `TAINT_GAP` | Taint propagation, interprocedural reach, or path reconstruction incomplete. |
| `VERSION_PARSE_GAP` | Package version parsed incorrectly or its specifier retained. |
| `WIRING_GAP` | Component built and tested but never invoked. |

---

## 2. Register summary

| Priority | Open gaps |
|---|---:|
| P0 | 4 |
| P1 | 12 |
| P2 | 16 |
| P3 | 2 |
| **Total** | **34** |

| Evidence tier | Gaps | Meaning |
|---|---:|---|
| MEASURED_OPEN | 1 | benchmark reproduced it; a number exists; not yet at target |
| MEASURED_CLOSED | 1 | benchmark reproduced it, it was fixed, and it re-benchmarked to target |
| UNMEASURED | 2 | the current corpora structurally cannot expose this |
| STRUCTURAL | 30 | confirmed by source inspection; no benchmark built for it yet |

| Root-cause class | Gaps |
|---|---:|
| `MODEL_GAP` | 6 |
| `DATA_GAP` | 4 |
| `TAINT_GAP` | 3 |
| `ALIAS_GAP` | 2 |
| `COVERAGE_GAP` | 2 |
| `WIRING_GAP` | 2 |
| `ARCH_GAP` | 1 |
| `DISCOVERY_GAP` | 1 |
| `ECOSYSTEM_GAP` | 1 |
| `ENUM_GAP` | 1 |
| `EVIDENCE_GAP` | 1 |
| `FORMAT_GAP` | 1 |
| `GRANULARITY_GAP` | 1 |
| `IDENTIFIER_GAP` | 1 |
| `PARSER_GAP` | 1 |
| `RESOLUTION_GAP` | 1 |
| `RULE_GAP` | 1 |
| `SANITIZER_GAP` | 1 |
| `SCOPE_GAP` | 1 |
| `STUB_GAP` | 1 |
| `VERSION_PARSE_GAP` | 1 |

| Cost profile | Count | Regression risk | Count |
|---|---:|---|---:|
| XS | 2 | LOW | 14 |
| S | 7 | MED | 13 |
| M | 14 | HIGH | 7 |
| L | 7 |  |  |
| XL | 4 |  |  |

---

## 3. What the benchmarks actually established

### 3.1 SAST — `sast-multilang-2026-10` (class A)

| Metric | Phase 4 baseline | Phase 4b | Phase 4c | Now |
|---|---:|---:|---:|---:|
| True positives | 7 | 10 | 13 | **13** |
| False positives | 1 | 1 | 0 | **0** |
| False negatives | 6 | 3 | 0 | **0** |
| Precision | 87.50% | 90.91% | 100.00% | **100.00%** |
| Recall | 53.85% | 76.92% | 100.00% | **100.00%** |
| F1 | 66.67% | 83.33% | 100.00% | **100.00%** |

Per category at the end: SQLi 5/5, command injection 5/5, path
traversal 2/2, code injection 1/1 — recall 1.0 in every category,
0 false positives across all 6 negative controls.

**Root-cause classification of the misses that were closed:**

| Missed / false-positive finding | Class |
|---|---|
| Java findings dropped — optional `dump/*.py` layer raised and was swallowed | `ARTIFACT` → closed |
| Qualified `flask.request.args` not a source | `SOURCE_GAP` |
| Django `request.GET` / `request.POST` not a source | `SOURCE_GAP` |
| PHP `$id = $_GET[...]` → `system(...)` invisible | `TAINT_GAP` |
| JS `req.query.id` → `cp.execSync(...)` invisible | `TAINT_GAP` + `ALIAS_GAP` |
| Parameterised query reported as injection | `SANITIZER_GAP` |
| `html.escape` treated as a shell sanitizer | `SANITIZER_GAP` |
| Taint not killed on reassignment | `SCOPE_GAP` |
| Taint leaked across functions | `SCOPE_GAP` |
| `query = "SELECT 1"` treated as a source (NT-05) | `SCOPE_GAP` (binding kind) |
| PHP `system(` produced then dropped by the evidence gate | `EVIDENCE_GAP` |
| PHP `print` / JS `RegExp.exec` matched as sinks | `SINK_GAP` (no concrete-sink validator) |

> **The honest reading of a 100% class-A score.** It proves those twelve
> mechanisms are fixed. It does **not** bound the miss rate on
> applications the corpus never contained — see G-005. Every class-A
> defect is now a regression test, which is why the suite is 207 tests
> and not a headline number.

### 3.2 SCA — `sca-multilang-2026-10` (class A)

| Metric | Before | Now | Trivy | Grype |
|---|---:|---:|---:|---:|
| CVE precision | 49.4% | **100.0%** | 100.0% | 100.0% |
| CVE recall | 54.3% | **100.0%** | 100.0% | 100.0% |
| CVE F1 | 49.7% | **100.0%** | 100.0% | 100.0% |
| Discovery precision | 61.1% | **61.1%** | 91.7% | 100.0% |
| Discovery recall | 100.0% | **100.0%** | 100.0% | 100.0% |

**Root-cause classification of the CVE defects that were closed:**

| Defect | Class |
|---|---|
| `_parse_requirements` kept `==`, so OSV got `version="==2.19.1"` → 39 invented CVEs | `VERSION_PARSE_GAP` |
| `_parse_package_json` stored the raw npm range → 4 invented CVEs incl. `ms@2.1.3` | `VERSION_PARSE_GAP` |
| `apply_vulnerability_overrides` replaced OSV with the local override → log4j 7 → 2 CVEs | `MERGE_GAP` |
| PURL emitted as `pkg:pypi/requests@==2.19.1` (invalid) | `VERSION_PARSE_GAP` |

Ground truth came from OSV.dev queried per exact `package@version`
**before** any compared tool ran, so neither tool is the reference.

**The one measured gap that remains open here is G-006** — discovery
precision 61.1%, caused by 7 synthesised transitive dependencies with
`version: unknown`. They never match a CVE, so the CVE figures above
are unaffected, but they are invented entries in a deliverable SBOM.

---

## 4. Priority action register

Grouped by priority; within each priority, gaps are listed by id.

### P0 — 4 gaps

| ID | Domain | Gap | Root cause | Tier | Cost | Risk |
|---|---|---|---|---|---|---|
| G-001 | Vulnerability intelligence | EPSS is a static 8-CVE table, not a feed | `DATA_GAP` | STRUCTURAL | M | LOW |
| G-002 | Vulnerability intelligence | KEV is ~9 hard-coded records, not the CISA catalog | `DATA_GAP` | STRUCTURAL | S | LOW |
| G-003 | Reporting honesty | Static EPSS/KEV must be labelled STATIC_REFERENCE until live | `EVIDENCE_GAP` | STRUCTURAL | XS | LOW |
| G-004 | BOM correlation | `aibom_abom_correlation` built, tested, never invoked | `WIRING_GAP` | STRUCTURAL | S | MED |

### G-001 · P0 · Vulnerability intelligence

**EPSS is a static 8-CVE table, not a feed**

| Requirement | Answer |
|---|---|
| Problem | Prioritisation cites an `epss` field that is a hard-coded table covering 8 CVEs. Outside those 8 the value is absent yet is rendered with the same authority as real intelligence. |
| Mature reference tool | Exploit Prediction Scoring System (FIRST.org) via Grype / Dependency-Track |
| How that tool does it | Pulls the weekly EPSS CSV/JSON feed, indexes by CVE, stores the score with a fetch timestamp, and refreshes on a schedule. |
| Current R-SecOpsX behaviour | `scanner/epss_intelligence_engine.py:6-15` holds a literal table of 8 CVE→score pairs. No network fetch, no timestamp, no refresh. |
| **Actual gap** | **No live EPSS feed. Scores exist for ≤8 CVEs of the ~250k published.** |
| Root-cause class | `DATA_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | LOW |
| **Implementation location** | `scanner/epss_intelligence_engine.py:6-15` |
| Evidence | enterprise_capability_matrix.md §3; file contents inspected. |

### G-002 · P0 · Vulnerability intelligence

**KEV is ~9 hard-coded records, not the CISA catalog**

| Requirement | Answer |
|---|---|
| Problem | A `kev` field implies CISA known-exploited status. With ~9 records the platform will silently report `not in KEV` for the overwhelming majority of exploited CVEs — a false negative presented as a negative. |
| Mature reference tool | CISA KEV catalog, consumed by Trivy / Grype / Dependency-Track |
| How that tool does it | Fetches https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, indexes by CVE, refreshes on the catalog cadence. |
| Current R-SecOpsX behaviour | `scanner/kev_intelligence_engine.py:13-77` holds ~9 literal records. |
| **Actual gap** | **No live KEV catalog. Absence of a record is indistinguishable from 'not known exploited'.** |
| Root-cause class | `DATA_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | S (≤1 day) |
| Regression risk | LOW |
| **Implementation location** | `scanner/kev_intelligence_engine.py:13-77` |
| Evidence | enterprise_capability_matrix.md §3; file contents inspected. |

### G-003 · P0 · Reporting honesty

**Static EPSS/KEV must be labelled STATIC_REFERENCE until live**

| Requirement | Answer |
|---|---|
| Problem | Until G-001/G-002 land, any report that renders these fields as intelligence is making a claim the data does not support. |
| Mature reference tool | Snyk / Dependency-Track |
| How that tool does it | Omits the field entirely when the feed is unavailable rather than rendering a stale or placeholder value. |
| Current R-SecOpsX behaviour | Fields rendered without any static/placeholder marker. |
| **Actual gap** | **No `STATIC_REFERENCE` / `INFERRED` labelling on non-live intelligence.** |
| Root-cause class | `EVIDENCE_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | XS (hours) |
| Regression risk | LOW |
| **Implementation location** | `reporting/pdf_report.py (EPSS/KEV render blocks) + any JSON/CSV writer emitting the fields` |
| Evidence | enterprise_capability_matrix.md §3 'Critical honesty finding'. |

### G-004 · P0 · BOM correlation

**`aibom_abom_correlation` built, tested, never invoked**

| Requirement | Answer |
|---|---|
| Problem | The SBOM↔AI-BOM↔ABOM↔CBOM correlation capability — a declared research differentiator — never runs during a scan, so no product output contains it. |
| Mature reference tool | No mainstream tool does cross-BOM correlation (this is the differentiator). |
| How that tool does it | n/a — no mainstream equivalent; nearest are Dependency-Track's asset/programme linkage. |
| Current R-SecOpsX behaviour | `scanner/aibom_abom_correlation.py` (~360 L, 5 test files, 52 tests) is never imported by `main.py`. Only `secret_blast_radius_correlation_engine` runs (`main.py:2593`). |
| **Actual gap** | **Zero production invocation. Unblocked by 5h identity gating, which removed the fabrication risk.** |
| Root-cause class | `WIRING_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | ✅ yes |
| Cost | S (≤1 day) |
| Regression risk | MED |
| **Implementation location** | `main.py — call site alongside main.py:2593` |
| Evidence | grep: no import of aibom_abom_correlation from main.py; verified in Phase 3. |

### P1 — 12 gaps

| ID | Domain | Gap | Root cause | Tier | Cost | Risk |
|---|---|---|---|---|---|---|
| G-005 | Benchmark coverage | Benchmark classes B, C, D unmeasured — 100% does not generalise | `COVERAGE_GAP` | UNMEASURED | L | LOW |
| G-006 | SBOM / SCA | Discovery precision 61.1% — 7 synthesised transitive deps with unknown versions | `DISCOVERY_GAP` | MEASURED_OPEN | M | MED |
| G-007 | SBOM / SCA | Only 3 manifest formats and 1 lockfile; 3 ecosystems | `ECOSYSTEM_GAP` | STRUCTURAL | L | MED |
| G-008 | Reachability | Reachability is package-level; §10 function granularity and type enum absent | `GRANULARITY_GAP` | STRUCTURAL | XL | MED |
| G-009 | RCMSP | RCMSP decision policy is a 59-line stub | `STUB_GAP` | STRUCTURAL | L | HIGH |
| G-010 | Risk modelling | No compensating-controls model; no inherent vs residual risk | `MODEL_GAP` | STRUCTURAL | L | HIGH |
| G-011 | Crypto (CBOM) | CBOM does not resolve mode, key size, or curve | `RESOLUTION_GAP` | STRUCTURAL | M | LOW |
| G-012 | SAST / parsing | No non-Python parser — tree-sitter absent repo-wide | `PARSER_GAP` | STRUCTURAL | XL | MED |
| G-013 | SAST / data flow | No inter-file data flow for Python/JS/Go/C# | `TAINT_GAP` | STRUCTURAL | XL | MED |
| G-014 | Vulnerability intelligence | No exploit / PoC availability intelligence | `DATA_GAP` | STRUCTURAL | M | LOW |
| G-015 | Research differentiator | Cross-domain attack path SBOM→SAST→Agent→Input not implemented end-to-end | `MODEL_GAP` | STRUCTURAL | XL | MED |
| G-016 | Secrets | Git-history secret scanning absent | `SCOPE_GAP` | STRUCTURAL | M | LOW |

### G-005 · P1 · Benchmark coverage

**Benchmark classes B, C, D unmeasured — 100% does not generalise**

| Requirement | Answer |
|---|---|
| Problem | The only measured SAST/SCA corpora are class A (controlled synthetic). A perfect class-A score proves the previously-found defects are gone; it says nothing about OWASP-style applications, real-world repositories, or AI/LLM code. |
| Mature reference tool | OWASP Benchmark, DVWA, Juice Shop, SecurityShepherd; project corpora used by Semgrep/CodeQL CI suites |
| How that tool does it | Runs against curated applications with published expected results, plus seeded real-world repos, and reports per-category recall. |
| Current R-SecOpsX behaviour | `analysis/benchmark_sast_corpus.py` measures 13 vulns + 6 controls, all hand-authored. `analysis/benchmark_sca_corpus.py` measures 11 packages / 70 CVEs, all hand-authored. |
| **Actual gap** | **Classes B (OWASP apps), C (real-world OSS), D (AI/LLM corpus) have no ground truth and have never been run.** |
| Root-cause class | `COVERAGE_GAP` |
| Evidence tier | UNMEASURED |
| Enterprise-essential | ✅ yes |
| Research-relevant | ✅ yes |
| Cost | L (1–2 weeks) |
| Regression risk | LOW |
| **Implementation location** | `analysis/benchmark_sast_corpus.py (extend), analysis/benchmark_sca_corpus.py (extend); new corpora under a fixture root` |
| Evidence | enterprise_capability_matrix.md §1 note: 'class B and class C are still not measured, so 100% here does not generalise'. |

### G-006 · P1 · SBOM / SCA

**Discovery precision 61.1% — 7 synthesised transitive deps with unknown versions**

| Requirement | Answer |
|---|---|
| Problem | R-SecOpsX emits 18 packages where 11 are declared. The 7 extras are invented from a hardcoded table with `version: unknown`, `direct: False`. They are unverifiable claims inside a deliverable SBOM. |
| Mature reference tool | Trivy (91.7%), Grype (100.0%) on the same corpus |
| How that tool does it | Reads the lockfile's resolved graph (npm lock, poetry.lock, etc.) so transitive edges come from real resolution data, never from a hardcoded table. |
| Current R-SecOpsX behaviour | `scanner/sbom.py` `_add_transitive` synthesises certifi, jinja2, path-to-regexp, qs, sqlparse, urllib3, werkzeug. They never match a CVE, so CVE precision stays 100%. |
| **Actual gap** | **Discovery F1 75.9% vs Grype 100%. Invented inventory entries in a signed deliverable.** |
| Root-cause class | `DISCOVERY_GAP` |
| Evidence tier | MEASURED_OPEN |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | MED |
| **Implementation location** | `scanner/sbom.py `_add_transitive`` |
| Evidence | reports/benchmark_reconciliation_sca.md: R-SecOpsX pkgs 18, precision 61.1%; extras listed by name. |

### G-007 · P1 · SBOM / SCA

**Only 3 manifest formats and 1 lockfile; 3 ecosystems**

| Requirement | Answer |
|---|---|
| Problem | Go, .NET, Ruby, Rust and PHP projects are invisible to SBOM generation, and npm ranges are only resolvable when package-lock.json happens to be present. |
| Mature reference tool | Trivy, Syft (15+ ecosystems each) |
| How that tool does it | Per-ecosystem manifest readers plus lockfile parsers that yield exact resolved versions, then a PURL for each. |
| Current R-SecOpsX behaviour | `scanner/sbom.py:731-745` handles requirements*.txt, package.json, pom.xml; `:739` package-lock.json only. |
| **Actual gap** | **No poetry.lock / pnpm-lock / yarn.lock / go.sum / Cargo.lock / composer.lock; no Go/.NET/NuGet/RubyGems/Crates/Composer.** |
| Root-cause class | `ECOSYSTEM_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | L (1–2 weeks) |
| Regression risk | MED |
| **Implementation location** | `scanner/sbom.py:731-745 and lockfile readers alongside npm_lock_graph_v2.py` |
| Evidence | enterprise_capability_matrix.md §2 'Manifest discovery' and 'Lockfiles' rows. |

### G-008 · P1 · Reachability

**Reachability is package-level; §10 function granularity and type enum absent**

| Requirement | Answer |
|---|---|
| Problem | The product is described as reachability-aware. It can only say whether an *import* of a vulnerable package appears — not whether the vulnerable function is on a call path. |
| Mature reference tool | Semgrep Supply Chain (NATIVE function-level), Trivy reachability (PARTIAL) |
| How that tool does it | Resolves the advisory's affected symbol, indexes the project's call graph, and reports whether that symbol is reachable; emits a reachability type (DIRECT/INDIRECT/...). |
| Current R-SecOpsX behaviour | `scanner/reachability.py:372` regex-extracts imports, matches to SBOM, emits REACHABLE/UNREACHABLE/UNKNOWN at `:273,343` with confidence 0.85/0.65/0.30. |
| **Actual gap** | **No `vulnerable_function`, no `call_path`, no DIRECT/INDIRECT/TRANSITIVE/CALL_FLOW/DATA_FLOW/CONFIGURATION/RUNTIME enum.** |
| Root-cause class | `GRANULARITY_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | ✅ yes |
| Cost | XL (multi-week) |
| Regression risk | MED |
| **Implementation location** | `scanner/reachability.py:227,238,250,273,343,372; §10 schema fields` |
| Evidence | enterprise_capability_matrix.md §4; 'Never infer from install alone' is correctly implemented and must be preserved. |

### G-009 · P1 · RCMSP

**RCMSP decision policy is a 59-line stub**

| Requirement | Answer |
|---|---|
| Problem | The platform's stated risk-decision capability is a hard-coded 3-branch function, so every risk decision reduces to three rules with no policy inputs. |
| Mature reference tool | Dependency-Track risk acceptance policy; internal GS1 RCMSP-style policy engines |
| How that tool does it | Evaluates a declarative policy over scored inputs (severity, exploitability, exposure, criticality, control coverage) and returns a decision with provenance. |
| Current R-SecOpsX behaviour | `core/rcmsp.py` = 59 lines; `evaluate_rcmsp:36` hard-codes 3 branches. |
| **Actual gap** | **§28 pipeline not implemented; no policy inputs beyond the three branches.** |
| Root-cause class | `STUB_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | ✅ yes |
| Cost | L (1–2 weeks) |
| Regression risk | HIGH |
| **Implementation location** | `core/rcmsp.py:36 (extend from 59 L)` |
| Evidence | enterprise_capability_matrix.md §7. |

### G-010 · P1 · Risk modelling

**No compensating-controls model; no inherent vs residual risk**

| Requirement | Answer |
|---|---|
| Problem | Findings carry no notion that a control may reduce residual risk, so all findings of a severity are treated identically regardless of compensating controls. |
| Mature reference tool | Dependency-Track (risk score with control context); NIST 800-30 style inherent/residual modelling |
| How that tool does it | Stores controls against assets/services, applies them as a multiplier/offset to inherent risk, and reports both values with provenance. |
| Current R-SecOpsX behaviour | Prose strings only: `sast.py:224`, `legacy_protocol_engine.py:88`. |
| **Actual gap** | **No controls module; §16 unmet; inherent vs residual risk not distinguished.** |
| Root-cause class | `MODEL_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | L (1–2 weeks) |
| Regression risk | HIGH |
| **Implementation location** | `new module + sast.py:224, legacy_protocol_engine.py:88` |
| Evidence | enterprise_capability_matrix.md §7. |

### G-011 · P1 · Crypto (CBOM)

**CBOM does not resolve mode, key size, or curve**

| Requirement | Answer |
|---|---|
| Problem | CBOM reports 'AES present' without saying whether it is GCM or ECB, and 'RSA present' without key size — so a weak-configuration finding is impossible to make. |
| Mature reference tool | Microsoft SBOM-Tool / Syft crypto inventory; OWASP crypto guidance |
| How that tool does it | Resolves the algorithm call's arguments (mode constant, key-size constant) through symbol/constant propagation, and records mode+size+padding on the crypto element. |
| Current R-SecOpsX behaviour | `cbom.py:70` AES rule text literally reads 'Verify AES mode is GCM/CTR'; `cbom.py:84` RSA reads 'Verify RSA key size ≥2048'. Regex over literals only. |
| **Actual gap** | **Mode, key size, curve, padding, protocol all unmet (§21).** |
| Root-cause class | `RESOLUTION_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | LOW |
| **Implementation location** | `scanner/cbom.py:70,84,118` |
| Evidence | enterprise_capability_matrix.md §6. |

### G-012 · P1 · SAST / parsing

**No non-Python parser — tree-sitter absent repo-wide**

| Requirement | Answer |
|---|---|
| Problem | Every non-Python language is analysed by regex + brace matching. Accepted file extensions (.kt .scala .rb .cs .cpp .c .h .vb) have no parser, so inclusion in SCANNABLE_EXT must not be read as support. |
| Mature reference tool | Semgrep, CodeQL (NATIVE parsers for all supported languages) |
| How that tool does it | Embeds a real grammar per language (tree-sitter for Semgrep) and produces a CST/AST consumed by shared data-flow passes. |
| Current R-SecOpsX behaviour | Python uses `ast` (`taint_engine.py:96`). Repo grep for tree-sitter/javalang = 0. `sast.py:42` SCANNABLE_EXT lists 7 further extensions. |
| **Actual gap** | **9 of 12 listed languages are PATTERN_ONLY; none of Rust/PowerShell supported.** |
| Root-cause class | `PARSER_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | XL (multi-week) |
| Regression risk | MED |
| **Implementation location** | `new parser module; scanner/taint_engine.py:96; scanner/sast.py:42` |
| Evidence | enterprise_capability_matrix.md §8 language coverage matrix. |

### G-013 · P1 · SAST / data flow

**No inter-file data flow for Python/JS/Go/C#**

| Requirement | Answer |
|---|---|
| Problem | A source in one file and a sink in another are never connected, so the most common real-world web-app pattern (router → handler → repository) is invisible. |
| Mature reference tool | CodeQL (NATIVE), Semgrep interfile (paid), Fortify/Checkmarx |
| How that tool does it | Builds a cross-file call/summary graph and propagates taint over summaries between files. |
| Current R-SecOpsX behaviour | Only Java has cross-file flow (`java_semantic_j5.py`). Python has a `_tainted_returns` heuristic. |
| **Actual gap** | **No inter-file flow for Python/JS/Go/C# (§ matrix MUST_IMPLEMENT).** |
| Root-cause class | `TAINT_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | ✅ yes |
| Cost | XL (multi-week) |
| Regression risk | MED |
| **Implementation location** | `scanner/taint_engine.py (Python path), new inter-file graph module` |
| Evidence | enterprise_capability_matrix.md §1 'Inter-file analysis' row. |

### G-014 · P1 · Vulnerability intelligence

**No exploit / PoC availability intelligence**

| Requirement | Answer |
|---|---|
| Problem | Prioritisation cannot distinguish 'theoretically exploitable' from 'public exploit exists today', which is the single largest practical severity lever. |
| Mature reference tool | Snyk, GitHub Advisory, Grype (PARTIAL) |
| How that tool does it | Joins advisory records to exploit databases / GitHub PoC references and stores a boolean-with-provenance. |
| Current R-SecOpsX behaviour | Absent (§3 MUST_IMPLEMENT). |
| **Actual gap** | **No exploit intelligence of any kind.** |
| Root-cause class | `DATA_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | LOW |
| **Implementation location** | `scanner/vulnerability_intel.py alongside query_osv_batch:321` |
| Evidence | enterprise_capability_matrix.md §3 'Exploit / PoC availability' row. |

### G-015 · P1 · Research differentiator

**Cross-domain attack path SBOM→SAST→Agent→Input not implemented end-to-end**

| Requirement | Answer |
|---|---|
| Problem | The declared research novelty — stitching a dependency to a tainted sink to an AI agent to an untrusted input — does not exist as a single traversable path. |
| Mature reference tool | No mainstream equivalent (this is the differentiator). |
| How that tool does it | n/a |
| Current R-SecOpsX behaviour | Each domain produces its own findings; `core/attack_graph.py` `get_attack_paths()`/`get_pivot_points()` exist and are contract-tested but are not fed cross-domain edges. |
| **Actual gap** | **§26 unmet: no end-to-end cross-domain path.** |
| Root-cause class | `MODEL_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | ✅ yes |
| Cost | XL (multi-week) |
| Regression risk | MED |
| **Implementation location** | `core/attack_graph.py:48,119 fed from sbom/sast/aibom correlation outputs` |
| Evidence | enterprise_capability_matrix.md §7 last row. |

### G-016 · P1 · Secrets

**Git-history secret scanning absent**

| Requirement | Answer |
|---|---|
| Problem | A secret deleted in the current working tree is never found, although it remains fully exploitable from history — this is the primary way real secret leaks are discovered. |
| Mature reference tool | Gitleaks, TruffleHog, detect-secrets (all NATIVE) |
| How that tool does it | Walks git objects/commits, applies the same rules per revision, and reports the commit where the secret was introduced plus whether it was later removed. |
| Current R-SecOpsX behaviour | Working-tree scan only. |
| **Actual gap** | **No history traversal, no entropy-over-commits.** |
| Root-cause class | `SCOPE_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | LOW |
| **Implementation location** | `scanner/secret_intelligence.py (history pass alongside SECRET_RULES:40)` |
| Evidence | enterprise_capability_matrix.md §5. |

### P2 — 16 gaps

| ID | Domain | Gap | Root cause | Tier | Cost | Risk |
|---|---|---|---|---|---|---|
| G-017 | SAST / taint | No field or alias sensitivity — TaintedVar tracks a name only | `ALIAS_GAP` | STRUCTURAL | L | HIGH |
| G-018 | SAST / taint | Import-alias resolution covers child_process only | `ALIAS_GAP` | STRUCTURAL | M | MED |
| G-019 | SAST / taint | Python interprocedural reach is a heuristic | `TAINT_GAP` | STRUCTURAL | L | HIGH |
| G-020 | SAST / architecture | Rules are inline Python dicts — no schema, no rule test harness | `RULE_GAP` | STRUCTURAL | M | MED |
| G-021 | SAST / false positives | No unified FP suppression framework | `MODEL_GAP` | STRUCTURAL | M | MED |
| G-022 | SAST / evidence | Path reconstruction is a flat string chain | `TAINT_GAP` | STRUCTURAL | M | MED |
| G-023 | SAST / sanitizers | Sanitizer sets incomplete per language | `SANITIZER_GAP` | STRUCTURAL | M | HIGH |
| G-024 | SAST / architecture | AST is fused into the taint engine, not a standalone branch | `ARCH_GAP` | STRUCTURAL | M | HIGH |
| G-025 | SBOM / SCA | SPDX output missing (CycloneDX only) | `FORMAT_GAP` | STRUCTURAL | M | LOW |
| G-026 | SBOM / SCA | CPE absent — NVD-only advisories unreachable | `IDENTIFIER_GAP` | STRUCTURAL | M | LOW |
| G-027 | Vulnerability intelligence | Single advisory source (OSV); no provenance timestamp/signature | `DATA_GAP` | STRUCTURAL | M | MED |
| G-028 | Reachability | Reachability confidence: 3 tiers, 2 labels; no lifecycle state | `ENUM_GAP` | STRUCTURAL | S | LOW |
| G-029 | Secrets | No allowlist/baseline; no revocation guidance | `MODEL_GAP` | STRUCTURAL | S | LOW |
| G-030 | VEX | VEX lacks justification provenance and confidence | `MODEL_GAP` | STRUCTURAL | S | LOW |
| G-031 | Graph / reporting | Graph schema validated but never surfaced in reports | `WIRING_GAP` | STRUCTURAL | S | LOW |
| G-032 | Risk modelling | No asset/CMDB criticality model | `MODEL_GAP` | STRUCTURAL | L | MED |

### G-017 · P2 · SAST / taint

**No field or alias sensitivity — TaintedVar tracks a name only**

| Requirement | Answer |
|---|---|
| Problem | `user.name` tainted does not make `user` tainted, and object fields passed around are invisible, so object-style flows are missed entirely. |
| Mature reference tool | CodeQL (NATIVE), SonarQube (NATIVE), Semgrep (PARTIAL) |
| How that tool does it | Tracks tainted access paths (base.field) and unifies aliases at assignment/parameter pass. |
| Current R-SecOpsX behaviour | `TaintedVar` records a bare identifier name. |
| **Actual gap** | **Object-field flows invisible; no alias unification.** |
| Root-cause class | `ALIAS_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | ✅ yes |
| Cost | L (1–2 weeks) |
| Regression risk | HIGH |
| **Implementation location** | `scanner/taint_engine.py TaintedVar definition and visit_Assign/visit_AugAssign` |
| Evidence | enterprise_capability_matrix.md §1 'Alias / field sensitivity' row. |

### G-018 · P2 · SAST / taint

**Import-alias resolution covers child_process only**

| Requirement | Answer |
|---|---|
| Problem | Only `child_process` receivers are resolved. Any other aliased import producing a sink (e.g. a wrapped exec, a db client) matches by substring and can both miss and over-match. |
| Mature reference tool | Semgrep, CodeQL (NATIVE import resolution) |
| How that tool does it | Resolves every import to its module of origin and attributes members to that origin. |
| Current R-SecOpsX behaviour | `_child_process_names` / `_project_child_process_alias` model one module. |
| **Actual gap** | **Single-module alias model.** |
| Root-cause class | `ALIAS_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | MED |
| **Implementation location** | `scanner/taint_engine.py `_child_process_names`, `_project_child_process_alias`` |
| Evidence | enterprise_capability_matrix.md §1 'Import-alias resolution' row. |

### G-019 · P2 · SAST / taint

**Python interprocedural reach is a heuristic**

| Requirement | Answer |
|---|---|
| Problem | Tainted values returned from a function are approximated rather than tracked, so returns are either missed or over-approximated. |
| Mature reference tool | CodeQL (NATIVE), Semgrep (function-local) |
| How that tool does it | Computes a function summary: tainted-in → tainted-out, then applies summaries at call sites. |
| Current R-SecOpsX behaviour | `_tainted_returns` heuristic. |
| **Actual gap** | **No real function summaries for Python.** |
| Root-cause class | `TAINT_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | ✅ yes |
| Cost | L (1–2 weeks) |
| Regression risk | HIGH |
| **Implementation location** | `scanner/taint_engine.py `_tainted_returns`` |
| Evidence | enterprise_capability_matrix.md §1 'Interprocedural (same file)' row. |

### G-020 · P2 · SAST / architecture

**Rules are inline Python dicts — no schema, no rule test harness**

| Requirement | Answer |
|---|---|
| Problem | Rules cannot be versioned, diffed, or validated, and there is no harness that asserts each rule fires on a positive and stays quiet on a negative. |
| Mature reference tool | Semgrep (YAML rules with message/parity metadata), CodeQL packs |
| How that tool does it | Declarative rule files with a schema, linting, and a per-rule test fixture. |
| Current R-SecOpsX behaviour | `REGEX_RULES` + ~90 `ENTERPRISE_RULES` inline in `scanner/sast.py`. |
| **Actual gap** | **No rule schema; no per-rule test harness.** |
| Root-cause class | `RULE_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | MED |
| **Implementation location** | `scanner/sast.py REGEX_RULES / ENTERPRISE_RULES` |
| Evidence | enterprise_capability_matrix.md §1 'Query/rule architecture' row. |

### G-021 · P2 · SAST / false positives

**No unified FP suppression framework**

| Requirement | Answer |
|---|---|
| Problem | Suppression is ad-hoc per rule (`_is_client_side_ssrf_context` etc.), so a new rule silently gains no suppression capability and existing suppressions are inconsistent. |
| Mature reference tool | Semgrep `# nosemgrep` + triage states; SonarQube suppressions with expiry |
| How that tool does it | A single suppression model (inline annotation, baseline file, or triage state) applied uniformly, with reason and expiry. |
| Current R-SecOpsX behaviour | Per-rule bespoke validators. |
| **Actual gap** | **No unified suppression model; no baseline.** |
| Root-cause class | `MODEL_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | MED |
| **Implementation location** | `scanner/sast.py validators; core/analyzer.py enrich_finding:528` |
| Evidence | enterprise_capability_matrix.md §1 'FP suppression framework' row. |

### G-022 · P2 · SAST / evidence

**Path reconstruction is a flat string chain**

| Requirement | Answer |
|---|---|
| Problem | The reported path is a concatenation, not a sequence of program points with conditions, so an analyst cannot verify or step through it. |
| Mature reference tool | CodeQL (paths with conditions), Fortify (numbered trace) |
| How that tool does it | Emits an ordered list of (file, line, condition) nodes and renders them as a trace. |
| Current R-SecOpsX behaviour | `TaintVisitor._make_path:144` builds a string chain. |
| **Actual gap** | **No structured path, no path condition, no trace UI.** |
| Root-cause class | `TAINT_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | MED |
| **Implementation location** | `scanner/taint_engine.py `_make_path:144`` |
| Evidence | enterprise_capability_matrix.md §1 'Path reconstruction' row. |

### G-023 · P2 · SAST / sanitizers

**Sanitizer sets incomplete per language**

| Requirement | Answer |
|---|---|
| Problem | Phase 4 established per-vuln-class sanitization (html.escape counts for XSS, not for a shell sink), but the class×language matrix is populated only where a defect forced it. |
| Mature reference tool | CodeQL sanitizer models, Semgrep taint mode `by-side-effect`/sanitizers |
| How that tool does it | Declares sanitizers per sink family per language, so a sanitizer only declassifies the classes it actually protects. |
| Current R-SecOpsX behaviour | `_sanitizer_classes` covering the classes already regression-tested. |
| **Actual gap** | **Coverage driven by found defects, not by a systematic matrix.** |
| Root-cause class | `SANITIZER_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | HIGH |
| **Implementation location** | `scanner/taint_engine.py `_sanitizer_classes`` |
| Evidence | enterprise_capability_matrix.md §1 'Sanitizer modelling' row; FN7/FN11 controls in phase4_taint_tranche_check.py. |

### G-024 · P2 · SAST / architecture

**AST is fused into the taint engine, not a standalone branch**

| Requirement | Answer |
|---|---|
| Problem | Architecture diagrams claim 5 analysis branches; AST is not one of them, so AST-based rules cannot run without going through taint. |
| Mature reference tool | Semgrep, CodeQL (parser → separate analyses) |
| How that tool does it | Parse once into an AST service consumed independently by each analysis. |
| Current R-SecOpsX behaviour | AST parsing lives inside `taint_engine.py`. |
| **Actual gap** | **No standalone AST branch.** |
| Root-cause class | `ARCH_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | HIGH |
| **Implementation location** | `scanner/taint_engine.py (extract) / new scanner/ast_branch.py` |
| Evidence | enterprise_capability_matrix.md §1 'Standalone AST branch' row. |

### G-025 · P2 · SBOM / SCA

**SPDX output missing (CycloneDX only)**

| Requirement | Answer |
|---|---|
| Problem | Enterprises and regulators frequently require SPDX; today only CycloneDX is emitted, so the deliverable fails a format requirement outright. |
| Mature reference tool | Syft (both), Trivy (both), Dependency-Track (both) |
| How that tool does it | Maps the internal component graph to SPDX 2.3/3.0 document fields. |
| Current R-SecOpsX behaviour | `reporting/cyclonedx_export.py` only. |
| **Actual gap** | **No SPDX writer.** |
| Root-cause class | `FORMAT_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | LOW |
| **Implementation location** | `new reporting/spdx_export.py beside cyclonedx_export.py` |
| Evidence | enterprise_capability_matrix.md §2 'SPDX / CycloneDX output' row. |

### G-026 · P2 · SBOM / SCA

**CPE absent — NVD-only advisories unreachable**

| Requirement | Answer |
|---|---|
| Problem | Advisories published only to NVD cannot be joined, because no CPE is produced. |
| Mature reference tool | Dependency-Check (CPE-native), Trivy, Grype |
| How that tool does it | Builds a CPE 2.3 string from vendor/product/version derived from the PURL and manifest metadata. |
| Current R-SecOpsX behaviour | PURL is NATIVE (`package_intelligence.py:471`); CPE absent. |
| **Actual gap** | **No CPE generation or matching.** |
| Root-cause class | `IDENTIFIER_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | LOW |
| **Implementation location** | `scanner/package_intelligence.py:471 (alongside PURL)` |
| Evidence | enterprise_capability_matrix.md §2 'CPE' row. |

### G-027 · P2 · Vulnerability intelligence

**Single advisory source (OSV); no provenance timestamp/signature**

| Requirement | Answer |
|---|---|
| Problem | Advisories visible only in NVD/GHSA-native feeds are unreachable, and cached records carry no fetch time, so staleness cannot be audited. |
| Mature reference tool | Trivy, Grype, Snyk (multiple sources with provenance) |
| How that tool does it | Merges OSV + NVD + GHSA per identifier with aliases, and stamps each record with source and fetch time. |
| Current R-SecOpsX behaviour | `vulnerability_intel.py:11,321,397` OSV batch only; provenance is the literal string `"source": "OSV"`. |
| **Actual gap** | **One source; no fetch timestamp or signature.** |
| Root-cause class | `DATA_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | M (days) |
| Regression risk | MED |
| **Implementation location** | `scanner/vulnerability_intel.py:11,321,397` |
| Evidence | enterprise_capability_matrix.md §3 'Advisory source' and 'Provenance on intel' rows. |

### G-028 · P2 · Reachability

**Reachability confidence: 3 tiers, 2 labels; no lifecycle state**

| Requirement | Answer |
|---|---|
| Problem | Only MEDIUM/LOW are derivable from 0.85/0.65/0.30, and there is no UNKNOWN→KEV lifecycle transition, so status evolution over time is not representable. |
| Mature reference tool | Dependency-Track (component status lifecycle) |
| How that tool does it | Keeps a status enum with transitions and records who/when changed it. |
| Current R-SecOpsX behaviour | `reachability.py:227,238,250`; no lifecycle state anywhere. |
| **Actual gap** | **Confidence collapses to 2 labels; no lifecycle enum.** |
| Root-cause class | `ENUM_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | S (≤1 day) |
| Regression risk | LOW |
| **Implementation location** | `scanner/reachability.py:227,238,250` |
| Evidence | enterprise_capability_matrix.md §3 and §4 rows. |

### G-029 · P2 · Secrets

**No allowlist/baseline; no revocation guidance**

| Requirement | Answer |
|---|---|
| Problem | Known-good values are re-reported on every scan, and a detected secret gives the analyst no remediation path beyond 'rotate'. |
| Mature reference tool | Gitleaks baseline file, TruffleHog verified+guidance |
| How that tool does it | A committed baseline of accepted findings, plus per-provider revocation instructions. |
| Current R-SecOpsX behaviour | Context scoring only (`_shannon_entropy:222`, thresholds `:241-243`); `validation_status: OFFLINE_ONLY_NOT_VALIDATED` at `:793` is correctly labelled. |
| **Actual gap** | **No allowlist/baseline; §22 revocation guidance absent.** |
| Root-cause class | `MODEL_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | S (≤1 day) |
| Regression risk | LOW |
| **Implementation location** | `scanner/secret_intelligence.py (baseline + guidance tables)` |
| Evidence | enterprise_capability_matrix.md §5 rows. |

### G-030 · P2 · VEX

**VEX lacks justification provenance and confidence**

| Requirement | Answer |
|---|---|
| Problem | A VEX statement asserting 'not affected' without a justification or who asserted it cannot be trusted or audited downstream. |
| Mature reference tool | Dependency-Track VEX (NATIVE) |
| How that tool does it | Emits each statement with justification, rationale, author, date, and confidence. |
| Current R-SecOpsX behaviour | `reporting/vex_export.py` (112 L), package-level, 4 statuses at `:29,44,54`. |
| **Actual gap** | **No justification, provenance, or confidence.** |
| Root-cause class | `MODEL_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | S (≤1 day) |
| Regression risk | LOW |
| **Implementation location** | `reporting/vex_export.py:29,44,54` |
| Evidence | enterprise_capability_matrix.md §2 'VEX' row. |

### G-031 · P2 · Graph / reporting

**Graph schema validated but never surfaced in reports**

| Requirement | Answer |
|---|---|
| Problem | A validated security graph exists but no consumer sees it, so the contract work has no product effect. |
| Mature reference tool | n/a |
| How that tool does it | n/a |
| Current R-SecOpsX behaviour | `core/graph_schema.py` `SecurityGraph.validate:58` runs; reports do not include the graph. |
| **Actual gap** | **Graph computed but not emitted.** |
| Root-cause class | `WIRING_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | — no |
| Research-relevant | ✅ yes |
| Cost | S (≤1 day) |
| Regression risk | LOW |
| **Implementation location** | `core/graph_schema.py:58 + reporting/pdf_report.py` |
| Evidence | enterprise_capability_matrix.md §7 'Graph schema' row. |

### G-032 · P2 · Risk modelling

**No asset/CMDB criticality model**

| Requirement | Answer |
|---|---|
| Problem | Risk cannot be weighted by business criticality because there is no criticality source; only path-based classification exists. |
| Mature reference tool | Dependency-Track asset/programme model |
| How that tool does it | Resolves a component to an asset, reads criticality from a CMDB-style registry, and weights risk accordingly. |
| Current R-SecOpsX behaviour | `analysis_context.py:208` path classification + AI-BOM assets. |
| **Actual gap** | **No CMDB/criticality model (§15 unmet).** |
| Root-cause class | `MODEL_GAP` |
| Evidence tier | STRUCTURAL |
| Enterprise-essential | ✅ yes |
| Research-relevant | — no |
| Cost | L (1–2 weeks) |
| Regression risk | MED |
| **Implementation location** | `analysis/analysis_context.py:208 + new criticality source` |
| Evidence | enterprise_capability_matrix.md §7 'Asset / business criticality' row. |

### P3 — 2 gaps

| ID | Domain | Gap | Root cause | Tier | Cost | Risk |
|---|---|---|---|---|---|---|
| G-033 | SBOM / SCA | Ranges without a lockfile resolve to `unknown` (deliberate recall loss) | `VERSION_PARSE_GAP` | MEASURED_CLOSED | S | HIGH |
| G-034 | Verification | Temporal age (6 dimensions) claimed but unverified | `COVERAGE_GAP` | UNMEASURED | XS | LOW |

### G-033 · P3 · SBOM / SCA

**Ranges without a lockfile resolve to `unknown` (deliberate recall loss)**

| Requirement | Answer |
|---|---|
| Problem | PEP 440 and npm ranges with no lockfile cannot be pinned, so those packages are skipped by advisory lookup and may carry unreported CVEs. |
| Mature reference tool | Trivy/Grype resolve ranges by reading the lockfile, or by picking the highest matching version. |
| How that tool does it | Never queries an advisory API with an unpinned version; resolves first or omits. |
| Current R-SecOpsX behaviour | `_resolve_pinned_version` / `_resolve_npm_version` return `unknown` for ranges; `ECOSYSTEM_MAP` skips `version == "unknown"`. |
| **Actual gap** | **Recall loss on unlocked manifests — accepted by design, because guessing a version produced 39 invented CVEs (defect closed in the SCA cycle).** |
| Root-cause class | `VERSION_PARSE_GAP` |
| Evidence tier | MEASURED_CLOSED |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | S (≤1 day) |
| Regression risk | HIGH |
| **Implementation location** | `scanner/sbom.py `_resolve_pinned_version`, `_resolve_npm_version`` |
| Evidence | Reversible only by reintroducing invented CVEs; tracked as action 5g. Kept deliberately. |

### G-034 · P3 · Verification

**Temporal age (6 dimensions) claimed but unverified**

| Requirement | Answer |
|---|---|
| Problem | `vulnerability_age_engine.py` exists but §11's six distinct age dimensions have never been asserted, so the capability is claimed without evidence. |
| Mature reference tool | n/a |
| How that tool does it | n/a |
| Current R-SecOpsX behaviour | Engine present; no test asserts the six dimensions are distinct and correct. |
| **Actual gap** | **Unverified claim — verify before asserting support.** |
| Root-cause class | `COVERAGE_GAP` |
| Evidence tier | UNMEASURED |
| Enterprise-essential | — no |
| Research-relevant | — no |
| Cost | XS (hours) |
| Regression risk | LOW |
| **Implementation location** | `analysis/vulnerability_age_engine.py + new test` |
| Evidence | enterprise_capability_matrix.md §7 'Temporal age' row: 'Verify before claiming'. |

---

## 5. Closed during this program

Retained so the trend is auditable and so a closed root cause is not
re-opened.

| Outcome | Root-cause classes involved |
|---|---|
| SAST class A recall 53.85% → 100% | `ARTIFACT`, `SOURCE_GAP`, `TAINT_GAP`, `SANITIZER_GAP`, `SCOPE_GAP`, `SINK_GAP` |
| SAST class A precision 87.50% → 100% | `SANITIZER_GAP`, `SCOPE_GAP`, `SOURCE_GAP` |
| SCA CVE F1 49.7% → 100% | `VERSION_PARSE_GAP`, `MERGE_GAP` |
| correlate() contract conflict | `CONTRACT_GAP`, `WIRING_GAP` |

---

## 6. Explicitly **not** proposed

The register is bounded in both directions. These were considered and
rejected, so they are not silently re-proposed later.

| Considered | Why not |
|---|---|
| Malicious-package detection | Already NATIVE (malicious_package_intelligence.py); no gap. |
| PURL generation | Already NATIVE and spec-correct after the SCA fixes. |
| License inventory | Already NATIVE via license_matrix_engine.py / license_policy_engine.py. |
| Shannon entropy for secrets | Already NATIVE with per-charset thresholds. |
| CVSS base score computation | Already NATIVE and computed from the vector, not just copied. |
| Install-alone reachability inference | Deliberately conservative and correct; must NOT be changed (UNKNOWN never becomes REACHABLE). |
| Bare source tokens in TAINT_SOURCES removed | Deliberately kept for FN safety; disambiguated by binding kind instead. |
| correlate() strict no-evidence fallback removal | Boundary fallback is the documented contract and is asserted by 4 passing tests; removing it would be churn without a defect. |

---

## 7. Next phase

Recommended order — close measurement before adding capability:

1. **G-003 then G-001/G-002** — labelling static EPSS/KEV is `XS` and
   removes an active honesty defect; the live feeds follow.
2. **G-005 (class B)** — build the OWASP-application corpus so the SAST
   number means something outside the synthetic set. This is the cheapest
   way to find out whether the 100% holds, and it is the input that makes
   every later `TAINT_GAP`/`PARSER_GAP` finding evidence-backed rather
   than structural.
3. **G-006** — the one P1 with an existing measured number attached.

G-004 (wiring `correlate()`) is unblocked and cheap, but it changes what
ships in reports and should be its own gated step.

Register generated 2026-10-06.
