# R-SecOpsX V11 — Enterprise Capability Matrix

**Phase 2 deliverable — Enterprise Benchmark**
**Status:** ACTIVE BASELINE · **Date:** 2026-10-05 · **Repository:** `D:\Data\Code test\R-SecOpsX_V11`

> **Phase 3 follow-on.** The prioritised, root-cause-classified gap register derived from
> this matrix plus both class-A benchmarks lives in [`gap_analysis.md`](gap_analysis.md),
> with [`../reports/gap_register.json`](../reports/gap_register.json) as source of truth.
> Regenerate with `python analysis/render_gap_register.py`.

> **Method.** Every `R-SecOpsX` cell below is grounded in inspected source (file:line), not in
> previously reported PASS results. Reference-tool capabilities are stated from their documented,
> generally-accepted behaviour. No production source was modified to produce this document.

---

## 0. Classification legend

### R-SecOpsX support level

| Class | Meaning |
|---|---|
| **NATIVE** | Real implementation, wired into the production pipeline, evidence-producing |
| **PARTIAL** | Real implementation but bounded (limited languages, limited depth, or limited data) |
| **PATTERN_ONLY** | Regex / window heuristic; no parser, no true data flow |
| **MISSING** | Capability absent |

### Recommendation

| Class | Meaning |
|---|---|
| **MUST_IMPLEMENT** | Enterprise-essential; gap blocks adoption or produces wrong decisions |
| **SHOULD_IMPLEMENT** | Materially improves defensibility; moderate cost |
| **RESEARCH_NOVELTY** | Where R-SecOpsX can legitimately differentiate |
| **NOT_NEEDED** | Not justified for this platform's scope |

---

## 1. SAST / data-flow benchmark

| Capability | R-SecOpsX | CodeQL | Semgrep | SonarQube | Fortify / Checkmarx | Gap | Action |
|---|---|---|---|---|---|---|---|
| Regex rule engine | **NATIVE** — `scanner/sast.py` `REGEX_RULES` + ~90 `ENTERPRISE_RULES` | PARTIAL | NATIVE | NATIVE | NATIVE | — | NOT_NEEDED |
| Language AST parsing | **PARTIAL** — Python `ast` only (`taint_engine.py:96`); no tree-sitter/javalang (repo grep = 0) | NATIVE (all) | NATIVE (many) | NATIVE | NATIVE | All non-Python languages lack a parser | MUST_IMPLEMENT |
| Standalone AST branch | **MISSING** — AST is fused inside taint engine, not a branch | NATIVE | NATIVE | NATIVE | NATIVE | Diagram claims 5 branches; AST is not one | SHOULD_IMPLEMENT |
| Intraprocedural taint | **PARTIAL** — Python true AST taint; Java J1/J3.1 bounded (`taint_engine.py:1051,1501`) | NATIVE | NATIVE | NATIVE | NATIVE | — | — |
| Interprocedural (same file) | **PARTIAL** — Java J3.2, 1–2 hop, regex method heads (`taint_engine.py:1819`) | NATIVE | PARTIAL | NATIVE | NATIVE | Python has only `_tainted_returns` heuristic | SHOULD_IMPLEMENT |
| Inter-file analysis | **PARTIAL** — Java J5 cross-file only (`java_semantic_j5.py`) | NATIVE | NATIVE | NATIVE | NATIVE | No inter-file flow for Python/JS/Go/C# | MUST_IMPLEMENT |
| Alias / field sensitivity | **MISSING** — `TaintedVar` tracks name only, no fields/aliases | NATIVE | PARTIAL | NATIVE | NATIVE | Object-field flows invisible | SHOULD_IMPLEMENT |
| Sanitizer modelling | **PARTIAL** — per-vuln-class `sanitized_for`; `html.escape` counts for XSS but not a shell sink (`taint_engine.py` `_sanitizer_classes`) | NATIVE | NATIVE | NATIVE | NATIVE | Sanitizer sets still incomplete per language | SHOULD_IMPLEMENT |
| Taint kill / reassignment | **PARTIAL** — constant-only expressions kill taint (`visit_Assign` `_constant_only`); `AugAssign` never declassifies | NATIVE | NATIVE | NATIVE | NATIVE | Kills only on *provably* constant RHS | — |
| Function-scoped taint | **PARTIAL** — per-function frames (`_push_scope` / `_pop_scope`); sibling functions cannot observe each other | NATIVE | NATIVE | NATIVE | NATIVE | Module frame still shared by top-level code | — |
| Path reconstruction | **PARTIAL** — `taint_path` string chain (`TaintVisitor._make_path:144`) | NATIVE (paths) | PARTIAL | NATIVE | NATIVE | No path condition / trace UI | SHOULD_IMPLEMENT |
| Framework source models | **PARTIAL** — Flask `request.*`, **Django `request.GET/POST`** (added Phase 4); bare tokens `query`/`params`/`kwargs` gated on the binding kind | NATIVE | NATIVE | NATIVE | NATIVE | Go/PHP/JS sources are window-based, not AST | SHOULD_IMPLEMENT |
| Bound-variable (inter-procedural *within file*) source→sink | **PARTIAL** — `ENTERPRISE_TAINT_RULES` source-line + 14-line window closes `$id = $_GET[...]` → `system(...)` and `const id = req.query.id` → `cp.execSync(...)` | NATIVE | NATIVE | NATIVE | NATIVE | Window is not a data-flow graph | SHOULD_IMPLEMENT |
| Import-alias resolution | **PARTIAL** — `_child_process_names` resolves `require`/`import` bindings so `cp.execSync` ≠ `re.exec` | NATIVE | NATIVE | NATIVE | NATIVE | Only `child_process` is modelled | SHOULD_IMPLEMENT |
| Query/rule architecture | **PARTIAL** — rules are inline Python dicts, not versioned/declarative contracts | NATIVE | NATIVE | NATIVE | NATIVE | No rule schema; no rule test harness | SHOULD_IMPLEMENT |
| FP suppression framework | **PARTIAL** — ad-hoc per-rule validators (`_is_client_side_ssrf_context` etc.) | NATIVE | NATIVE | NATIVE | NATIVE | No unified suppression model | SHOULD_IMPLEMENT |

**Reproduced SAST defects — closure status:**

1. 🔴 `_apply_r13_v2r12` loaded two non-existent `dump/*.py` files → `RuntimeError` for every `.java` file → swallowed at `sast.py:1056`. **CLOSED (Phase 4)** — fails open only when the optional artifacts are genuinely absent; all Java taint layers now reach the report.
2. 🟠 `_base_finding` `controls` latent `NameError`. **CLOSED (Phase 4).**
3. 🟠 FPs reproduced: parameterized query, `html.escape`, taint-not-killed, cross-function leak, list-argv `subprocess.run`. **CLOSED (Phase 4)** — all five are now negative controls in `phase4_taint_tranche_check.py` (20/20).
4. 🟠 FNs reproduced: qualified `flask.request.args`, Django `request.GET` / `request.POST`. **CLOSED (Phase 4).**
5. 🟠 **NEW (Phase 4c)** FP: a local `query = "SELECT 1"` was a taint source purely because the identifier collides with `req.query` / `**query`. **CLOSED** — bare source tokens are declined only when the binding is a provably constant-only expression (`_binding_kind == "const"`, innermost-frame resolution). 20/20 FN-safety cases prove no token lost its source semantics.
6. 🟠 **NEW (Phase 4c)** FNs: bound-variable PHP/JS flows were invisible because every static rule requires the superglobal/request object *inside* the sink call. **CLOSED** — three new `ENTERPRISE_TAINT_RULES` reuse the existing source-line + window mechanism, gated by a concrete-sink validator (non-literal argument + resolved `child_process` receiver).

### Measured benchmark — `sast-multilang-2026-10`

Ground truth authored **before** the scan (`analysis/benchmark_sast_corpus.py`): 13 vulnerabilities across Python, JavaScript, Java, C#, Go, PHP + 6 negative controls. Reproducible via `python analysis/benchmark_sast_corpus.py`.

| Metric | Phase 4 baseline | Phase 4b | Phase 4c | Δ |
|---|---:|---:|---:|---:|
| True positives | 7 | 10 | **13** | +6 |
| False positives | 1 | 1 | **0** | −1 |
| False negatives | 6 | 3 | **0** | −6 |
| Precision | 87.50% | 90.91% | **100.00%** | +12.50 pp |
| Recall | 53.85% | 76.92% | **100.00%** | +46.15 pp |
| F1 | 66.67% | 83.33% | **100.00%** | +33.33 pp |
| Scan time | 3.0 s | 3.2 s | 3.0 s | — |

Phase 4c is itself two steps: the three new taint rules moved the corpus to
12 TP / 0 FP / 1 FN (F1 96.00%) and the EVIDEX `system(` sink alias closed the
last FN (F1 100.00%) — a finding the scanner produced was being dropped by the
evidence gate, which is why the benchmark, not the unit tests, is the gate that
matters.

Per category, final: SQLi 5/5, command injection 5/5, path traversal 2/2, code injection 1/1.

> **Weakness remaining after Phase 4c:** none in this corpus. The corpus is a *controlled synthetic* benchmark (class A); class B (OWASP applications) and class C (real-world projects) are still not measured, so 100% here does **not** generalise — it only proves the 7 defects above are gone.

---

## 2. SBOM / SCA benchmark

| Capability | R-SecOpsX | Trivy | Syft | Grype | Dependency-Check | Dependency-Track | Gap | Action |
|---|---|---|---|---|---|---|---|---|
| Manifest discovery | **PARTIAL** — `requirements*.txt`, `package.json`, `pom.xml` only (`sbom.py:731-745`) | NATIVE | NATIVE | — | NATIVE | NATIVE | 3 formats | MUST_IMPLEMENT |
| Lockfiles | **PARTIAL** — `package-lock.json` only (`sbom.py:739`, `npm_lock_graph_v2.py`) | NATIVE | NATIVE | — | NATIVE | NATIVE | No poetry/pnpm/yarn/go.sum/Cargo.lock/composer.lock | MUST_IMPLEMENT |
| Ecosystems | **PARTIAL** — PyPI, npm, Maven | NATIVE (15+) | NATIVE (15+) | NATIVE | NATIVE (many) | NATIVE | No Go/.NET/NuGet/RubyGems/Crates/Composer | MUST_IMPLEMENT |
| Transitive graph | **NATIVE** — `analysis/dependency_graph_v2.py` + npm lock edges (`main.py:2264-2360`) | NATIVE | NATIVE | NATIVE | PARTIAL | NATIVE | — | — |
| PURL | **NATIVE** — `package_intelligence.py:471`, `cyclonedx_export.py:90` | NATIVE | NATIVE | NATIVE | NATIVE | NATIVE | — | NOT_NEEDED |
| CPE | **MISSING** | NATIVE | NATIVE | NATIVE | NATIVE | NATIVE | Needed for NVD-only advisories | SHOULD_IMPLEMENT |
| SPDX / CycloneDX output | **NATIVE** — `cyclonedx_export.py` (CycloneDX); **SPDX missing** | NATIVE | NATIVE | NATIVE | PARTIAL | NATIVE | No SPDX | SHOULD_IMPLEMENT |
| License inventory | **NATIVE** — `license_matrix_engine.py`, `license_policy_engine.py` | NATIVE | NATIVE | — | — | NATIVE | — | NOT_NEEDED |
| Malicious package signals | **NATIVE** — `malicious_package_intelligence.py` | NATIVE | — | — | — | PARTIAL | — | — |
| VEX | **PARTIAL** — `reporting/vex_export.py` (112 L), package-level, 4 statuses (`vex_export.py:29,44,54`) | PARTIAL | — | PARTIAL | — | NATIVE | No justification provenance/confidence | SHOULD_IMPLEMENT |

### Measured benchmark — `sca-multilang-2026-10`

Ground truth from **OSV.dev**, queried per exact package@version *before* any
compared tool ran. No tool is treated as the reference. Reproduce with
`python analysis/benchmark_sca_corpus.py`. Full detail:
`reports/benchmark_reconciliation_sca.md`.

Fixture: 11 declared packages across PyPI / npm / Maven, **70 CVEs** on 7 of
them, **4 safe controls** with zero known CVEs (six, colorama, ms,
is-number). Realistic manifest forms — PEP 440 pins, npm `^`/`~` ranges plus
a `package-lock.json`, a `pom.xml`.

| Metric | R-SecOpsX | Trivy | Grype |
|---|---:|---:|---:|
| Packages discovered | 18 | 13 | 12 |
| Discovery precision | 61.1% | 91.7% | 100.0% |
| Discovery recall | **100.0%** | **100.0%** | **100.0%** |
| Discovery F1 | 75.9% | 95.7% | 100.0% |
| Vulnerable packages identified | 7/7 | 7/7 | 7/7 |
| **Safe controls falsely matched** | **0** | **0** | **0** |
| CVE TP / FP / FN | 70 / 0 / 0 | 70 / 0 / 0 | 70 / 0 / 0 |
| **CVE precision** | **100.0%** | **100.0%** | **100.0%** |
| **CVE recall** | **100.0%** | **100.0%** | **100.0%** |
| **CVE F1** | **100.0%** | **100.0%** | **100.0%** |

**Before this phase R-SecOpsX scored CVE F1 49.7%** (precision 49.4%, recall
54.3%; 39 invented, 32 missed) while both reference tools scored 100%. Three
defects closed:

1. 🔴 `_parse_requirements` kept the pin operator, so OSV was queried with
   `version="==2.19.1"`. OSV cannot evaluate that against an affected range
   and falls back to *every* advisory ever filed for the package — 39
   invented CVEs (django alone: 35). Proven by querying OSV twice on the same
   package: `==2.2.0` → 52 CVEs (17 correct), `2.2.0` → 43 (43 correct).
2. 🟠 `_parse_package_json` stored the raw npm range (`^4.17.4`). Same
   failure, only visible once the fixture used realistic ranges: 4 invented
   CVEs **including a false match on `ms@2.1.3`, a package with zero known
   CVEs**.
3. 🟠 `apply_vulnerability_overrides` *replaced* the advisory set with the
   local override, discarding OSV — log4j-core collapsed from 7 CVEs to 2,
   losing CVE-2021-44832 and CVE-2021-45105.

Both manifest fixes also repair the emitted **PURL**: it was
`pkg:pypi/requests@==2.19.1` (and `@%3D%3D2.19.1` via `build_purl`) — invalid
under the purl spec. It now reads `pkg:pypi/requests@2.19.1`.

**Remaining gap:** discovery precision 61.1%. R-SecOpsX synthesises 7
undeclared transitive dependencies (certifi, jinja2, path-to-regexp, qs,
sqlparse, urllib3, werkzeug) from a hardcoded table with `version: unknown`
and `direct: False`. They never produce a vulnerability match, so CVE
precision is unaffected — but they are unverifiable claims inside a
deliverable SBOM, and Trivy/Grype do not emit them.

---

## 3. Vulnerability intelligence benchmark

| Capability | R-SecOpsX | Grype | Dependency-Track | Snyk | GitHub Advisory | Gap | Action |
|---|---|---|---|---|---|---|---|
| Advisory source | **NATIVE** — OSV batch API + cache (`vulnerability_intel.py:11,321,397`) | NATIVE (multi) | NATIVE (multi) | NATIVE | NATIVE | Single source (OSV) | SHOULD_IMPLEMENT |
| CVSS base score | **NATIVE** — extracted **and computed from vector** (`vulnerability_intel.py:139,193`) | NATIVE | NATIVE | NATIVE | NATIVE | — | NOT_NEEDED |
| CVSS vector retention | **PARTIAL** — vector parsed then largely discarded | NATIVE | NATIVE | NATIVE | NATIVE | Vector not surfaced as evidence | SHOULD_IMPLEMENT |
| CWE mapping | **NATIVE** — `core/mapper.py` | NATIVE | NATIVE | NATIVE | NATIVE | — | — |
| **EPSS** | 🔴 **STATIC 8-CVE table** (`analysis/epss_intelligence_engine.py:12-21`) — not a feed; **labelled `STATIC_REFERENCE`** | — | NATIVE (live) | NATIVE | — | No live EPSS | MUST_IMPLEMENT |
| **KEV** | 🔴 **~9 hard-coded records** (`analysis/kev_intelligence_engine.py:13-86`) + a second 7-CVE set at `analysis/vulnerability_age_engine.py:9-12` — not the CISA catalog; **labelled `STATIC_REFERENCE`** | — | NATIVE (live) | NATIVE | NATIVE | No live KEV | MUST_IMPLEMENT |
| Exploit / PoC availability | **MISSING** | PARTIAL | NATIVE | NATIVE | NATIVE | No exploit intel | MUST_IMPLEMENT |
| Fixed version | **NATIVE** — `_fixed_versions:270` | NATIVE | NATIVE | NATIVE | NATIVE | — | — |
| Vulnerability lifecycle state | **MISSING** | — | PARTIAL | PARTIAL | — | No UNKNOWN→KEV lifecycle | SHOULD_IMPLEMENT |
| Provenance on intel | **PARTIAL** — `"source": "OSV"` only | PARTIAL | NATIVE | NATIVE | NATIVE | No fetch timestamp/signature | SHOULD_IMPLEMENT |

> **Critical honesty finding:** the platform reports `epss` and `kev` fields as if they were
> intelligence. They are **static placeholders covering ≤9 CVEs**. Any prioritization that cites
> EPSS/KEV today is only meaningful for those specific CVEs. This must be labelled
> **INFERRED / STATIC_REFERENCE** in reporting until live feeds are wired.
>
> **Labelling requirement: SATISFIED (G-003, Phase 3+).** `analysis/intelligence_provenance.py`
> defines the token vocabulary; all three engines emit `epss_provenance` / `kev_provenance`;
> PDF, Excel, VEX and CycloneDX render it; `main.py:_apply_epss_kev_provenance_banner` publishes
> `metadata.epss_kev_provenance` with `live_feeds_wired: false`. The **data** gap (live feeds)
> is untouched and remains action register item #3.

---

## 4. Reachability benchmark — *core differentiator*

| Capability | R-SecOpsX | Trivy (reachability) | Dependency-Track | Semgrep Supply Chain | Gap | Action |
|---|---|---|---|---|---|---|
| Import-reference graph | **NATIVE** — `scanner/reachability.py:372` regex-extracts imports → SBOM match | NATIVE | NATIVE | NATIVE | — | — |
| REACHABLE / UNREACHABLE / UNKNOWN | **NATIVE** (`reachability.py:273,343`) | NATIVE | NATIVE | NATIVE | — | — |
| Reachability confidence | **NATIVE** — 0.85 / 0.65 / 0.30 → MEDIUM/LOW (`reachability.py:227,238,250`) | PARTIAL | PARTIAL | PARTIAL | Only 3 tiers, 2 labels | SHOULD_IMPLEMENT |
| **Vulnerable-function reachability** | 🔴 **MISSING** — package-level only, never function-level | PARTIAL | PARTIAL | NATIVE | Requirement §10 unmet: `vulnerable_function`, `call_path` absent | MUST_IMPLEMENT |
| Data-flow reachability | **MISSING** | — | — | PARTIAL | No source→vulnerable-fn path | MUST_IMPLEMENT |
| Reachability type enum | 🔴 **MISSING** — no DIRECT/INDIRECT/TRANSITIVE/CALL_FLOW/DATA_FLOW/CONFIGURATION/RUNTIME | — | — | — | §10 enum not implemented | MUST_IMPLEMENT |
| Never infer from install alone | ✅ **NATIVE** — status UNKNOWN when not observed | — | — | — | Correctly conservative | — |

**Verdict:** R-SecOpsX has a *real but package-granular* reachability engine. It must **not** be
described as function-level reachability until §10 is implemented.

---

## 5. Secrets benchmark

| Capability | R-SecOpsX | Gitleaks | TruffleHog | detect-secrets | Gap | Action |
|---|---|---|---|---|---|---|
| Provider-specific rules | **NATIVE** — `SECRET_RULES` + `KNOWN_SECRET_RULES` (`secret_intelligence.py:40,165`) | NATIVE | NATIVE | NATIVE | — | — |
| Shannon entropy | **NATIVE** — `_shannon_entropy:222`, thresholds per charset (`:241-243`) | NATIVE | NATIVE | NATIVE | — | — |
| Context scoring | **PARTIAL** | NATIVE | NATIVE | NATIVE | No allow-list/baseline | SHOULD_IMPLEMENT |
| Git history scanning | **MISSING** — working-tree only | NATIVE | NATIVE | NATIVE | No history/entropy-over-commits | MUST_IMPLEMENT |
| Live validation | **NATIVE (optional)** — `apply_optional_live_secret_validation:799`, off by default | — | NATIVE | — | — | — |
| Default state honesty | ✅ **NATIVE** — `validation_status: OFFLINE_ONLY_NOT_VALIDATED` (`:793`) | — | — | — | Correctly labelled | — |
| Revocation guidance | **MISSING** | PARTIAL | NATIVE | — | §22 unmet | SHOULD_IMPLEMENT |

---

## 6. Crypto (CBOM) benchmark

| Capability | R-SecOpsX | Best practice | Gap | Action |
|---|---|---|---|---|
| Algorithm inventory | **NATIVE** — `cbom.py` MD5/SHA1/DES/AES/RSA/EC rules | NATIVE | — | — |
| **Mode resolution (GCM vs ECB)** | 🔴 **MISSING** — AES rule text literally says *"Verify AES mode is GCM/CTR"* (`cbom.py:70`) → mode not resolved | NATIVE | §21 (`AES-256-GCM`) unmet | MUST_IMPLEMENT |
| Key size resolution | 🔴 **MISSING** — RSA rule says *"Verify RSA key size ≥2048"* (`cbom.py:84`) → size not resolved | NATIVE | §21 unmet | MUST_IMPLEMENT |
| Curve / padding / protocol | **MISSING** | NATIVE | §21 unmet | SHOULD_IMPLEMENT |
| Private key / trust store | **PARTIAL** — PEM detection (`cbom.py:118`) | NATIVE | No trust-store inventory | SHOULD_IMPLEMENT |
| Constant/symbol resolution for crypto | **MISSING** — regex on literals only | NATIVE | §21 technique stack unmet | SHOULD_IMPLEMENT |

---

## 7. BOM correlation / attack graph / RCMSP — *research differentiators*

| Capability | R-SecOpsX | Industry reference | Gap | Action |
|---|---|---|---|---|
| Attack graph `get_attack_paths()` / `get_pivot_points()` | **NATIVE** — `core/attack_graph.py:48,119`, contract-tested | ATT&CK tools | — | RESEARCH_NOVELTY |
| Graph schema | **NATIVE** — `core/graph_schema.py` `SecurityGraph.validate:58` | — | Not surfaced in reports | SHOULD_IMPLEMENT |
| **SBOM↔AI-BOM↔ABOM↔CBOM correlation** | 🔴 **SPLIT** — `aibom_abom_correlation.py` (360 L, 5 test files) is **never called from `main.py`**; only `secret_blast_radius_correlation_engine` runs (`main.py:2593`) | **No mainstream tool does this** | Built but unwired | **MUST_IMPLEMENT (P0)** |
| RCMSP decision policy | 🔴 **STUB** — `core/rcmsp.py` = **59 lines**, hard-coded 3-branch `evaluate_rcmsp:36` | — | §28 pipeline not implemented | MUST_IMPLEMENT |
| Compensating controls model | 🔴 **MISSING** — prose strings only (`sast.py:224`, `legacy_protocol_engine.py:88`) | — | §16 unmet; no inherent vs residual risk | MUST_IMPLEMENT |
| Asset / business criticality | **PARTIAL** — path classification (`analysis_context.py:208`) + AI-BOM assets; **no CMDB/criticality model** | — | §15 unmet | MUST_IMPLEMENT |
| Exposure intelligence | **NATIVE** — `exposure_surface_engine.py:116` | — | — | — |
| Temporal age (6 dimensions) | **PARTIAL** — `vulnerability_age_engine.py` exists; §11's six distinct ages unverified | — | Verify before claiming | SHOULD_IMPLEMENT |
| Evidence schema | **NATIVE** — `core/evidence_schema.py` (238 L) + JSON schema + `QualifiedEvidence:134` | — | — | RESEARCH_NOVELTY |
| Evidence adapter | **NATIVE** — `core/evidence_adapter.py` (290 L) | — | — | RESEARCH_NOVELTY |
| Cross-domain attack path (SBOM→SAST→Agent→Input) | 🔴 **MISSING** end-to-end | — | §26 unmet | **RESEARCH_NOVELTY** |

---

## 8. Language coverage matrix (§32)

| Language | Parser | AST | Symbols | Data flow | Taint | SBOM | **Level** |
|---|---|---|---|---|---|---|---|
| Python | `ast` ✅ | ✅ | partial | intraproc | **true AST taint** | PyPI | **PARTIAL** |
| Java | none (regex+brace) | ❌ | partial | J1/J3.1/J3.2 | bounded, J1–J5 | Maven | **PARTIAL** |
| JavaScript | none | ❌ | ❌ | window only | window (±14 lines) | npm | **PATTERN_ONLY** |
| TypeScript | none | ❌ | ❌ | window only | window | npm | **PATTERN_ONLY** |
| Go | none | ❌ | ❌ | ❌ | window only | ❌ | **PATTERN_ONLY** |
| C# | none | ❌ | ❌ | ❌ | window only | ❌ | **PATTERN_ONLY** |
| PHP | none | ❌ | ❌ | ❌ | window only | ❌ | **PATTERN_ONLY** |
| C / C++ | none | ❌ | ❌ | ❌ | regex only | ❌ | **PATTERN_ONLY** |
| Ruby | none | ❌ | ❌ | ❌ | regex only | ❌ | **PATTERN_ONLY** |
| Kotlin / Scala | none | ❌ | ❌ | ❌ | regex only | ❌ | **PATTERN_ONLY** |
| Rust | — | — | — | — | — | ❌ | **UNSUPPORTED** |
| PowerShell | `.sh`-adjacent only | ❌ | ❌ | ❌ | ❌ | ❌ | **UNSUPPORTED** |

⚠️ `SCANNABLE_EXT` (`sast.py:42`) accepts `.kt .scala .rb .cs .cpp .c .h .vb`, but **no parser exists**
for any of them. Inclusion in `SCANNABLE_EXT` must **not** be read as language support.

---

## 9. Enterprise scorecard

| Domain | NATIVE | PARTIAL | PATTERN_ONLY | MISSING | Verdict |
|---|---|---|---|---|---|
| SAST / taint | 2 | 5 | 0 | 5 | **PARTIAL** — FP controls missing, Java taint dropped |
| SBOM / SCA | 4 | 3 | 0 | 1 | **PARTIAL** — 3 ecosystems only |
| Vuln intelligence | 3 | 2 | 0 | 2 | **PARTIAL — EPSS/KEV are static placeholders** |
| Reachability | 3 | 1 | 0 | 3 | **PARTIAL** — package-level, not function-level |
| Secrets | 3 | 1 | 0 | 2 | **NATIVE** (strongest) |
| CBOM | 1 | 1 | 0 | 4 | **PATTERN_ONLY** |
| Correlation / RCMSP | 3 | 1 | 0 | 3 | **PARTIAL — unwired + stub** |

---

## 10. Priority action register

| # | Priority | Item | Evidence | Phase |
|---|---|---|---|---|
| 1 | **P0** | Fix `_apply_r13_v2r12` — restore all Java taint findings | `taint_engine.py:2284`; E2E: only J5 survived | **DONE — Phase 4** |
| 2 | **P0** | Wire `aibom_abom_correlation` into `main.py` | built + tested, never imported — **unblocked by 5h** (identity gating now prevents fabricated edges) | 12 |
| 3 | **P0** | Live EPSS + CISA KEV feeds | `analysis/epss_intelligence_engine.py:12-21`, `analysis/kev_intelligence_engine.py:13-86` static | 6 |
| 3a | ~~P0~~ **DONE** | Label static EPSS/KEV `STATIC_REFERENCE` | 29 dedicated tests in `tests/test_v11_g003_static_reference_labelling.py`; label verified in the emitted PDF via `pypdf`/`pdftotext`; suite **236/0**, integrity **20/20**, SAST F1 1.0 and SCA CVE F1 1.0 unchanged, PDF smoke PASS | 3 |
| 4 | **P0** | Sanitizer + taint-kill + function scoping | 5 FPs reproduced | **DONE — Phase 4** |
| 5 | **P0** | Django sources (`request.GET/POST`) | 2 FNs reproduced | **DONE — Phase 4** |
| 5a | **P0** | Bound-variable PHP/JS source→sink | 3 FNs, benchmark GT-03/12/13 | **DONE — Phase 4c** |
| 5b | **P0** | Bare source token collides with local constant | FP, benchmark NT-05 | **DONE — Phase 4c** |
| 5c | **P0** | EVIDEX `command` sink missing PHP `system(` | GT-13 dropped at `enrich_finding` | **DONE — Phase 4c** |
| 5d | ~~P1~~ **DONE** | `correlate()` contract conflict — **resolved** | Executable proof: a PASSING and a FAILING test in the same suite are structurally identical and demand opposite outcomes, so *no* implementation reaches 0 failures without changing an assertion. Owner approved Option 1; 8 assertions migrated to the implemented boundary contract with original names recorded in-file. Suite **190/0**, integrity **20/20**, no production file touched. **Analysis + migration record: `docs/known_contract_conflicts.md`.** | 12 |
| 5h | ~~P0~~ **DONE** | `correlate()` fabricated agent→model edges — identity gating | `correlate()` now links an agent **only to the model it declares** (`model_id`, else `model_name`, case/whitespace-insensitive); no declaration ⇒ documented boundary fallback; a declaration matching no supplied model ⇒ **no edge at all**; `model_resolution` still never gates. Removed 4 invented alternate keys (`resolved_model_id`, `ai_model_id`, …) that no producer emits. 17 dedicated tests in `tests/test_v11_abom_identity_gating.py`. | 12 |
| 5e | **P1** | Benchmark class B/C/D (OWASP apps, real-world repos, AI/LLM corpus) | Only class A (controlled synthetic) is measured — see §1 and §2 | 13 |
| 5f | **P1** | SBOM discovery precision 61.1% — 7 synthesized transitive deps with `version: unknown` | `sbom.py` `_add_transitive`; §2 measured benchmark | 13 |
| 5g | **P2** | Requirement *ranges* (PEP 440) and npm ranges without a lockfile resolve to `unknown`, costing advisory recall | `_resolve_pinned_version` / `_resolve_npm_version` deliberately prefer recall loss to invented CVEs | 13 |
| 6 | **P1** | SBOM: poetry/pnpm/yarn/go.sum/Cargo/Composer + Go/.NET/Ruby/Crates | 3 formats only | 5 |
| 7 | **P1** | Function-level reachability + §10 type enum | package-level only | 7 |
| 8 | **P1** | Compensating controls + inherent/residual risk | no module | 6 |
| 9 | **P1** | Real RCMSP policy engine (59 L → pipeline) | `rcmsp.py:36` | 14 |
| 10 | **P1** | CBOM mode/key-size/curve resolution | `cbom.py:70,84` | 10 |
| 11 | **P2** | Non-Python AST (tree-sitter) | 0 hits repo-wide | 4 |
| 12 | **P2** | Git-history secret scanning | working-tree only | 5 |
| 13 | **P2** | SPDX output | CycloneDX only | 5 |

---

## 11. Legitimate research novelty (§34)

Not novelty-by-feature-parity — these have **no mainstream equivalent**:

1. **Cross-BOM correlation** — SBOM + AI-BOM + ABOM + CBOM into one contextual attack path.
2. **Evidence-qualified RCMSP decisions** — `QualifiedEvidence` → decision state → policy → outcome → provenance, explicitly non-numeric.
3. **Agent-aware supply-chain risk** — Agent → Model → Tool → Dependency → Vulnerable Function.
4. **Age + exploitability + reachability + exposure joint temporal prioritization** — *conditional on real EPSS/KEV* (currently blocked by static placeholders).

**Condition:** novelty claims are defensible **only after** items 2, 3, 9 above close. Until then
the correlation engine is unwired and RCMSP is a stub.

---

*Generated by Phase 2 benchmark. Production source: unmodified.*
