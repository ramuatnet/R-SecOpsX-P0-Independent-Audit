# SAST_ARCHITECTURE_REUSE.md — extend-don't-duplicate map (verified at HEAD `6a07066`)

**Purpose:** satisfy plan §0 boundary 14 ("Extend existing engines and contracts. Do not create parallel taint, scoring, finding, rule-loading, graph or reporting implementations") with a concrete, verified map. Every implementation slice in this overnight MUST touch only the modules listed here for its capability; any new module requires a gap that this map shows is genuinely unoccupied.

## 1. Capability → authoritative module map

| Capability | Authoritative module(s) (verified this run) | Extension surface | DO NOT create |
|---|---|---|---|
| Rule loading + validation | `scanner/rules/loader.py` (authoritative; `core/rule_loader.py` = documented back-compat shim :11-22) | YAML entries in `scanner/rules/enterprise_v1.yaml` / `regex_v1.yaml`; schema `scanner/rules/schema_v1.json` (`additionalProperties: false` — extend schema ONLY for necessary metadata) | a second loader or Python-side rule registry |
| Regex/enterprise rule execution | `scanner/sast.py` (`ENTERPRISE_RULES` :136, `REGEX_RULES` :142, `COMPILED_ENTERPRISE_RULES` :189-193; pack append :182-187) | migrate pack rules INTO YAML (C1) rather than adding new Python packs | per-language Python rule packs (except where a migration bridge already exists) |
| Rule parity enforcement | `tests/test_report_parity.py:378-391` (computed, never pinned), `tests/test_rule_format_v1.py:65-77` | extend the computed-parity pattern | pinned count assertions |
| Taint analysis | `scanner/taint_engine.py` (AST + regex tables) | add sources/sinks/sanitizers rows + `ENTERPRISE_TAINT_RULES` | a parallel taint engine |
| Cross-file propagation | `scanner/taint_interproc.py` (module index :120-207, resolver :227-280, worklist :616-693, disclosed caps :104-107) | extend caps/limits only with fixture evidence; keep disclosures | a second interproc pass |
| Reachability / call graph | `scanner/python_reachability.py:259-296` (`build_call_graph`), `scanner/reachability.py` | reuse for D2/view work | a new graph builder |
| Finding identity / dedupe | `accuracy/layer.py` (DUPLICATE verdict :178), `analysis/ufib_brain.py` (DUPLICATE disposition :588-597), `core/finding_model.py` | add stable-ID regression tests reusing the existing identity | a second dedupe/identity system |
| Verdict arbitration | `analysis/ufib_brain.py` (`_decide`, gates G1-G8, `RELEASE_DISPOSITIONS` :588-597) + `accuracy/layer.py::_decide` (:66-92; TRUE_POSITIVE cap :155-163) | add conflict/incomplete-evidence tests; extend gates additively | `core/verdict.py` or any second arbitration path |
| Suppression | `accuracy/suppressions.py` (inline :26-45, `.sastignore` :48-64, baseline :67-81) + `core/file_index.py:239-280` | add expiry/owner/stale AUDIT fields additively; never auto-delete | a second suppression mechanism |
| Scoring | `analysis/scoring/score.py` (explain-row schema :38-56, `score_finding` :281-333, `score_findings` :348-395) + sidecar CLI `analysis/scoring/connect.py` | wire `payload["scoring"]` + `--explain-score` (B6) | a third score model; merging with `core/risk_scorer` (different per-finding contract) |
| Canonical counts | `core/report_aggregates.py` (`build` :182-268, identities :211-218, `COUNT_UNITS` :54-90) | extend invariants via `tools/report_audit.py` checks | renderer-side recounting |
| Value honesty | `core/value_state.py` (`cell()` :320-323, resolve ladder :237-294, `REASON_TEXT` :96-117) | add reasons/fields only with documented provenance | literal defaults in renderers (enforced by `tests/test_no_renderer_literal_defaults.py`) |
| Report audit gate | `tools/report_audit.py` (`CHECKS` :210-217, fail-closed :273-294) | add SAST invariants (stable IDs, verdict consistency, suppression explainability, cross-format parity) | a second audit tool |
| SARIF export | `reporting/sarif_export.py` (`build_sarif` :209-226; properties incl. `taint_path` :178-187) | emit `codeFlows` from the existing taint_path data (E1) | a second SARIF writer |
| Diff/changed-line | `scanner/changed_line_security.py` (:51-178 annotation pass) + `scanner/change_intelligence.py` (git diff :159-248) | add flag-set-equality gate + CLI flag (E2) | a separate diff scanner |
| Incremental caching | `core/file_index.py` (per-scan hashes :294,383-401) | future E3 design extends the index | cross-scan cache outside the index contract |
| Telemetry | `core/telemetry.py` (`build_document` :26-57) + `core/finding_model.py::build_rule_telemetry` :165 | add p50/p95/cache-ratio fields additively (E6) | a new telemetry schema |
| Explain CLIs | `main.py:3285-3315` + `core/filter_trace.py:180-309` + `analysis/ufib_release.py:121-152` | add `--explain-score` reading the scoring explain rows (E7/B6) | placeholder explanations |
| Baseline/lifecycle | `scanner/finding_lifecycle_intelligence.py:216-233,303` + `--baseline` report diff `main.py:3276-3284` | add determinism/line-movement tests (E5) | a second lifecycle model |
| Compliance mapping | `scanner/compliance_mapper.py` (vuln_type→OWASP/CWE/NIST/PCI/ISO/SOC2/ATT&CK) + `core/attack_mappings.py` (858 techniques, STIX-pinned) | rule-level mapping field or NONE resolution (C5) | a second mapping catalogue |
| Business logic / IDOR | `analysis/business_logic_risk_engine.py` (:12-63), `analysis/business_logic_correlation_engine.py` (:141-190), `scanner/sast.py:1704-1780` (REST-IDOR detector) | add patterns only with positive/negative/ambiguous fixtures | duplicate rule families |
| Gap-register data | `reports/gap_register.json` (authored Phase-3 data; `analysis/render_gap_register.py` renders FROM it) | restore the gitignored worktree artifact; never regenerate silently | a synthetic register |
| Dead-code CI gate | `analysis/audit_dead_code.py` + `analysis/validation/ci_matrix.py:206` + `.github/workflows/validation.yml:79,164` | fix scope (exclude untracked evidence trees) | a second audit script |
| Test collection / markers | (no conftest exists — new file is the sanctioned policy layer per cltask rule 2) | create `conftest.py` with registered markers + collection-time enforcement | ad-hoc skip without registration |

## 2. Established spec-name deltas (recorded, not silently absorbed)

| Spec name | Real implementation at HEAD | Evidence |
|---|---|---|
| `core/verdict.py` / `final_state` | UFIB dispositions + accuracy verdicts (two layered vocabularies; `REJECTED_FALSE_POSITIVE`/`SUPPRESSED_*`, no bare REJECTED/CONTESTED) | analysis/ufib_brain.py:588-597; accuracy/config.py:19-24 |
| `reporting/cell.py` | `core/value_state.py::cell()` (same contract: `--` or `unknown (<reason>)`) | core/value_state.py:297-323 |
| `analysis/dedupe.py` (CNT-13) | DUPLICATE verdict/disposition in the accuracy/UFIB layers | accuracy/layer.py:178 |
| `tools/ground_truth.py` (REC-01) | `analysis/juice_shop_ground_truth.py` (cltask §1.3 itself prescribes extending it) | cltask §1.3 row |
| FND-01 `scanner/engine.py` | `core/filter_trace.py` + `core/analyzer.py` + `main.py` | cltask §1.3 row |
| `scanner/walk.py` (FND-02) | `core/file_index.py` (distinct from raw `scanner/walk.py` — documented) | pending_features §1 |
| `analysis/spans.py` (FND-03) | `scanner/span_layer.py` (native-core-dependent grammar path) | scanner/span_layer.py:6-17 |
| `scanner/rules/*.yaml` (FND-06) | `scanner/rules/*.yaml` + `scanner/rules/loader.py` | loader docstring |

## 3. Deliberate non-merges (verified distinct contracts)

- `analysis/scoring/score.py` (finding-level explainable score artifact) vs `core/risk_scorer.score_finding` (pipeline per-finding risk used at `core/analyzer.py:1163`) — different inputs/outputs; B6 wires the FIRST as `payload["scoring"]`, never replaces the second.
- `core/file_index.py` (per-scan index) vs `scanner/walk.py` (raw walk) — documented distinct layers.
- `payload["rule_telemetry"]` (in-report per-rule tp/fp) vs `telemetry.json` (scan-stages/drops/regex) — E6 extends the latter additively.
