# UFIB Phase 1–2: Repository Architecture & Baseline Audit

Date: 2026-10-27 · Branch `master` · HEAD `0571e46` · Suite: **3167 passed, 42 skipped**

This audit was produced by reading the code, not by assumption. Every claim below names the
module and the evidence source. This document is the baseline the UFIB work is measured
against; it is committed before any UFIB code lands.

---

## 1. Scan orchestration (main.py, 6,046 lines)

`main()` → per-engine scans → `raw` list assembly (k8s, tf, docker, compose, LLM, advanced-AI,
api-abuse, secrets, git-history, SAST, taint) → the central pipeline in `main()`:

| Stage | Line | What it does |
|---|---|---|
| Intake boundary | 3363 | `_filter_findings_to_target` drops out-of-scope findings |
| Deduplication | 3367 | `_dedupe_findings` groups occurrences under roots (`group_key`, `instances`) |
| Normalization | 3370 | `normalize_payload` → `core/finding_model.py` |
| Payload build | 3372 | `core.analyzer.build_report_payload` |
| Context enrichment | 3382 | `enrich_findings_context` |
| Occurrence evidence gate | 3422 | `_prune_unsupported_occurrences` — removes grouped occurrences whose evidence does not support the finding |
| Evidence validation | 3430–3436 | `core.analyzer._apply_evidex_validation` per finding — stamps `evidence_valid`, `evidence_validation`, `evidence_validation_detail` |
| v11 intelligence | 3444 | `core.v11_intelligence.enrich_payload` |
| Compliance / secret intel | 3455/3466 | framework mappings, live secret validation |
| … | 3473–5200 | dependency views, attack paths, KEV/EPSS, governance, SBOM exports, BOMs |
| Final integrity | 1470/2367/2493 | `_final_report_integrity_pass`, `_apply_final_report_safety`, `_rebuild_finding_derived_aggregates` |
| JSON write | 5518 | `clean_report.json` |
| Gate persist | 5838–5855 | `scan_timing`, `security_gate` rewritten into the same file |

## 2. Detection engines and rule registries (measured)

| Engine module | Table | Rules |
|---|---|---|
| `scanner/taint_engine.py` | `ENTERPRISE_TAINT_RULES` (+`_JAVA_J2_RULES`) | 14 |
| `scanner/sast.py` | `ENTERPRISE_RULES` / `REGEX_RULES` | 160 / 17 |
| `scanner/secret_intelligence.py` | `KNOWN_SECRET_RULES` / `SECRET_RULES` | 13 / 10 |
| `scanner/iac_terraform.py` / `iac_docker.py` / `iac_kubernetes.py` | `RULES` (+k8s `MISSING_RULES`) | 18 / 17 / 12+5 |
| `scanner/llm_security.py` | `LLM_RULES` | 40 |
| `scanner/cbom.py` | `CRYPTO_RULES` | 10 |
| `scanner/sbom.py` + `scanner/vulnerability_intel.py` | SCA via OSV querybatch | advisory-driven |
| `analysis/privacy_data_exposure_engine.py` | `PII_PATTERNS` / `EXPOSURE_PATTERNS` | 10 / 7 |
| `scanner/git_history_secrets.py`, `scanner/manifests/*`, `scanner/ast_validators.py`, `scanner/multipart_flow.py` | supporting | — |

**319 rules across 12 tables** — verified by the security brain's L3 sweep (`--brain`).

## 3. Existing evidence architecture (reuse targets — do NOT duplicate)

- `core/evidence_schema.py`: versioned `Evidence` model — `evidence_id`, `EvidenceSource`,
  `EvidenceTimestamp`, `EvidenceProvenance` (source, observed_at, engine, component, tool,
  decision_consumer), `EvidenceType` ∈ {pattern, taint, sink, static, dynamic, dependency,
  secret, graph, context, other}, `EvidenceConfidence` ∈ {HIGH, MEDIUM, LOW, UNKNOWN}.
- `core/evidence_adapter.py`: `normalize_finding_evidence` / `qualify_finding_evidence` —
  builds `canonical_evidence` + `canonical_qualified_evidence` on every finding.
- `core/finding_model.py`: canonical `finding_id` (UUID5), coarse `classification` ∈
  {confirmed, control_gap, heuristic, informational} (strict: non-IaC confirmation requires
  `taint_validated` AND `sink_validated` AND `evidence_valid`), `evidence_state`, severity
  demotion rules, `build_rule_telemetry` (per-rule benchmark precision).
- `core/analyzer.py`: `_apply_evidex_validation` (taint/sink candidate validation),
  `_finalize_occurrence_integrity`, occurrence pruning.
- SARIF exporter already surfaces decision fields via `_decision_properties`
  (decision_state, reportable_finding, evidence_valid, evidence_state, …).

## 4. Finding lifecycle — where findings can be created / modified / suppressed

Creation: every engine's `scan_file`/`scan_*` (scanner/*), git-history secrets, OSV enrichment
(dependency_risk_register — packages, not findings), privacy engine (indicators).
Modification: intake filter, dedupe, `normalize_finding` (severity demotion for heuristic/
control_gap), `_attach_canonical_evidence`, occurrence pruning, evidex validation, v11 intel,
compliance/secret enrichments, `_cleanup_report_noise`, `_apply_final_report_safety`,
`_rebuild_finding_derived_aggregates`, `_redact_secret_evidence` (report-level redaction).
Suppression: EXCLUDED_DIRS/FILES gates, nonproduction context gates (secrets, privacy),
scanner-result-XML/JSON detectors, occurrence evidence gate.
Release: `clean_report.json` write (5518), then every renderer reads `payload["findings"]`:
SARIF, VEX, CycloneDX, SPDX, Excel, PDF, webhook/Jira/DefectDojo. Security gate persisted last.

## 5. Existing false-positive controls (measured, with corpus evidence)

- Path gates: `_skip` (SAST + secrets) — EXCLUDED_DIRS incl. `bundle`/`out`, scanner-result
  JSON/XML detectors (I18/I19).
- Secrets: `_is_nonproduction_context` (tests/fixtures/docs suppress known-signature rules),
  synthetic/example value gates, `validated_live` classification.
- Privacy: `_is_nonproduction_text` + `SKIP_DIRS` (synced to bundle/out/vendor in `0571e46`).
- Occurrence evidence gate + evidex validation (taint candidate checking).
- `classify_finding`: non-IaC findings cannot be `confirmed` without taint+sink validation;
  heuristic/control_gap demoted from Critical/High.
- Corpus: 133 expected findings, currently **133 TP / 0 FP** (IaC rule defects fixed in
  `9daa043` and the I18/I20 batches; FP fixtures retained with honest zero labels).
- Triage tool: `analysis/validation/triage_report.py` (measured on the aclean production
  report: 1,615 findings → 1,134 LIKELY_FP / 481 NEEDS_REVIEW / 0 LIKELY_REAL).

## 6. Identified weaknesses (the UFIB gap)

W1. Evidence validation is **generic, not category-aware** — `_apply_evidex_validation`
    checks taint/sink candidates the same way for SQLi, secrets, and weak-random; there is no
    per-category contract for what evidence a claim REQUIRES.
W2. No **security claim interpreter** — rules emit titles; nothing states the testable claim
    or its strength; a keyword-only match and a taint-validated flow look identical in kind.
W3. **No counterevidence/contradiction analysis** — nothing searches for parameterized
    queries, canonicalized paths, allow-listed SSRF, placeholder secrets, or pod-level
    security-context inheritance (the exact FP shapes measured in the aclean batch).
W4. **No explicit dispositions / release authorization** — every detected finding flows to
    every report as an equal; the security gate only counts severities. There is no
    CONFIRMED vs NEEDS_REVIEW vs REJECTED distinction in the release path.
W5. **No audit trail of decisions** — when `_apply_evidex_validation` fails a finding, the
    report carries a flag but no per-gate, per-requirement decision history.
W6. Applicability dimensions (severity / confidence / reachability / environmental exposure)
    are **blended** into `risk_score`; nothing evaluates them separately (SCA comes closest
    with reachability_status).
W7. Severity/confidence vocabulary is consistent but **not gated against failed mandatory
    evidence** for category-specific requirements.

## 7. Baseline measurements (recorded before UFIB)

- Golden corpus: **133 expected / 133 TP / 0 FP — precision 100%, recall 100%** (baseline JSON
  captured at `rsx_check/ufib_baseline_corpus.json`; corpus expanded by later commits — the
  IaC FP fixtures remain with honest zero labels and the rules no longer fire on them).
- Test suite: **3167 passed, 42 skipped** (~5 min wall).
- Production benchmark (aclean RBI2 scan, `reports/aclean/clean_report.json`, 1,615 findings):
  triage 1,134 LIKELY_FP (70.2%) / 481 NEEDS_REVIEW / 0 LIKELY_REAL — this is UFIB's
  end-to-end precision benchmark, since the golden corpus is saturated.
- Security brain: 24/24 checks PASS at HEAD.

## 8. Constraints respected by the UFIB design

- Additive only: UFIB adds `ufib`, `disposition`, `release_eligible`; it never overwrites
  detector output, severity, confidence, or `classification`.
- Fail-soft but loud: a UFIB crash must not abort the scan (advisory-feed contract) — but it
  must mark the release manifest so unvalidated findings cannot be released as CONFIRMED.
- Zero silent loss: every finding keeps its disposition and rationale in the released JSON;
  the manifest total must equal the findings population.
- Category-aware, never a generic suppression layer; no broad directory/language suppression.
