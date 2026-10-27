# UFIB Final Acceptance Matrix

Date: 2026-10-27 · HEAD `2c47602` · Suite **3191 passed, 42 skipped** · Security brain 24/24 PASS

Status vocabulary: **PASS** = implemented AND verified by a named test/artifact in this
repository. **NOT_TESTED** = implemented but not yet verified. **BLOCKED** = cannot be
verified from this host. **FAIL** = verified and not met.

## 1. Core design principle

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1.1 | Detection → evidence → claim → validation → release separation | **PASS** | `analysis/ufib_brain.py` G1–G9; e2e scan manifest (`rsx_check/ufib_e2e/clean_report.json`) |
| 1.2 | Mandatory validation failure never overridden by severity/confidence/LLM | **PASS** | `test_decisive_counterevidence_beats_severity_and_confidence` (Critical+HIGH+decisive CE → REJECTED); no LLM exists in the decision path |
| 1.3 | Finding never released as confirmed when a mandatory gate fails | **PASS** | `_decide()` policy + corpus guard (0 unverified rejections on 133 labelled TPs) |
| 1.4 | Weak→precise claim rewrite (mission 3.3 examples) | **PASS** | `test_claim_never_stronger_than_evidence`; contracts carry exact claims per category |

## 2. Phase deliverables

| Phase | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Repository inventory & baseline | **PASS** | `docs/ufib_baseline_audit.md` (commit `595f998`), baseline corpus 133/133/0 recorded |
| 2 | End-to-end finding lifecycle audit | **PASS** | audit doc §1, §4 (line-referenced: creation→modification→suppression→release) |
| 3 | Universal evidence schema & provenance | **PASS** | UFIB-EVIDENCE-1 states (OBSERVED/INFERRED/VALIDATED/UNKNOWN/CONTRADICTED) on every finding's `ufib.evidence[]`; reuses `core/evidence_schema.py` |
| 4 | Security claim interpreter | **PASS** | `build_claim()` + `test_claim_never_stronger_than_evidence` |
| 5 | Category evidence contracts | **PASS** | 27 contracts; 316/316 engine rules resolve (1 documented DEFAULT allowlist entry); `test_every_measured_rule_maps_to_a_contract` |
| 6 | Multi-gate validation engine | **PASS** | G1–G9 implemented; 16 gate/unit tests + 7 family-parametrized corpus guards |
| 7 | Counterevidence & contradiction analysis | **PASS** | G6 collectors (parameterized SQL, argv, canonicalization, allow-lists, placeholders, pod-level inheritance, prose-contamination guards); mixed-path qualification (mission 6 "one safe path must not suppress a vulnerable path") |
| 8 | Data-flow & context integration | **PASS** | G4 consumes evidex verdicts; file-context consult via bounded cached reader; context-unverifiable cap (`test_unreadable_context_caps_confirmation_at_likely`) |
| 9 | Dedup & root-cause preservation | **PASS** | G7 records grouping; dedup stays upstream (mission: never merge by rule/file alone — UFIB does not merge) |
| 10 | Severity/confidence/applicability validation | **PASS** | G8 records four dimensions separately; no score overrides gates |
| 11 | Centralized release controller | **PASS** | `ufib_release.py`; manifest refreshed at both JSON-write boundaries; `refresh_preserves_dispositions_and_holds_late_arrivals` |
| 12 | Positive/negative/ambiguous/regression corpus | **PASS** | 24 UFIB tests + 7-family parametrized guard; corpus fixtures (positive=negative pairs for SQLi/deser/secrets) |
| 13 | End-to-end benchmark | **PASS** (scoped) | Live e2e scan (flask_sql): manifest + SARIF/JSON 0 mismatches; aclean production report benchmarked (below) |
| 14 | Final acceptance review | **PASS** | This document |

## 3. Quantitative acceptance criteria (mission 8)

| Invariant | Status | Evidence |
|---|---|---|
| 1. Zero CONFIRMED with missing mandatory evidence | **PASS** | `_decide` routes G3≠PASS away from CONFIRMED; corpus guard + gate tests |
| 2. Zero CONFIRMED from identifier/keyword-only matches | **PASS** | `test_claim_never_stronger_than_evidence` (WEAK) + G2 FAIL→REJECTED; secrets require value evidence (finding or file) |
| 3. Zero released-as-confirmed when a mandatory gate fails | **PASS** | G9 policy + e2e manifest (flask_sql: SQLi released only as LIKELY with G6 UNKNOWN recorded) |
| 4. Zero silent loss through the pipeline | **PASS** | `zero_silent_loss` invariant asserted in manifest (e2e + aclean: 1615/1615, flask_sql 3/3) + `refresh_preserves_dispositions...` |
| 5. Zero arbitrary suppression of labelled TPs | **PASS** | corpus guard: 133 TPs → 0 unverified rejections; the 2 rejections verified against fixture bytes (AWS documentation-example key; CBOM "Mock" material) with reasons in the audit block |
| 6. Every disposition auditable | **PASS** | `ufib.disposition_rationale` + per-gate reasons + `original_detector_fields` snapshot; e2e artifacts show them |
| 7. All report formats follow one release policy | **PASS** (JSON+SARIF) / **NOT_TESTED** (Excel/PDF/HTML disposition rendering — they consume the same findings, but format-specific rendering of dispositions is not yet verified) | `test_sarif_carries_the_same_disposition`; e2e cross-format check: 0 mismatches |
| 8. Existing regression tests pass | **PASS** | 3191 passed, 42 skipped (from 3167 pre-UFIB; 24 added, none deleted or weakened) |
| 9. No precision claim without a reproducible benchmark | **PASS** (bounds stated) | Benchmarks below; claim-level labelled evaluation set does not yet exist — see honest limits |
| 10. No coverage claim without capability evidence | **PASS** | Coverage table below distinguishes measured vs inferred |

## 4. Benchmarks (reproduction commands in §6)

**Golden corpus (detection baseline, pre-existing):** 133 expected / 133 TP / 0 FP — unchanged by UFIB (detection untouched).

**UFIB corpus lifecycle guard (claim level):** 133 labelled TPs → **100 released** (CONFIRMED/LIKELY), **31 held** with recorded reasons (control_gap/llm manual-review by contract; flow-unknown → INSUFFICIENT), **2 claim-rejected, both verified-backed** (CBOM "Mock…Key" material; AWS `AKIAIOSFODNN7EXAMPLE` documentation example). **Zero unverified rejections.**

**Live e2e production scan** (`main.py tests/e2e_targets/flask_sql`, exit 0): 3 findings → 2 CONFIRMED + 1 LIKELY (SQLi held at LIKELY because G6 recorded qualifying counterevidence — the brain refused to blindly confirm); manifest `scan_status: COMPLETE`, `zero_silent_loss: true`; SARIF↔JSON dispositions identical (0 mismatches).

**aclean production report (RBI2, 1,615 findings, 0.2 ms/finding):**
- The two rules the engineer flagged as FP families — `MISSING_RATE_LIMIT_ENDPOINT` (265) and `SPRING_MISSING_VALIDATION` (220) — release **0 rows** (all NEEDS_REVIEW, manual-review contract).
- Control_gap family: 491/491 held, 0 released.
- Release-set reduction 1,615 → 988 (38.8% fewer released rows), zero silent loss, 0 ANALYSIS_ERROR.
- Cross-tab vs triage: all 491 control-gap rows (the triage's largest LIKELY_FP blocks) now held with reasons.

## 5. Coverage gaps and honest limits

- **Claim-level labelled evaluation set does not exist.** Precision ≥95% (mission 8 target) is NOT claimed: the corpus labels assert detection, not claim truth. The two verified claim-rejections are the only independently verifiable claim labels today. Building that evaluation set is the next required step before any precision percentage is published.
- **aclean ran without source context** (target not on this host): all context-dependent confirmations were capped at LIKELY by the context-unverifiable rule — the manifest records this honestly. Re-running UFIB on the production host (files readable) is required for claim-level conclusions there.
- **The sast-family corpus guard holds 27/34** because the guard runs without full grouping/evidex context; production behavior is demonstrated by the live e2e scan, not by that number.
- **Excel/PDF/HTML**: dispositions flow through the shared findings list, but format-specific rendering is NOT_TESTED.
- **Interprocedural/cross-file flow analysis**: not added by UFIB; G4 consumes existing evidex/taint evidence only, and limitations are recorded per contract.

## 6. Reproduction commands

```bash
# Unit + gate + release + corpus-guard tests
py -m pytest tests/test_ufib_contracts_brain.py tests/test_ufib_corpus_guard.py -q

# Live e2e: manifest + SARIF/JSON consistency
py main.py tests/e2e_targets/flask_sql --output-dir <out> --no-pdf --no-excel
#   -> inspect <out>/clean_report.json release_manifest + per-finding ufib blocks
#   -> compare Security_Report.sarif result.properties.ufib_disposition

# aclean production benchmark (host-local report copy)
python -c "import json,sys; sys.path.insert(0,'.')
from analysis.ufib_release import apply_ufib_to_payload
d=json.load(open(r'D:\Data\Code test\reports\aclean\clean_report.json',encoding='utf-8'))
payload={'findings':d['findings'],'metadata':{}}
apply_ufib_to_payload(payload, d['metadata']['target'])
import json as j; print(j.dumps(payload['release_manifest']['by_disposition'], indent=2))"

# Full suite
py -m pytest -q --ignore=backup --ignore=dump --ignore=quarantine
```

## 7. Files changed (this UFIB changeset)

- `analysis/ufib_contracts.py` (new) — 27 contracts, claim interpreter, token resolution
- `analysis/ufib_brain.py` (new) — G1–G9, counterevidence collectors, dispositions
- `analysis/ufib_release.py` (new) — release controller, manifest, fail-soft policy
- `main.py` — UFIB stage + two manifest-refresh boundaries
- `reporting/sarif_export.py` — `ufib_disposition`/`ufib_release_eligible` properties
- `tests/test_ufib_contracts_brain.py`, `tests/test_ufib_corpus_guard.py` (new)
- `docs/ufib_baseline_audit.md` (Phase 1–2), this matrix
