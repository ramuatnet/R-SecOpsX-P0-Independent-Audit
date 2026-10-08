# R-SecOpsX V11 — Enterprise Web UI Architecture

**Phase:** INSPECT + DESIGN (architecture only — no implementation performed)
**Date:** 2026-10-06
**Repository:** `D:\Data\Code test\R-SecOpsX_V11`
**Measured against:** `clean_report.json`, Juice Shop corpus, 9.13 MB, 80 top-level keys

> **Method.** Every capability claim below is grounded in inspected source or in a
> measured field of a real scan artifact. Where a capability the brief names does
> not exist, it is recorded as absent rather than assumed. No production source was
> modified to produce this document, and no absence has been upgraded to a
> positive claim.

---

## 1. Executive status

The scan engine already emits **more than enough data** for a credible enterprise
UI: 80 top-level sections, a 227-key metadata block, five BOM inventories, a
per-finding evidence model, and a formal decision-object layer (RCMSP).

Two structural facts shape the whole design:

1. **There is no HTTP surface at all.** `main.py` is a CLI. Grep for
   `flask|FastAPI|uvicorn|http.server|aiohttp` across `scanner/`, `core/`,
   `reporting/` and `main.py` returns **only rule *patterns* that match Flask /
   Django code in scan targets** — zero server imports. Any web UI requires a new
   backend, not a re-wiring of an existing one.
2. **The artifact is 9.13 MB and cannot be shipped to a browser.**
   `v11_intelligence` alone is **19.1%**, `grouped` **10.9%** (a parallel 102-element
   view of the same key set), `sbom` **10.4%**. The API must therefore **project**,
   never proxy the artifact.

The single most important design decision follows from (1):

> **The API is a separate process that reads artifacts from disk. `main.py` must
> never import it.** This makes the entire UI feature set **zero-regression-risk**
> to the scan pipeline, and it is the only option that survives a future
> requirement for the scanner to run in a locked-down network segment with no
> inbound ports.

---

## 2. Inspection — what data actually exists

Counts are measured, not estimated. "Brief name" maps each requested view to the
section that would feed it.

### 2.1 Inventory

| Brief name | Artifact section(s) | Measured | Notes |
|---|---|---|---|
| findings | `findings[]`, `grouped[]` | 102 / 102 | same 144-key union, **all values differ**, distinct `finding_id`s — two views, not a copy |
| severity | `metadata.severity_distribution` (+`_sast`/`_sca`/`_scope`) | C1 H4 M42 L58 | **sum 105 ≠ 102** — see §3.1 |
| age | `vulnerability_age_summary`, per-CVE `vulnerability_age*` | `LEGACY_HIGH_RISK` | `age_buckets`, `patch_urgency_counts`, `outbreak_status_counts` |
| SBOM | `sbom[]`, `sbom_summary`, `top_cves`, `dependency_risk_register` | 168 pkgs / 13 CVEs / 3 at risk | reachability-aware |
| reachability | `reachability_summary`, `reachability_vulnerability_summary` | 3 reachable, 0 not-observed | never converts UNKNOWN→REACHABLE |
| CBOM | `cbom[]`, `crypto_misuse_summary` | 2 | MD5 weak hashing |
| AI-BOM | `aibom[]`, `ai_model_risk_summary` | 34 | `MODEL_HINT`, `confidence_score`, provenance |
| ABOM | `abom[]`, `bom_correlation`, `bom_correlation_summary` | 25 | `human_approval_detected`, `asset_scope` |
| ML-BOM | `mlbom[]` | **0 (empty)** | must render an honest empty state |
| API-BOM | `apibom[]`, `api_abuse_risk_summary` | 245 | `auth_hint`, `methods`, route |
| IaC | folded into `findings[]` (`TF_*`=3, `DOCKER_*`=3, k8s=0) | 6 | **no dedicated top-level section** |
| LLM Security | **no section exists** | 2 findings w/ `LLM*` OWASP; 1 `LLM*` rule_id | see §3.3 |
| MITRE ATT&CK | `mitre[]`, `findings[].mitre` | 7 tactics, 21/102 mapped | see §3.4 |
| OWASP | `owasp{}` (10 entries), `framework_mapping_summary` | 10 categories | global mapping is real |
| compliance | `compliance_summary{}`, `findings[].pci_dss/nist/iso27001/soc2` | 8 frameworks | **see §3.2** |
| evidence | `findings[].canonical_evidence`, `.canonical_qualified_evidence` | 102/102 | `evidence_id`, `qualified`, `qualified_at` |
| attack graph | `v11_intelligence.findings[].intelligence.attack_graph` | 102 × 24 nodes | **see §3.5** |
| attack paths | `attack_paths[]` | **0 (empty)** | |
| RCMSP | `...intelligence.rcmsp` | 102/102 dicts | `decision_state`, `decision_outcome`, `provenance` |
| rule quality | `rule_telemetry{}` | 25 rules | **`precision` is `null` for all 25** |
| governance | `governance_signals[]`, `release_readiness`, `executive_decision` | 7 | `DO_NOT_RELEASE` P0 conf 0.95 |
| control coverage | `security_control_coverage_summary` | ratio 0.1, rule 0.03 | semantics string present |
| secrets | `secret_intelligence_summary` | 68 detected, 0 confirmed | `OFFLINE_ONLY_NOT_VALIDATED` |
| reporting | PDF ×2, XLSX ×3, SARIF, VEX, CycloneDX, `Scan_Performance.json` | — | already generated server-side |

### 2.2 Per-finding fields the UI can genuinely rely on

These were found by enumerating the 144-key union and measuring population rates.
They are the strongest asset in the payload — a UI can grade evidence per finding
rather than presenting a flat list.

| Field group | Measured | Use |
|---|---|---|
| **Evidence quality** | `evidence_score` / `evidence_quality`: 70×71, 100×12, 55×11 | numeric evidence grade per finding |
| | `evidence_confidence`: MEDIUM 69, HIGH 22, LOW 11 | confidence badge |
| | `evidence_validation` (82 text), `evidence_validation_detail` (structured dict, 12) | *why* evidence was accepted |
| **Redaction** | `evidence_redacted` True×**63**, `evidence_redaction_type = REPORT_SECRET_VALUE_REDACTION` | redaction is **systematic**, not incidental |
| **Validity** | `validity_state`: UNKNOWN×68; `validity_validation_mode`: OFFLINE_ONLY_NOT_VALIDATED×68; `validated_live` False×64; `offline_only` True×64 | the artifact *already* says secrets are unvalidated — the UI must repeat it |
| **Taint** | `taint_chain` / `taint_path` / `rule_dataflow` on **12/102** only; `sink_validated` 101/102 | taint view is honest for 12 findings only |
| **Benchmark provenance** | `benchmark_ground_truth` (dataset `OWASP_JUICE_SHOP`), `benchmark_profile: juice_shop`×23, `is_synthetic` True×23 | the UI can *prove* which findings are fixture-derived |
| **Classification** | `classification`: heuristic 94, control_gap 8 | separates signal from control-mapping artefacts |
| **Decision** | `decision_state`: REVIEW_REQUIRED×68, `decision_reason`, `reportable_finding` True×68 | per-finding disposition |
| **Precision** | `precision_metadata` on **2/102** | ties directly to G-071 |
| **Context** | `context_class` on **2/102** only | nearly absent — do not build a view on it |
| **Language** | typescript 44, yaml 35, unknown 8, json 4, terraform 3 | enables a language filter |

### 2.3 What does **not** exist

| Requested | Status | Evidence |
|---|---|---|
| **MITRE ATLAS dashboard** | **NOW IMPLEMENTED (this cycle)** — attribution, not a view | `core/atlas_mappings.py`; 54/120 live AI rules carry an `AML.T*` technique, 66 carry none by design; **G-063 closed, G-078 open** |
| **RCMSP dashboard** | data exists (102/102) but is **per-finding only**; no aggregate/rollup section | `core/rcmsp.py`, `core/v11_intelligence.py` |
| **Dashboard modules** | **none** — no `*dash*` file in `scanner/`, `core/`, `reporting/` | filename probe |
| **Severity / age dashboards** | data exists; no view layer | — |
| **Dependency manifest** | **none** — no `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` anywhere (**G-072**) | recursive probe |
| HTTP API / auth | **none** (**G-072**) | — |
| **FREE-AI / RBI traceability** | **none** (**G-077**) — 12 of 26 recommendations have partial rules, none carries a recommendation id | grep: FREE-AI / RBI / sutra = 0 hits |

Third-party libraries *are* imported (`reportlab`, `openpyxl`, `matplotlib`,
`yaml`) but **undeclared**. A web deployment cannot be reproduced today.

---

## 3. Measured integrity facts that constrain the UI

These are not opinions. A dashboard built naively over these fields will state
something false to a CISO. Each one becomes a **hard requirement** in §4.3.

### 3.1 `total_findings` (105) ≠ `len(findings)` (102) — *by design, must be disclosed*

```
metadata.severity_distribution = {Critical:1, High:4, Medium:42, Low:58}  sum=105
metadata.total_findings        = 105
len(findings)                  = 102  →  actual {Medium:42, Low:58, High:2}
metadata.severity_distribution_scope = "SAST_findings_plus_unique_vulnerable_dependency_packages"
```

`main.py:2059` — `total_findings = sast_findings + vulnerable_packages`. The
"missing" 1 Critical + 2 High **are the 3 vulnerable dependency packages**.
This is honest and self-describing, but the consequence for the UI is severe:

> A single donut chart of "findings by severity" is **wrong by construction**. The
> same circle mixes code defects with dependency risk. The UI must render
> **stacked, separately-labelled populations** and print
> `severity_distribution_scope` verbatim next to any combined figure.

### 3.2 `compliance_summary` disagrees with the finding-level data — **no authoritative compliance metric**

| Framework | `compliance_summary` | Actual non-empty on `findings[]` |
|---|---|---|
| OWASP | 21 | **102** |
| CWE | 21 | **102** |
| ISO 27001 | **102** | 90 (`iso_27001`) |
| NIST 800-53 | **102** | 90 (`nist_800_53`) |
| SOC 2 | **102** | 90 |
| PCI DSS | 19 | 90 |
| MITRE ATT&CK | 13 | 21 |
| CIS | 6 | (no per-finding field at all) |
| — | — | `compliance_controls` **102/102** |

The two sources are wrong in **opposite directions** and cannot both be shown.
A third field, `compliance_controls`, is populated on all 102 findings and is the
most plausible authoritative source — but it is not reconciled against
`compliance_summary` anywhere.

> **Design consequence: the Compliance view must not present a single coverage
> number per framework until the discrepancy is resolved.** It must either show all
> three sources side by side with their provenance, or refuse to render the chart.

### 3.3 LLM Security has almost no persisted substrate

Console reported `2617 raw → 9 actionable | 2608 contextual`. The artifact
contains **no LLM section, no LLM metadata keys**, 2 findings carrying an `LLM*`
OWASP code and 1 `LLM*` rule_id. The 2608 contextual findings are **not
reviewable anywhere**.

> The AI-Security view must be built on **AI-BOM (34) + ABOM (25) + CBOM (2)**,
> which are rich, and must **not** claim to represent the LLM rule engine. The
> 2608 dropped findings need to be surfaced as a disclosed limitation.

### 3.4 MITRE list is thin and partly placeholder

`mitre[]` has 7 entries; **`T1595` has the description `"Mapped ATT&CK technique"`** —
a placeholder string, not tactic semantics. Only 21/102 findings carry a `mitre`
value. There is no 15-tactic matrix, and no tactic-dataset provenance field.

> The MITRE view must render the **full tactic set with explicit zeros** and carry
> `dataset_version` / `as_of`. Rendering only observed tactics hides 8 tactics and
> implies coverage that was never measured.

### 3.5 The attack graph is a fixed template — per-finding reachability is not real

```
distinct attack_graph signatures across 102 findings : 1
every finding : nodes=24, relationships=25, reachable=True, path_count=160
```

`core/ai_graphs.py` builds agent/mcp/rag graphs from an **evidence id only** — not
from the finding's rule, location or data flow. Consequently RCMSP returns
`SECURITY_REVIEW_REQUIRED / HIGH` for **every** finding, which is vacuous.

> **The Attack Path view must ship disabled.** Enabling a "reachable" badge that
> is constant across all findings is exactly the UNKNOWN→REACHABLE upgrade the
> project forbids. `core/ai_graphs.py` needs finding-specific inputs first.

### 3.6 Per-finding OWASP mapping is ~2% populated, while global mapping is full

Two independent mapping paths exist and they disagree sharply:

| Path | Measured |
|---|---|
| Global `framework_mapping_summary` | fully populated, 10 OWASP categories, `mapped_findings` = total |
| Global `owasp{}` | 10 categories with counts |
| Per-finding `vuln_type`→OWASP in `intelligence.owasp_mapping` | **100/102 `UNMAPPED`**, 2 `DIRECT` |
| Per-finding `owasp_id` / `owasp_edition` / `owasp_llm_top10` / `owasp_llm_top10_2026` | **2/102 (2%)** |

G-058 already registered the *metadata-level* parallel fields
(`owasp_top10_2021`, `mitre_attack`, `iso_27001_2022`, `owasp_api_top10_2023`) as
**0**. This inspection shows the same emptiness one level down, at finding level:
the 2026 OWASP and LLM editions are effectively unpopulated.

> A per-finding "mapped to" chip must not be rendered from either per-finding
> path. Only the global rollup is trustworthy today.

### 3.6b `risk_category` and `severity` disagree — a second presentation trap

```
severity      : Low 58 | Medium 42 | High 2
risk_category : Medium 88 | High 14        ← 14 "High risk" vs 2 "High severity"
priority      : P4 58 | P3 42 | P2 2        (consistent with severity)
```

14 findings are "High risk" but only 2 are "High severity". A UI that mixes these
into one badge — or that sorts by one and labels with the other — will
systematically misrepresent urgency. **`severity` and `risk_category` must be
rendered as two distinct, separately-labelled axes**, and the ordering key stated
explicitly.

### 3.7 Population heterogeneity and unvalidated secrets

```
analysis_scope            : production 79 | benchmark_synthetic 23
evidence_valid            : 101/102  (one finding lacks valid evidence)
preserved_for_evaluation  : 102/102
source_type               : null on 102/102  (no taint provenance on regex findings)
rule_telemetry.precision  : null on all 25 rules
secrets                   : 68 detected, 0 confirmed_active, live validation DISABLED
```

A dashboard showing "102 findings" is misleading if 23 are synthetic. Secrets must
never be rendered as validated/active.

### 3.8 What is **already** safe (verified, do not re-litigate)

- **Secret material is redacted at scan time, systematically.** Across 66
  secret-class findings, 58 evidence blocks carry explicit markers (`[REDACTED]`,
  `[HIGH-ENTROPY VALUE REDACTED]`) and **no unredacted value was found** in
  `snippet` or `evidence`. The mechanism is explicit in the schema:
  `evidence_redacted` is `True` on **63** findings, all with
  `evidence_redaction_type = REPORT_SECRET_VALUE_REDACTION`. (Bounded claim:
  verified by pattern search over `snippet` and `evidence`, not by exhaustive
  entropy analysis. The redaction flag itself is the authoritative signal, and the
  UI should key off it rather than re-implement detection.)
- **The artifact already declares its own epistemic limits.**
  `validity_state: UNKNOWN` (68), `validity_validation_mode:
  OFFLINE_ONLY_NOT_VALIDATED` (68), `validated_live: False` (64),
  `offline_only: True` (64). A UI that respects these fields is honest about
  secrets *without any new engine work*.
- **Provenance is present on nearly everything** — `*_provenance`,
  `*_provenance_counts`, `live_feeds_used`, `catalog_version`, `as_of`,
  `coverage_*_semantics`. This is the strongest asset for an honest UI.

### 3.9 Absolute-path disclosure — a genuine frontend safety issue

```
metadata.target                            D:\Data\Code test\prodtest\juice-shop-git
findings[].canonical_evidence.…full_path    102/102 absolute
aibom[].file                               34/34 absolute
abom[].file                                25/25 absolute
cbom[].file                                 2/2 absolute
```

**163 absolute paths** disclose scanner host layout, target location and the
operator's directory structure (`D:\Data\Code test\...`). `apibom[].file` and
`findings[].file` are already relative — the inconsistency is itself the smell.

> Path normalisation at the API boundary is **mandatory**, not optional.

---

## 4. Design

### 4.1 Process and trust boundary

```
        scanner process                web process (new)
        ---                ---
  main.py ──writes──> reports/<scan>/   web/serve.py ──reads──> artifact (read-only)
  (CLI, unchanged)   clean_report.json        │
                      SARIF/VEX/CycloneDX     ├──> web/project.py   (projections + aggregates)
                      *.pdf *.xlsx            ├──> web/provenance.py(envelope + scope strings)
                      Scan_Performance.json    └──> web/redact.py     (path normalisation)
                                                   │
                                          role-scoped responses only
                                                   ▼
                                          browser (SPA, no policy logic)
```

Hard rules:

- **No reverse dependency.** `web/` must not import `scanner/` or `core/`. It
  consumes artifacts only. Enforced by a test.
- **Read-only mount.** The web process opens the artifact with `rb` and never
  writes to `reports/`.
- **No artifact proxying.** No endpoint returns the raw 9.13 MB document.

### 4.2 API surface (projections, not proxies)

| Endpoint | Persona | Returns |
|---|---|---|
| `GET /api/scans` | all | scan index: id, target **redacted**, date, tool version, phase timings |
| `GET /api/scans/{id}/decision` | CIO, CTO, CISO | `executive_decision`, `release_readiness`, `governance_signals`, risk score **+ its model string** |
| `GET /api/scans/{id}/severity` | CISO | **two** labelled series (`_sast`, `_sca`) + `scope` string verbatim |
| `GET /api/scans/{id}/findings` | SecEng, AppSec | paginated projection: id, severity, vuln_type, rule_id, file (rel), line, confidence, `analysis_scope`, `evidence_valid` |
| `GET /api/scans/{id}/findings/{fid}` | AppSec | detail + redacted evidence + `canonical_qualified_evidence` |
| `GET /api/scans/{id}/boms/{ai,abom,cbom,apibom,mlbom}` | AI-Sec, AppSec | inventory projection, paths normalised, confidence retained |
| `GET /api/scans/{id}/dependencies` | AppSec, SecEng | `top_cves`, reachability, EPSS/KEV + `*_provenance` |
| `GET /api/scans/{id}/attack/mitre` | CISO, SecEng | **15 tactics, explicit zeros**, `dataset_version` (blocked on §3.4 work) |
| `GET /api/scans/{id}/attack/graph` | SecEng | **404 + `feature_unavailable_reason`** until §3.5 is fixed |
| `GET /api/scans/{id}/compliance` | Compliance | **dual-source**, both counts + provenance; no single number (§3.2) |
| `GET /api/scans/{id}/rule-quality` | SecEng | counts only; `precision: null` rendered as **"unmeasured"**, never 0% |
| `GET /api/scans/{id}/artifacts` | all | download links for PDF/XLSX/SARIF/VEX/CycloneDX — served by the existing files, not regenerated |

Every response carries the envelope in §4.3. Pagination is mandatory on
`/findings` (102 now, thousands on a monorepo).

### 4.3 Provenance envelope (cross-cutting, non-optional)

```json
{
  "provenance": {
    "tool": "R-SecOpsX SAST v2.0",
    "scan_id": "…",
    "scan_date": "2026-10-06T10:20:26.031691Z",
    "engine_modes": { "kev": "LIVE_CISA_KEV_V1", "epss": "LIVE_FIRST_ORG_EPSS_V1" },
    "populations": {
      "total_findings_field": 105,
      "findings_array": 102,
      "severity_scope": "SAST_findings_plus_unique_vulnerable_dependency_packages",
      "analysis_scope": { "production": 79, "benchmark_synthetic": 23 },
      "evidence_valid": 101
    },
    "known_limitations": [
      "attack_paths is empty; per-finding reachability is not established",
      "per-finding OWASP mapping is UNMAPPED for 100/102 findings",
      "2608 contextual LLM findings were not persisted",
      "secrets are OFFLINE_ONLY_NOT_VALIDATED"
    ],
    "coverage_semantics": { "control_coverage_ratio": "STATIC_EVIDENCE_ONLY_NOT_CONTROL_EFFECTIVENESS" }
  }
}
```

The `known_limitations` list is **derived at runtime from the artifact**, not
hard-coded — so it cannot drift from reality. This is what lets the UI be
honest without a human maintaining a caveats file.

### 4.4 Role model

| Capability | CIO | CTO | CISO | SecEng | AppSec | AI-Sec | Compliance |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Release decision / risk score | ● | ● | ● | ○ | | ○ | ○ |
| Severity (dual-population) | ● | ● | ● | ○ | ○ | | ○ |
| Governance signals | ● | ● | ● | ○ | | | ● |
| Finding triage list | | ○ | ● | ● | ● | ○ | |
| Finding detail + redacted evidence | | | ○ | ● | ● | ○ | |
| Taint / data-flow detail | | | | ● | ● | | |
| Rule quality | | | ○ | ● | ● | | |
| SBOM + reachability | ○ | ○ | ● | ● | ● | | ● |
| AI-BOM / ABOM / CBOM / ML-BOM | | ○ | ● | ○ | | ● | |
| LLM findings (2) | | | ● | ○ | ○ | ● | |
| MITRE tactic coverage | ● | | ● | ● | ● | ● | |
| Attack graph | | | ○ | ● | ● | ○ | |
| Compliance dual-source | ● | | ● | | | | ● |
| Evidence & RCMSP audit trail | | | ● | ● | ● | ○ | ● |
| Artifact downloads | ● | ● | ● | ● | ● | ● | ● |

`●` full · `○` summary/redacted. Two orthogonal axes are enforced **separately**:

- **Section** — which artifact sections a role may read at all.
- **Field** — within a permitted section, which fields (notably `snippet` and
  `evidence[]`) are masked. A role may see a finding exists without seeing its
  matched line.

### 4.5 Frontend

- **SPA, no framework lock-in decision yet.** Given the undeclared-dependency
  problem (§2.3), a **build-free ES-module frontend** keeps the web tier
  dependency-free, matching the project's stdlib-first posture.
- **No policy logic client-side.** Severity mapping, scope labelling, reachability
  badges and "unmeasured" states are computed server-side. A browser must never be
  able to upgrade UNKNOWN → REACHABLE or treat `null` precision as zero.
- Charts render **explicit zeros** with a `—` marker for unmeasured; every chart
  has a *populations* caption sourced from the envelope.
- Every data view shows a **provenance chip** (`engine_modes`, `as_of`,
  `provenance`) — the data is already there, so this is cheap and is what makes
  the product defensible in an audit.

---

## 5. Feature justification

Required fields: problem / reference tool / how it does it / current behavior /
actual gap / enterprise-essential / research-relevant / cost / regression risk /
exact implementation location.

### F-1 · Read-only scan artifact API *(foundation)*
- **Problem:** no HTTP surface exists; the UI cannot exist.
- **Reference tool:** Dependency-Track API; GitHub Advanced Security; osv-scanner `--experimental-json`.
- **How:** async index + REST projections + pagination + stable finding IDs.
- **Current behavior:** CLI only; writes `clean_report.json`, SARIF, VEX, CycloneDX, PDF, XLSX, `Scan_Performance.json` to `reports/<scan>/`.
- **Actual gap:** entire web tier absent; no auth, no pagination, no projection layer.
- **Enterprise-essential:** yes — it is the precondition for every other feature.
- **Research-relevant:** no (enabling infrastructure).
- **Cost:** ~5–7 days. Stdlib `http.server`/`socketserver` keeps zero new deps; `requirements.txt` must be authored regardless.
- **Regression risk:** **zero** — provided `web/` is never imported by `main.py` (enforce with a test).
- **Location:** new `web/serve.py`, `web/routes.py`, `web/project.py`, `web/provenance.py`, `web/redact.py`, `tests/test_v11_web_boundary.py`.

### F-2 · Provenance envelope + derived known-limitations *(foundation)*
- **Problem:** every measured defect in §3 becomes a **false statement** in the UI unless the payload carries its own honesty metadata.
- **Reference tool:** SARIF `invocations[].toolExecutionNotifications`; VEX `justification`; OpenSSF Scorecard evidence.
- **How:** self-describing artifacts; VEX explicitly records *why* something is not asserted.
- **Current behavior:** provenance exists **per section** (`*_provenance`, `live_feeds_used`, `catalog_version`, `coverage_*_semantics`) but there is **no aggregate envelope**, no population reconciliation, and no limitations list.
- **Actual gap:** §3.1 population mismatch, §3.4 placeholder descriptions, §3.7 heterogeneous populations are all invisible to a consumer.
- **Enterprise-essential:** yes — this is the difference between a dashboard and a defensible control.
- **Research-relevant:** yes — auto-derived epistemic-status from artifact structure is a genuine contribution.
- **Cost:** ~2 days.
- **Regression risk:** zero (pure function over the artifact).
- **Location:** `web/provenance.py::build_envelope(payload)`; consumed by every route.

### F-3 · Executive risk & release decision (CIO / CTO)
- **Problem:** "are we shipping?" must be one answer, traceable to gates.
- **Reference tool:** GitLab pipeline merge gates; Endor/Scanitrix release gates.
- **How:** derive verdict from blocking gates, expose drivers, never recompute silently.
- **Current behavior:** `release_readiness` = `REMEDIATE_BEFORE_RELEASE` / P1 / confidence 0.85 with 1 blocking + 3 review gates; `executive_decision` = `DO_NOT_RELEASE` / P0 / 0.95 with 5 drivers; 7 `governance_signals`.
- **Actual gap:** no view; and `risk_score` has **no audience separation** — one number is currently offered to board and engineer alike.
- **Enterprise-essential:** yes.
- **Research-relevant:** low.
- **Cost:** ~1 day.
- **Regression risk:** zero.
- **Location:** `web/routes.py::decision`; source `metadata.release_readiness*`, `metadata.executive_decision*`.

### F-4 · Severity & posture dashboard (CISO)
- **Problem:** the single most-scrutinised number is currently **wrong by construction** (§3.1).
- **Reference tool:** Snyk risk dashboards; Wiz; Microsoft Defender Cloud Apps.
- **How:** stacked, separately-labelled populations; never a merged donut.
- **Current behavior:** `severity_distribution` (+`_sast`, `_sca`, `_scope`), `risk_score` + `risk_score_model`, `security_control_coverage_summary` (ratio 0.1, rule 0.03, `coverage_grade: LIMITED`).
- **Actual gap:** no dual-population rendering; the control-coverage ratio is at risk of being read as control *effectiveness*, which its own semantics string forbids.
- **Enterprise-essential:** yes — and it is the highest-risk page to get wrong.
- **Research-relevant:** moderate (population-heterogeneity-aware severity presentation).
- **Cost:** ~2 days.
- **Regression risk:** zero.
- **Location:** `web/routes.py::severity`; must emit `_sast` and `_sca` separately and print `severity_distribution_scope`.

### F-5 · Finding triage workbench (SecEng / AppSec)
- **Problem:** 102 findings with 144 keys each cannot be trialled by eye; monorepos make this worse.
- **Reference tool:** Semgrep Findings UI; CodeQL web; Snyk triage queues.
- **How:** server-side filter/sort/paginate on stable IDs; bulk status with an audit trail.
- **Current behavior:** `findings[]` with `finding_id`, `severity`, `priority`, `vuln_type`, `rule_id`, `engine`, `confidence`, `analysis_scope`, `evidence_valid`, `group_key`, `instances`.
- **Actual gap:** no pagination/projection; `grouped[]` is a **full second 102-element
  copy** of the same 144-key schema with different values and different
  `finding_id`s (10.9% of the artifact) — the UI must not present both or assume
  they are interchangeable; `taint_chain`/`taint_path`/`rule_dataflow` are
  populated on only **12/102**, so a taint view is honest for 12 findings and must
  be absent for the other 90.
- **Enterprise-essential:** yes.
- **Research-relevant:** no.
- **Cost:** ~3 days.
- **Regression risk:** zero.
- **Location:** `web/project.py::finding_projection`; paginated at `/findings`.

### F-6 · Rule-quality view (SecEng)
- **Problem:** 25 rules fire; without quality data, tuning is blind. A `null` precision must not be read as 0%.
- **Reference tool:** Semgrep `--metrics=fp`; CodeQL query metrics; snyk rule confidence.
- **How:** report measured precision with an explicit *unmeasured* state.
- **Current behavior:** `rule_telemetry` — 25 rules, each `{tp, fp, unknown, total, precision: null}`.
- **Actual gap:** `precision` is **null for every rule** (telemetry exists, quality
  does not); `precision_metadata` is populated on only **2/102** findings, so even
  the per-finding quality trail is nearly empty. The class-A benchmark proves 1.0
  F1 on 13 fixtures, but that is a fixture set, not corpus precision.
- **Enterprise-essential:** yes for rule-lifecycle governance.
- **Research-relevant:** **high** — publishing `tp/fp/unknown/total` with null
  precision is an honest, novel telemetry design.
- **Cost:** ~1 day.
- **Regression risk:** zero.
- **Location:** `web/routes.py::rule_quality`; source `rule_telemetry` **plus** the
  per-finding `precision_metadata` (§2.2), which lets a rule be inspected against
  the 2 findings that do carry metadata.

### F-7 · AI security view (AI-Sec)
- **Problem:** the brief expects an LLM dashboard; the artifact cannot support one.
- **Reference tool:** Protect AI (Lakera); Mindgard; Roblox/Scale AI asset inventories.
- **How:** model/agent/tool inventory with confidence and provenance, separate from rule findings.
- **Current behavior:** `aibom` 34 (`provider`, `model_hint`, `confidence_score`, `detection_mode: REGEX`), `abom` 25 (`framework`, `tools_detected`, `human_approval_detected`, `asset_scope`, `validation_only`), `cbom` 2, `mlbom` **0**.
- **Actual gap:** **LLM Security has no persisted section** (§3.3) — 2608 contextual findings unreviewable; ML-BOM empty; all BOM `file` fields absolute (§3.9).
- **Enterprise-essential:** yes for AI-Sec, **no** for the other six personas.
- **Research-relevant:** high (ABOM `validation_only` / `human_approval_detected` are unusual, defensible signals).
- **Cost:** ~2 days; the LLM substrate gap is a **separate** remediation.
- **Regression risk:** zero.
- **Location:** `web/routes.py::boms`; source `aibom`/`abom`/`cbom`/`mlbom`.

### F-8 · Compliance dashboard (Compliance)
- **Problem:** this is the page a compliance officer will screenshot into an audit — and it is currently unsound (§3.2).
- **Reference tool:** Vanta/Drata; osv.dev; OSV-Scanner; NIST CSF dashboards.
- **How:** map findings → controls with explicit *coverage vs. conformance* separation, and version the framework catalogue.
- **Current behavior:** `compliance_summary` {8 frameworks} vs. per-finding `owasp`/`cwe`/`pci_dss`/`nist`/`iso27001`/`soc2`.
- **Actual gap:** **the two sources disagree in both directions**; G-058 already records `owasp_top10_2021`/`mitre_attack`/`iso_27001_2022`/`owasp_api_top10_2023` at **0**; no framework-dataset version; no CIS per-finding field.
- **Enterprise-essential:** yes — and **blocked** until §3.2 is resolved.
- **Research-relevant:** moderate (conflict presentation as a first-class view).
- **Cost:** ~1 day to build the **dual-source** view; remediation is separate and unspecified.
- **Regression risk:** zero — but shipping a single-number view would be a *truthfulness* regression.
- **Location:** `web/routes.py::compliance`; must render both sources until G-0xx is closed.

### F-9 · MITRE ATT&CK coverage (CISO / SecEng)
- **Problem:** tactic coverage is a board-level metric; observed-only rendering overstates it.
- **Reference tool:** MITRE ATT&CK Navigator; AttackIQ; VECTR.
- **How:** fixed 15-enterprise-tactic matrix with explicit zeros, dataset version pinned.
- **Current behavior:** `mitre[]` = 7 entries; **`T1595` description is the placeholder `"Mapped ATT&CK technique"`**; 21/102 findings carry `mitre`.
- **Actual gap:** no 15-tactic matrix, no dataset provenance, placeholder text; G-054 measured **1/5 PASS**.
- **Enterprise-essential:** yes for CISO reporting.
- **Research-relevant:** high (zero-explicit coverage over a pinned dataset).
- **Cost:** ~1 day UI; remediation is a **pinned ATT&CK dataset** decision (G-054, blocked on redistribution).
- **Regression risk:** zero.
- **Location:** `web/routes.py::attack_mitre`; must refuse to render until a versioned dataset is wired.

### F-10 · Evidence & RCMSP audit trail (CISO / Compliance)
- **Problem:** "why did the tool say this?" must be answerable without the PDF.
- **Reference tool:** osv.dev provenance; in-toto attestations; SLSA provenance; CycloneDX pedigree.
- **How:** every decision references evidence IDs; evidence carries its own qualification.
- **Current behavior:** `canonical_evidence` 102/102 (`evidence_id`, `source`, `timestamp`, `provenance`, `type`, `content_or_context`); `canonical_qualified_evidence` 102/102 (`qualified`, `qualified_at`, `qualification_reason`); RCMSP 102/102 (`decision_context`/`decision_state`/`decision_policy`/`decision_outcome`/`provenance`). Richer per-finding fields also exist: `evidence_score`, `evidence_confidence`, `evidence_validation_detail`, `evidence_redacted` (63) with `evidence_redaction_type`, plus `decision_state`/`decision_reason`/`reportable_finding` (68).
- **Actual gap:** no rollup; RCMSP is unreachable from the top level (`v11_intelligence.findings[].intelligence.rcmsp` — a 3-level nest); and per §3.5 its output is currently **vacuous** (`SECURITY_REVIEW_REQUIRED` for every finding), so it must be presented as a decision *record*, not a decision. Note the two distinct decision layers — per-finding `decision_state` (`REVIEW_REQUIRED`, 68) and the payload-level `release_readiness`/`executive_decision` — which must not be presented as one decision.
- **Enterprise-essential:** yes.
- **Research-relevant:** **high** — separating evidence from decision and refusing to reduce RCMSP to a score is a defensible research position.
- **Cost:** ~2 days.
- **Regression risk:** zero.
- **Location:** `web/routes.py::evidence`; source `canonical_qualified_evidence` + `intelligence.rcmsp`.

### F-11 · Attack-path visualisation (SecEng / AppSec) — **HOLD**
- **Problem:** attack paths are the product's most compelling story.
- **Reference tool:** BloodHound; PMapper; attack-tree tools.
- **How:** render only paths established by real graph evidence.
- **Current behavior:** `attack_paths[]` **= 0**; per-finding `attack_graph` is **one identical 24-node template for all 102 findings** with `reachable: true` always.
- **Actual gap:** **there is nothing true to render.** `core/ai_graphs.py` derives graphs from the evidence id alone, so every finding looks reachable.
- **Enterprise-essential:** desirable; **not yet honestly renderable.**
- **Research-relevant:** high once `ai_graphs.py` takes finding-specific inputs.
- **Cost:** 0 now; substantial later.
- **Regression risk:** shipping it now would be a **correctness regression** — a constant "reachable" badge across all findings is precisely the forbidden UNKNOWN→REACHABLE upgrade.
- **Location:** blocked. Endpoint returns `404 {feature_unavailable_reason}`; fix site is `core/ai_graphs.py` + `core/attack_graph.py`.

---

## 6. Sequencing

| # | Step | Depends on | Days |
|---|---|---|---|
| 1 | `requirements.txt` + `web/redact.py` (path normalisation) + `web/provenance.py` | — | 2 |
| 2 | `web/serve.py`, `web/project.py`, routes for `/decision`, `/severity`, `/findings` | 1 | 4 |
| 3 | Frontend shell + F-3, F-4, F-5 views | 2 | 3 |
| 4 | BOM routes + F-7, F-6 | 2 | 2 |
| 5 | F-8 dual-source compliance, F-10 evidence/RCMSP | 2 | 3 |
| 6 | F-9 MITRE matrix (after dataset decision) | G-054 | 1 |
| 7 | F-11 attack paths (after `ai_graphs.py` rework) | new | TBD |

Steps 1–5 are **independent of every blocked gap** and can start immediately.

---

## 7. Blockers and open questions

**Blocking a specific view:**

| Blocker | Blocks | Needs |
|---|---|---|
| §3.5 fixed attack-graph template | F-11 | `core/ai_graphs.py` rework to consume finding-specific inputs |
| §3.2 compliance source conflict | F-8 single-number view | Authoritative definition of "compliance coverage" |
| §3.3 no persisted LLM substrate | LLM dashboard | Persist actionable + contextual LLM findings, or disclose permanently |
| §3.4 7-tactic list + placeholder text | F-9 matrix | Pinned ATT&CK dataset + redistribution decision (G-054) |
| G-058 parallel framework fields at 0 | F-8 depth | Framework-mapping decision |

**Needs a decision from you (not resolvable by inspection):**

1. **Zero-dashboard meaning.** "ZERO Dashboard" is ambiguous — **zero-day**
   (the artifact supports this: `vulnerability_age_summary.zero_day_status_counts`,
   per-CVE `zero_day_status` / `zero_day_method`) or **zero-trust** (no data
   exists). This document assumes **zero-day**; confirm before implementation.
2. **Framework for the SPA.** Build-free ES modules (matches the stdlib-first
   posture, zero new deps) vs. React/Vue (faster to build, adds a build chain).
3. **AuthN/AuthZ provider.** No auth exists. OIDC/SAML integration implies an
   identity provider; the role matrix in §4.4 needs a real principal source.
4. **Multi-tenancy.** Is one deployment per target, or one multi-tenant
   deployment? This decides whether `target` isolation is a UI concern or a
   storage concern.
5. **Compliance framework set.** Which of the 8 (`CIS`, `CWE`, `ISO 27001`,
   `MITRE ATT&CK`, `NIST 800-53`, `OWASP`, `PCI DSS`, `SOC 2`) are in scope for
   v1 of the UI.

---

## 8. Gaps this inspection produced

These are new and belong in `reports/gap_register.json`:

| ID | Title | Tier | Evidence |
|---|---|---|---|
| G-063 | **MITRE ATLAS attribution - CLOSED this cycle** | MEASURED_CLOSED | `core/atlas_mappings.py`; benchmark 5/5; 54/120 rules attributed; dataset pinned to ATLAS 2026.09 / format 6.0.0 |
| G-078 | ATLAS coverage is 54/120; 66 rules carry no technique | MEASURED_OPEN | governance/compliance obligations and agentic deferrals; a few are unread-definition near-misses |
| G-077 | No FREE-AI / RBI traceability layer | MEASURED_OPEN | 12 of 26 recommendations have partial rules; none carries a recommendation id |
| G-076 | Evidence validation fails `TP_NOSQL_DYNAMIC_QUERY` | MEASURED_OPEN | 6/7 exit 1; **pre-existing**, isolated by import graph (benchmark imports only `core.analyzer`) |
| G-064 | `compliance_summary` conflicts with per-finding framework fields in both directions | MEASURED_OPEN | ISO/NIST/SOC2 claim 102 vs 90 actual; OWASP/CWE claim 21 vs 102 actual; `compliance_controls` 102/102 unreconciled |
| G-065 | LLM Security produces no persisted artifact - 2608 contextual findings unreviewable | MEASURED_OPEN | no `llm*` top-level or metadata key; 2 LLM OWASP findings; `raw_llm_finding` true on 2 |
| G-066 | Per-finding OWASP mapping is ~2% populated while global mapping is full | MEASURED_OPEN | `owasp_mapping` 100/102 UNMAPPED; `owasp_id`/`owasp_edition`/`owasp_llm_top10_2026` 2/102 |
| G-067 | `attack_graph` is one fixed 24-node template for every finding; `reachable` is always true | MEASURED_OPEN | 1 distinct signature / 102 findings; `core/ai_graphs.py` uses evidence id only |
| G-068 | `attack_paths` and `bom_correlation` are empty while status labels read `CORRELATED` | MEASURED_OPEN | `attack_paths`=0; `bom_correlation`=0 with `status: CORRELATED` |
| G-069 | `mitre[]` has 7 tactics with a placeholder description and no dataset version | MEASURED_OPEN | `T1595.description == "Mapped ATT&CK technique"`; 21/102 mapped |
| G-070 | 163 absolute scanner-host paths disclosed in the artifact | MEASURED_OPEN | `metadata.target`, 102 `full_path`, 34+25+2 BOM `file` fields |
| G-071 | `rule_telemetry.precision` is null for all 25 rules; `precision_metadata` on 2/102 | MEASURED_OPEN | measured over `js_fix` artifact |
| G-072 | No dependency manifest despite 4 third-party libraries; no HTTP surface | STRUCTURAL | `requirements*.txt`/`pyproject.toml`/`setup.py` = none; server imports = 0 |
| G-073 | `risk_category` and `severity` disagree (14 High-risk vs 2 High-severity) | MEASURED_OPEN | `priority` tracks `severity`, not `risk_category`; no derivation recorded |
| G-074 | `grouped[]` is a full second 102-element copy of the 144-key schema | MEASURED_OPEN | same key union, 130/144 shared keys differ, `finding_id` differs |
| G-075 | Taint evidence on only 12/102 findings, no not-applicable marker | MEASURED_OPEN | `taint_chain`/`taint_path`/`rule_dataflow` 12/102; `source_type`/`data_flow` null 102/102 |

**All 16 are registered in `reports/gap_register.json` (78 rows, schema-clean,
rendered into `docs/gap_analysis.md`).**

> **Correction to an earlier statement in this document.** An earlier revision
> recorded the project's `OWASP_LLM_TOP10_2026` catalogue as a *speculative*
> forward edition, and `LLM08 Hidden Context Exposure` as possibly invented.
> Both claims were wrong. The **OWASP Top 10 for LLM Applications 2026 was
> published 4 August 2026**, and all 10 entries match the project's catalogue
> exactly. `genai.owasp.org/llm-top-10/` still serves the 2025 list, which is
> why the discrepancy was initially missed. The project's docstring citation to
> the OWASP GenAI Crosswalk (v4.0.0 / 2026-Q3) was accurate all along.

---

## 9. Recommended next phase

**IMPLEMENT step 1 only** — the two foundations with zero regression risk and no
blocked dependencies:

1. `requirements.txt` declaring the **already-imported** `reportlab`, `openpyxl`,
   `matplotlib`, `pyyaml` (plus `pytest`). No code change; makes the deployment
   reproducible.
2. `web/redact.py` — absolute → repo-relative path normalisation for the 163
   disclosed paths, with a test asserting **0** absolute paths in any response.
3. `web/provenance.py::build_envelope(payload)` — the §4.3 envelope with
   **runtime-derived** `known_limitations`, plus `tests/test_v11_web_boundary.py`
   asserting `web/` imports nothing from `scanner/` or `core/`.

Then re-run the gate set (`pytest`, `compile_gate`, integrity PS1, all
benchmarks) and report. Steps 2–5 of §6 follow.

**Not started silently:** nothing beyond the three artifacts above has been
implemented. Decisions 1–5 in §7 are requested before any persona-facing view is
built.