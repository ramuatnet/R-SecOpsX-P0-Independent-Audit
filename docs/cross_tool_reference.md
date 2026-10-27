# Cross-Tool Reference — what each reference tool contributes to R-SecOpsX

Date: 2026-10-27 · Branch `feature/accuracy-layer` · Companion to
`docs/rule_gap_analysis.md` (codeshield, MIT — the mission's formal import source)
and `docs/fp_root_causes.md`.

## 1. Honest status

The formal rule import in this mission was **codeshield only** (license-verified
MIT). The cross-check below covers the rest of the reference list in three
tiers: **(A) already cross-checked with stored artifacts**, **(B) adopted
techniques already in the codebase**, **(C) concrete adoptables now mapped** —
plus the one empirical step still owed (a current BenchmarkJava re-run).

## 2. (A) Already cross-checked — with stored artifacts in this tree

| Tool / benchmark | Artifact in tree | Headline result |
|---|---|---|
| **OWASP BenchmarkJava** | `analysis/validation/owasp_benchmark.py` (2,740 labelled tests, per-test scoring, dual recall) + `D:\Data\Code test\reports\BenchmarkJava-master\benchmarkjava_accuracy_v3_2_2026091*.json` | **precision 78.0% / recall 54.9% / F1 64.5%** (777 TP / 219 FP / 638 FN / 1,106 TN) — measured 2026-09-12/13, i.e. BEFORE the I1–I22 FP batches, UFIB and the accuracy layer |
| **Lacework FortiCNAPP** (CNAP) | `LACEWORK_*_2026102*.md` (6 reports: llama_index, django, flask, prodtest batch8/9, petclinic) | head-to-head on SCA/SAST/secrets with byte-validated CNAP runs; V11 SCA matched OSV ground truth while CNAP produced no usable SCA on SecBench.js |
| **SecBench.js vs OSV** (ground truth) | `SECBENCH_JS_V11_DELTA_20261022.md` | V11 SCA recovered **609/609 (100%)** OSV-vulnerable pins, 0 missed; advisory-ID coverage 1,034/1,034 after alias closure |
| **codeshield** (MIT) | `docs/rule_gap_analysis.md` + `accuracy/rule_gap_analysis.csv` | 22/30 equivalent, 3 imported as disabled `CS_` rules, 2 ideas ported, 5 rejected with reasons |

## 3. (B) Techniques already adopted from the reference ecosystem

| Technique | Origin tools | Where it lives here |
|---|---|---|
| Shannon-entropy secret gating | detect-secrets, trufflehog, gitleaks, codeshield | `accuracy/validators.py::secret_check` (`_shannon_entropy`, attributed) |
| Known credential formats (AKIA/ghp_/AIza/xox/sk_live/JWT/PEM) | gitleaks, trufflehog, detect-secrets | `scanner/secret_intelligence.py` KNOWN_SECRET_RULES + accuracy formats table |
| Placeholder/`[REDACTED]` abstention | gitleaks allowlists, detect-secrets | UFIB G6 + accuracy `secret_check` |
| OSV-backed SCA with alias closure | OSV.dev (trivy/grype/DependencyTrack use the same feed) | `scanner/vulnerability_intel.py` querybatch + cache |
| CycloneDX SBOM/VEX exports | CycloneDX, DependencyTrack, grype | `reporting/cyclonedx_export.py`, `vex_export.py` |
| Per-test benchmark scoring with community labels | OWASP Benchmark methodology | `analysis/validation/owasp_benchmark.py` |
| ASVS/OWASP/MITRE/PCI/NIST mapping per finding | OWASP ASVS/WSTG/Top-10 | `analysis/framework_enrichment_engine.py`, XLSX mapping sheets |
| Minified/vendor file scoping | codeshield `is_minified`, Bearer | LLM engine G2b + taint I21 guard + accuracy `minified_check` |

## 4. (C) Concrete adoptables mapped to concrete files

| From | Adoptable | Target file | Status |
|---|---|---|---|
| semgrep-rules | per-rule **metadata standard** (`confidence`, `owasp`, `cwe`, `fix`-guidance as data) | `accuracy/rules_pack_cs.py` already carries cwe/owasp/severity per CS_ rule; extend to a shared schema | done for CS_ pack |
| find-sec-bugs / spotbugs | Java **sink-classification patterns** (taint summaries per sink API) — candidate confirm/deny entries for the accuracy sink table | `accuracy/sink_table.py` | partial; extend per-family as measured FPs demand |
| gitleaks | **allowlist + stopwords** model for secret FPs | accuracy secret validator | partial (placeholder/sentence checks); add global stopwords file if production demands |
| Bearer | **privacy dataflow classes** (PII sinks by destination) | privacy engine + accuracy layer | future (needs flow evidence) |
| njsscan / gosec | per-language rule packs with negative tests | `accuracy/rules_pack_cs.py` pattern | adopted as the pack format |
| CodeQL / joern | interprocedural dataflow as the path to raise INSUFFICIENT→CONFIRMED | `accuracy/validators.py::taint_confirm` currently intra-procedural | **known limitation**, recorded per contract |
| BenchmarkUtils | benchmark runner conventions (expectedresults CSV) | already mirrored in `owasp_benchmark.py` | done |
| OWASP Top-10/ASVS docs | mapping authority | already shipped | done |

## 5. The one empirical step still owed

**Re-run BenchmarkJava with current code.** The stored numbers (78.0/54.9/64.5)
predate: I1–I22 FP batches, UFIB (claim gates + counterevidence) and the
accuracy layer. Expected direction: precision ↑ (bundle/export/constant/
identifier-tail FPs are structurally gone), recall unchanged (fixes are
additive gates, never removals) — but the mission's rule is "no claimed
precision improvement without a reproducible benchmark", so:

```
# ~40 min on the existing runner (BenchmarkJava tree is on this machine):
python analysis/validation/owasp_benchmark.py \
    --benchmark "D:\Data\Code test\reports\BenchmarkJava-master\BenchmarkJava-master" \
    --out reports/owasp_benchmark_after_accuracy_layer
```

Commit the resulting JSON beside the 2026-09 baseline for a dated before/after.

## 6. What the accuracy layer deliberately does NOT adopt

- Any engine change (Aho-Corasick, AST rewrites): forbidden by mission constraints.
- Broad keyword rules from any source (their precision is below the bar the
  production triage demonstrated).
- Network enrichment at scan time (OSV stays behind the offline-first cache).
