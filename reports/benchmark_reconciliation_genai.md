# Benchmark reconciliation - OWASP GenAI Red Team Lab

**Benchmark ID:** `ai-llm-corpus-genai-2026-10`  
**Generated:** 2026-10-06T10:21:49.498708+00:00  
**Ground truth:** `reports/ground_truth_genai.json`, authored by reading the source **before** the product ran  
**Corpus:** OWASP GenAI Red Team Lab - 416 files, 108 code files  
**Findings reported:** 68 (27 in ground-truth categories, 44 outside them and therefore **unevaluated**, not called false positives)

## Scorecard A - pre-registered ground truth

| Category | Positives | TP | FN | Recall |
|---|---:|---:|---:|---:|
| PATH_TRAVERSAL | 5 | 5 | 0 | 1.0000 |
| CODE_INJECTION | 1 | 1 | 0 | 1.0000 |
| HARDCODED_CREDENTIAL | 5 | 5 | 0 | 1.0000 |
| **overall** | **11** | **11** | **0** | **1.0000** |

**Precision note:** precision is not scored on the pre-registered ground truth alone: the GT covers three categories, so findings outside them would be wrongly called false positives. See the findings audit.

### Negative controls

0 of 6 violated (rate 0.0000); respected: NC-01, NC-02, NC-03, NC-04, NC-05, NC-06

## Scorecard B - per-finding audit

| Verdict | Count |
|---|---:|
| TP | 22 |
| UNEVALUATED | 3 |
| DUPLICATE | 1 |
| FP | 1 |

**Precision = 0.9565**

True positives by origin: {'post_hoc_review': 11, 'pre_registered': 11} - entries recorded as `post_hoc_review` are real defects the hand-written ground truth missed, disclosed rather than quietly added.

### False positives by root cause

| Root cause | Count | Meaning |
|---|---:|---|
| `CONTEXT_MISCLASSIFIED` | 1 | Value is not part of any authorization decision. |

## Scorecard C - credential recall without hand-authoring bias

Method: regex enumeration over code+config files excluding docs, tests and lockfiles; stated in enumerate_credential_positives()  
**16 / 29 = 0.5517**

The hand-written ground truth covered only a few credential sites; this card re-derives them mechanically so credential recall is quoted against every site in the corpus rather than the handful that were read.

## Missed findings - root cause

## False positives - examples

| File:line | Rule | Root cause | Reason |
|---|---|---|---|
| `exploitation/embedding_inversion/config/config.toml:1` | `CONFIG_CONTEXTUAL_CREDENTIAL` | `CONTEXT_MISCLASSIFIED` | no authorization decision depends on this value |

## Measured summary

| Measure | Value |
|---|---:|
| Recall (pre-registered GT) | 1.0000 |
| Precision (per-finding audit) | 0.9565 |
| Credential recall (mechanical) | 0.5517 |
| Negative-control violation rate | 0.0000 |
| Findings outside GT categories (unevaluated) | 44 |

