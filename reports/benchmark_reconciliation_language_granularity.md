# Language-granularity benchmark

Root cause: G-059

Corpus: `sast-multilang-2026-10`  
Ground truth: analysis/benchmark_sast_corpus.GROUND_TRUTH (authored independently of the scanner), authored before the scan.

## Per language

| language | technique | GT vulns | neg ctrl | TP | FP | FN | TN | precision | recall | F1 | smallest recall step |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| csharp | REGEX (enterprise text pass only) | 1 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 1.0 |
| go | REGEX (enterprise text pass only) | 1 | 0 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 1.0 |
| java | REGEX (java_semantic text patterns) | 3 | 1 | 3 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% | 0.3333 |
| javascript | REGEX (enterprise text pass only) | 2 | 0 | 2 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 0.5 |
| php | REGEX (enterprise text pass only) | 2 | 0 | 2 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 0.5 |
| python | AST (ast.parse) | 4 | 5 | 4 | 0 | 0 | 5 | 100.0% | 100.0% | 100.0% | 0.25 |

## By detection technique

| technique | languages | GT vulns | TP | FP | FN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AST (ast.parse) | 1 | 4 | 4 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| REGEX (enterprise text pass only) | 4 | 6 | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| REGEX (java_semantic text patterns) | 1 | 3 | 3 | 0 | 0 | 100.0% | 100.0% | 100.0% |

## Reconciliation with the class-A benchmark

TP/FP/FN/TN = 13/0/0/6, P=100.0% R=100.0% F1=100.0% - identical by construction: the stratification only regroups the same `reconcile()` output.

## Detectability

Largest per-language ground truth: **4**; needed to attribute a granularity delta: **10**.

A language with N=1 can only score 0.0 or 1.0, so a per-language F1 of 1.0 on this corpus does not show that the regex path is as good as an AST - it shows the corpus cannot tell the difference.

## Honest limitation

This measures outcomes, not mechanisms. It splits the class-A number by language and labels each language with the technique its dispatch uses, verified against source at runtime. It cannot isolate granularity as the cause of any difference, because no difference is detectable at these denominators.

## Verdict

- v1_dispatch_labels_match_source: PASS
- v2_stratification_reconciles_with_class_a: PASS
- v3_every_language_with_truth_is_measured: PASS
- v4_corpus_detects_granularity_delta: FAIL
