# Benchmark Reconciliation — `sast-multilang-2026-10`

Languages: python, javascript, java, csharp, go, php

| Metric | Count |
|---|---:|
| Ground-truth vulnerabilities | 13 |
| Negative controls (must not fire) | 6 |
| R-SecOpsX findings | 13 |
| True positives | 13 |
| False positives | 0 |
| False negatives | 0 |
| True negatives | 6 |
| Detection rate | 100.0% |
| Precision | 100.0% |
| Recall | 100.0% |
| F1 | 100.0% |

## Detection by category

| Category | Ground truth | Detected | Missed | Recall |
|---|---:|---:|---:|---:|
| code_injection | 1 | 1 | 0 | 100.0% |
| command_injection | 5 | 5 | 0 | 100.0% |
| path_traversal | 2 | 2 | 0 | 100.0% |
| sql_injection | 5 | 5 | 0 | 100.0% |

## Missed vulnerabilities

_None._

## False positives

_None._
