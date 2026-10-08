# SBOM/SCA Benchmark Reconciliation — `sca-multilang-2026-10`

Ground truth established from **OSV.dev**, queried per exact
package@version before any compared tool ran. No tool is treated as
the reference.

| Ground truth | Count |
|---|---:|
| Packages declared | 11 |
| Packages with >=1 CVE | 7 |
| Safe controls (0 CVEs) | 4 |
| Total CVEs | 70 |

## Tool comparison

| Metric | R-SecOpsX | Trivy | Grype |
|---|---:|---:|---:|
| Packages discovered | 18 | 13 | 12 |
| Discovery precision | 61.1% | 91.7% | 100.0% |
| Discovery recall | 100.0% | 100.0% | 100.0% |
| Discovery F1 | 75.9% | 95.7% | 100.0% |
| Version parsed correctly | 11 | 11 | 11 |
| Version mismatched | 0 | 0 | 0 |
| Version still carries its specifier | 0 | 0 | 0 |
| Vulnerable pkgs identified | 7/7 | 7/7 | 7/7 |
| Safe controls falsely matched | 0 | 0 | 0 |
| CVE TP | 70 | 70 | 70 |
| CVE FP (invented) | 0 | 0 | 0 |
| CVE FN (missed) | 0 | 0 | 0 |
| CVE precision | 100.0% | 100.0% | 100.0% |
| CVE recall | 100.0% | 100.0% | 100.0% |
| CVE F1 | 100.0% | 100.0% | 100.0% |

### R-SecOpsX

- Extra packages (not declared): certifi, jinja2, path-to-regexp, qs, sqlparse, urllib3, werkzeug

| Package | GT CVEs | Reported | Correct | Missed | Invented |
|---|---:|---:|---:|---:|---:|
| commons-lang3 3.14.0 | 1 | 1 | 1 | 0 | 0 |
| django 2.2.0 | 43 | 43 | 43 | 0 | 0 |
| express 4.17.1 | 2 | 2 | 2 | 0 | 0 |
| flask 2.0.0 | 2 | 2 | 2 | 0 | 0 |
| lodash 4.17.4 | 10 | 10 | 10 | 0 | 0 |
| log4j-core 2.14.1 | 7 | 7 | 7 | 0 | 0 |
| requests 2.19.1 | 5 | 5 | 5 | 0 | 0 |

### Trivy

- Extra packages (not declared): log4j-api
- Project's own artifact (not a dependency, excluded from FP): sca-bench

| Package | GT CVEs | Reported | Correct | Missed | Invented |
|---|---:|---:|---:|---:|---:|
| commons-lang3 3.14.0 | 1 | 1 | 1 | 0 | 0 |
| django 2.2.0 | 43 | 43 | 43 | 0 | 0 |
| express 4.17.1 | 2 | 2 | 2 | 0 | 0 |
| flask 2.0.0 | 2 | 2 | 2 | 0 | 0 |
| lodash 4.17.4 | 10 | 10 | 10 | 0 | 0 |
| log4j-core 2.14.1 | 7 | 7 | 7 | 0 | 0 |
| requests 2.19.1 | 5 | 5 | 5 | 0 | 0 |

### Grype

- Project's own artifact (not a dependency, excluded from FP): sca-bench

| Package | GT CVEs | Reported | Correct | Missed | Invented |
|---|---:|---:|---:|---:|---:|
| commons-lang3 3.14.0 | 1 | 1 | 1 | 0 | 0 |
| django 2.2.0 | 43 | 43 | 43 | 0 | 0 |
| express 4.17.1 | 2 | 2 | 2 | 0 | 0 |
| flask 2.0.0 | 2 | 2 | 2 | 0 | 0 |
| lodash 4.17.4 | 10 | 10 | 10 | 0 | 0 |
| log4j-core 2.14.1 | 7 | 7 | 7 | 0 | 0 |
| requests 2.19.1 | 5 | 5 | 5 | 0 | 0 |
