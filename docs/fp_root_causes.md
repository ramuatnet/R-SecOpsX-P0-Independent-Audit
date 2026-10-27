# FP Root Causes — measured on the RBI2 production scan

Source data: 1,615-finding production scan (`reports/aclean/clean_report.json`, R-SecOpsX
SAST v2.1, 2026-10-26) plus the deployed-fix re-scan (VA, 1,122 findings, 2026-10-27).
Every cause below names the producing code path and the measured count.

| # | Root cause | Code path | Measured count (aclean) | Status |
|---|---|---|---|---|
| b | Scanner output re-scanned (`RBI7SASTSBOMSCA-result.json`) | `scanner/sast.py` `_should_scan` accepted any `.json`; I19 detector added in `5a1451e`, deployed build lacked the export's envelope markers | **98** rows (all CONFIG_CONTEXTUAL_CREDENTIAL) | detector extended (this branch) for `secret-id`/`scan_date` signatures |
| c | Credential rules on i18n resources (`messages*.properties`, UI labels) | `scanner/secret_intelligence.py` generic key/value parser; no `bundle` exclusion in v2.1 | **441** rows across 6 files (64/61 per file) | I18 `bundle` exclusion — deployed, verified (VA: 0 rows) |
| f/a | Multipart traversal on constant/property sinks (`new File(propValue + ReportConstants.X)`) | `scanner/taint_engine.py` window: src token matched lines away from sink; identifier tail `getFile(`/`copyFile(` also matched the sink regex | **211** → 162 after I20; **146** of the 162 are `propValue+CONST` shapes | I20 `\bFile\(` deployed; I21 argument-scope + word-bounded token + minified guard on this branch (measured: suppresses 146/162) |
| g | Absence-based rules on every endpoint, no context | `scanner/taint_engine.py` MISSING_RATE_LIMIT_ENDPOINT / `scanner/sast.py` SPRING_MISSING_VALIDATION | **265 + 220 = 485** (100% scored LIKELY_FP by triage; VA shows same counts) | accuracy layer: design-level tag + lower confidence + suppressed unless state-changing/auth endpoint |
| d | Layer mismatch (server rules on front-end bundles) | taint/sast engines accept `main-*.js`/minified chunks; no per-rule layer gate | measured on VA: minified-chunk multipart rows present (2 of the 16 survivors); SSRF/rate-limit on `.ts` files | accuracy layer: rule→language/layer map + drop |
| a | Evidence/rule mismatch | window pairing binds the rule's sink to whatever line the window landed on (evidence = sink line of a DIFFERENT construct, e.g. XXE rule reporting on log/parser factory lines, traversal on `setAccessible`) | quantified by the accuracy layer's evidence-sink consistency validator on the target scan (MISLABELED bucket) | accuracy layer: sink table + MISLABELED verdict with suggested rule |
| e | Constant/literal sinks | window has no constant-proof across files (`ReportConstants` cross-file) | subset of f above | I21 argument-scope gate + constant-proof extension |
| h | Duplicates | grouped occurrences already merged upstream (`_dedupe_findings`); residual duplicates are cross-root same-line repeats | measured: dedup ratio 1.0 in aclean metadata; residual low | accuracy layer: file+line+type merge as a final pass |
| i | Evidence Valid = INVALID still emitted | `_apply_evidex_validation` stamps `evidence_valid=False` but the finding still flows to reports | aclean: 3 rows evidence_valid=False | accuracy layer: audit-only, excluded from filtered list |

Aggregate: the four deployed fixes (I18 bundle 441, I19-partial, I20 49) plus the accuracy
layer's absence-based suppression (485) and evidence-consistency (MISLABELED/LFP) buckets
account for the engineer's ~4% true-positive observation on the 1,615-row triage.
