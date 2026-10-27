# Accuracy Layer — how it works, flags, how to extend

Schema `RSECOPSX-ACCURACY-1` · policy 1.0.0 · branch `feature/accuracy-layer`

## What it is

A **post-detection** validation & suppression stage. It runs AFTER the
existing rules produce candidate findings (and after the UFIB stage) and
BEFORE reporting. It changes nothing about detection:

- no rule, regex, rule ID, severity, CWE mapping or engine function was
  modified — legacy rule files are byte-for-byte identical;
- with the layer disabled the scan output is **byte-identical** to the
  legacy run (asserted by `tests/test_accuracy_layer.py::test_layer_disabled_is_exact_legacy`);
- suppressed/held findings are never deleted — every finding carries
  verdict, confidence and reason in `clean_report.json → accuracy.audit`.

## Flags

| Flag | Default | Effect |
|---|---|---|
| `RSECOPSX_ACCURACY_LAYER` | `1` (ON) | `0`/`false` → exact legacy output (rollback one-liner) |
| `RSECOPSX_ACCURACY_INCLUDE_REVIEW` | `0` | include NEEDS_REVIEW in the filtered list |
| `RSECOPSX_ACCURACY_CONTEXT` | `10` | context window (± lines) for sink checks |
| `RSECOPSX_ACCURACY_SECRET_ENTROPY` | `3.0` | Shannon bits/char threshold for generic secrets |

## Verdicts

`TRUE_POSITIVE` (only with a traced source-to-sink path),
`NEEDS_REVIEW`, `LIKELY_FALSE_POSITIVE`, `MISLABELED` (a real sink of a
different type is present — suggested rule attached), `SUPPRESSED_USER`,
`SUPPRESSED_KNOWN`, `DUPLICATE`.

Outputs in `clean_report.json`:

```
accuracy.filtered_finding_ids   # TRUE_POSITIVE (+ NEEDS_REVIEW behind the flag)
accuracy.audit                  # EVERY finding with verdict/confidence/reason
accuracy.counts                 # per-verdict counts
metadata.accuracy_summary       # renderable summary
per-finding .accuracy           # {verdict, confidence, reason, schema}
```

## Validators (`accuracy/validators.py`)

| Validator | Mission cause | Effect |
|---|---|---|
| `sink_consistency` | (a) evidence/rule mismatch | no claimed sink in window → LIKELY_FALSE_POSITIVE; a *different* family's sink → MISLABELED + suggested rule |
| context window | (multi-line calls) | ±`RSECOPSX_ACCURACY_CONTEXT` lines over a bounded cached read |
| `mitigation_check` | (f) mitigated code | `@Valid`, prepared statements, hardened XML parsers, canonical path containment, SecureRandom, safe YAML → downgrade |
| `minified_check` | (b) non-source files | name patterns, longest-line >2000, whitespace ratio <2% |
| `secret_check` | (c)/(H) | key-name AND value: entropy, formats (AKIA/ghp_/AIza/xox/sk_live/JWT/PEM), placeholders, `[REDACTED]` (abstains — redaction is a privacy control), sentences, i18n labels |
| `layer_gate` | (d) layer mismatch | rule families mapped to languages/layers; cross-layer → audit |
| `taint_confirm` | (lightweight taint) | TRUE_POSITIVE requires a traced path; else NEEDS_REVIEW |
| dedup | (h) duplicates | keyed file+line+type, later ones → DUPLICATE (audit) |
| `absence_check` | (g) absence-based | design-level tag, −confidence, suppressed unless state-changing/auth endpoint |

## Suppression mechanisms (`accuracy/suppressions.py`)

1. **Inline**: `// sast-ignore RULE_ID reason` (`#` for Python) within ±2 lines.
2. **File**: `.sastignore` at the target root — rule IDs or path substrings per line.
3. **Baseline**: `baseline/sast_baseline.json` — `{rule_id: [{file, line}]}`; matching
   findings are `SUPPRESSED_KNOWN`.

All three land in `accuracy.audit` with their source. A user decision
outranks every validator.

## How to add a validator

1. Add a function in `accuracy/validators.py` returning
   `(verdict_or_None, confidence_delta, reason)`.
2. Call it in `accuracy/layer.py::apply_accuracy_layer` (inside the
   context-available branch if it needs file context).
3. Add tests: one positive (verdict fires), one negative (clean code passes).

## How to add a suppression source

Extend `accuracy/suppressions.py::suppression_check`; return
`(SUPPRESSED_*, reason)`. Always keep the finding visible in the audit.

## How to enable a CS_ imported rule

`accuracy/rules_pack_cs.py` — set `enabled: True` on the rule after its
positive/negative tests pass (they ship disabled). Patterns are ReDoS-audited
at import time.

## Rollback

```
RSECOPSX_ACCURACY_LAYER=0 py main.py <target> ...
```
→ exact legacy output, verified by the snapshot test.
