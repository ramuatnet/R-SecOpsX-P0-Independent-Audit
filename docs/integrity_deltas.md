# Integrity deltas (ftasks ground rule 2)

Every phase records its measured **before/after** from `/tmp/r` — the
test-policy scan of `juice-shop-git`
(`python -m scanner.cli --target juice-shop-git --formats pdf,json,xlsx --out /tmp/r`).
Numbers come from `clean_report.json` / the audit summary line; the audit
violation count is command 3's exit-condition count.

Phase *N*'s **before** is phase *N-1*'s **after** (one scan per phase:
the gate scan *is* the next phase's before).

| phase | metric | before | after | notes |
|-------|--------|--------|-------|-------|
| P0 | findings / raw_candidates / filter_trace | 63 / absent / absent | 63 / 250 / 187 | FND-01..08; population unchanged, drops now ledgered (187 + 63 = 250) |
| P0 | total_reported / sast_records | 66 / 63 | 66 / 63 | aggregates identity held on both sides of the phase |
| P0 | audit violations (command 3) | 1 (AUD-004: filter_trace absent) | 0 | before-audited on `/tmp/r_before` and `/tmp/r_before2` |
| P0 | parity tests (command 2) | n/a (file is the phase's gate) | 14 passed | `tests/test_report_parity.py` |
| P0 | scan wall time | 323 s (old code, 14:14) | 462 s / 477 s (P0, 14:25 / 14:35) | NOT a code regression — see drift note below |

### P0 wall-time drift note (FND-02 "wall time does not regress")

Cross-window totals on this host are confounded by a run-order drift that
was measured directly: **the pre-P0 code re-run in the same window as the
P0 scans took 499 s (perf total 496.5 s) — slower than either P0 run**
(459.6 / 474.9 s), and its "Scanning OWASP LLM security rules" phase went
127.0 s (14:14) → 237.3 s (14:47) with no code change in that phase's
path (verified: `scanner/llm_security.py`, `scanner/llm_context_precision*`
and `_scan_llm_security`/`_apply_llm_context_precision` are untouched by
P0). Same-window comparison — the only fair one — shows P0 ≤ pre-P0
(474.9 s vs 496.5 s). Two further observations from the same data:

- **"Generating SBOM & dependency analysis" 10.7/11.1 s → 0.7/1.0 s** is
  *cache*-driven, not code: both pre-P0 runs read `data/.vuln_cache.json`
  at its HEAD state, both P0 runs read the warm A-state the first gate
  scan produced. The cache file is left uncommitted (churn, not P0 work).
- Scan outputs land in the user TEMP; four gate scans were written there
  during the phase (r_before, r_before2, r, r_after3).

## Interpretation notes

- **FND-01 arithmetic form.** ftasks Accept writes
  `sum(len(t) for t in filter_trace) + len(findings) == len(raw_candidates)`.
  The payload field is the declared `list[dict]` of canonical
  `{stage, rule, path, line, reason}` entries ("every discard *appends*"
  that dict), so the equivalent count form is asserted:
  `len(filter_trace) + len(findings) == metadata.raw_candidates`
  (flat entries; the `sum(len(t)…)` grouping only makes sense for
  stage-bucketed storage, which contradicts the flat-append spec).
  Occurrence-level drops stay on each surviving finding's own
  `filter_trace` (T-0.1) and in `drops.json`; only population-level
  discards enter the payload list, because only those consume a raw
  candidate.
- **CNT-02 vs §0 additive-only JSON.** `total_findings`→`sast_records`
  (and the release-manifest / accuracy-summary renames) are implemented
  as *additive* new fields plus renderer migration off the old keys —
  §0 forbids removals, the Accept's `grep -c "total_findings" == 0` is
  scoped to `reporting/*` (the item's own file scope). The old keys stay
  in the payload for compatibility until a schema-major version.
