# SAST_CAMPAIGN_ERRATUM.md — dated erratum for `SAST_OVERNIGHT_EXECUTION_REPORT.md` (acceptance closure, Phase C)

**Date:** 2026-11-18 · **Erratum type:** additive (the historical report text is preserved; a dated pointer-addendum is appended at the end of the tracked report, below all original content)
**Report corrected:** `audit_output/SAST_OVERNIGHT_EXECUTION_REPORT.md` (committed at `b42316c`)
**Authority:** acceptance audit `ACCEPT_WITH_REVISIONS` — condition 2 (`audit_output/SAST_ACCEPTANCE_REVIEW/SAST_ACCEPTANCE_AUDIT.md` §11; findings D-2/D-3 in `SAST_BOUNDARY_DEVIATIONS.md`)

## E-1 · Ending HEAD

| | |
|---|---|
| Original claim | "Ending HEAD: `2603e58`" |
| Corrected value | **`b42316c8fc94773e34f70081a64b42b3448a2881`** |

Explanation: `2603e58` is an **ancestor** of `b42316c`. The additional commit
`b42316c` ("docs: SAST overnight closure — execution report + test summary +
reconciled inventory/matrix/roadmap") contains exactly the six closure
deliverables mandated by the campaign plan §10 (+400/−0, docs only, no code).
The 11 implementation commits (`3ff8c20`…`2603e58`) are unchanged and exactly
as reported. Verified by `git merge-base --is-ancestor 2603e58 b42316c` (OK)
and `git log --oneline 6a07066..b42316c` (12 entries, 0 merges).

## E-2 · Campaign commit count

| | |
|---|---|
| Original claim | "11 linear commits" |
| Corrected value | **12 total: 11 implementation + 1 closure** |

The implementation chain (start `6a07066` → `2603e58`) is exactly the 11
reported commits; the closure commit `b42316c` post-dates the campaign report
itself.

## E-3 · New tests

| | |
|---|---|
| Original claim | "23 new tests" |
| Corrected value | **22 new tests** |

Verified twice independently by the acceptance audit: (a) the exact count of
added `def test_` functions in `git diff 6a07066..b42316c -- tests/` = 22
(sarif_codeflows 5 + scoring_payload_wire 5 + ground_truth_invariants 4 +
report_audit_gate 7 + dead_code_guard 1); (b) the collected delta
5,204 − 5,182 = 22. All 22 pass in the final regression.

## E-4 · Items NOT corrected (verified accurate)

- Final regression counts (3 failed / 5,127 passed / 74 skipped) — verified
  against `final_regression2.log`.
- The 3 remaining failure identities (SCA-class, unchanged) — verified in both
  logs.
- Zero new failures — verified.
- The skip arithmetic (66 → 74) — verified; and the identity-level ledger that
  the campaign left partially open is now complete
  (`SAST_SKIP_SET_LEDGER.csv`: both resumed tests individually named, the ten
  Rust relocations individually listed).

## E-5 · Erratum mechanics

- The historical report's original text is preserved byte-identical above the
  dated addendum marker (the established convention — same discipline as the
  F-CDX16-R4 addendum).
- This erratum file is the full record; the appended report addendum is a
  short pointer to it.
- No commit is made by this closure task (commit policy §9 — awaiting explicit
  authorization); the report append is therefore a **proposed tracked-file
  change** present in the working tree only.
