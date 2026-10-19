# R-SecOpsX SAST v2.1 — Release Notes

**Commit:** `df91b4d` (tagged `v2.1`) · **Date:** 2026-10-19 · **Classification:** CONFIDENTIAL

## What's in this release

Built on the v2.0 line (through the V4 interop milestone `4d77233`: real
OWASP aibom-generator + cbomkit runs, emitted-BOM schema matrix), this cut
adds the 2026-10-19 report-validation session:

- **G-batch (`d8bdb70`) — 20 measured false positives removed across all 13
  prodtest reports**, red-first with controls:
  LLM07 pattern escaping (DVWA), RegExp-literal-exec strip (LLMForge),
  minified-bundle + strict-AI-context gate for LLM02/PROMPT_TEMPLATE
  (WebGoat/railsgoat vendor JS), LLM05 pip gate (wrongsecrets/argip CI),
  PEM key-body requirement for PRIVATE_KEY_HEADER (WebGoat/wrongsecrets),
  SSRF bare-source case fix, prototype-pollution cross-line/minified gate
  (7 vendor rows).
- **H1 (`df91b4d`) — python SQL interpolation build-site rule
  `PY_SQL_INTERPOLATED_QUERY`**, closing two measured detection failures:
  dvpwa `sqli/dao/student.py` (`%`-format, the target's intended SQLi) and
  VAmPI `models/user_model.py:72` (f-string) — both missed because the
  value crosses a route→dao/model module boundary that intra-procedural
  taint structurally cannot see. Ownership rule: attacker-tainted flows
  stay with TAINT_SQL_INJECTION at the sink, so labelled fixtures never
  double-count.

## Quality evidence (all gates run at this commit, fresh)

| Gate | Result |
|---|---|
| `pytest tests/` | 2638 passed / 42 skipped |
| `analysis.validation.e2e` | 6/6 (determinism, artifacts, fail-on exits) |
| `analysis.validation.ci_matrix` | 5/5 (golden corpus incl.) |
| Golden corpus | 115/115 recall · 75.7% precision · F1 86.1 · fp 37 (unchanged) |
| OWASP BenchmarkJava | 1415/1415 · 100% recall · 0 FP · off-target 17 (unchanged) |
| 13 prodtest targets (full fresh re-scan) | −20 FP rows · +2 SQLi rows · 0 unintended changes · every true positive kept |

Reproducibility: a worktree rerun at the pre-fix baseline was byte-identical
to the original reports, so every before/after number above is exact.

## Known limitations (disclosed, ship with the release)

1. **No cross-function python taint (route → dao/model).** H1 reports both
   measured misses at their build sites; full source→sink chain findings
   across module boundaries need summary-based inter-procedural propagation
   — feature-sized, requires its own benchmark/corpus cycle before shipping.
2. **Solidity (`.sol`) is not in the scan extension set** and **no rule
   declares `ruby` in `langs`** (Ruby files are enumerated but only generic/
   secrets patterns can match). Both are documented coverage gaps, not
   regressions.
3. **42 skips are by design** — ~38 are artifact-snapshot tests whose
   external snapshot directory was cleaned by OS temp cleanup; they skip
   themselves when it is absent.
4. **CI runs Python 3.12; local gates were validated on Python 3.14.**
   No git remote is configured in this repository, so the CI run itself is
   unverified from this machine.
5. **Semgrep/scancode differentials are CI-only** (not installable on local
   3.14) — reported as BLOCKED, never silent agreement.
6. **Corpus precision is 75.7% (37 residual FP)** — pre-existing, itemized
   (cpp 2 / python 17 / rust 3 / java 6 / manifest 9), all classified as
   closed-set candidates or SCA-presentation items, not detection gaps.

## Deployment checklist

- Deploy **from the tag** (`git checkout v2.1`), not the working directory —
  the tree carries modified scan caches and untracked working docs.
- Default scan flags for production pipelines:
  `python main.py <target> -o <out> --no-pdf --no-excel` (PDF is the slow
  phase; add it only when a document deliverable is needed).
- Exit-code gating: `--fail-on {critical,high,medium}` (published in
  `clean_report.json → metadata.security_gate`).
- Re-run gates after any scanner edit: the F7/F8 discipline — a scan-level
  change gets a FULL fresh benchmark dump, never `--reuse-findings`.
