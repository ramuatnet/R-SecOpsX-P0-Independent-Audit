# B-3 · Historical Mangled Commit Subject — Documentation Note (tasks.md §5/§6)

**Date:** 2026-11-17 · **Type:** documentation-only record · **History untouched** (no amend/rebase/filter/reset — prohibited and unnecessary)

## 1. The historical artifact

Commit **`3fbc317dfbef917ca7205059f81bbbe33936a744`** (branch `fix/rg2-platform-selected-version`, parent `5f32431` — F-RG-2 remediation, 2026-11-16) carries the subject:

> `F-RG-2: Gradle platform/BOM-selected version shape (g:a -> selected) -- extractor resolves at selected version with version_selected_by_platform disclosure, paired oracle parsing + skip-orphan fix, (5)-hardening leaf tally (11 red / 3 green matrix; mockito identity-identical; micrometer first extraction 547 edges, agreement modulo F-RG-1)`

The fragment **"(5)-hardening leaf tally"** is a commit-time character-mangling of the intended **"§5-hardening leaf tally"** (the UTF-8 section sign `§` did not survive the commit command line). The original finding is F-RG2-R3 (Info, `FRG_2_INDEPENDENT_REVIEW.md` §1 R3).

## 2. Canonical interpretation

"(5)-hardening leaf tally" **means "§5-hardening leaf tally"** — the leaf-handling behavior defined in **§5 of the F-RG-2 remediation proposal** (`F_RG_2_REMEDIATION_PROPOSAL.md`), implemented and reported in §2/§4 of `F_RG_2_IMPLEMENTATION_REPORT.md`: *an unparseable line with no subtree is tallied + disclosed instead of failing the whole file; an unparseable node **with** a subtree keeps the fatal error* (implemented as the skip-orphan fix + S13 "§5 leaf-tally" scenario; two pre-existing tests were updated to the redefined contract, names unchanged).

## 3. Scope verification (read-only, this run)

- `git log --format=%s 889170a..HEAD` scanned: **exactly one** subject in the entire audit history contains the mangling (`3fbc317`); **zero** subjects contain the UTF-8 `§` character (later commits deliberately avoid it).
- Mitigation precedent: the F-RG-1 commit (`20542e3`) used ASCII "section-2.5" wording by design (D-036) — the convention is ASCII-only section markers in commit subjects; no commit-msg hook exists to enforce it (the convention lives in the decision records).
- Commit identity/ancestry verified read-only: parent `5f32431` exact; no history operation performed.

## 4. Disposition

**CLOSE WITH EVIDENCE** (per `B1_B7_HYGIENE_BACKLOG_ASSESSMENT.md` §B-3, classification A record-only). The commit subject is immutable history and is **preserved exactly as committed**; this note plus the original finding record (`FRG_2_INDEPENDENT_REVIEW.md` §1 R3), the F-RG-2 review acceptance (D-032/D-033), and the backlog assessment §B-3 make the issue fully auditable. No further action required; recurrence is prevented by the ASCII-only subject convention already adopted (D-036).

## 5. References

- Finding: `audit_output/FRG_2_INDEPENDENT_REVIEW.md` §1 R3 (Info)
- Backlog: `audit_output/B1_B7_HYGIENE_BACKLOG_ASSESSMENT.md` §B-3; `OVERNIGHT_REMEDIATION_BACKLOG.md` (F-RG2-R3 row: record-only, immutable history)
- Canonical behavior: `audit_output/F_RG_2_REMEDIATION_PROPOSAL.md` §5; `audit_output/F_RG_2_IMPLEMENTATION_REPORT.md` §2/§4/§6
- Integration record: `audit_output/F_RG_2_FAST_FORWARD_INTEGRATION_REPORT.md` (D-034)
