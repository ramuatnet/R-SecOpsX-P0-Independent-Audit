# SAST_FIXTURE_PROVENANCE_ASSESSMENT.md — Phase B (acceptance closure)

**Date:** 2026-11-18 · **Head:** `b42316c8fc94773e34f70081a64b42b3448a2881`
**Boundary honored:** V11 was NOT accessed for this assessment (inspection limited to the P0_AUDIT copies + existing evidence). The existing V11-derived fixtures were **not touched, deleted, overwritten, or relocated**.
**Decision status: `OWNER_DECISION_REQUIRED` — no option is implemented or approved by this task** (mandatory stop condition honored).

## 1. Fixture inventory (verified this run)

| Fixture | Path / count | Git status | Dependent tests (verified by grep) |
|---|---|---|---|
| Phase-3 gap register | `reports/gap_register.json` (1 file, 418,030 B) | **gitignored** (`.gitignore:7`) — untracked, commit-inert | 6 test modules reference it: `test_v11_g035_framework_taint.py` (4 tests read it — the recovered set), `test_v11_p0_owasp_aibom_conformance.py` (5 recovered tests), `test_v11_report_validation_fixes.py` (1 skip-conditional test at :461), `test_v11_root_cause_priority.py` (1 skipif test at :238), plus `test_v11_g001_g002_live_feeds.py` / `test_v11_g003_static_reference_labelling.py` (references) — **12+ tests dependent** |
| Quarantine record | `quarantine/` — **56 files** incl. `MANIFEST.txt` | **gitignored** (`.gitignore:14`) | `test_v11_dead_code_guard.py` (MANIFEST existence + pinned strings: the three moved-module records + "Nothing here was deleted." at :123-130); `test_dependency_quarantine_join.py`, `test_g062_client_assigned_20261024.py`, `test_privacy_single_engine.py` (references) |
| Legacy backup copies | `backup/` — **127 `.py` files** | **gitignored** (`.gitignore:13`) | `test_privacy_single_engine.py::test_backup_copies_are_excluded` (needs real def-bearing legacy copies), plus references in `test_v11_abom_regression_differential.py`, `test_v11_mojibake_and_ap_content.py`, `test_v11_dead_code_guard.py` |

## 2. Provenance and content character

- **Origin:** the campaign (P0-4, 2026-11-17) copied all three READ-ONLY from the protected V11 reference tree into these gitignored paths. Disclosed in `SAST_OVERNIGHT_EXECUTION_REPORT.md` §2/§8 and classified by the acceptance audit as `DEVIATION_DISCLOSED__OWNER_APPROVAL_REQUIRED` (`SAST_BOUNDARY_DEVIATIONS.md` D-1).
- **Content character:** all three are **authored project data, not generatable artifacts**:
  - `gap_register.json` — the Phase-3 authored register (source of truth per `analysis/render_gap_register.py`, which only RENDERS from it; no generator for the JSON exists in-repo). Environment-specific: it records this project's own gap history.
  - `quarantine/MANIFEST.txt` — an authored move-record with pinned required strings; the 56 files are the quarantined legacy modules themselves.
  - `backup/` — historical pre-refactor code copies (legacy snapshots).
- **Reconstructability from an authorized in-repo source: NO for all three.** No generator exists for the register JSON; the MANIFEST and backup content record history that no longer exists in the live tree. Reconstruction would require either owner-provided copies or authoring new fixture data (Option B).

## 3. Fresh-clone reproducibility impact

On a fresh clone of this branch (no local V11 access):
- **9 tests fail unconditionally** (g035 ×4 + aibom ×5 — `FileNotFoundError` on the register).
- **2 tests skip honestly** (`test_ship_gap_register_default_source_is_the_repo_register`, `test_the_real_register_ranking_is_sane` — both conditional on the register).
- **2 tests fail or vacuously pass** depending on `quarantine/` / `backup/` presence (`test_quarantine_manifest_records_every_move` fails without the MANIFEST; the privacy test self-returns without `backup/`).
- The dead-code gate itself is fixture-independent (quarantine/backup are in its own SKIP_DIRS).

## 4. Alternatives (assessment only — NONE implemented)

### Option A — Owner ratification (retain as-is)
Retain the three local fixtures under an explicit, recorded owner approval declaring their provenance (V11 read-only copies, 2026-11-17) and their standing role as this worktree's prod-tree fixtures.
- **Pros:** zero code churn; the recovered tests keep running; matches the tests' authored environment (V11-era).
- **Cons:** reproducibility gap remains on any fresh clone; the provenance chain rests on the campaign's disclosure + owner sign-off; the fixtures stay invisible to git (no integrity pinning).
- **Requires:** a recorded owner decision naming the three paths.

### Option B — Independent replacement (committed fixtures + provenance manifest + reproducibility tests)
Design committed fixtures under `tests/fixtures/` (e.g. `tests/fixtures/prod_tree/`): a **minimal, purpose-built** register fixture covering the schema/closure-ledger properties the tests assert; a MANIFEST-style record fixture; a small legacy-copy fixture set.
- **Pros:** fully portable; git-pinned integrity; fresh-clone green.
- **Cons:** substantive design work — the g035/aibom tests assert specific register content (closure rows, root-cause names), so the fixture must be authored to the assertions WITHOUT manufacturing false history (the register is project data; a synthetic copy must be explicitly labeled as a test fixture, never presented as the real Phase-3 register); the "seven moved modules" record must match the guard's pinned strings; scope is beyond a closure task.
- **Note:** `ship_gap_register`/`render_gap_register` treat the repo-root register as the source of truth — Option B needs a fixture-source override or a documented copy step, so test behavior stays honest.

### Option C — Environment-conditional tests (`requires_prod_tree` policy)
Convert the 9 unconditional failure sites (and optionally the 2 already-conditional sites) to the registered `requires_prod_tree` marker (the conftest policy already supports conditional skips with mandatory reasons, added during the campaign).
- **Pros:** fresh clones degrade honestly (skip with reason instead of failing); zero fixture fabrication; uses the existing policy layer.
- **Cons:** reduces the locally-verifiable coverage of 9 governance tests to zero on hosts without the fixtures (the tests only run where the prod-tree artifacts exist) — meaningful coverage is PRESERVED on this worktree (they run here) but lost on clean clones; the acceptance audit's concern about fixture provenance remains unresolved (the tests still consume V11-derived data on this host).
- **Feasibility check:** the marker policy exists (`conftest.REGISTERED_MARKERS` includes `requires_prod_tree` with a reason) — semantics support it.

## 5. Decision

**`OWNER_DECISION_REQUIRED`.** All current files are preserved untouched; no test conditions were changed; no replacement evidence was manufactured. Options A/B/C are ready for an explicit owner decision; the mandatory stop condition is recorded here and in `SAST_ACCEPTANCE_CLOSURE_SUMMARY.md`.
