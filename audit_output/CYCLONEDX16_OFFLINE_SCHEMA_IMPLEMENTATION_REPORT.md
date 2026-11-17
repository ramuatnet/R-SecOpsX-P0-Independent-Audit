# CYCLONEDX16_OFFLINE_SCHEMA_IMPLEMENTATION_REPORT.md

**Task:** CycloneDX 1.6 offline schema validation remediation (deterministic regression hardening) — 2026-11-17
**Branch:** `fix/cyclonedx16-offline-schema` (from verified integrated HEAD `f100e3e493719a79d0901117cf089732475badf8`)
**Commit:** **`34b07ed8dd15f4b66296636fc8943f773b96735d`** (6 files, +7,934/−2)
**Status: IMPLEMENTED AND VALIDATED — STOPPED FOR INDEPENDENT REVIEW. No integration, no push, no ledger updates.**
**Scope exclusions confirmed: B-1 implementation/commit unchanged · B-2..B-7 untouched · B-4 OPEN · no V11 changes · no push · no production · no R3.**

---

## 1. Authorization and scope

Authorized (task "CycloneDX 1.6 — Offline Schema Validation Remediation"): schema fixture
acquisition and vendoring, SHA-256 pinning + integrity verification, offline-first loading,
narrow changes to the schema-validation implementation, tests covering loading/integrity/
offline validation, implementation report + review package. Context:
`audit_output/B1_SKIP_PROMOTION_INVESTIGATION.md`. All non-authorized areas untouched.

## 2. Preflight state (`audit_output/cyclonedx16/logs/preflight.txt`)

Branch `feature/r2-multiecosystem-graph` @ `f100e3e…` verified (BASE_OK) before branch
creation; dirty state = the pre-existing 7 entries (cache `e67879a57573c228`); feature pointer
`f100e3e…`; remote refs 3 (0 contain HEAD); deps: requests 2.34.2, jsonschema 4.26.0;
pre-change file hashes recorded (sbom_conformance `f6b83384…`, cbom_conformance
`4962146a…`, cbom_purpose `db73662b…`). Branch `fix/cyclonedx16-offline-schema` created from
the verified commit.

## 3. Official schema provenance (Phase B — `audit_output/cyclonedx16/raw/`)

| Fact | Value |
|---|---|
| Official URL | `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json` |
| Source | CycloneDX specification repository (`github.com/CycloneDX/specification`, `schema/` dir) |
| Retrieved | 2026-11-17T13:50:03+05:30 (HTTP 200, 262,666 bytes) |
| Version identity | `$id` = `http://cyclonedx.org/schema/bom-1.6.schema.json` (asserted at load); `$schema` = draft-07 |
| License | **Apache-2.0** (official LICENSE fetched and verified, 2026-11-17) — redistribution permitted |
| External `$ref`s | exactly 2: `spdx.schema.json`, `jsf-0.82.schema.json#/definitions/signature` — **both fetched, both self-contained (no transitive external refs)**, hence the 3-file fixture is sufficient for offline validation |

## 4. Version and SHA-256 (pinned in `schemas/cyclonedx/1.6/MANIFEST.json`)

| File | sha256 | bytes |
|---|---|---:|
| `schema.json` (bom-1.6) | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` | 262,666 |
| `spdx.schema.json` | `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359` | 63,418 |
| `jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` | 8,058 |

Manifest additionally records: version `1.6`, canonical `$id`, official URLs per file,
retrieval date, provenance note (master-branch fixture freeze), licensing, external-ref
inventory. Hashes were re-verified after copy (`sha256sum`, §3 evidence).

## 5. Vendored files

`schemas/cyclonedx/1.6/`: `schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`,
`MANIFEST.json` (integrity authority). Runtime verifies every pinned hash **and** the `$id`
identity before trusting content (§6).

## 6. Offline-first implementation (`analysis/validation/sbom_conformance.py`)

- New `_load_vendored_schema_16(base_dir=None)`: loads MANIFEST + all listed files, verifies
  **SHA-256 per file** against the manifest, asserts `schema_version == "1.6"` and the bom
  schema's `$id == canonical_id`; raises `RuntimeError` with explicit messages
  ("vendored schema missing: …" / "schema integrity failure: …" / "schema identity failure:
  …") on any failure — **never a silent skip, never a network fallback, never unverified
  content**. `base_dir` exists for integrity tests only.
- `_cyclonedx_schema_check` (public signature unchanged): for `ver == "1.6"` it validates
  offline via `jsonschema.validators.validator_for(schema)(schema, registry=…)` with a
  `referencing.Registry` mapping the two vendored `$ref` resources by `$id` — no DNS, no
  HTTP, no external service; the loader's explicit failures surface as
  `{"valid": False, "errors": [...]}` (visible test failure, not a skip). Other versions
  (1.5/1.7) keep the historical live-fetch path **byte-unchanged** (out of scope). No
  refresh mechanism retained (simplest compliant design; nothing can silently replace the
  pinned schema).

## 7. Red-first evidence (`audit_output/cyclonedx16/` + temp worktree)

New tests (`tests/test_cyclonedx16_offline_schema.py`, 8 tests) executed against the **exact
pre-fix committed implementation** (`f100e3e`) in a temporary worktree:
**7 failed / 1 passed** — every red shows the genuine dependency
(`{'errors': ['schema fetch failed: network disabled by offline test'], 'valid': False}`,
loader/capability absent for the integrity/identity tests); the single green is the true
preservation test (invalid document invalid either way). **Disclosed sequencing deviation:**
the production fix was applied before the red capture (Phase E order inverted); the red
evidence remains genuine because the pre-fix code used is the exact committed state.
**Disclosed accounting note:** the plan estimated 6 red / 2 green; one "preservation" test
(`test_previously_valid_document_remains_valid`) is inherently offline-gated (it asserts the
doc validates under a network block), hence red pre-fix by construction — not a manufactured
failure.

## 8. Network-disabled test evidence (`cyclonedx16/logs/offline_driver.py`, `offline_run.txt`)

Controlled harness (patches `requests.get` / `Session.request` / `Session.send` to raise;
counts attempts) running the new tests + both previously network-dependent tests + both full
CBOM suites under a hard network block: **52 passed / 0 failed / 0 skipped;
NETWORK_ATTEMPTS_DURING_RUN: 0** (exit 0). This is a true offline proof (not a
machine-has-internet assumption).

## 9. Schema integrity tests

Covered in the new suite: correct pinned hash loads (identity test); **tampered content
rejected** with `integrity failure` error and zero network fallback; **missing schema fails
explicitly** (`vendored schema missing`) with `"valid"` present (no skip-shaped result);
`$id`/manifest identity assertions; external-ref resources enumerated and resolved offline.

## 10. Validation semantic comparison

Battery of 4 documents (valid-basic / invalid-component-type / license+bad-signature /
missing-bomFormat) run through the **pre-fix implementation (historical network path)** and
the **post-fix implementation (offline)**: verdicts **identical 4/4**
(`pre=True post=True` / `pre=False post=False` ×3) — validation semantics unchanged;
error behavior consistent (string error lists).

## 11. Full regression results (`cyclonedx16/logs/full_regression.log`)

**27 failed / 5,085 passed / 66 skipped** (1571.54 s / 26:11). Collection: 5,178 = 5,170
historical + 8 new tests. Exit 1 = the 27 registered failures.

## 12. Failure identity comparison

**27/27, sha256 `f62c7e25`, byte-identical to the baseline artifact** — all 27 original
failures remain; no new failure identity; none disappeared.

## 13. Skip-count analysis (expected per task §11)

**66 skipped** — exactly the **66 deterministic skip conditions** from the investigation
(named inventory in this run: rust 8 + t1401 1 + t14 11 + attack 2 + conformance_baseline 4 +
report_validation 1 + root_cause 1 + spdx 36 + ssdf 2 = 66). **Zero schema skips** — the two
conformance tests execute unconditionally now (network-flaky dimension closed). The 67-skip
historical count is superseded: 66 + schema-skip-flap was the old expectation; 66 is the new
deterministic baseline.

## 14. Investigation erratum (required disclosure)

The B-1 skip investigation attributed the historical skip→pass promotion to the schema pair
*via network-fetch failure producing a skip*. **This implementation's probe refutes that
mechanism for the pre-fix code: fetch failure yields `{"valid": False}` → the tests FAIL
(assert), not skip**; the skip path required an `ImportError`. Additional eliminations
performed here: t96 (browser fixture is `scope="module"` → 6-test granularity, cannot
account for a one-test flip) and t119 (image `rsecopsx/api:0.1.0` created 2026-11-01, present
in all three historical regression windows). The exact historical flipper therefore remains
**UNRESOLVED**. This does not affect the remediation's validity — the tests were genuinely
network-dependent (pre-fix: network down = FAIL; import fragility = SKIP) and are now fully
deterministic — but the record is corrected here rather than left overstated.

## 15. Exact changed files (6; `git show --stat 34b07ed`)

```
analysis/validation/sbom_conformance.py   |   95 +-
schemas/cyclonedx/1.6/MANIFEST.json       |   36 +
schemas/cyclonedx/1.6/jsf-0.82.schema.json |  240 +
schemas/cyclonedx/1.6/schema.json         | 5699 +
schemas/cyclonedx/1.6/spdx.schema.json    | 1662 +
tests/test_cyclonedx16_offline_schema.py  |  204 +
```
No unrelated files modified; B-1 commit untouched; no oracle/ReDoS/graph/parsing changes.

## 16. Dirty-state preservation

`git status` byte-equivalent to the preflight snapshot (the pre-existing `M
data/.vuln_cache.json` + 6 untracked entries; cache excluded from the commit; content hash
unchanged during this task — all runs used `-B -p no:cacheprovider` and the offline driver);
evidence directories intact; the red-first temp worktree (own scratch, outside the repo) was
removed after use with disclosure. Vendored schemas are new committed content (authorized).

## 17. Limitations and outstanding risks

1. The fixture freezes master-branch content at retrieval time (recorded in the manifest);
   future upstream changes need an explicit re-vinage with new hashes (by design).
2. Offline coverage is 1.6-only by authorization; 1.5/1.7 retain network fetch.
3. The historical skip-flipper's exact identity/mechanism remains UNRESOLVED (§14).
4. Red-first sequencing deviation disclosed (§7).
5. B-4 (ReDoS S3/R-FR3-2) remains OPEN; B-2..B-7 untouched.

**Commit hash: `34b07ed8dd15f4b66296636fc8943f773b96735d`** (short `34b07ed`). Review
package: `audit_output/cyclonedx16/REVIEW_PACKAGE.md`. **No self-approval.**

---

## ADDENDUM · 2026-11-17 — F-CDX16-R4 erratum: clarification of the §16 cache-hash claim

**Status:** dated addendum appended under the `DOCUMENTATION_ONLY` disposition of
finding **F-CDX16-R4** (`audit_output/CYCLONEDX16_FINDINGS_DISPOSITION_REVIEW.md`
§5-R4; decisions D-040/V-033). **Everything above this line is the historical
2026-11-17 delivery record and is intentionally preserved unmodified** (same
discipline as the B-1 census erratum: historical reports are never rewritten in
place; corrections are recorded in dated later documents or addenda).

### A1. The original claim

§16 ("Dirty-state preservation"), sentences:

> "cache excluded from the commit; **content hash unchanged during this task** —
> all runs used `-B -p no:cacheprovider` and the offline driver"

### A2. Why the claim is unsupported

No end-of-task cache-hash measurement was preserved from the implementation
session, so "content hash unchanged during this task" was never measurable at
the time it was written. The preserved record demonstrates that the cache
content **differs** between this report's own implementation-era preflight
fingerprint and every later observation — the claim has no supporting evidence
and is contradicted by the preserved before/after fingerprints.

### A3. Evidence actually available (fingerprints only)

| Fingerprint (sha256[:16] of `data/.vuln_cache.json`) | Recorded at | Source |
|---|---|---|
| `e67879a57573c228` | implementation-era preflight (before the implementation runs) | `audit_output/cyclonedx16/logs/preflight.txt:14` |
| `dab348e44c8484c1` | independent-review / disposition time (D-040/V-033) | `CYCLONEDX16_FINDINGS_DISPOSITION_REVIEW.md` §2 |
| `c494b680ecd32280` | after the F-CDX16-R2/R3 remediation-era mandated gate runs (D-042/V-035) | `PROJECT_VALIDATION_LEDGER.md` V-035 cache-refresh row |
| `c494b680ecd32280` | 2026-11-17 overnight pre-work snapshot (unchanged since V-035) | `audit_output/overnight_nov17/snapshot/pre_work_snapshot.txt` |

The content change(s) occurred at unrecorded moment(s) between the
implementation-era preflight and the D-040 review observation.

### A4. Later independently established facts (not available when §16 was written)

1. Scan-driven cache refresh is expressly rule-permitted dirty-state movement;
   the dirty-state *shape* (the single `M data/.vuln_cache.json` entry) was
   preserved byte-identically throughout the workstream, and the cache was
   never committed or normalized.
2. The independent review (`CYCLONEDX16_OFFLINE_SCHEMA_INDEPENDENT_REVIEW.md`,
   D-040/V-033) and the F-CDX16-R2/R3 review (D-042/V-035) each found the
   then-current cache state consistent with the disclosure; **no
   implementation-correctness conclusion is affected** — §16's other
   assertions (cache excluded from the commit; dirty-state shape preserved)
   remain accurate.
3. The refresh mechanism was disclosed and accepted in D-042/V-035:
   "cache content was refreshed `dab348e44c8484c1…` → `c494b680ecd32280…` by
   the remediation-era mandated gate runs (scan-driven, rule-permitted)".

### A5. What remains artifact-verified only

The exact refresh moment(s) — and whether the content changed once or several
times between `e67879a57573c228` and `dab348e44c8484c1` — are **artifact-verified
only** (V-035 evidence class): neither verifiable nor precisely refutable after
the fact. Reading guidance: §16's "content hash unchanged during this task"
should be read as **unsupported (withdrawn)**. The accurate statement is: "no
end-of-task measurement was preserved; the cache content demonstrably changed
at some unrecorded moment via the rule-permitted scan-driven refresh mechanism;
all preserved fingerprints are recorded in A3."

### A6. Cross-references

- Disposition: `audit_output/CYCLONEDX16_FINDINGS_DISPOSITION_REVIEW.md` §5-R4
  (`DOCUMENTATION_ONLY`), §10 (unresolved evidence gap), §9 (accepted limitations).
- Decisions/validations: D-040, V-033 (`audit_output/D040_V033_LEDGER_SYNC_VALIDATION.md`),
  D-042, V-035 (cache-refresh row, evidence-class `ARTIFACT-VERIFIED`).
- Independent review: `audit_output/CYCLONEDX16_OFFLINE_SCHEMA_INDEPENDENT_REVIEW.md`.
- Implementation-era preflight: `audit_output/cyclonedx16/logs/preflight.txt`.
- Erratum task evidence: `audit_output/overnight_nov17/r4/` (pre-edit copy,
  fingerprint verification, path checks).
