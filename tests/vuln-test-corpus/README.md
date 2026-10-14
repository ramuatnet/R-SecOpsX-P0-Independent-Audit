# Golden corpus for technique validation (Phase V0.1)

A fixture without ground truth is an illustration. It reads convincingly and
proves nothing. Every file here carries a label stating what the scanner must
find in it, keyed to an exact line, so a missed detection becomes a measurable
false negative instead of an opinion.

## Layout

Fixtures are filed by technique family, because a family determines which
engine produces the findings and therefore how they must be scored:

```
vuln-test-corpus/
  sast/<lang>/        one safe + one vulnerable fixture per language
  sca/<eco>/<case>/   manifests with versions pinned from OSV records
  ai_ml/              model-loading and inference fixtures
  secrets/            reserved — provider keys, config files, decoys
  iac/                reserved — terraform, kubernetes, docker
  sbom/               reserved
  cbom/               reserved
```

`sast/` and `ai_ml/` carry 18 fixtures; `sca/` carries 4. The remaining
families are reserved for later phases and are deliberately empty rather than
stuffed with fixtures nobody has labelled. An unlabelled fixture is worse than
an absent one: it looks like coverage and scores like nothing.

Each fixture sits beside `<fixture>.ground_truth.json`. A bare
`ground_truth.json` per directory is also accepted by the loader, but the
per-fixture spelling is used here because one directory holds both the safe
and the vulnerable case and a shared label file would have to name its fixture
anyway.

## What qualifies as ground truth

**The truth must not come from the scanner.** A label derived from a scan run
records what the tool did, not what is true — and it closes every detection
gap by construction, since the scanner misses it, the label omits it, and the
corpus scores clean.

Three sources are accepted, in descending strength:

| Family | Truth comes from | Why that is independent |
|---|---|---|
| `sca/` | OSV advisories in `reports/.vuln_cache.json` | The CVE, advisory ID and severity are copied from a record that published its answer before this tool existed |
| `sast/`, `ai_ml/` | The fixture's own observable behaviour | A query assembled from request data and then executed is SQL injection whether or not any rule reports it |
| `secrets/` | The key format the detector claims to implement | This is a test of the implementation rather than of the world, and is labelled accordingly |

`rule_id` names the **vulnerability class**, not the shipping rule
(`SAST-SQLI`, not `TAINT_SQL_INJECTION`). A corpus keyed to shipped rule IDs
is silently coupled to the scanner: renaming a rule rewrites what the corpus
claims is true about the code. Mapping shipped rules onto this vocabulary is
V0.2's normalizer job.

`line` is the **sink** — the line where the dangerous operation happens — for
injection CWEs; the path-construction line for CWE-22; the assignment line for
CWE-798; and the `readObject` / `pickle.load` / `exec` call for CWE-502 and
CWE-94. This is fixed by the schema and is never adjusted to match scanner
output. See the 4 "duplicate anchor" extras below for what that costs, and why
the cost is worth paying.

## A fixture must be visible to the tool under test

`generate_sbom` locates manifests by canonical glob — `requirements*.txt`,
`package.json`, `pom.xml`. An earlier pass named these fixtures
`vulnerable_package.json` and `vulnerable_pom.xml`, matching none of those
globs, so the SBOM path returned 0 packages and every SCA label scored a false
negative against a scanner that had never been shown the file.

That is the quietest way a corpus rots: the labels stay valid, the validator
stays green, and the reported gap is entirely an artefact of the corpus. Each
SCA case therefore gets its own directory holding the **canonical** filename —
what the globs require, and what a real project looks like.

## Two deliberate exclusions

`SECRET_KEY="***"` in `sast/python/vulnerable_app.py`, `PASS="***"` in
`VulnerableServlet.java`, and `API_KEY="***"` in `ai_ml/vulnerable_model.py`
are **not** labelled. A redaction marker exposes no credential, so calling it
one is false, and a scanner that reports it produces a finding a reviewer
cannot action. The reserved `secrets/` family is where that opposite
expectation belongs — that placeholders *are* suppressed — and it stays
reserved until those fixtures carry labels, because an unlabelled decoy case
would assert nothing.

A fixture that parses as broken input is a fixture that fails for the wrong
reason. `SafeServlet.java:11` was repaired from a corrupted
`PASS=System...S");` to `System.getenv("DB_PASS")`, matching the file's own
`// from env` intent. Had it been left broken, a parse failure would have
produced zero findings and read as a clean pass.

## Validation

`analysis/validation/corpus.py` loads and checks the labels. Every check
exists because a label that no longer matches its fixture is worse than no
label, since it manufactures a clean bill of health from a stale claim:

- `expected_count` equals `len(expected_findings)` — a corpus that counts 5
  and lists 3 cannot be scored against both
- every `line` exists in the fixture, and is non-zero for line-anchored
  families
- every `evidence` string appears on the line it names — the load-bearing
  check, which fails loudly the moment a fixture is edited without
  re-deriving its truth
- `rule_id` is in the canonical vocabulary; `severity` is canonical title case
- no duplicate label for one `(rule_id, file, line)`
- labels are never counted as fixtures, and a label names the fixture it sits
  beside

`tests/test_v01_golden_corpus.py` applies all of it, and additionally corrupts
copies to prove each check fires. A validator that always returned `[]` would
otherwise pass every assertion above.

```
py -m pytest tests/test_v01_golden_corpus.py -q
```

## Measured result — 2026-10-11

20 fixtures, 36 labelled findings, 0 problems, 42 tests passing.

Scored with each family by the engine that actually produces its findings —
SAST via `scanner.sast.scan_directory`, SCA via
`scanner.sbom.generate_sbom` + `scanner.vulnerability_intel.query_osv_batch`.

| | Count |
|---|---|
| Labelled findings | 36 |
| Reported | 16 |
| **Recall** | **44.4%** |
| Findings on safe fixtures | 11 |
| Duplicate anchors on vulnerable fixtures | 4 |

**SCA: 4/4, 100%.** Once the fixtures were named so the SBOM path could see
them, every advisory was found.

**8 of the 20 misses are a coverage gap, not a rule failure.** `vulnerable.cpp`
and `vulnerable.rs` account for all 8. The enterprise rule table registers
rules for java, csharp, javascript, typescript, go, php, python, yaml, xml,
json and graphql — **not** for C++ or Rust. Reporting these as detection
misses would blame the rules for a language they were never written for.

**12 misses are real detection gaps** — rules exist for the language and the
finding is not reported: Python command injection, Python and AI-ML
deserialization, Python SSTI, three on `VulnerableController.cs`, three on
`vulnerable.go`, and two on `vulnerable.php`.

**11 findings sit on fixtures that expect none** — genuine false-positive
candidates. `SafeServlet.java` carries 7, including four `JAVA_J5_*` rules
firing on line 22, a `PreparedStatement` line that has nothing to do with XSS,
command injection or path traversal. The others are `SafeController.cs` (2),
`safe.php` (1) and `safe_app.py` (1) — in each case the fixture guards the
sink with a whitelist, a `..` check or an escaping call, and the rule fires
regardless.

**4 extras are not false positives.** `VulnerableServlet.java` and
`VulnerableController.cs` report the *correct* vulnerability at a different
line than the label anchors (the scanner anchors at `createStatement`,
`FileInputStream` and `ObjectInputStream` construction; the labels anchor at
the sink). This is the documented cost of fixing the sink rule, and it is
V0.2's normalizer and comparator — not a label edit — that should reconcile
line-tolerant matches.

## Reproducing the measurement

The numbers above are evidence, deliberately **not** a test. Encoding them as
one would demand the corpus agree with the tool today, erasing the very gap
this phase exists to expose. To reproduce, score each family with its own
engine and compare on `(package, version, CVE)` for SCA and on
`(line, CWE)` for SAST. Never derive labels from that output.
