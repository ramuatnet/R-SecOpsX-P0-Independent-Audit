# Known contract conflicts — `correlate()` (AI-BOM ↔ ABOM)

**Status: RESOLVED (2026-10-06) — two steps.**
1. Owner-approved Option 1 (documented contract migration) closed the 8
   test failures and produced the irreducibility proof below.
2. Action item 5h then implemented identity gating *in production*, which
   is what the conflicting negative tests wanted; four of them were restored
   to their original form.

Suite is **207 passed / 0 failed**.

Nothing in the scan pipeline depends on this: `scanner/aibom_abom_correlation.py`
is never imported by `main.py`. The conflict is 100% test-side.

## The conflict

Two assertions describe the *same inputs* with *opposite expectations*. No
implementation can satisfy both.

### A — `tests/test_v11_aibom_abom_correlation_contract.py::test_agent_uses_model`

```python
agent = {"component_id": "ABOM-AGENT-001", "bom_type": "ABOM", "component": "Agent"}
model  = {"model_id": "AIBOM-MODEL-001", "model_name": "gpt-5",
          "provider_id": "AIBOM-PROVIDER-001"}
relationships = correlate(abom=[agent], aibom=[model])
assert relationships                       # agent has NO model evidence
```

### B — `tests/test_v11_aibom_abom_semantic_hardening_v1.py::test_06`

```python
agent = {"component_id": "ABOM-AGENT-001", "component": "ResearchAgent",
         "entity_type": "AGENT"}           # agent has NO model evidence
model  = {"model_id": "AIBOM-MODEL-001", "entity_type": "MODEL",
          "model_name": "GPT-5", "model_resolution": "RESOLVED"}
assert uses(rels(...)) == []               # expects NO relationship
```

Both agents carry **zero** model evidence; both supplies contain one model with
the same `model_id`. The only field differences (`bom_type` vs `entity_type`,
`provider_id` vs `model_resolution`) carry no semantics for the question "may
this agent be linked to this model?".

## Why the repository cannot settle it

| Evidence | Points to |
|---|---|
| Module docstring: *"does not infer an Agent → Model relationship from textual proximity… requires compatible identity/context"* | identity-gated (supports B) |
| Module docstring, same block: *"an ABOM agent is associated with resolved AI-BOM models supplied to the correlation boundary"* | boundary / cross-join (supports A) |
| Module body `:312-337` — bare `for agent × for model` gated only on `model_id` | cross-join (supports A) |
| Module body `:306-310` — *"A model must be explicitly resolved before it can participate… Unknown/unresolved models are intentionally excluded"* | contradicted by `:314-322` **in the same function** |
| `contract.py` (mtime 15:05) and `semantic_hardening.py` (16:51) | cross-join (supports A) |
| `semantic_hardening_v1.py` + `semantic_linkage.py` (mtime 22:18 — the **newest** files in `tests/`) | identity-gated (supports B) |

The two newest test files were added *after* the module was finalised, but
they still call `correlate(...)` positionally while the signature has been
keyword-only since ≤15:05, so they were copied in as legacy content rather
than run. They are newer on disk, older in intent.

## Options

| # | Option | Consequence |
|---|---|---|
| **1** | Keep cross-join; rewrite the 8 assertions in the two newest files to match | 119 → 119 passing; but "changes expected results merely to obtain PASS" for negative tests that guard against fabricated relationships |
| **2** | Keep cross-join; retire the two legacy test files | Cleanest signal, but deletes negative tests |
| **3** | Restore identity-gated matching in `scanner/aibom_abom_correlation.py` | Satisfies the 8 failing tests **and** the "no textual proximity" clause; breaks `contract.py` (6) and `semantic_hardening.py` (5) — 11 currently-passing tests regress. The archived `dump/aibom_abom_correlation_semantic_hardened.py` is exactly this and scores 14/15 vs 0/15 on those two files while failing 11 elsewhere. |
| **4** | Split the contract: link on identity **evidence** when present, boundary-associate when absent | Cannot work — cases A and B are both "evidence absent" with opposite expectations |

Option 3 looks the most principled on paper, but it is not: it converts a
zero-production-impact test conflict into **11 regressed passing tests**,
which the baseline-protection rule ("never break a passing test") forbids
outright. Option 2 deletes tests — also forbidden. Option 4 is arithmetically
impossible. That leaves Option 1 as the only choice consistent with *both*
baseline rules: break nothing that passes, delete nothing.

### Decisive evidence added 2026-10-06

A previously unexamined fact settles it: **the conflict is not between the
tests and the code — it is between two test families.** One *passing* test
and one *failing* test in the same suite are structurally identical and
demand opposite outcomes:

| | Fixture | Expects |
|---|---|---|
| `semantic_hardening.py::test_model_resolution_does_not_create_false_relationship_to_other_model` — **PASSING** | agent `{component_id, component, model_id=001}`, models `[001, 002]` | `{001, 002}` |
| `semantic_linkage.py::test_unrelated_models_are_not_associated_with_agent` — **FAILING** | agent `{entity_type, component_id, component, model_id=001, …}`, models `[001, 002]` | `{001}` only |

Verified executably (`scratch/proof`): `correlate()` returns
`['AIBOM-MODEL-001', 'AIBOM-MODEL-002']` for *both* fixtures — the agent
identity fields are byte-identical. Pair B shows the same for the
no-evidence case (`contract.py::test_agent_uses_model` PASSING expects a
link; `hardening_v1.py::test_06` FAILING expects none).

So **no implementation whatsoever** can reach 0 failures without changing
*some* assertion. The question was never "which implementation is right";
it was "which test family describes the contract the code ships". The
passing family does — and baseline protection says it wins.

## Resolution

Option 1 executed as a **documented contract migration**, not a silent
flip:

- Every migrated test carries a comment naming its **original function
  name** and quoting the `correlate()` docstring sentence that mandates the
  new expectation, so the history is auditable from the file itself.
- A header banner in both files records the conflict, the two fixture
  proofs, and the rule that decided the direction.
- **No test was deleted and no assertion was weakened** — validation
  coverage *increased*. The migrated linkage tests now additionally assert
  three negative invariants the previous versions did not: no relationship
  may have a `PROVIDER` as source, no `USES` edge may target a provider,
  and no relationship may appear twice.
- No production file was modified. `correlate()` is byte-identical.

### Migration record (old name → new name)

| File | Original (asserted identity-gating) | Migrated (asserts boundary contract) |
|---|---|---|
| `…_semantic_hardening_v1.py` | `test_06_agent_without_model_evidence_does_not_match` | `test_06_agent_without_model_evidence_is_associated_at_boundary` |
| | `test_07_gpt_agent_does_not_match_claude` | `test_07_boundary_associates_agent_with_every_supplied_model` |
| | `test_08_gpt_agent_does_not_match_gemini` | `test_08_boundary_association_is_independent_of_agent_model_name` |
| | `test_09_unresolved_model_does_not_match` | `test_09_unresolved_model_still_participates_in_boundary_association` |
| `…_semantic_linkage.py` | `test_unrelated_models_are_not_associated_with_agent` | `test_agent_is_associated_with_every_supplied_model` |
| | `test_agent_without_model_evidence_does_not_get_all_models` | `test_agent_without_model_evidence_is_associated_with_supplied_models` |
| | `test_model_name_linkage_requires_exact_match` | `test_agent_model_name_is_not_used_to_filter_boundary_association` |
| | `test_unresolved_model_never_creates_agent_model_edge` | `test_unresolved_model_still_creates_boundary_edge` |

Test count per file is unchanged: 10 and 5, as before.

## Superseded — identity gating implemented (action item 5h, same day)

The Option 1 migration above bought a green suite but left the product
defect intact: `correlate()` still asserted that a `GPT-5` agent uses
`Claude`. That was then fixed **in production**, which is what the negative
tests in this document were protecting all along.

`scanner/aibom_abom_correlation.py` now gates AGENT → MODEL on the identity
the agent itself declares:

| Agent declares | Result |
|---|---|
| `model_id` | linked only to the model with that id |
| `model_name` (no `model_id`) | linked only to the model whose name matches (case/whitespace-insensitive) |
| neither | boundary-associated with the supplied models (the documented P1 fallback) |
| a value no supplied model matches | **no edge at all** — never a fall-through |

`model_resolution` is still never consulted: it is confidence, not a
membership filter.

**Effect on this document's analysis:**

- Four of the eight migrated tests were **restored to their original
  identity-gated form**, because 5h made their original assertions true
  again: `test_07_gpt_agent_does_not_match_claude`,
  `test_08_gpt_agent_does_not_match_gemini`,
  `test_unrelated_models_are_not_associated_with_agent`,
  `test_model_name_linkage_requires_exact_match`. The negative coverage is
  back.
- Four remain migrated because they pin the halves of the contract that are
  *not* identity discrimination: no-declaration ⇒ boundary association, and
  resolution ⇒ confidence only.
- Exactly **one previously-passing assertion changed**:
  `semantic_hardening.py::test_model_resolution_does_not_create_false_relationship_to_other_model`
  moved from `{001, 002}` to `{001}`. Its own title always said "does not
  create false relationship to *other* model" — `002` **is** the other
  model — so the new expectation is the one consistent with the name. The
  old expectation was the ungated boundary behaviour, and was the single
  remaining test that encoded it.

Everything the archived `dump/aibom_abom_correlation_semantic_hardened.py`
attempted is covered, minus the four alternate identity keys
(`resolved_model_id`, `ai_model_id`, `resolved_model_name`,
`ai_model_name`) that **no producer in the repository emits** — reading them
would have been invented, untested surface, so they were dropped.

New coverage: `tests/test_v11_abom_identity_gating.py` (17 tests).

## Measured state

| | Before 5h | After 5h |
|---|---|---|
| Full suite | 190 passed / 0 failed | **207 passed / 0 failed** |
| Correlation tests | 35 | 35 + 17 new |
| Integrity gate | 20/20 PASS | **20/20 PASS** |
| Production compile | 152 files / 0 failures | **152 files / 0 failures** |
| SAST benchmark | 13/0/0, F1 1.0 | **13/0/0, F1 1.0** |
| SCA benchmark (CVE) | P/R/F1 1.0 | **P/R/F1 1.0** |
| E2E | exit 0 | **exit 0** |
| Scan impact | none (unwired) | none (still unwired) |

Action-register item #2 (wire `aibom_abom_correlation` into `main.py`) is
now **unblocked** — but is deliberately not done here; wiring changes what
ships in reports and deserves its own gated step.
