# FIXTURE_PROVENANCE.md — `tests/fixtures/prod_tree/`

**These files are independently authored synthetic test fixtures. They are not
copies, extracts, reconstructions, or representations of the authentic Phase-3
register, historical quarantine records, or legacy production backups.**

Created 2026-11-18 for the Option B fixture-governance task (authorized by the
owner; see `audit_output/SAST_OPTION_B_FIXTURE_IMPLEMENTATION/`). No V11
content was accessed, inspected, or copied for this implementation — every
fixture was authored from the ASSERTIONS of the consuming tests, not from any
existing fixture's contents.

| Fixture | Type | Consumed by |
|---|---|---|
| `gap_register/synthetic_gap_register.json` | synthetic register (schema/renderer contract) | `tests/test_prod_tree_fixture_contract.py` |
| `quarantine/MANIFEST-SYNTHETIC.txt` + `synthetic_moved_module_{a,b}.py` | synthetic quarantine record | `tests/test_prod_tree_fixture_contract.py` |
| `backup/synthetic_legacy_copy_{a,b}.py` | synthetic legacy copies | `tests/test_prod_tree_fixture_contract.py` |

The authentic-history tests (which require the REAL repository-root artifacts:
`reports/gap_register.json`, `quarantine/MANIFEST.txt`, `backup/`) remain
separately identified with the registered `requires_prod_tree` policy — see
`AUTHENTIC_HISTORY_TEST_DISPOSITION.md` in the Option B evidence directory.
The synthetic fixtures never claim to reproduce historical project evidence.
