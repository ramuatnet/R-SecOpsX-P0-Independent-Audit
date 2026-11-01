"""T-9.12 self-scan clean (task.md section 13 "self-scan clean").

Pins the committed repo-root ``.sastignore`` policy against the
``analysis.validation.self_scan`` SCOPE_* tuples, pins the inline
``# sast-ignore`` annotation set that drives the measured row count to
zero, and pins the clean-bar definition (filtered_count == 0 under
RSECOPSX_ACCURACY_INCLUDE_REVIEW=1).

Two small-scope e2e runs exercise the gate end-to-end through the full
main.py pipeline without the multi-minute full-repo scan: deploy/ must
come out clean (rc 0) and a synthetic dirty tree must come out dirty
(rc 1).  The dirty tree lives under an rsx_t112_ temp prefix so the
secrets scanner's nonproduction-path heuristics cannot mask it.
"""
from __future__ import annotations

import os
import pathlib
import shutil

REPO = pathlib.Path(__file__).resolve().parents[1]
SASTIGNORE = REPO / ".sastignore"

# One representative (file, expected-substring) per annotated site.  The
# needle carries rule id + the reason's first word: a rule-id swap or a
# truncated reason breaks it, while a harmless suffix append does not
# (mutation M3 taught that a bare rule-id needle is not observability).
ANNOTATED_SITES = (
    ("analysis/asm/tlsinfo.py",
     "sast-ignore PY_TLS_CERT_VALIDATION_DISABLED two-stage"),
    ("analysis/serve/storage.py",
     "sast-ignore PY_SQL_INTERPOLATED_QUERY parameterized"),
    ("analysis/validation/mutation.py",
     "sast-ignore OPENAI_KEY eval-fixture"),
    ("analysis/api_abuse_engine.py",
     "sast-ignore API_PAYMENT_DUPLICATE_ACTION documentation"),
    ("analysis/secret_blast_radius_correlation_engine.py",
     "sast-ignore HARDCODED_CREDENTIAL_COMPARISON risk-level"),
    ("analysis/secret_live_validation_engine.py",
     "sast-ignore AI_PROVIDER_SECRET_EXPOSURE self-test"),
    ("core/deduplicator.py", "sast-ignore MD5_USAGE non-security"),
    ("scanner/model_artifact.py",
     "sast-ignore LLM04_MODEL_DENIAL_OF_SERVICE bounded"),
    ("scanner/nvd_client.py",
     "sast-ignore LLM06_SENSITIVE_INFORMATION_DISCLOSURE env-var"),
    ("scanner/multipart_flow.py",
     "sast-ignore PY_REDOS_NESTED_QUANTIFIER bounded"),
    ("scanner/iac_models.py", "sast-ignore PY_REDOS_NESTED_QUANTIFIER covers"),
    ("scanner/undeclared_dependency_intelligence.py",
     "sast-ignore PY_REDOS_NESTED_QUANTIFIER bounded"),
    ("scanner/abom.py", "sast-ignore PY_REDOS_NESTED_QUANTIFIER bounded"),
    ("scanner/aibom.py", "sast-ignore PY_REDOS_NESTED_QUANTIFIER bounded"),
    ("analysis/dast/oob.py",
     "sast-ignore LLM06_SENSITIVE_INFORMATION_DISCLOSURE hostname"),
    ("accuracy/rules_pack_cs.py", "sast-ignore PEM_PRIVATE_KEY rule-data"),
    ("reporting/excel_report.py",
     "sast-ignore LLM06_SENSITIVE_INFORMATION_DISCLOSURE data-classification"),
    ("tools/diag_aibom_p05_receiver.py",
     "sast-ignore PY_REDOS_NESTED_QUANTIFIER bounded"),
)


def _sastignore_rules() -> list[str]:
    rules = []
    for line in SASTIGNORE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rules.append(line)
    return rules


def test_sastignore_scope_matches_pinned_tuples():
    from analysis.validation import self_scan

    rules = _sastignore_rules()
    expected = list(self_scan.SCOPE_PATH_RULES) + list(
        self_scan.SCOPE_FILENAME_RULES)
    assert rules == expected, (rules, expected)


def test_sastignore_reason_comments_present():
    text = SASTIGNORE.read_text(encoding="utf-8")
    # every scope group carries a human-readable reason
    assert "intentional vulnerability fixtures" in text
    assert "generated caches" in text
    assert "rule-data" in text
    assert "eval" in text


def test_path_rules_exclude_at_walk_filenames_stay_finding_level():
    from analysis.validation import self_scan
    from core import file_index

    for pat in self_scan.SCOPE_PATH_RULES:
        assert file_index._is_path_rule(pat), pat
    for pat in self_scan.SCOPE_FILENAME_RULES:
        assert not file_index._is_path_rule(pat), pat

    rules = _sastignore_rules()
    assert file_index._path_rule_matches("tests/test_x.py", rules)
    assert file_index._path_rule_matches("data/cache.json", rules)
    assert file_index._path_rule_matches("baseline/old.json", rules)
    assert not file_index._path_rule_matches("analysis/sast.py", rules)


def test_filename_rules_suppress_self_match_paths():
    from accuracy import suppressions
    from analysis.validation import self_scan

    rules = _sastignore_rules()
    for pat in self_scan.SCOPE_FILENAME_RULES:
        hit = suppressions._matches_ignore(
            "SOME_RULE", "scanner/" + pat, rules)
        assert hit, pat


def test_baseline_pin_matches_module():
    import json

    from analysis.validation import self_scan

    data = json.loads((REPO / self_scan.BASELINE_PATH).read_text(
        encoding="utf-8"))
    assert data == self_scan.BASELINE_ENTRIES, data


def test_rust_sources_carry_no_markers_or_rule_ids():
    """T-1.3: rule ids may not appear in rust sources -- the rust
    self-match rows therefore travel in the baseline, never as inline
    markers (that trade broke the rust_core gate once; pinned here)."""
    for rel in ("rust/src/engine.rs", "rust/src/spans.rs"):
        text = (REPO / rel).read_text(encoding="utf-8")
        assert "sast-ignore" not in text, rel
        assert "RUST_HARDCODED_CREDENTIAL" not in text, rel


def test_is_clean_bar_is_zero_filtered():
    from analysis.validation import self_scan

    assert self_scan.is_clean(0) is True
    assert self_scan.is_clean(1) is False
    assert self_scan.is_clean(2) is False


def test_disclosure_greppable():
    from analysis.validation import self_scan

    text = self_scan.__doc__.lower()
    for needle in ("self-scan clean", "filtered_count", "exit codes",
                   ".sastignore", "never deleted",
                   "measured, not asserted"):
        assert needle in text, needle


def test_inline_annotation_sites_pinned():
    for rel, needle in ANNOTATED_SITES:
        text = (REPO / rel).read_text(encoding="utf-8", errors="replace")
        assert needle in text, f"{rel} lost marker {needle!r}"


def test_e2e_deploy_scope_is_clean():
    from analysis.validation import self_scan

    result = self_scan.run_self_scan(REPO / "deploy", timeout=600)
    assert result.get("rc") in (0, 1), result
    assert result.get("filtered_count") is not None, result
    assert result["rc"] == 0, result
    assert self_scan.is_clean(result["filtered_count"])


def test_e2e_dirty_tree_is_not_clean():
    from analysis.validation import self_scan

    base = pathlib.Path(os.environ.get("LOCALAPPDATA", "/tmp")) / "Temp"
    dirty = base / "rsx_t112_dirty_e2e"
    shutil.rmtree(dirty, ignore_errors=True)
    dirty.mkdir(parents=True)
    try:
        (dirty / "app.py").write_text(
            "import os\n\n\ndef run(user_input):\n"
            "    os.system(user_input)\n",
            encoding="utf-8")
        result = self_scan.run_self_scan(dirty, timeout=600)
        assert result.get("rc") == 1, result
        assert not self_scan.is_clean(result["filtered_count"] or 0), result
    finally:
        shutil.rmtree(dirty, ignore_errors=True)
