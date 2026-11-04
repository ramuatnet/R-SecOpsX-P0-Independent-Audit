"""ftasks test-policy command 2 — parity + foundation invariants.

    python -m pytest tests/test_report_parity.py -q

One file, grown per phase (ftasks §1: three commands, nothing else, at
the end of every phase).  Phase 0 (FND) registers:

  * FND-01 — the payload carries ``filter_trace``; every population-level
    discard appends the canonical ``{stage, rule, path, line, reason}``
    entry; ``len(filter_trace) + len(findings) == raw_candidates``.
  * a build smoke so the harness itself fails loudly if the payload
    stops building.

Later phases append their parity assertions (ftasks GTE-02 lists the
final set: CNT-01, CNT-03, RND-13, VRD-08, DEC-01, REC-10 …).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core import filter_trace  # noqa: E402
from core.analyzer import build_report_payload  # noqa: E402


def test_smoke_payload_builds():
    """The payload still builds from an empty scan (harness sanity)."""
    payload = build_report_payload([], [], "smoke-target")
    assert isinstance(payload, dict)
    assert isinstance(payload.get("findings"), list)
    assert isinstance(payload.get("aggregates"), dict)


def test_fnd01_payload_carries_filter_trace():
    """FND-01 red→green: attach_to_payload materialises the ledger.

    Red before implementation: ``attach_to_payload`` does not exist yet,
    so this fails with ImportError — the stated reason (the contract the
    phase must add).
    """
    filter_trace.begin_scan()  # isolation: earlier files' ledgers must not leak
    payload = {"findings": [], "metadata": {}}
    filter_trace.attach_to_payload(payload, raw_candidates=0)
    assert isinstance(payload.get("filter_trace"), list), (
        "FND-01: filter_trace must be on the payload")
    assert payload["metadata"].get("raw_candidates") == 0
    assert (
        len(payload["filter_trace"]) + len(payload["findings"])
        == payload["metadata"]["raw_candidates"]
    ), "FND-01 arithmetic must hold"


def test_fnd01_drop_entry_shape_and_arithmetic():
    """One recorded drop + one survivor == two raw candidates."""
    filter_trace.begin_scan()
    filter_trace.record_finding_drop(
        {"rule_id": "RULE_A", "file": "src/x.py", "line": 7,
         "title": "t", "severity": "High"},
        "intake_exact_dedupe", "exact duplicate", decision="merged",
    )
    payload = {
        "findings": [{"rule_id": "RULE_B", "file": "src/y.py", "line": 9}],
        "metadata": {},
    }
    filter_trace.attach_to_payload(payload, raw_candidates=2)
    trace = payload["filter_trace"]
    assert len(trace) == 1, "the one ledger drop must appear on the payload"
    entry = trace[0]
    assert set(entry) == {"stage", "rule", "path", "line", "reason"}, (
        f"FND-01 canonical entry keys, got {sorted(entry)}")
    assert entry["stage"] == "intake_exact_dedupe"
    assert entry["rule"] == "RULE_A"
    assert entry["path"] == "src/x.py"
    assert entry["line"] == 7
    assert entry["reason"] == "exact duplicate"
    assert (
        len(payload["filter_trace"]) + len(payload["findings"])
        == payload["metadata"]["raw_candidates"]
    ), "FND-01 arithmetic must hold"


def test_fnd01_assertion_catches_silent_drop():
    """A population shrink with no ledger entry must fail the arithmetic.

    This is the kill switch for silent drops: if any filter removes a
    candidate without calling record_finding_drop, the attach-time assert
    fires (stated reason: counts disagree).
    """
    filter_trace.begin_scan()  # empty ledger — the drop was "silent"
    payload = {
        "findings": [{"rule_id": "RULE_B"}],
        "metadata": {},
    }
    try:
        filter_trace.attach_to_payload(payload, raw_candidates=2)
    except AssertionError as exc:
        assert "raw_candidates" in str(exc) or "filter_trace" in str(exc)
        return
    raise AssertionError(
        "FND-01: raw_candidates=2 with 1 finding and 0 recorded drops "
        "must assert — a candidate vanished without a ledger entry")


def _fnd02_source_lines(substring: str, skip: tuple[str, ...] = ()) -> list[str]:
    """`file:lineno` for every line under scanner/ + analysis/ containing
    ``substring`` (the FND-02 Accept grep, made executable).  The test file
    itself lives in tests/, outside that scope, so the needles below are
    not self-matches.
    """
    hits: list[str] = []
    for base in ("scanner", "analysis"):
        for path in sorted((REPO_ROOT / base).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel in skip:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if substring in line:
                    hits.append(f"{rel}:{lineno}")
    return hits


def test_fnd02_no_rglob_outside_walk():
    """FND-02 Accept, red first: ``grep -rn "rglob(" scanner/ analysis/``
    must match only ``scanner/walk.py``.

    Before the migration this fails and names every surviving line (the
    stated reason: raw per-engine walks still exist).
    """
    hits = _fnd02_source_lines("rglob(", skip=("scanner/walk.py",))
    assert not hits, (
        "FND-02 rglob survivors (migrate to scanner.walk.walk): "
        + ", ".join(hits)
    )


def test_fnd02_no_iter_files_left():
    """FND-02 prose: replace every rglob *and* ``_iter_files``.

    Per-engine enumeration wrappers are gone — engines query
    ``file_index.index_for(...)`` at the call site, standalone scripts use
    ``scanner.walk.walk``.  Red first: fails listing the remaining defs.
    """
    hits = _fnd02_source_lines("def _iter_files")
    assert not hits, (
        "FND-02 _iter_files survivors (inline the index query): "
        + ", ".join(hits)
    )


def _fnd03_bare_slice_ints() -> list[str]:
    """`file:lineno` for every bare integer literal sitting in a slice
    bound (lower/upper/step) under ``analysis/``.

    A "bare integer" is an ``ast.Constant`` int — or a signed ``-N`` /
    ``+N`` unary spelling of one — written directly as a slice bound.
    Bounds that are already names, attributes or expressions are fine.
    """
    import ast

    def _is_int_lit(node: ast.AST) -> bool:
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
        ):
            return True
        return (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, (ast.USub, ast.UAdd))
            and isinstance(node.operand, ast.Constant)
            and isinstance(node.operand.value, int)
            and not isinstance(node.operand.value, bool)
        )

    hits: list[str] = []
    for path in sorted((REPO_ROOT / "analysis").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            # utf-8-sig: five analysis/ files carry a BOM, and ast.parse
            # rejects the BOM character — skipping them would hollow out
            # the Accept.
            tree = ast.parse(
                path.read_text(encoding="utf-8-sig", errors="replace"))
        except OSError:
            continue
        except SyntaxError as exc:
            # Skipping an unparseable file would hollow out the Accept.
            # Every analysis/ module compiles (brain L0), so this is a
            # real failure, not a tolerated state.
            raise AssertionError(
                f"FND-03: {rel} does not parse, so the Accept cannot "
                f"see its slices: {exc}") from exc
        for node in ast.walk(tree):
            if not isinstance(node, ast.Slice):
                continue
            for bound in (node.lower, node.upper, node.step):
                if bound is not None and _is_int_lit(bound):
                    hits.append(f"{rel}:{bound.lineno}")
    return hits


def test_fnd03_no_bare_int_in_analysis_slice():
    """FND-03 Span table, red first: no bare integer in a slice in
    ``analysis/`` — every slice bound reads a name from
    ``analysis.spans``.

    Before the span table exists this fails and names every surviving
    site (stated reason: magic integers still cut spans ad hoc).
    """
    hits = _fnd03_bare_slice_ints()
    assert not hits, (
        "FND-03 bare-int slices (name them via analysis.spans): "
        + ", ".join(hits[:40])
        + (f" (+{len(hits) - 40} more)" if len(hits) > 40 else "")
    )


def test_fnd04_200_deep_normalises_and_sets_truncated():
    """FND-04 Iterative traversal, red first: a 200-deep fixture
    normalises without ``RecursionError`` and sets ``truncated``.

    Drives both normalise entry points named by the phase — report-noise
    cleanup (``_clean_node``) and the SBOM advisory chain
    (``_normalize_record``).  Red before the phase: with the cap still at
    10_000 a 200-deep structure never overflows, so no report surfaces
    and the ``truncated`` marker does not exist yet (stated reason:
    depth_guard metadata missing / marker unset).
    """
    import main  # the two normalise entries live here (T-0.4 layout)

    depth = 200  # ftasks Accept: MAX_DEPTH=64 << 200 << old cap 10_000

    # -- entry 1: _cleanup_report_noise -> _clean_node -------------------
    node: dict = {"leaf": "value"}
    for _ in range(depth):
        node = {"n": node}
    payload = {"findings": [], "deep": node, "metadata": {}}
    main._cleanup_report_noise(payload)  # must not raise RecursionError
    guard = (payload.get("metadata") or {}).get("depth_guard")
    assert guard, "FND-04: overflowing walk must surface depth_guard"
    assert guard.get("max_depth") == 64, (
        f"FND-04: MAX_DEPTH must be 64, got {guard.get('max_depth')}")
    assert guard.get("truncated") is True, (
        "FND-04: 200-deep > MAX_DEPTH must set the truncated marker")

    # -- entry 2: _normalize_fixed_version_fields -> _normalize_record ---
    record: dict = {"name": "pkg0", "fixed_versions": ["1.0.0"]}
    for _ in range(depth):
        record = {"name": "pkg", "vulnerabilities": [record]}
    payload2 = {"sbom": [record], "metadata": {}}
    main._normalize_fixed_version_fields(payload2)  # no RecursionError
    guard2 = (payload2.get("metadata") or {}).get("depth_guard")
    assert guard2, "FND-04: overflowing normalise must surface depth_guard"
    assert guard2.get("truncated") is True, (
        "FND-04: 200-deep advisory chain must set the truncated marker")


def test_fnd05_redos_fixture_completes_and_logs_to_filter_trace():
    """FND-05 Regex budget, red first: the ReDoS fixture completes under
    the 50 ms per-line budget and the breach lands in ``filter_trace``
    with the rule ID.

    Red before the phase: ``LINE_BUDGET_MS`` does not exist yet and no
    breach path writes to the payload ledger (stated reason:
    AttributeError on the budget constant).
    """
    import re
    import time

    from core import filter_trace, regex_budget

    assert regex_budget.LINE_BUDGET_MS == 50, (
        "FND-05: the per-line wall-clock budget is 50 ms")

    # nested-quantifier audit (FND-05) must flag the fixture's pattern
    assert "nested_quantifier" in regex_budget.audit_pattern(r"(a+)+b"), (
        "FND-05: the ReDoS fixture pattern must be audited as suspect")

    filter_trace.begin_scan()
    pattern = re.compile(r"(a+)+b")
    attack = "a" * (70 * 1024) + "!"   # single line, guard-eligible
    t0 = time.perf_counter()
    matches = list(regex_budget.rule_finditer(
        pattern, attack, rule_id="FND05_FIXTURE", file_path="redos.txt"))
    elapsed = time.perf_counter() - t0
    assert matches == [], "catastrophe must not yield matches"
    assert elapsed < 5.0, (
        f"FND-05: ReDoS fixture must complete under budget, took {elapsed:.1f}s")

    payload = {"findings": [], "metadata": {}}
    filter_trace.attach_to_payload(payload, raw_candidates=0)
    violations = [e for e in payload["filter_trace"]
                  if e.get("stage") == "regex_budget_exceeded"]
    assert violations, (
        "FND-05: the breach must appear in filter_trace with its rule id")
    entry = violations[0]
    assert set(entry) == {"stage", "rule", "path", "line", "reason"}, (
        f"FND-05 canonical entry keys, got {sorted(entry)}")
    assert entry["rule"] == "FND05_FIXTURE"
    assert entry["path"] == "redos.txt"
    assert entry["reason"], "the breach must say what exceeded the budget"

    # violations are scan-integrity notices, not population discards --
    # the FND-01 identity must still hold once they are on the payload.
    drops = [e for e in payload["filter_trace"]
             if e.get("stage") != "regex_budget_exceeded"]
    assert (
        len(drops) + len(payload["findings"])
        == payload["metadata"]["raw_candidates"]
    ), "FND-01 arithmetic must ignore violation entries"


def test_fnd05_line_path_matches_whole_source():
    """FND-05 parity: for a provably line-safe pattern the per-line path
    must yield the EXACT whole-source finditer match set (ground rule 7).

    Also pins the classifier's fallback: a pattern that can cross a
    newline (``\\s``) or re-anchor (``^`` without MULTILINE) must take the
    whole-source path instead of guessing.
    """
    import re

    from core import regex_budget

    # line-safe: positive classes only, no dot, no anchors, no escapes
    safe = re.compile(r"AKIA[0-9A-Z]{16}")
    assert regex_budget._line_safe(safe), (
        "FND-05: a plain literal+positive-class pattern is line-safe")

    source = ("nothing here\n"
              "key = AKIA0123456789ABCDEFG\n"
              "trailing text\n"
              "AKIA9999999999999999\n")
    via_line = list(regex_budget.rule_finditer(
        safe, source, rule_id="FND05_PARITY", file_path="multi.txt"))
    via_whole = list(safe.finditer(source))
    assert via_whole, "fixture must actually contain matches"
    assert [(m.start(), m.end()) for m in via_line] == \
        [(m.start(), m.end()) for m in via_whole], (
        "FND-05: line path and whole-source finditer must agree exactly")

    # an unsafe pattern must be classified out (fallback, not a guess)
    crosses_newline = re.compile(r"AKIA[0-9A-Z\s]{16}")
    assert not regex_budget._line_safe(crosses_newline), (
        "FND-05: \\s can consume a newline, so the pattern is not line-safe")
    reanchors = re.compile(r"^AKIA[0-9A-Z]{16}")
    assert not regex_budget._line_safe(reanchors), (
        "FND-05: ^ without MULTILINE re-anchors per chunk")


def test_fnd06_loaded_count_equals_yaml_plus_shim():
    """FND-06 Declarative rules, red first: the loaded sast tables must
    equal the YAML rules plus the code-side (Python) shim pack, and every
    YAML entry must carry the canonical FND-06 field set.

    Red before the phase: ``scanner.rules`` does not exist yet (stated
    reason: ModuleNotFoundError on the new declarative home).  The YAML
    side counts the RAW entries the files declare -- not the legacy
    adapters sast consumes -- so a rule dropped or duplicated inside the
    adapter cannot make both sides agree by construction.
    """
    from scanner import sast
    from scanner.php_webshell_rules import as_sast_rules
    from scanner.rules import loader  # FND-06 (new): the declarative home

    yaml_e = loader.load_yaml_entries("enterprise_v1.yaml")
    yaml_r = loader.load_yaml_entries("regex_v1.yaml")
    pack = as_sast_rules()

    # Accept: loaded count equals YAML + shim (the Python-side pack).
    assert len(sast.ENTERPRISE_RULES) == len(yaml_e) + len(pack), (
        "FND-06: ENTERPRISE_RULES=%d != YAML %d + pack %d"
        % (len(sast.ENTERPRISE_RULES), len(yaml_e), len(pack)))
    assert len(sast.REGEX_RULES) == len(yaml_r), (
        "FND-06: REGEX_RULES=%d != YAML %d"
        % (len(sast.REGEX_RULES), len(yaml_r)))

    # The canonical field set every YAML entry declares (no pinned count:
    # the parity above is computed, never hardcoded).
    canonical = {"id", "cwe", "severity", "family", "pattern",
                 "span", "exts", "negative"}
    for entry in list(yaml_e) + list(yaml_r):
        missing = canonical - set(entry)
        assert not missing, (
            "FND-06: %s missing canonical fields %s"
            % (entry.get("id"), sorted(missing)))


def test_fnd07_redaction_preserves_delimiters():
    """FND-07 Redaction preserves delimiters, red first.

    Before the phase the structural check fails: the assignment
    regex's value class stops at the first space, so redacting
    ``password = '${security.hash(req.body.password || '')}'`` emits
    ``password = '[REDACTED SECRET] || '')}'`` -- the ``${...}`` span is
    cut before its closing delimiter, leaving a dangling `` || ''``, a
    ``')}`` tail and a broken quote pair on juice-shop
    ``routes/login.ts:34`` (stated reason: the redacted password
    segment is not immediately closed by its quote).

    The fixture is the verbatim source line; the untouched email
    template keeps its own `` || ''`` (original content, balanced
    inside its own ``${...}``), so exactly one `` || ''`` may remain.
    """
    import main as main_module

    # verbatim routes/login.ts:34 from the juice-shop target
    evidence = (
        "    models.sequelize.query(`SELECT * FROM Users WHERE email = "
        "'${req.body.email || ''}' AND password = "
        "'${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, "
        "{ model: UserModel, plain: true }) // vuln-code-snippet vuln-line "
        "loginAdminChallenge loginBenderChallenge loginJimChallenge"
    )
    red = main_module._redact_secret_text(evidence)

    # Accept: balanced quotes after redaction (both kinds).
    assert red.count("'") % 2 == 0, red
    assert red.count('"') % 2 == 0, red

    # The ${...} span is redacted THROUGH its closing delimiter: no
    # residue between the marker and the closing quote.
    assert "password = '[REDACTED SECRET]'" in red, red

    # The span's inner ` || ''` default operand never dangles outside
    # the marker (the untouched email template keeps its own).
    assert red.count(" || ''") == 1, red

    # The span's opening delimiter went with it.
    assert "${security.hash(req.body.password" not in red, red


def test_fnd08_manifest_committed_and_covers_three_artifacts():
    """FND-08 Baseline snapshot, red first: the capture tool exists, the
    SHA manifest is committed, and it covers exactly the three phase-gate
    artifacts with fixture copies that hash to the recorded values.

    Red before the phase: ``tools/baseline.py`` does not exist yet and
    ``tests/fixtures/baseline/manifest.json`` has never been written
    (stated reason: FileNotFoundError on the capture tool / manifest).
    """
    import hashlib
    import json as _json

    baseline_py = REPO_ROOT / "tools" / "baseline.py"
    assert baseline_py.is_file(), (
        "FND-08: tools/baseline.py missing (the capture tool)")

    manifest_path = REPO_ROOT / "tests" / "fixtures" / "baseline" / "manifest.json"
    assert manifest_path.is_file(), (
        "FND-08: tests/fixtures/baseline/manifest.json not committed yet")

    manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files")
    assert isinstance(files, dict) and files, (
        "FND-08: manifest['files'] must enumerate the captured artifacts")
    assert set(files) == {"Security_Report.pdf", "Security_Report.xlsx",
                          "clean_report.json"}, (
        "FND-08: manifest must cover exactly the three phase-gate "
        "artifacts, got %s" % sorted(files))

    for name, meta in sorted(files.items()):
        sha = str(meta.get("sha256") or "")
        assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), (
            f"FND-08: {name} sha256 is not a hex digest: {sha!r}")
        assert int(meta.get("bytes") or 0) >= 1024, (
            f"FND-08: {name} captured at {meta.get('bytes')} bytes "
            "(non-trivial like AUD-005/006)")
        # capture honesty: the fixture copy on disk hashes to the manifest
        copy = manifest_path.parent / name
        assert copy.is_file(), f"FND-08: fixture copy missing: {name}"
        actual = hashlib.sha256(copy.read_bytes()).hexdigest()
        assert actual == sha, (
            f"FND-08: {name} fixture copy hashes to {actual[:12]}… "
            f"but manifest records {sha[:12]}…")


def test_fnd08_audit_baseline_diffs(tmp_path):
    """FND-08 Accept: ``report_audit.py --baseline`` diffs.

    Identical bytes pass the baseline check; a single flipped byte in one
    artifact is reported as an AUD-B01 sha256 diff.  Red before the
    phase: the fixture copies do not exist yet because ``tools/baseline.py``
    has never captured them (stated reason: FileNotFoundError on
    ``tests/fixtures/baseline/Security_Report.pdf``).
    """
    import shutil

    from tools import report_audit

    base = REPO_ROOT / "tests" / "fixtures" / "baseline"
    for name in ("Security_Report.pdf", "clean_report.json",
                 "Security_Report.xlsx"):
        shutil.copy(base / name, tmp_path / name)

    # identical bytes: the diff is empty
    assert report_audit._check_baseline(tmp_path, None) == [], (
        "FND-08: artifacts identical to the manifest must diff clean")

    # one flipped byte: the diff names the artifact
    pdf = tmp_path / "Security_Report.pdf"
    data = pdf.read_bytes()
    pdf.write_bytes(bytes([data[0] ^ 0xFF]) + data[1:])
    problems = report_audit._check_baseline(tmp_path, None)
    assert problems, "FND-08: a changed artifact must be reported"
    assert "Security_Report.pdf" in problems[0], problems
    assert "sha256" in problems[0], problems
