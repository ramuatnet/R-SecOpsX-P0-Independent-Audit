"""T-1.1 + T-1.2: the Rust engine bridge.

Without a built extension these tests SKIP with the build instructions
(RSX_RUST_REQUIRED=1 turns that into a hard failure -- used by the
`rust_core` ci_matrix gate). Config-building tests never need the
extension: they pin the Python side of the contract (one source of truth
for the rule program and policy lists) against scanner.sast itself.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in {p for p in sys.path}:
    sys.path.insert(0, str(REPO))

REQUIRED = os.environ.get("RSX_RUST_REQUIRED", "").strip().lower() in {"1", "true", "yes"}
CORPUS = REPO / "tests" / "vuln-test-corpus"
TP_FILE = CORPUS / "sast" / "python" / "vulnerable_app.py"
TP_LINE = 27  # subprocess.check_output(cmd, shell=True, ...)


@pytest.fixture()
def rust_engine():
    from scanner import rust_engine as mod

    return mod


@pytest.fixture()
def core(rust_engine):
    try:
        return rust_engine.load_extension()
    except RuntimeError as e:
        if REQUIRED:
            pytest.fail(str(e))
        pytest.skip(str(e))


@pytest.fixture()
def config(rust_engine):
    return rust_engine.build_config(CORPUS)


# --------------------------------------------------------------------------
# Config contract (no extension required)
# --------------------------------------------------------------------------


def test_config_is_json_and_rule_program_matches_tables(config, rust_engine):
    from scanner import sast

    # Serialises (the bridge hands Rust a JSON string).
    round_tripped = json.loads(json.dumps(config, ensure_ascii=True))
    assert round_tripped["schema"] == rust_engine.CONFIG_SCHEMA

    ids = [r["id"] for r in round_tripped["rules"]]
    expected = [r.get("id") for r in sast.REGEX_RULES] + [
        r.get("id") for r in sast.COMPILED_ENTERPRISE_RULES
    ]
    assert ids == expected, "rule order must be REGEX_RULES then COMPILED_ENTERPRISE_RULES"

    for built, src in zip(
        round_tripped["rules"][: len(sast.REGEX_RULES)], sast.REGEX_RULES
    ):
        assert built["pattern"] == src["pattern"].pattern
        assert built["kind"] == "regex"
    for built, src in zip(
        round_tripped["rules"][len(sast.REGEX_RULES) :], sast.COMPILED_ENTERPRISE_RULES
    ):
        assert built["pattern"] == src["pat"]
        assert built["kind"] == "enterprise"


def test_config_statics_equal_make_finding(config, rust_engine):
    """Every static field is exactly what the Python engine would compute;
    only the per-match fields are stripped for Rust to fill."""
    from scanner import sast

    by_id = {r["id"]: r for r in sast.REGEX_RULES + sast.COMPILED_ENTERPRISE_RULES}
    sample = config["rules"][:5] + [
        r for r in config["rules"] if r["id"] == "EVAL_CALL"
    ] + config["rules"][-3:]
    for rule in sample:
        source = by_id[rule["id"]]
        full = sast._make_finding(source, "", 0, "", "")
        for key in rust_engine._PER_MATCH_KEYS:
            full.pop(key, None)
        assert rule["static_finding"] == full, rule["id"]
        for key in rust_engine._PER_MATCH_KEYS:
            assert key not in rule["static_finding"]


def test_remediation_language_edge_shipped(config):
    """_remediation has language branches (js-yaml deserialisation, js
    code_injection/path_traversal); the bridge ships exactly those."""
    by_id = {r["id"]: r for r in config["rules"]}
    eval_call = by_id["EVAL_CALL"]
    # code_injection has a js/ts branch, so both languages must ship.
    assert set(eval_call["remediation_by_lang"]) >= {"javascript", "typescript"}
    assert eval_call["remediation_by_lang"]["javascript"] != (
        eval_call["static_finding"]["remediation"]
    )
    # No language branch -> no per-language entries.
    assert by_id["AWS_ACCESS_KEY"]["remediation_by_lang"] == {}


def test_missing_extension_fails_loud_with_build_instructions(rust_engine, monkeypatch):
    """No silent engine switch: asking for rust without a build raises with
    the exact build command (also checked when a real build exists, by
    pointing the search at an empty tree)."""
    import scanner.rust_engine as mod

    saved_core = mod._CORE
    saved_err = mod._LOAD_ERROR
    monkeypatch.setattr(mod, "_CORE", None)
    monkeypatch.setattr(mod, "_LOAD_ERROR", None)
    monkeypatch.setattr(
        mod, "_build_candidates", lambda: [Path(mod.os.devnull) / "nope.pyd"]
    )
    # A previously imported extension would mask the failure path: drop the
    # module AND any cargo target dirs a prior load put on sys.path.
    monkeypatch.delitem(sys.modules, "rsecopsx_core", raising=False)
    monkeypatch.setattr(
        sys,
        "path",
        [p for p in sys.path if "target" not in Path(p).parts],
    )
    try:
        with pytest.raises(RuntimeError) as exc:
            mod.load_extension()
        msg = str(exc.value)
        assert "cargo build --release" in msg
        assert "--engine rust" in msg
    finally:
        mod._CORE = saved_core
        mod._LOAD_ERROR = saved_err


# --------------------------------------------------------------------------
# Extension-backed behaviour
# --------------------------------------------------------------------------


def _rust_scan(core, target: Path) -> dict:
    return json.loads(core.scan(str(target), json.dumps(_cfg(target))))


def _cfg(target: Path) -> dict:
    from scanner import rust_engine

    return rust_engine.build_config(target)


def test_envelope_schema_and_finding_shape(core, rust_engine):
    env = _rust_scan(core, CORPUS)
    assert env["schema"] == rust_engine.ENVELOPE_SCHEMA
    status = env["status"]
    assert status.get("engine", "").startswith("rsecopsx rust core")
    assert isinstance(status.get("rules_unsupported"), list)
    assert isinstance(status.get("rules_unprefilterable"), list)
    # Disclosures are part of the contract: no silent degradation.
    limits = status.get("limits") or []
    assert limits and any("line-based" in str(x) for x in limits)
    walk = status.get("walk") or {}
    for key in ("files", "excluded_dirs", "excluded_files",
                "scanner_result_skipped", "sastignore_skipped"):
        assert key in walk

    findings = env["findings"]
    assert findings, "corpus must produce findings"
    for f in findings:
        for key in ("rule_id", "file", "line", "snippet", "evidence",
                    "group_key", "language", "severity", "priority"):
            assert key in f, f
        assert f["engine"] == "rsecopsx_core.rust"
        assert f["evidence"] == f"{f['file']}:{f['line']}: {f['snippet']}"
        short = f["snippet"][:120]
        assert f["group_key"] == f"{f['rule_id']}|{f['file']}|{f['line']}|{short}"
        assert f["line"] >= 1


def test_known_single_line_tp_is_detected(core):
    """The corpus shell=True sink (single-line match) must be found by the
    Rust engine with the same shipping rule id the Python engine reports."""
    from scanner.sast import scan_file

    py_here = [f for f in scan_file(str(TP_FILE)) if f["line"] == TP_LINE]
    assert py_here, "python engine must find the known TP (oracle sanity)"

    env = _rust_scan(core, CORPUS)
    rust_here = [
        f
        for f in env["findings"]
        if f["file"].endswith("vulnerable_app.py") and f["line"] == TP_LINE
    ]
    py_ids = {f["rule_id"] for f in py_here}
    rust_ids = {f["rule_id"] for f in rust_here}
    missing = py_ids - rust_ids
    assert not missing, f"rust engine missed python findings at line {TP_LINE}: {missing}"


def test_walk_policy_sastignore_and_scanner_result(core, tmp_path):
    """Walk-level policy parity: .sastignore path rules and third-party
    scanner-result exports are skipped, excluded dirs are pruned, and the
    skips are COUNTED in status (never silent)."""
    (tmp_path / ".sastignore").write_text("skipme/\n", encoding="utf-8")
    vuln = "import os\nos.system(request.args.get('cmd'))\n"
    (tmp_path / "keep_me.py").write_text(vuln, encoding="utf-8")
    (tmp_path / "skipme").mkdir()
    (tmp_path / "skipme" / "ignored.py").write_text(vuln, encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.py").write_text(vuln, encoding="utf-8")
    # Scanner-result JSON: content signatures, not filename.
    (tmp_path / "report.json").write_text(
        json.dumps(
            {
                "total_findings": 1,
                "scan_date": "2026-01-01",
                "tool": "some-scanner",
                "findings": [{"rule_id": "X", "secret-id": "Y"}],
            }
        ),
        encoding="utf-8",
    )

    env = _rust_scan(core, tmp_path)
    walk = env["status"]["walk"]
    assert walk["sastignore_skipped"] >= 1
    assert walk["excluded_dirs"] >= 1
    assert walk["scanner_result_skipped"] >= 1

    files = {f["file"] for f in env["findings"]}
    assert any(f.endswith("keep_me.py") for f in files), "policy must keep the real file"
    assert not any("ignored.py" in f for f in files), ".sastignore path rule must skip"
    assert not any("dep.py" in f for f in files), "excluded dir must be pruned"
    assert not any("report.json" in f for f in files), "scanner-result export must not scan"


def test_deterministic_double_scan(core, tmp_path):
    """Never regress determinism: identical input -> byte-identical envelope."""
    (tmp_path / "app.py").write_text(
        "import os\nos.system(request.args.get('cmd'))\neval(request.args.get('x'))\n",
        encoding="utf-8",
    )
    a = core.scan(str(tmp_path), json.dumps(_cfg(tmp_path)))
    b = core.scan(str(tmp_path), json.dumps(_cfg(tmp_path)))
    assert a == b


def test_disclosure_lines_surface_status(rust_engine, core):
    """--engine rust prints degradations on the CLI (checked here through
    the same helper main.py uses)."""
    rust_engine.disclosure_lines()  # pre-scan state must not crash
    rust_engine.scan_directory(CORPUS)  # the path main.py uses records status
    lines = rust_engine.disclosure_lines()
    text = "\n".join(lines)
    assert "engine:" in text
    assert "limit:" in text
    # Unsupported rules must be named, never dropped silently.
    status = rust_engine._LAST_STATUS
    assert status is not None
    if status.get("rules_unsupported"):
        assert "UNSUPPORTED rules" in text


# --------------------------------------------------------------------------
# T-1.3: the rule program (literal set, bindings, declarative gates)
# --------------------------------------------------------------------------


def test_config_ships_contract_bindings_and_declarative_gates(config):
    """YAML is the single source: contract/sink bindings ride along, and
    the two behaviour gates the Python engine applies are shipped as
    declarative data -- the Rust engine never keys on a rule id."""
    by_id = {r["id"]: r for r in config["rules"]}
    assert by_id["AWS_ACCESS_KEY"]["contract_ref"] == "hardcoded_secret"
    assert by_id["PHP_SQL_INTERMEDIATE_QUERY"]["sink_category"] == "sql"

    # Declarative skip list: derived exactly where Python derives it.
    assert by_id["NPM_SUPPLY_CHAIN_SCRIPT"]["skip_file_names"] == [
        "package-lock.json"
    ]
    for rid, row in by_id.items():
        if rid != "NPM_SUPPLY_CHAIN_SCRIPT":
            assert row["skip_file_names"] == [], rid

    # Data-file gate == REGEX_RULES of the executable-injection class, no more.
    gated = {rid for rid, row in by_id.items() if row["data_file_gate"]}
    expect = {
        row["id"]
        for row in config["rules"]
        if row["kind"] == "regex" and row.get("vuln_type") == "code_injection"
    }
    assert gated == expect
    assert gated, "the gate must actually apply to something (guard against silent None)"


def test_rule_program_literals_and_determinism(core, rust_engine, config):
    """compile_rules stamps every rule's literal set; the program is
    byte-stable, and empty literals are exactly the unprefilterable set
    the engine discloses (fail-safe, never a blackout)."""
    raw = json.dumps(config, ensure_ascii=True, sort_keys=True)
    p1 = core.compile_rules(raw)
    p2 = core.compile_rules(raw)
    assert p1 == p2, "rule program must be byte-deterministic"
    program = json.loads(p1)
    assert program["schema"] == rust_engine.PROGRAM_SCHEMA

    # Index-aligned (the tables carry one duplicate id by design -- both
    # engine and Python run BOTH rows, so order and length must match).
    assert len(program["rules"]) == len(config["rules"])
    literals: dict[str, list] = {}
    for built, src_row in zip(program["rules"], config["rules"]):
        assert built["id"] == src_row["id"]
        lits = built.get("literals")
        assert isinstance(lits, list), built["id"]  # present, possibly empty
        literals.setdefault(built["id"], lits)

    # Extraction sanity: mandatory runs of a representative rule.
    sub = literals["SUBPROCESS_SHELL_TRUE"]
    assert "subprocess." in sub and "True" in sub

    # Empty literal sets == the engine's disclosed unprefilterable list.
    rust_engine.scan_directory(REPO / "tests" / "vuln-test-corpus")
    status = rust_engine._LAST_STATUS
    unpref = set(status["rules_unprefilterable"])
    assert unpref == {rid for rid, lits in literals.items() if lits == []}


def test_program_scan_matches_config_scan_byte_identical(core, config):
    """The compiler must not change what the engine finds: scanning the
    corpus with the raw config and with the compiled program produces
    byte-identical envelopes (parity of the compile step itself)."""
    raw = json.dumps(config, ensure_ascii=True, sort_keys=True)
    program = core.compile_rules(raw)
    env_cfg = core.scan(str(REPO / "tests" / "vuln-test-corpus"), raw)
    env_prog = core.scan(str(REPO / "tests" / "vuln-test-corpus"), program)
    assert env_cfg == env_prog


def test_no_rule_logic_in_rust_source():
    """T-1.3: no rule id, and no per-rule knowledge tokens, may appear in
    the Rust sources -- gates travel as declarative data in the program."""
    from scanner import sast

    sources = "".join(
        f.read_text(encoding="utf-8")
        for f in sorted((REPO / "rust" / "src").glob("*.rs"))
    )
    rule_ids = [
        r.get("id")
        for r in (list(sast.REGEX_RULES) + list(sast.COMPILED_ENTERPRISE_RULES))
        if r.get("id")
    ]
    leaked = [rid for rid in rule_ids if rid in sources]
    assert not leaked, f"rule ids in Rust source: {leaked}"
    for token in ("code_injection", "package-lock", "NPM_SUPPLY_CHAIN_SCRIPT"):
        assert token not in sources, token


def test_declarative_skip_file_mechanism(core, rust_engine):
    """The skip list is honoured by the engine generically (mechanism
    test with a synthetic rule; the real derivation is pinned above)."""
    tmp = __import__("tempfile").mkdtemp(prefix="rsx_skip_")
    tmp = Path(tmp)
    (tmp / "open.json").write_text("EVILTOKEN here", encoding="utf-8")
    (tmp / "blocked.json").write_text("EVILTOKEN here", encoding="utf-8")
    config = {
        "schema": rust_engine.CONFIG_SCHEMA,
        "scannable_ext": [".json"],
        "lang_by_ext": {".json": "json"},
        "rules": [
            {
                "id": "SYNTH_SKIP",
                "pattern": "EVILTOKEN",
                "flags": "",
                "kind": "regex",
                "skip_file_names": ["blocked.json"],
                "static_finding": {},
            }
        ],
    }
    env = json.loads(core.scan(str(tmp), json.dumps(config)))
    hits = [f for f in env["findings"] if f["rule_id"] == "SYNTH_SKIP"]
    files = sorted(Path(f["file"]).name for f in hits)
    assert files == ["open.json"], files
