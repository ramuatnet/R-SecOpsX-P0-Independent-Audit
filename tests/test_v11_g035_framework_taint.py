"""G-035 -- framework-aware taint for the AI/LLM corpus.

The pre-registered GenAI ground truth registered six positives the engine
could not see: 0/5 PATH_TRAVERSAL and 0/1 CODE_INJECTION.  Each one failed
for a different structural reason, and each failure is pinned by a test
below so a future refactor cannot silently re-open the gap:

  GT-01  FastAPI ``/{bucket}/{object:path}`` route parameter is not a source
  GT-02  ``request.get_json() or {}`` -- a source nested in a BoolOp never
         taints its target, and ``remainder = ""`` in the sibling ``else:``
         then declassified the value
  GT-03/04 ``kv.persist(persist_path=...)`` / ``ctx.persist(persist_dir=...)``
         are file-write sinks the sink map did not know
  GT-05  ``self.headers``/``self.rfile.read`` on a BaseHTTPRequestHandler,
         plus a value that crosses a same-file function boundary
  GT-06  attacker bytes written into an importable ``__init__.py``

Two negative controls guard the *scoping* of the new behaviour, because the
first implementation over-reached and was measured doing so:

  NC-A   ``os.getenv``/``sys.argv``/``input()`` do NOT seed a callee. The
         original unrestricted version turned
         ``run_cmd(f'cd "{SANDBOX_DIR}" && docker build ...')`` into three
         command-injection findings and one negative-control violation.
  NC-B   a constant assignment in the same block still kills taint, so the
         baseline "tainted then constant" control is unaffected.
"""
from __future__ import annotations

import textwrap

import pytest


def _run(tmp_path, source: str) -> list[dict]:
    from scanner.taint_engine import analyze_file

    path = tmp_path / "sample.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return analyze_file(str(path))


def _lines(findings: list[dict], vuln_type: str | None = None) -> set[int]:
    return {
        int(f.get("line") or 0)
        for f in findings
        if vuln_type is None or str(f.get("vuln_type")) == vuln_type
    }


def _find(source: str, source_line: str, sink_line: str) -> int:
    """1-based line number on which ``sink_line`` appears in ``source``."""
    for idx, raw in enumerate(source.splitlines(), 1):
        if sink_line in raw:
            return idx
    raise AssertionError(f"sink line not present: {sink_line!r}")


# ---------------------------------------------------------------------------
# Sources the engine previously could not see
# ---------------------------------------------------------------------------
def test_fastapi_route_path_parameter_reaches_open(tmp_path):
    """GT-01: a ``{name:path}`` converter binds attacker input."""
    src = '''
        from fastapi import APIRouter

        router = APIRouter()

        @router.put("/{bucket_name}/{object_key:path}")
        async def put_object(bucket_name: str, object_key: str):
            target_dir = os.path.join("data", bucket_name)
            file_path = os.path.join(target_dir, object_key)
            with open(file_path, "wb") as fh:
                fh.write(b"x")
    '''
    sink = _find(src, None, 'open(file_path, "wb")')
    findings = _run(tmp_path, src)
    assert sink in _lines(findings, "path_traversal")


def test_flask_convertor_route_parameter_reaches_open(tmp_path):
    """GT-01 (Flask spelling): ``/<path:name>`` binds attacker input."""
    src = '''
        @app.route("/download/<path:fname>", methods=["POST"])
        def download(fname):
            with open(fname, "wb") as fh:
                fh.write(b"x")
    '''
    sink = _find(src, None, 'open(fname, "wb")')
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


def test_route_parameter_not_in_template_is_not_seeded(tmp_path):
    """A decorated handler must not taint arguments the route never binds."""
    src = '''
        @app.route("/static")
        def serve(path):
            open(path)
    '''
    assert not _lines(_run(tmp_path, src), "path_traversal")


def test_http_handler_request_surfaces_are_sources(tmp_path):
    """GT-05: ``self.headers``/``self.rfile`` are the stdlib request surface."""
    src = '''
        from http.server import BaseHTTPRequestHandler

        class AgentHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                open(body)
    '''
    sink = _find(src, None, "open(body)")
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


def test_source_nested_in_boolop_taints_target(tmp_path):
    """GT-02: ``request.get_json(...) or {}`` carries attacker control."""
    src = '''
        def chat():
            data = request.get_json(force=True, silent=True) or {}
            query = data.get("query", "")
            open(query)
    '''
    sink = _find(src, None, "open(query)")
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


def test_source_nested_in_cast_taints_target(tmp_path):
    src = '''
        def handler():
            length = int(self.headers.get("Content-Length", 0))
            open(length)
    '''
    sink = _find(src, None, "open(length)")
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


# ---------------------------------------------------------------------------
# Taint kill must be block-aware
# ---------------------------------------------------------------------------
def test_else_branch_constant_does_not_declassify(tmp_path):
    """The GT-02 shape: ``remainder = ""`` sits in the sibling ``else:``."""
    src = '''
        def chat():
            data = request.get_json() or {}
            query = data.get("q", "")
            if ":" in query:
                parts = query.split(":", 1)
                remainder = parts[1].strip()
            else:
                remainder = ""
            open(remainder)
    '''
    sink = _find(src, None, "open(remainder)")
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


def test_same_block_constant_assignment_still_kills(tmp_path):
    """Baseline negative control: straight-line declassification still works."""
    src = '''
        def tainted_then_constant():
            x = input()
            x = "safe"
            subprocess.run(x)
    '''
    assert not _lines(_run(tmp_path, src), "command_injection")


def test_constant_in_enclosing_block_kills_nested_taint(tmp_path):
    """An outer unconditional assignment overwrites an inner-branch taint."""
    src = '''
        def f(cond):
            if cond:
                x = request.args.get("q")
            x = "safe"
            subprocess.run(x)
    '''
    assert not _lines(_run(tmp_path, src), "command_injection")


# ---------------------------------------------------------------------------
# Sinks the sink map did not know
# ---------------------------------------------------------------------------
def test_persist_path_keyword_is_a_file_write_sink(tmp_path):
    """GT-03/GT-04: vector and KV stores take the destination as a keyword."""
    src = '''
        def save_session():
            data = request.get_json() or {}
            persist_dir = data.get("persist_dir", "")
            store.persist(persist_dir=persist_dir)
    '''
    sink = _find(src, None, "store.persist(persist_dir=persist_dir)")
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


def test_persist_with_constant_destination_is_not_reported(tmp_path):
    src = '''
        def save():
            store.persist(persist_dir="./fixed")
    '''
    assert not _lines(_run(tmp_path, src), "path_traversal")


def test_write_into_importable_module_is_code_injection(tmp_path):
    """GT-06: fixed path, attacker content, .py target == CWE-94."""
    src = '''
        import os, tempfile

        def build(payload):
            root = tempfile.mkdtemp()
            with open(os.path.join(root, "rag_dataset.json"), "w") as fh:
                fh.write("{}")
            with open(os.path.join(root, "__init__.py"), "w") as fh:
                fh.write(payload)

        data = request.get_json() or {}
        build(data["q"])
    '''
    sink = _find(src, None, 'fh.write(payload)')
    assert sink in _lines(_run(tmp_path, src), "code_injection")


def test_write_into_data_file_is_not_code_injection(tmp_path):
    src = '''
        import os, tempfile

        def build(payload):
            root = tempfile.mkdtemp()
            with open(os.path.join(root, "data.json"), "w") as fh:
                fh.write(payload)

        data = request.get_json() or {}
        build(data["q"])
    '''
    assert not _lines(_run(tmp_path, src), "code_injection")


# ---------------------------------------------------------------------------
# Same-file interprocedural seeding, and the bounds on it
# ---------------------------------------------------------------------------
def test_same_file_interprocedural_seed_reaches_sink(tmp_path):
    """GT-02: ``_peek(remainder)`` then ``open(path, "r")`` inside ``_peek``."""
    src = '''
        def _peek(path):
            target_path = path.strip()
            with open(target_path, "r") as fh:
                return fh.read()

        def chat():
            data = request.get_json() or {}
            query = data.get("query", "")
            parts = query.split(":", 1)
            return _peek(parts[1])
    '''
    sink = _find(src, None, 'open(target_path, "r")')
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


def test_keyword_argument_seeds_callee_parameter(tmp_path):
    src = '''
        def _read(target):
            open(target)

        def chat():
            data = request.get_json() or {}
            _read(target=data["q"])
    '''
    sink = _find(src, None, "open(target)")
    assert sink in _lines(_run(tmp_path, src), "path_traversal")


def test_operator_controlled_source_does_not_seed_callee(tmp_path):
    """NC-A: env/CLI/input describe the operator's machine, not the network.

    This is the measured regression from the first G-035 implementation:
    unrestricted seeding reported ``run_cmd(f'cd "{SANDBOX_DIR}" ...')`` as
    command injection and violated negative control NC-03.
    """
    src = '''
        import os, subprocess

        SANDBOX_DIR = os.getenv("SANDBOX_DIR", "/srv/sandbox")

        def run_cmd(cmd):
            subprocess.run(cmd, shell=True)

        run_cmd(f"cd {SANDBOX_DIR} && docker build .")
    '''
    assert not _lines(_run(tmp_path, src), "command_injection")


def test_request_source_does_seed_callee(tmp_path):
    """Positive control for the network-only bound above."""
    src = '''
        import subprocess

        def run_cmd(cmd):
            subprocess.run(cmd, shell=True)

        run_cmd(request.args.get("cmd"))
    '''
    assert _lines(_run(tmp_path, src), "command_injection")


def test_caller_locals_are_hidden_from_the_callee(tmp_path):
    """Name resolution must not leak a caller frame into a seeded callee."""
    src = '''
        def callee(binding):
            open(name)

        def caller():
            name = request.args.get("n")
            callee(name)
    '''
    assert not _lines(_run(tmp_path, src), "path_traversal")


def test_seeded_parameter_is_declassified_in_same_block(tmp_path):
    """A seeded value that the callee immediately overwrites is not taint."""
    src = '''
        def handler(path):
            path = "safe"
            open(path)

        handler(request.args.get("p"))
    '''
    assert not _lines(_run(tmp_path, src), "path_traversal")


def test_recursion_terminates(tmp_path):
    src = '''
        import request

        def walk(n):
            walk(n)
            open(n)

        walk(request.args.get("q"))
    '''
    findings = _run(tmp_path, src)
    assert len(_lines(findings, "path_traversal")) <= 1


# ---------------------------------------------------------------------------
# EVIDEX must accept the sinks the taint engine now reports
# ---------------------------------------------------------------------------
def test_evidex_accepts_persist_path_traversal():
    from core.analyzer import enrich_finding

    enriched = enrich_finding({
        "vuln_type": "path_traversal",
        "rule_id": "TAINT_PATH_TRAVERSAL",
        "file": "app/server.py",
        "line": 357,
        "snippet": "kv.persist(persist_path=path)",
        "taint_path": "request.get_json() -> data -> path -> kv.persist",
        "severity": "High",
    })
    assert enriched, "persist path traversal must survive enrich_finding"
    assert enriched.get("evidence_valid") is True


def test_evidex_accepts_python_write_code_injection():
    from core.analyzer import enrich_finding

    enriched = enrich_finding({
        "vuln_type": "code_injection",
        "rule_id": "TAINT_CODE_INJECTION",
        "file": "app/server.py",
        "line": 402,
        "snippet": "fh.write(payload)",
        "taint_path": "request.get_json() -> data -> payload -> fh.write(payload)",
        "severity": "Critical",
    })
    assert enriched, "module write must survive enrich_finding"
    assert enriched.get("evidence_valid") is True


def test_evidex_still_rejects_code_injection_without_a_sink(tmp_path):
    """The widening is by sink alias, not by removing the sink contract."""
    from core.analyzer import _validate_security_evidence

    result = _validate_security_evidence({
        "vuln_type": "code_injection",
        "rule_id": "TAINT_CODE_INJECTION",
        "file": "app/server.py",
        "line": 10,
        "snippet": "user_input",
        "taint_path": "request.args -> user_input",
    })
    assert result["sink_present"] is False
    assert result["valid"] is False


# ---------------------------------------------------------------------------
# Register guard -- reports/gap_register.json is the Phase 3 source of truth,
# so the closure claimed for this phase has to be recorded in it.
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_ROOT = _Path(__file__).resolve().parents[1]


def _reg() -> dict:
    return _json.loads(
        (_ROOT / "reports" / "gap_register.json").read_text(encoding="utf-8")
    )


def test_g035_is_recorded_as_measured_closed_with_before_and_after():
    by_id = {g["id"]: g for g in _reg()["gaps"]}
    g35 = by_id["G-035"]
    assert g35["evidence_tier"] == "MEASURED_CLOSED"
    ev = g35["evidence"]
    # a closure without a BEFORE number is a claim, not a measurement
    assert "BEFORE" in ev and "AFTER" in ev, "closure must carry before/after"
    assert "0/5" in ev and "5/5" in ev, "path traversal before/after missing"
    assert "0/1" in ev and "1/1" in ev, "code injection before/after missing"
    assert "5/11" in ev and "11/11" in ev, "overall recall before/after missing"
    assert "0/6" in ev, "negative controls must be reported"
    # every closed row is backed by a test file, not by a scan count alone
    assert "tests/test_v11_g035_framework_taint.py" in ev
    assert "319 passed" in ev, "regression suite result missing"


def test_g035_closure_ledger_entry_names_every_root_cause_involved():
    reg = _reg()
    hits = [e for e in reg["closed_this_program"] if "G-035" in e["item"]]
    assert len(hits) == 1, f"expected exactly one G-035 ledger entry, got {len(hits)}"
    causes = set(hits[0]["root_causes"])
    # the four structural causes plus the evidence catalogue they exposed
    assert causes == {
        "FRAMEWORK_SOURCE_GAP",
        "TAINT_GAP",
        "SINK_GAP",
        "SCOPE_GAP",
        "EVIDENCE_GAP",
    }
    for cause in causes:
        assert cause in reg["root_cause_classes"], cause


def test_g035_scoping_decision_is_recorded_not_silently_dropped():
    """The withheld half of this phase must be visible in the register."""
    hits = [n for n in _reg()["not_proposed"] if "os.getenv" in n.get("item", "")]
    assert len(hits) == 1, "operator-controlled cross-function propagation not recorded"
    # the reason has to carry the measurement, not just an opinion
    assert "NC-03" in hits[0]["reason"], hits[0]["reason"]
    assert "negative control" in hits[0]["reason"] or "negative-control" in hits[0]["reason"]


def test_new_rows_added_alongside_this_phase_keep_the_register_schema():
    reg = _reg()
    for gid in ("G-045", "G-046"):
        g = [x for x in reg["gaps"] if x["id"] == gid]
        assert len(g) == 1, gid
        g = g[0]
        assert g["cost"] in {"XS", "S", "M", "L", "XL"}, gid
        assert g["regression_risk"] in {"LOW", "MED", "HIGH"}, gid
        assert isinstance(g["enterprise_essential"], bool), gid
        assert isinstance(g["research_relevant"], bool), gid
        assert g["evidence"].strip(), gid
        assert g["root_cause_class"] in reg["root_cause_classes"], gid
