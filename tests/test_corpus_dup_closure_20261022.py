"""Bucket C — duplicate-reporting closure (red-first, 2026-10-22).

Twenty corpus rows are SECOND reports of a defect already reported by a
sibling row. One defect, one row: every kill below is provable by
partner presence plus receiver-variable identity, and the row that
survives is the label-anchored canonical (java L23/L38/L50, rust L14) or
the deeper specific claim (terraform statement-level wildcard rule,
provider-signature secret rule).

Three mechanisms, one contract:

* AST pair kills (``scanner/ast_validators.py``) run as a POST-pass over
  the rows that survived bucket B's guard kills, so a partner removed by
  a guard can never justify a kill and a row whose partner row is absent
  from the surviving list always keeps.
* The terraform wildcard pair defers inside ``scan_terraform``: the
  line-pattern rule ``TF_IAM_WILDCARD_ACTION`` keeps only lines the
  statement-level ``TF_AWS_IAM_WILDCARD_ACTION_SERVICE`` does not claim.
* The secret fallback layers defer inside ``scan_file``: every generic
  claim (``GENERIC_HIGH_ENTROPY_SECRET``) and the name-gated
  ``SOURCE_HARDCODED_CREDENTIAL`` yield to a specific rule on the SAME
  (file, line); a fallback alone on its line keeps.  The SOURCE anchor
  bug (a leading ``\\s*`` letting the match swallow the blank line above
  an assignment, reporting JWT_SIGNING_SECRET at L2 instead of L3) is
  fixed by anchoring on the identifier group.

Grammar-dependent tests skip when the grammar is absent (LOCAL-only
wheel contract); the secrets and terraform kills are grammar-free.
"""
import re
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import tree_sitter_support as ts  # noqa: E402

try:
    from scanner.ast_validators import VALIDATED_RULE_IDS  # noqa: E402
except Exception:                                # pragma: no cover
    VALIDATED_RULE_IDS = frozenset()

CORPUS = Path(__file__).parent / "vuln-test-corpus"

JAVA_OK = ts.grammar_available("java")
RUST_OK = ts.grammar_available("rust")

needs_java = pytest.mark.skipif(
    not JAVA_OK, reason="tree-sitter-java grammar not installed")
needs_rust = pytest.mark.skipif(
    not RUST_OK, reason="tree-sitter-rust grammar not installed")


# ---------------------------------------------------------------------------
# Scanning helpers (temp copies exactly like the harness)
# ---------------------------------------------------------------------------

def _scan_sast(rel_dir: str, name: str) -> list[dict]:
    from scanner.sast import scan_directory

    tmp = Path(tempfile.mkdtemp(prefix="rsx_dup_"))
    try:
        shutil.copy2(CORPUS / rel_dir / name, tmp / name)
        rows = scan_directory(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return [f for f in rows
            if Path(str(f.get("file", ""))).name == name]


def _scan_tf(name: str) -> list[dict]:
    from scanner.iac_terraform import scan_terraform

    return scan_terraform(str(CORPUS / "iac" / "terraform" / name))


def _scan_secrets(name: str, corpus: Path = CORPUS) -> list[dict]:
    from scanner.secret_intelligence import scan_secret_intelligence

    tmp = Path(tempfile.mkdtemp(prefix="rsx_sec_"))
    try:
        shutil.copy2(corpus / "secrets" / name, tmp / name)
        rows = scan_secret_intelligence(str(tmp))["secret_intelligence_findings"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return [f for f in rows
            if Path(str(f.get("file", ""))).name == name]


def _rows(rows: list[dict], rule: str, line: int) -> list[dict]:
    return [f for f in rows
            if f.get("rule_id") == rule and int(f.get("line") or 0) == line]


def _keys(rows: list[dict]) -> set:
    return {(str(f.get("rule_id")), int(f.get("line") or 0)) for f in rows}


# ---------------------------------------------------------------------------
# Integration kills — corpus duplicate rows gone, canonical row survives
# ---------------------------------------------------------------------------

@needs_java
def test_java_deser_constructor_row_dies_sink_row_survives():
    """The ctor row L48 is the duplicate; the readObject row L50 carries
    the SAST-DESER label (evidence ``ois.readObject()``)."""
    rows = _scan_sast("sast/java", "VulnerableServlet.java")
    assert not _rows(rows, "JAVA_OBJECTINPUTSTREAM_DESERIALIZATION", 48), rows
    assert _rows(rows, "JAVA_OBJECTINPUTSTREAM_DESERIALIZATION", 50), rows


@needs_java
def test_java_jdbc_context_row_dies_intermediate_sink_survives():
    """L22 (bare ``createStatement()`` context) is the duplicate of the
    L23 ``executeQuery(sql)`` row that carries the SAST-SQLI label."""
    rows = _scan_sast("sast/java", "VulnerableServlet.java")
    assert not _rows(rows, "JAVA_JDBC_SQL_CONCAT", 22), rows
    assert _rows(rows, "JAVA_JDBC_SQL_INTERMEDIATE_QUERY", 23), rows


@needs_java
def test_java_path_consumption_row_dies_construction_survives():
    """L39 (``new FileInputStream(f)`` consumption) is the duplicate of
    the label-anchored multipart construction row L38
    (evidence ``new File("/var/www/uploads/" + fileName)``)."""
    rows = _scan_sast("sast/java", "VulnerableServlet.java")
    assert not _rows(rows, "JAVA_TAINT_PATH_TRAVERSAL", 39), rows
    assert _rows(rows, "TAINT_MULTIPART_TRAVERSAL", 38), rows
    # The file must keep BOTH canonical rows for its other labels.
    assert _rows(rows, "JAVA_TAINT_COMMAND_INJECTION", 32), rows


@needs_rust
def test_rust_format_construction_row_dies_sink_row_survives():
    """L13 (``format!`` construction) is the duplicate of the L14
    ``conn.prepare(&sql)`` row that carries the SAST-SQLI label."""
    rows = _scan_sast("sast/rust", "vulnerable.rs")
    assert not _rows(rows, "RUST_SQL_FORMAT", 13), rows
    assert _rows(rows, "RUST_SQL_SINK", 14), rows


def test_terraform_statement_rule_supersedes_line_rule():
    """iam_wildcard.tf reports the bare ``"*"`` once: the G21
    statement-level rule survives, the pre-existing line rule defers."""
    rows = _scan_tf("iam_wildcard.tf")
    assert _rows(rows, "TF_AWS_IAM_WILDCARD_ACTION_SERVICE", 1), rows
    assert not _rows(rows, "TF_IAM_WILDCARD_ACTION", 1), rows


# ---------------------------------------------------------------------------
# Secrets — signature/statement claims supersede generic fallbacks
# ---------------------------------------------------------------------------

#: Exact surviving rows per fixture: one claim per labelled literal.
SECRET_SURVIVORS = {
    "aws_credentials.py": {("AWS_ACCESS_KEY", 2)},
    "github_token.py": {("GITHUB_TOKEN", 4)},
    "gitlab_huggingface.py": {("GITLAB_TOKEN", 1), ("HUGGINGFACE_TOKEN", 2)},
    "jwt_signing.py": {("JWT_SIGNING_SECRET", 3)},
    "openai_key.py": {("OPENAI_KEY", 1)},
    "package_registry_tokens.py": {("NPM_TOKEN", 2), ("PYPI_TOKEN", 3)},
    "stripe_key.py": {("STRIPE_SECRET_KEY", 2)},
}


@pytest.mark.parametrize("name", sorted(SECRET_SURVIVORS))
def test_secret_signature_row_is_the_only_claim(name):
    rows = _scan_secrets(name)
    assert _keys(rows) == SECRET_SURVIVORS[name], rows


def test_secret_source_anchor_sits_on_the_assignment_line():
    """A blank line above the assignment must not move the anchor: the
    old ``text[:m.start()]`` counted the blank line the leading
    ``\\s*`` swallowed (the jwt_signing L2 symptom)."""
    src = 'import x\n\nDB_PASSWORD = "s3cr3tS3cr3t1234"\n'
    with tempfile.TemporaryDirectory(prefix="rsx_anchor_") as tmp:
        Path(tmp, "anchored.py").write_text(src, encoding="utf-8")
        from scanner.secret_intelligence import scan_secret_intelligence
        rows = scan_secret_intelligence(tmp)["secret_intelligence_findings"]
    rows = [f for f in rows
            if Path(str(f.get("file", ""))).name == "anchored.py"]
    assert not [f for f in rows if int(f.get("line") or 0) == 2], rows
    assert _rows(rows, "SOURCE_HARDCODED_CREDENTIAL", 3), rows


def test_secret_fallback_row_keeps_without_signature_partner():
    """Kill-on-proof: with no provider signature claiming the line, the
    name-gated SOURCE rule is the only claim and must survive."""
    src = 'SERVICE_PASSWORD = "hunter2hunter2secret"\n'
    with tempfile.TemporaryDirectory(prefix="rsx_fb_") as tmp:
        Path(tmp, "plain.py").write_text(src, encoding="utf-8")
        from scanner.secret_intelligence import scan_secret_intelligence
        rows = scan_secret_intelligence(tmp)["secret_intelligence_findings"]
    rows = [f for f in rows
            if Path(str(f.get("file", ""))).name == "plain.py"]
    assert _rows(rows, "SOURCE_HARDCODED_CREDENTIAL", 1), rows


def test_secret_fallback_deferral_matrix():
    """The deferral tiers, directly: GENERIC yields to any sibling claim,
    SOURCE yields to a provider signature, a lone fallback keeps."""
    from scanner.secret_intelligence import _defer_fallback_claims

    def row(rule, line, file="f.py"):
        return {"rule_id": rule, "file": file, "line": line}

    both = _defer_fallback_claims([
        row("SOURCE_HARDCODED_CREDENTIAL", 2),
        row("GENERIC_HIGH_ENTROPY_SECRET", 2),
        row("AWS_ACCESS_KEY", 2),
    ])
    assert _keys(both) == {("AWS_ACCESS_KEY", 2)}

    named_only = _defer_fallback_claims([
        row("SOURCE_HARDCODED_CREDENTIAL", 4),
        row("GENERIC_HIGH_ENTROPY_SECRET", 4),
    ])
    assert _keys(named_only) == {("SOURCE_HARDCODED_CREDENTIAL", 4)}

    lone_generic = _defer_fallback_claims([row("GENERIC_HIGH_ENTROPY_SECRET", 9)])
    assert _keys(lone_generic) == {("GENERIC_HIGH_ENTROPY_SECRET", 9)}

    # Different lines are different claims: proximity must not defer.
    apart = _defer_fallback_claims([
        row("SOURCE_HARDCODED_CREDENTIAL", 2),
        row("AWS_ACCESS_KEY", 3),
    ])
    assert _keys(apart) == {("SOURCE_HARDCODED_CREDENTIAL", 2),
                            ("AWS_ACCESS_KEY", 3)}


# ---------------------------------------------------------------------------
# Pair-kill keep controls — every kill is conditional on the partner
# ---------------------------------------------------------------------------

@needs_java
def test_deser_constructor_keeps_without_readobject_partner(tmp_path):
    target = tmp_path / "NoSink.java"
    target.write_text(
        "import java.io.*;\n"
        "class NoSink {\n"
        "  void load(InputStream in) throws Exception {\n"
        "    ObjectInputStream ois = new ObjectInputStream(in);\n"
        "  }\n"
        "}\n", encoding="utf-8")
    from scanner.sast import scan_directory
    rows = [f for f in scan_directory(str(tmp_path))
            if Path(str(f.get("file", ""))).name == "NoSink.java"]
    assert _rows(rows, "JAVA_OBJECTINPUTSTREAM_DESERIALIZATION", 4), rows


@needs_java
def test_jdbc_context_row_keeps_without_intermediate_partner(tmp_path):
    """A literal-query JDBC file: the context row has no intermediate
    sibling (the partner predicate fails on ``q``), so nothing kills."""
    target = tmp_path / "LiteralQuery.java"
    target.write_text(
        "import java.sql.*;\n"
        "class LiteralQuery {\n"
        "  void run(Connection conn) throws SQLException {\n"
        "    String q = \"SELECT id FROM users WHERE active = 1\";\n"
        "    Statement stmt = conn.createStatement();\n"
        "    ResultSet rs = stmt.executeQuery(q);\n"
        "  }\n"
        "}\n", encoding="utf-8")
    from scanner.sast import scan_directory
    rows = [f for f in scan_directory(str(tmp_path))
            if Path(str(f.get("file", ""))).name == "LiteralQuery.java"]
    assert _rows(rows, "JAVA_JDBC_SQL_CONCAT", 5), rows
    assert not _rows(rows, "JAVA_JDBC_SQL_INTERMEDIATE_QUERY", 6), rows


@needs_java
def test_path_consumption_keeps_without_construction_partner(tmp_path):
    """Direct taint into the stream constructor: no ``new File(var)``
    sibling row exists, so the consumption row is the only claim."""
    target = tmp_path / "DirectRead.java"
    target.write_text(
        "import jakarta.servlet.*;\n"
        "import jakarta.servlet.http.*;\n"
        "import java.io.*;\n"
        "class DirectRead extends HttpServlet {\n"
        "  void doGet(HttpServletRequest req, HttpServletResponse resp)\n"
        "      throws ServletException, IOException {\n"
        "    try (FileInputStream fis = new FileInputStream(\n"
        "        new File(req.getParameter(\"file\")))) {\n"
        "      resp.getWriter().println(fis.available());\n"
        "    }\n"
        "  }\n"
        "}\n", encoding="utf-8")
    from scanner.sast import scan_directory
    rows = [f for f in scan_directory(str(tmp_path))
            if Path(str(f.get("file", ""))).name == "DirectRead.java"]
    assert _rows(rows, "JAVA_TAINT_PATH_TRAVERSAL", 7), rows


@needs_rust
def test_rust_format_row_keeps_without_sink_partner(tmp_path):
    target = tmp_path / "nosqlsink.rs"
    target.write_text(
        "fn report(user: &str) -> String {\n"
        "    let sql = format!(\"SELECT * FROM users WHERE name = '{}'\", user);\n"
        "    sql\n"
        "}\n", encoding="utf-8")
    from scanner.sast import scan_directory
    rows = [f for f in scan_directory(str(tmp_path))
            if Path(str(f.get("file", ""))).name == "nosqlsink.rs"]
    assert _rows(rows, "RUST_SQL_FORMAT", 2), rows


# ---------------------------------------------------------------------------
# Escape hatch and registration
# ---------------------------------------------------------------------------

@needs_java
def test_escape_hatch_restores_java_pair_rows(monkeypatch):
    monkeypatch.setenv("RSX_AST_VALIDATION", "0")
    rows = _scan_sast("sast/java", "VulnerableServlet.java")
    assert _rows(rows, "JAVA_OBJECTINPUTSTREAM_DESERIALIZATION", 48), rows
    assert _rows(rows, "JAVA_JDBC_SQL_CONCAT", 22), rows
    assert _rows(rows, "JAVA_TAINT_PATH_TRAVERSAL", 39), rows


@needs_rust
def test_escape_hatch_restores_rust_pair_rows(monkeypatch):
    monkeypatch.setenv("RSX_AST_VALIDATION", "0")
    rows = _scan_sast("sast/rust", "vulnerable.rs")
    assert _rows(rows, "RUST_SQL_FORMAT", 13), rows


def test_pair_rules_are_registered_in_the_closed_set():
    for rule in ("JAVA_OBJECTINPUTSTREAM_DESERIALIZATION",
                 "JAVA_JDBC_SQL_CONCAT", "RUST_SQL_FORMAT",
                 "JAVA_TAINT_PATH_TRAVERSAL"):
        assert rule in VALIDATED_RULE_IDS, rule
