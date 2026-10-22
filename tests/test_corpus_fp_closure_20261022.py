"""Golden-corpus FP closure — 2026-10-22, red-first suite (family B + A pins).

Baseline measured before this file existed (analysis.validation.run):
44 FP = 24 spurious + 20 duplicate at 100% recall (115/115).

Family A — SCA labels (pins, this file):
    11 verified-true advisory rows were counted as FPs because the two
    fixture labels (written 2026-10-11/12) predated two 2026 lodash
    advisories and documented only the rails metapackage row of the
    Gemfile fixture (nine real actionpack advisories went unlisted).
    Every added row was verified version-aware: OSV querybatch returned
    it FOR the pinned version and every ``fixed_versions`` entry is
    greater than the pinned version. The labels were curated by hand —
    the harness itself never adjusts a label — and the change
    STRENGTHENS the gate (33 expected SCA findings instead of 22; any
    future miss becomes an FN). 44 -> 33 FP measured.

Family B — safe-fixture guard-window rows (this file, red-first):
    10 rows where the rule fired although the fixture proves the value
    is validated (whitelist / traversal guard with an early exit, or a
    literal auto-escaped template). Each kill is kill-on-proof through
    the closed-set ``ast_validators`` layer; every vulnerable twin has a
    control assertion, and the python XSS/CMDI shapes that the corpus
    cannot pin (their vulnerable twins are masked by same-line merges)
    get constructed keep-controls instead.

GRAMMAR CONTRACT
----------------
python/rust/cpp grammars are LOCAL-only wheels (same contract as the
js/ts/go/csharp/php/java set): absence degrades to ``parse() is None``
and every finding passes through byte-identical. Every assertion that
depends on a grammar skips itself when that grammar is absent, so CI
(stdlib-only) stays green while measuring nothing it cannot measure.

Run: python -m pytest tests/test_corpus_fp_closure_20261022.py -q
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.validation.corpus import validate_ground_truth  # noqa: E402
from scanner import tree_sitter_support as ts  # noqa: E402

CORPUS = Path(__file__).parent / "vuln-test-corpus"

#: (fixture dir relative to corpus, fixture name, rule id, line, grammar lang)
SAFE_ROWS = [
    ("sast/java", "SafeServlet.java", "JAVA_PATH_TRAVERSAL_FILE", 46, "java"),
    ("sast/java", "SafeServlet.java", "JAVA_TAINT_COMMAND_INJECTION", 35, "java"),
    ("sast/java", "SafeServlet.java", "JAVA_TAINT_PATH_TRAVERSAL", 47, "java"),
    ("sast/php", "safe.php", "PHP_PATH_USER_INPUT_VAR", 41, "php"),
    ("sast/python", "safe_app.py", "TAINT_COMMAND_INJECTION", 28, "python"),
    ("sast/python", "safe_app.py", "TAINT_XSS", 40, "python"),
    ("sast/rust", "safe.rs", "RUST_COMMAND_EXEC", 39, "rust"),
    ("sast/rust", "safe.rs", "RUST_PATH_FORMAT", 53, "rust"),
    ("sast/cpp", "safe.cpp", "CPP_HARDCODED_CREDENTIAL", 39, "cpp"),
    ("sast/cpp", "safe.cpp", "CPP_PATH_SNPRINTF_INTERP", 83, "cpp"),
]

#: Vulnerable twins that MUST keep their row after the kills land.
#: (dir, fixture, rule id, line, lang) — python's two taint rows are
#: asserted through vuln_type because the corpus representative for
#: vulnerable_app.py L27 is the same-line window rule (group merge).
VULN_KEEP = [
    ("sast/java", "VulnerableServlet.java", "JAVA_TAINT_COMMAND_INJECTION", 32, "java"),
    ("sast/java", "VulnerableServlet.java", "JAVA_TAINT_PATH_TRAVERSAL", 39, "java"),
    ("sast/java", "VulnerableServlet.java", "TAINT_MULTIPART_TRAVERSAL", 38, "java"),
    ("sast/php", "vulnerable.php", "PHP_PATH_USER_INPUT_VAR", 27, "php"),
    ("sast/rust", "vulnerable.rs", "RUST_COMMAND_EXEC", 33, "rust"),
    ("sast/rust", "vulnerable.rs", "RUST_PATH_FORMAT", 45, "rust"),
    ("sast/cpp", "vulnerable.cpp", "CPP_HARDCODED_CREDENTIAL", 11, "cpp"),
    ("sast/cpp", "vulnerable.cpp", "CPP_PATH_SNPRINTF_INTERP", 48, "cpp"),
]


def _scan_fixture(rel_dir: str, name: str) -> list[dict]:
    """Scan one fixture exactly the way the harness does (temp copy, so the
    label files and neighbours cannot influence the result)."""
    from scanner.sast import scan_directory

    tmp = Path(tempfile.mkdtemp(prefix="rsx_fp_"))
    try:
        shutil.copy2(CORPUS / rel_dir / name, tmp / name)
        rows = scan_directory(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return [f for f in rows
            if Path(str(f.get("file", ""))).name == name]


def _finding(rule: str, line: int, snippet: str, chain=None) -> dict:
    f = {"rule_id": rule, "line": line, "snippet": snippet,
         "vuln_type": "test"}
    if chain is not None:
        f["taint_chain"] = chain
    return f


# ---------------------------------------------------------------------------
# Family A — SCA label curation pins (guard against silent drift)
# ---------------------------------------------------------------------------

def _load(rel: str) -> dict:
    return json.loads((CORPUS / rel).read_text(encoding="utf-8"))


def test_sca_labels_are_sound_after_curation():
    for rel_fixture, rel_label in [
        ("sca/npm/vulnerable/package.json",
         "sca/npm/vulnerable/package.json.ground_truth.json"),
        ("sca/rubygems/vulnerable/Gemfile.lock",
         "sca/rubygems/vulnerable/Gemfile.lock.ground_truth.json"),
    ]:
        truth = _load(rel_label)
        assert validate_ground_truth(truth, CORPUS / rel_fixture) == [], (
            "the curated labels must pass the corpus validator")


def test_npm_label_covers_the_two_2026_lodash_advisories():
    truth = _load("sca/npm/vulnerable/package.json.ground_truth.json")
    assert truth["expected_count"] == len(truth["expected_findings"]) == 8
    cves = {f["cve"] for f in truth["expected_findings"]}
    assert {"CVE-2026-2950", "CVE-2026-4800"} <= cves, cves
    assert set(truth["expected_cves"]) == cves


def test_gemfile_label_covers_every_actionpack_row():
    truth = _load("sca/rubygems/vulnerable/Gemfile.lock.ground_truth.json")
    assert truth["expected_count"] == len(truth["expected_findings"]) == 10
    pairs = {(f["package"], f["cve"]) for f in truth["expected_findings"]}
    actionpack = {cve for pkg, cve in pairs if pkg == "actionpack"}
    assert actionpack == {
        "CVE-2023-28362", "CVE-2023-22795", "CVE-2023-22797",
        "CVE-2024-26143", "CVE-2024-28103", "CVE-2023-22792",
        "CVE-2024-47887", "CVE-2024-54133", "CVE-2024-41128",
    }, actionpack
    assert ("rails", "CVE-2024-26143") in pairs


def test_sca_family_scores_zero_false_positives():
    """The measured closure for family A: every SCA row now matches a label."""
    from analysis.validation.run import run_corpus
    result = run_corpus(CORPUS, families=["sca"])
    sca_rows = [d for d in result["details"] if d["family"] == "sca"]
    assert sca_rows, "no SCA fixtures scored"
    for d in sca_rows:
        assert d["fp"] == 0, (d["fixture"], d["extra"])
        assert d["fn"] == 0, (d["fixture"], d["missed"])


# ---------------------------------------------------------------------------
# Family B — integration: safe fixtures must go dark, twins must stay lit
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel_dir,name,rule,line,lang", SAFE_ROWS)
def test_safe_fixture_row_is_gone(rel_dir, name, rule, line, lang):
    if not ts.grammar_available(lang):
        pytest.skip(f"{lang} grammar is a LOCAL-only wheel; absent = keep")
    rows = _scan_fixture(rel_dir, name)
    hits = [f for f in rows
            if f.get("rule_id") == rule and f.get("line") == line]
    assert not hits, (
        f"{name}:{line} still reports {rule} although the fixture proves "
        f"the value validated before the sink")


@pytest.mark.parametrize("rel_dir,name,rule,line,lang", VULN_KEEP)
def test_vulnerable_twin_row_survives(rel_dir, name, rule, line, lang):
    if not ts.grammar_available(lang):
        pytest.skip(f"{lang} grammar is a LOCAL-only wheel; absent = keep")
    rows = _scan_fixture(rel_dir, name)
    hits = [f for f in rows
            if f.get("rule_id") == rule and f.get("line") == line]
    assert hits, (
        f"{name}:{line} lost {rule} — a guard kill escaped its proof")


def test_python_vulnerable_cmdi_still_reports():
    """The corpus representative of vulnerable_app.py L27 is a same-line
    merge; assert on the vulnerability, not the winning rule id."""
    rows = _scan_fixture("sast/python", "vulnerable_app.py")
    assert any(f.get("line") == 27
               and f.get("vuln_type") == "command_injection" for f in rows), rows


# ---------------------------------------------------------------------------
# Family B — validator-level kill/keep pairs (fast, engine-merge-proof)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel_dir,name,rule,line,snippet,chain,lang", [
    # ---- kills (safe shapes, real fixture files as context) ----
    ("sast/java", "SafeServlet.java", "JAVA_TAINT_COMMAND_INJECTION", 35,
     'Process p = Runtime.getRuntime().exec(cmd);',
     ["userInput", "cmd", "Runtime.getRuntime().exec("], "java"),
    ("sast/java", "SafeServlet.java", "JAVA_TAINT_PATH_TRAVERSAL", 47,
     'try (FileInputStream fis = new FileInputStream(f)) {',
     ["fileName", "f", "new FileInputStream("], "java"),
    ("sast/java", "SafeServlet.java", "JAVA_PATH_TRAVERSAL_FILE", 46,
     'File f = new File("/var/www/uploads/" + fileName);',
     ["fileName", "new File("], "java"),
    ("sast/php", "safe.php", "PHP_PATH_USER_INPUT_VAR", 41,
     'include("/var/www/includes/" . $file);', None, "php"),
    ("sast/rust", "safe.rs", "RUST_COMMAND_EXEC", 39,
     'let output = Command::new(parts[0])', None, "rust"),
    ("sast/rust", "safe.rs", "RUST_PATH_FORMAT", 53,
     'let path = format!("/var/www/uploads/{}", filename);', None, "rust"),
    ("sast/cpp", "safe.cpp", "CPP_HARDCODED_CREDENTIAL", 39,
     'const char* sql = "SELECT * FROM users WHERE name = ?";', None, "cpp"),
    ("sast/cpp", "safe.cpp", "CPP_PATH_SNPRINTF_INTERP", 83,
     'snprintf(path, sizeof(path), "/var/www/uploads/%s", file);', None, "cpp"),
])
def test_validator_kills_safe_shape(rel_dir, name, rule, line, snippet,
                                    chain, lang):
    if not ts.grammar_available(lang):
        pytest.skip(f"{lang} grammar absent")
    from scanner.ast_validators import apply_ast_validation
    out = apply_ast_validation([_finding(rule, line, snippet, chain)],
                               str(CORPUS / rel_dir / name))
    assert out == [], out


@pytest.mark.parametrize("rel_dir,name,rule,line,snippet,chain,lang", [
    # ---- keeps (unguarded vulnerable twins) ----
    ("sast/java", "VulnerableServlet.java", "JAVA_TAINT_COMMAND_INJECTION", 32,
     'Process p = Runtime.getRuntime().exec(cmd);',
     ["userInput", "cmd", "Runtime.getRuntime().exec("], "java"),
    ("sast/java", "VulnerableServlet.java", "JAVA_TAINT_PATH_TRAVERSAL", 39,
     'try (FileInputStream fis = new FileInputStream(f)) {',
     ["fileName", "f", "new FileInputStream("], "java"),
    ("sast/php", "vulnerable.php", "PHP_PATH_USER_INPUT_VAR", 27,
     'include("/var/www/includes/" . $file); // no validation', None, "php"),
    ("sast/rust", "vulnerable.rs", "RUST_COMMAND_EXEC", 33,
     'let output = Command::new("sh")', None, "rust"),
    ("sast/rust", "vulnerable.rs", "RUST_PATH_FORMAT", 45,
     'let path = format!("/var/www/uploads/{}", filename);', None, "rust"),
    ("sast/cpp", "vulnerable.cpp", "CPP_HARDCODED_CREDENTIAL", 11,
     'const char* db_pass = "hardcoded_password";', None, "cpp"),
    ("sast/cpp", "vulnerable.cpp", "CPP_PATH_SNPRINTF_INTERP", 48,
     'snprintf(path, sizeof(path), "/var/www/uploads/%s", file);', None, "cpp"),
])
def test_validator_keeps_unguarded_vulnerable_shape(rel_dir, name, rule, line,
                                                    snippet, chain, lang):
    if not ts.grammar_available(lang):
        pytest.skip(f"{lang} grammar absent")
    from scanner.ast_validators import apply_ast_validation
    out = apply_ast_validation([_finding(rule, line, snippet, chain)],
                               str(CORPUS / rel_dir / name))
    assert len(out) == 1, (rule, out)


# ---------------------------------------------------------------------------
# Constructed python keep-controls (the corpus twins are merge-masked)
# ---------------------------------------------------------------------------

_PY_XSS_KILL = '''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/t")
def tmpl():
    name = request.args.get("name", "")
    return render_template_string("Hello {{ name }}", name=name)
'''

_PY_XSS_FSTRING_KEEP = '''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/t")
def tmpl():
    name = request.args.get("name", "")
    return render_template_string(f"Hello {name}")
'''

_PY_XSS_SAFE_FILTER_KEEP = '''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/t")
def tmpl():
    name = request.args.get("name", "")
    return render_template_string("Hello {{ name|safe }}", name=name)
'''

_PY_XSS_TAINTED_TEMPLATE_KEEP = '''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/t")
def tmpl():
    tpl = request.args.get("tpl", "")
    return render_template_string(tpl)
'''

_PY_CMDI_KEEP = '''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/r")
def run():
    cmd = request.args.get("cmd", "")
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
'''


def test_python_xss_literal_template_is_killed(tmp_path):
    if not ts.grammar_available("python"):
        pytest.skip("python grammar absent")
    from scanner.ast_validators import apply_ast_validation
    f = tmp_path / "app.py"
    f.write_text(_PY_XSS_KILL, encoding="utf-8")
    finding = _finding("TAINT_XSS", 8,
                       'return render_template_string("Hello {{ name }}", name=name)',
                       ["request.args.get('name', '')", "name"])
    assert apply_ast_validation([finding], str(f)) == []


@pytest.mark.parametrize("src,snippet,line,chain,label", [
    (_PY_XSS_FSTRING_KEEP,
     'return render_template_string(f"Hello {name}")', 8,
     ["request.args.get('name', '')", "name"], "f-string template"),
    (_PY_XSS_SAFE_FILTER_KEEP,
     'return render_template_string("Hello {{ name|safe }}", name=name)', 8,
     ["request.args.get('name', '')", "name"], "|safe filter"),
    (_PY_XSS_TAINTED_TEMPLATE_KEEP,
     'return render_template_string(tpl)', 8,
     ["request.args.get('tpl', '')", "tpl"], "tainted template"),
    (_PY_CMDI_KEEP,
     'return subprocess.check_output(cmd, stderr=subprocess.STDOUT)', 8,
     ["request.args.get('cmd', '')", "cmd"], "unguarded cmdi"),
])
def test_python_constructed_keeps(tmp_path, src, snippet, line, chain, label):
    if not ts.grammar_available("python"):
        pytest.skip("python grammar absent")
    from scanner.ast_validators import apply_ast_validation
    f = tmp_path / "app.py"
    f.write_text(src, encoding="utf-8")
    rule = "TAINT_COMMAND_INJECTION" if "cmdi" in label else "TAINT_XSS"
    out = apply_ast_validation([_finding(rule, line, snippet, chain)], str(f))
    assert len(out) == 1, (label, out)


def test_cpp_non_exit_consequence_keeps(tmp_path):
    """path-3 kills only a comment-only/empty rejection branch: a branch
    that executes something non-exiting is not proof of rejection."""
    if not ts.grammar_available("cpp"):
        pytest.skip("cpp grammar absent")
    from scanner.ast_validators import apply_ast_validation
    src = (
        "#include <cstdio>\n"
        "int main() {\n"
        "    char* file = getenv(\"FILE\");\n"
        "    if (std::string(file).find(\"..\") != std::string::npos) {\n"
        "        fprintf(stderr, \"rejecting\\n\");\n"
        "    } else {\n"
        "        char path[260];\n"
        "        snprintf(path, sizeof(path), \"/var/www/uploads/%s\", file);\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    f = tmp_path / "x.cpp"
    f.write_text(src, encoding="utf-8")
    finding = _finding("CPP_PATH_SNPRINTF_INTERP", 8,
                       'snprintf(path, sizeof(path), "/var/www/uploads/%s", file);')
    out = apply_ast_validation([finding], str(f))
    assert len(out) == 1, out


# ---------------------------------------------------------------------------
# Escape hatch + grammar-fact pins
# ---------------------------------------------------------------------------

def test_ast_validation_env_disables_the_pass():
    import os
    from scanner.ast_validators import apply_ast_validation
    finding = _finding("CPP_PATH_SNPRINTF_INTERP", 83,
                       'snprintf(path, sizeof(path), "/var/www/uploads/%s", file);')
    os.environ["RSX_AST_VALIDATION"] = "0"
    try:
        out = apply_ast_validation([finding],
                                   str(CORPUS / "sast/cpp" / "safe.cpp"))
        assert out == [finding]
    finally:
        del os.environ["RSX_AST_VALIDATION"]


@pytest.mark.skipif(not ts.grammar_available("rust"),
                    reason="rust grammar absent")
def test_rust_grammar_facts():
    tree = ts.parse("rust", 'fn f() {\n    if x.contains("a") {\n'
                            '        return;\n    }\n}\n')
    assert tree is not None
    ifs = [n for n in ts.walk(tree.root_node) if n.type == "if_expression"]
    assert ifs, "rust spells its if node if_expression"
    assert ifs[0].child_by_field_name("condition") is not None
    assert ifs[0].child_by_field_name("consequence") is not None
    assert ts.if_node_types("rust") == frozenset({"if_expression"})
    funcs = [n for n in ts.walk(tree.root_node)
             if n.type == "function_item"]
    assert funcs, "rust functions are function_item nodes"


@pytest.mark.skipif(not ts.grammar_available("python"),
                    reason="python grammar absent")
def test_python_grammar_facts():
    tree = ts.parse("python", "def f():\n    if x:\n        return 1\n"
                              "    # note\n")
    assert tree is not None
    ifs = [n for n in ts.walk(tree.root_node) if n.type == "if_statement"]
    assert ifs and ifs[0].child_by_field_name("condition") is not None
    assert ifs[0].child_by_field_name("consequence") is not None
    comments = {n.type for n in ts.walk(tree.root_node)
                if "comment" in n.type}
    assert "comment" in comments
    assert "function_definition" in ts.FUNCTION_TYPES["python"]


@pytest.mark.skipif(not ts.grammar_available("cpp"),
                    reason="cpp grammar absent")
def test_cpp_grammar_facts():
    tree = ts.parse("cpp", "int main() {\n    if (a) {\n"
                           "        // reject\n    } else {\n"
                           "        use();\n    }\n}\n")
    assert tree is not None
    ifs = [n for n in ts.walk(tree.root_node) if n.type == "if_statement"]
    assert ifs, "cpp spells its if node if_statement"
    node = ifs[0]
    cond = node.child_by_field_name("condition")
    cons = node.child_by_field_name("consequence")
    alt = node.child_by_field_name("alternative")
    assert cond is not None and cond.type == "condition_clause"
    assert cons is not None and cons.type == "compound_statement"
    assert alt is not None and alt.type == "else_clause"
    comments = {n.type for n in ts.walk(tree.root_node)
                if "comment" in n.type}
    assert "comment" in comments
    assert "function_definition" in ts.FUNCTION_TYPES["cpp"]


def test_new_rules_are_registered_only_with_their_grammar():
    from scanner.ast_validators import VALIDATED_RULE_IDS
    # The closed set may only grow by evidence-listed ids.
    assert VALIDATED_RULE_IDS >= {
        "JAVA_PATH_TRAVERSAL_FILE",
        "JAVA_TAINT_COMMAND_INJECTION",
        "JAVA_TAINT_PATH_TRAVERSAL",
        "PHP_PATH_USER_INPUT_VAR",
        "TAINT_COMMAND_INJECTION",
        "TAINT_XSS",
        "RUST_COMMAND_EXEC",
        "RUST_PATH_FORMAT",
        "CPP_HARDCODED_CREDENTIAL",
        "CPP_PATH_SNPRINTF_INTERP",
    }, sorted(VALIDATED_RULE_IDS)
