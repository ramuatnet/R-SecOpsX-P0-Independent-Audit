"""F7 (corpus batch): Rust SQL execution-sink detection (vulnerable.rs L14).

The golden corpus labels SAST-SQLI at vulnerable.rs line 14,
``conn.prepare(&sql)`` -- the EXECUTION of the query string built one line
earlier by ``format!("SELECT * FROM users WHERE name = '{}'", user)``
(``user`` comes from the actix-web query map).  The shipped RUST_SQL_FORMAT
rule anchors at the BUILD line (13), and the corpus scorer's location
identity is line-exact (tolerance 0 by design), so a build-site finding
cannot satisfy a sink-site expectation: 114/115, the lone recorded miss.

This fix adds the sink-side rule RUST_SQL_SINK: a rusqlite execution call
(``prepare``/``execute``/``query``) whose SQL argument is a BORROWED
VARIABLE, fired only when this file provably BUILDS that variable with a
``format!`` call whose template carries a SQL keyword
(SELECT/INSERT/UPDATE/DELETE).  The gate is one-hop and file-local; it
keeps every non-building borrower dark:

  * the safe.rs parameterised form ``conn.prepare("... WHERE name = ?1")``
    passes a literal, not a borrowed variable -- the pattern never matches;
  * ``conn.prepare(&q)`` where ``q`` was never built from a SQL ``format!``
    (``self.query``, a params!()-validated handle, ...) fails the gate;
  * ``format!`` without a SQL keyword (HTML templates, path builders) fails
    the gate, so the sibling RUST_PATH_FORMAT shape stays dark here too.

The rule complements rather than replaces RUST_SQL_FORMAT: both findings
name the same defect, at its build site and at its execution site, which
is how the Java layers already report (build + sink rows coexist).

Red-first protocol: the two sink tests and the corpus L14 assertion must
FAIL before the fix (the measured miss); the literal-argument control and
the no-SQL-build control must PASS in both phases, and safe.rs must carry
no CWE-89 row in either phase.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.sast import scan_directory  # noqa: E402

CORPUS_RUST = ROOT / "tests" / "vuln-test-corpus" / "sast" / "rust"

RUST_PRELUDE = """use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use rusqlite::{Connection, params};
use std::collections::HashMap;

"""


def scan_text(java_source: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f7_") as tmp:
        p = pathlib.Path(tmp) / "fixture.rs"
        p.write_text(java_source, encoding="utf-8")
        return scan_directory(tmp, workers=1)


def cwe89(findings: list) -> list:
    return [f for f in findings
            if str(f.get("cwe") or "").upper() == "CWE-89"]


def line_of(src: str, needle: str) -> int:
    return next(i for i, l in enumerate(src.splitlines(), 1)
                if needle in l)


# --- TP shapes (RED before the sink rule) ----------------------------------

def test_tpd_prepare_sink_with_format_built_sql_fires():
    """vulnerable.rs shape: format!-built `sql` executed via prepare(&sql)."""
    src = RUST_PRELUDE + """
#[get("/profile")]
async fn profile(info: web::Query<HashMap<String, String>>) -> impl Responder {
    let user = info.get("user").unwrap_or(&"".to_string());
    let conn = Connection::open("test.db").unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", user);
    let mut stmt = conn.prepare(&sql).unwrap();
    let mut out = String::new();
    HttpResponse::Ok().body(out)
}
"""
    rows = [f for f in cwe89(scan_text(src))
            if str(f.get("file") or "").endswith("fixture.rs")]
    sink_line = line_of(src, "conn.prepare(&sql)")
    assert any(int(f.get("line") or 0) == sink_line for f in rows), \
        "prepare(&sql) sink with format!-built sql stayed dark"


def test_tpd_execute_sink_family_fires():
    """Same API family, the execute(&q) verb with a built query string."""
    src = RUST_PRELUDE + """
#[get("/add")]
async fn add(info: web::Query<HashMap<String, String>>) -> impl Responder {
    let name = info.get("name").unwrap_or(&"".to_string());
    let conn = Connection::open("test.db").unwrap();
    let q = format!("INSERT INTO users (name) VALUES ('{}')", name);
    let n = conn.execute(&q, []);
    HttpResponse::Ok().body("ok")
}
"""
    rows = cwe89(scan_text(src))
    sink_line = line_of(src, "conn.execute(&q")
    assert any(int(f.get("line") or 0) == sink_line for f in rows), \
        "execute(&q) sink with format!-built q stayed dark"


# --- Controls (must PASS in both phases) -----------------------------------

def test_tn_literal_prepare_stays_dark():
    """safe.rs parameterised form: literal SQL, no borrowed variable."""
    src = RUST_PRELUDE + """
#[get("/profile")]
async fn profile(info: web::Query<HashMap<String, String>>) -> impl Responder {
    let user = info.get("user").unwrap_or(&"".to_string());
    let conn = Connection::open("test.db").unwrap();
    let mut stmt = conn.prepare("SELECT * FROM users WHERE name = ?1").unwrap();
    let rows = stmt.query_map(params![user], |row| row.get::<_, String>(0)).unwrap();
    HttpResponse::Ok().body("ok")
}
"""
    assert not cwe89(scan_text(src)), "literal prepare must stay dark"


def test_tn_borrowed_sql_without_build_stays_dark():
    """A borrowed query handle with no SQL format! build in the file."""
    src = RUST_PRELUDE + """
#[get("/profile")]
async fn profile() -> impl Responder {
    let conn = Connection::open("test.db").unwrap();
    let mut stmt = conn.prepare(&self.query).unwrap();
    HttpResponse::Ok().body("ok")
}
"""
    assert not cwe89(scan_text(src)), \
        "borrowed ident without SQL build must stay dark"


def test_tn_format_without_sql_keyword_stays_dark():
    """format! builds a template with no SQL keyword: not a query string."""
    src = RUST_PRELUDE + """
#[get("/page")]
async fn page(info: web::Query<HashMap<String, String>>) -> impl Responder {
    let name = info.get("name").unwrap_or(&"".to_string());
    let conn = Connection::open("test.db").unwrap();
    let tpl = format!("<div>{}</div>", name);
    let mut stmt = conn.prepare(&tpl).unwrap();
    HttpResponse::Ok().body("ok")
}
"""
    assert not cwe89(scan_text(src)), \
        "format! without SQL keyword must stay dark"


# --- Corpus end-to-end (the measured F7 gap) -------------------------------

def test_corpus_vulnerable_rs_l14_sqli_detected():
    """The golden corpus's lone miss: vulnerable.rs line 14, CWE-89."""
    rows = [f for f in cwe89(scan_directory(str(CORPUS_RUST), workers=1))
            if str(f.get("file") or "").endswith("vulnerable.rs")]
    assert any(int(f.get("line") or 0) == 14 for f in rows), \
        "corpus vulnerable.rs L14 CWE-89 (conn.prepare(&sql)) missed"


def test_corpus_safe_rs_has_no_cwe89():
    """safe.rs parameterised query must carry no CWE-89 row at all."""
    rows = [f for f in cwe89(scan_directory(str(CORPUS_RUST), workers=1))
            if str(f.get("file") or "").endswith("safe.rs")]
    assert not rows, f"safe.rs must stay dark on CWE-89, got {rows}"
