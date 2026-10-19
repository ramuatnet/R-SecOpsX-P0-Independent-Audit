"""H1 -- python SQL statements built by string interpolation at the build
site (Bandit B608 contract), scoped so the taint layer keeps sole ownership
of the attacker-tainted case.

Measured detection failures (original prodtest reports carry no SQLi row
for either):
  * dvpwa  sqli/dao/student.py:43-44
      q = ("INSERT INTO students (name) "
           "VALUES ('%(name)s')" % {'name': name})   # then execute(q)
  * VAmPI  models/user_model.py:72
      user_query = f"SELECT * FROM users WHERE username = '{username}'"
      query = db.session.execute(text(user_query))

In both shapes the interpolated value is an ordinary function parameter
that crosses a module boundary from the route handler, so no
intra-procedural taint row can ever see it.  The rule must stay silent
when the value IS attacker-tainted (corpus vulnerable_app.py:16, e2e
flask_sql/app.py:16): there the taint engine reports at the sink and a
second row would double-count one defect as an extra finding.
"""
from scanner.taint_engine import _python_ast_findings

PY = "PY_SQL_INTERPOLATED_QUERY"


def _ids(source: str) -> list[str]:
    return [r["rule_id"] for r in _python_ast_findings("app.py", source)]


def _rows(source: str) -> list[dict]:
    return [r for r in _python_ast_findings("app.py", source)
            if r["rule_id"] == PY]


# ---------------------------------------------------------------------------
# RED shapes: the two measured misses (+ the concat sibling)
# ---------------------------------------------------------------------------
def test_percent_format_dao_param_fires():
    """dvpwa student.py: implicit-concat SQL string %-formatted by param."""
    rows = _rows('''
async def create(conn, name):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {'name': name})
    await conn.execute(q)
''')
    assert rows, "dvpwa-shaped %-format SQL interpolation must fire"
    assert rows[0]["line"] == 3  # anchors at the q = ... statement start
    assert rows[0]["vuln_type"] == "sql_injection"


def test_fstring_model_param_fires():
    """VAmPI user_model.py: f-string SELECT with an untainted param."""
    rows = _rows('''
def get_user(username):
    user_query = f"SELECT * FROM users WHERE username = '{username}'"
    query = db.session.execute(text(user_query))
    return query.fetchone()
''')
    assert rows, "VAmPI-shaped f-string SQL interpolation must fire"
    assert rows[0]["line"] == 3
    assert "username" in rows[0]["snippet"]


def test_concat_param_fires():
    """The string-concat sibling of the two measured shapes."""
    rows = _rows('''
def get_user(id_):
    q = "SELECT * FROM users WHERE id = " + str(id_)
    return conn.execute(q)
''')
    assert rows, "concatenated SQL statement text must fire"


def test_format_call_param_fires():
    """The .format() sibling."""
    rows = _rows('''
def get_user(username):
    q = "SELECT * FROM users WHERE username = '{}'".format(username)
    return conn.execute(q)
''')
    assert rows, ".format()-interpolated SQL statement text must fire"


# ---------------------------------------------------------------------------
# Controls: cases that must stay dark
# ---------------------------------------------------------------------------
def test_tainted_fstring_left_to_taint_layer():
    """corpus vulnerable_app.py:16 / e2e flask_sql:16 -- taint owns it.

    A second PY row here would be counted as an extra finding (one
    ground-truth label consumes one row), moving corpus precision off
    its baseline.
    """
    source = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/profile")
def profile():
    user = request.args.get("user", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{user}'"
    cursor.execute(query)
'''
    ids = _ids(source)
    assert PY not in ids, "tainted interpolation must stay taint-owned"
    assert "TAINT_SQL_INJECTION" in ids, (
        "the taint row for the same line must remain the only row")


def test_percent_format_json_template_stays_dark():
    """VAmPI user_model.py:74 -- % format without a SQL keyword-pair."""
    assert PY not in _ids('''
def json_debug(ret):
    fin_query = '{"username": "%s", "email": "%s"}' % (ret[1], ret[3])
    return fin_query
''')


def test_fstring_non_sql_message_stays_dark():
    assert PY not in _ids('''
def load_obj(obj):
    return f"Loaded object: {obj}"
''')


def test_constant_interpolation_stays_dark():
    """Interpolating a literal string cannot alter statement structure."""
    assert PY not in _ids('''
TABLE = "users"
def q():
    return f"SELECT * FROM {'users'} WHERE 1=1"
''')


def test_parameterized_statement_stays_dark():
    assert PY not in _ids('''
def get_user(id_):
    return conn.execute("SELECT * FROM users WHERE id = ?", (id_,))
''')


def test_select_without_from_stays_dark():
    """A lone keyword is prose or a fragment, not a statement shape."""
    assert PY not in _ids('''
def summarize(rows):
    return f"selected {len(rows)} rows for report"
''')
