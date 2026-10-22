"""Red-first tests: next-tier CNAP-ahead items (A1), re-derived from the
fresh post-batch-10 CNAP-vs-V11 weakness join (2026-10-22).

Corpus: scan-reports\\DVWA-master (108 CNAP weaknesses; 8 residuals, of
which 6 adjudicated CNAP FPs and 2 genuine V11 gaps fixed here):

A1a vulnerabilities/authbypass/change_user_details.php:48 (CNAP INJ-SQL-001,
    Medium) -- SQL sink fed by a query variable built from the php://input
    JSON body two hops down (``file_get_contents('php://input')`` ->
    ``json_decode`` -> ``$data->field`` concat). The batch-10 SQL rule
    propagated only one hop, so the json_decode hop broke the chain.
A1b vulnerabilities/sqli/source/high.php:11+31 (CNAP INJ-SQL-001, Medium)
    -- SQL sink fed by ``$_SESSION['id']``, which DVWA stores from
    ``$_POST['id']`` in session-input.php:12. Session state is otherwise
    server-set (login rows, flash data), so ``$_SESSION`` is NOT a general
    request source; a corpus pre-pass collects only keys PROVEN
    request-derived somewhere in the corpus.

Controls (adjudicated CNAP FPs / deliberate divergences) must stay dark:
config-interpolated queries (includes/DBMS/MySQL.php), parameterized
statements, unproven session keys, DB-derived session assignment.
"""
import pytest

from scanner import sast
from scanner.sast import scan_file, scan_directory


def _ids(findings):
    return {str(f.get("rule_id")) for f in findings}


def _write(tmp_path, name, code):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    return p


@pytest.fixture(autouse=True)
def _isolate_corpus_session_keys():
    """Each test starts from (and leaves) an empty corpus-proof set."""
    sast._CORPUS_SESSION_SOURCE_KEYS.clear()
    yield
    sast._CORPUS_SESSION_SOURCE_KEYS.clear()


# DVWA vulnerabilities/authbypass/change_user_details.php:25-48 (trimmed).
JSON_BODY_SQL = """<?php
try {
	$json = file_get_contents('php://input');
	$data = json_decode($json);
	if (is_null ($data)) {
		exit;
	}
} catch (Exception $e) {
	exit;
}

$query = "UPDATE users SET first_name = '" . $data->first_name . "', last_name = '" .  $data->surname . "' where user_id = " . $data->id . "";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( 'fail' );
"""

# DVWA vulnerabilities/sqli/source/high.php:3-11 (mysql branch, trimmed).
HIGH_PHP = """<?php
if( isset( $_SESSION [ 'id' ] ) ) {
	$id = $_SESSION[ 'id' ];
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
			$result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( 'err' );
}
"""

# DVWA vulnerabilities/sqli/session-input.php:12 (the session-stored POST).
PROVEN_SESSION = """<?php
$_SESSION[ 'id' ] =  $_POST[ 'id' ];
"""

# Login-style session assignment from a database row: NOT request-derived.
DB_DERIVED_SESSION = """<?php
$_SESSION[ 'id' ] = $row['user_id'];
"""


class TestA1aJsonBodyTwoHop:
    def test_sql_json_body_two_hop_fires(self, tmp_path):
        """change_user_details.php:48: php://input -> json_decode -> concat
        query var -> mysqli_query($query)."""
        findings = scan_file(
            str(_write(tmp_path, "change_user_details.php", JSON_BODY_SQL)))
        assert "PHP_SQL_INTERMEDIATE_QUERY" in _ids(findings), _ids(findings)

    def test_taint_chain_names_json_operand(self, tmp_path):
        """Report-intake survival: the finding must carry a non-empty
        source-to-sink chain naming the sink, or the EVIDEX gate deletes
        it. Either the tainted carrier ($query) or the operand inside its
        assignment ($data) satisfies the contract."""
        rule = next(r for r in sast.COMPILED_ENTERPRISE_RULES
                    if r["id"] == "PHP_SQL_INTERMEDIATE_QUERY")
        m = rule["pattern"].search(JSON_BODY_SQL)
        assert m, "sink pattern must match the fixture"
        chain = sast._php_rule_taint_chain(
            "PHP_SQL_INTERMEDIATE_QUERY", JSON_BODY_SQL, m)
        assert "-> mysqli_query" in chain, chain
        assert "$query" in chain or "$data" in chain, chain


class TestA1bSessionProvenKey:
    def test_corpus_key_collected_from_direct_assignment(self, tmp_path):
        _write(tmp_path, "session-input.php", PROVEN_SESSION)
        keys = sast._collect_corpus_session_keys(tmp_path)
        assert "id" in keys, keys

    def test_corpus_key_collected_through_one_var_hop(self, tmp_path):
        """`$id = $_POST['id']; $_SESSION['id'] = $id;` is request-derived
        too (bounded two-pass closure, same semantics as the file-local
        taint helper)."""
        _write(tmp_path, "setter.php", """<?php
$id = $_POST[ 'id' ];
$_SESSION[ 'id' ] =  $id;
""")
        keys = sast._collect_corpus_session_keys(tmp_path)
        assert "id" in keys, keys

    def test_session_sql_fires_when_key_proven(self, tmp_path):
        _write(tmp_path, "session-input.php", PROVEN_SESSION)
        keys = sast._collect_corpus_session_keys(tmp_path)
        assert "id" in keys, keys
        findings = scan_file(
            str(_write(tmp_path, "sqli/source/high.php", HIGH_PHP)))
        assert "PHP_SQL_INTERMEDIATE_QUERY" in _ids(findings), _ids(findings)

    def test_taint_chain_names_session_operand(self, tmp_path):
        sast._CORPUS_SESSION_SOURCE_KEYS.add("id")
        rule = next(r for r in sast.COMPILED_ENTERPRISE_RULES
                    if r["id"] == "PHP_SQL_INTERMEDIATE_QUERY")
        m = rule["pattern"].search(HIGH_PHP)
        assert m, "sink pattern must match the fixture"
        chain = sast._php_rule_taint_chain(
            "PHP_SQL_INTERMEDIATE_QUERY", HIGH_PHP, m)
        assert "-> mysqli_query" in chain, chain
        assert "$query" in chain or "$id" in chain, chain

    def test_unproven_session_key_stays_dark(self, tmp_path):
        """No assignment of that session key from a request source exists
        anywhere in the corpus -> session state stays server-set."""
        sast._collect_corpus_session_keys(tmp_path)  # empty corpus
        findings = scan_file(str(_write(tmp_path, "high.php", HIGH_PHP)))
        assert "PHP_SQL_INTERMEDIATE_QUERY" not in _ids(findings)

    def test_db_derived_session_key_stays_dark(self, tmp_path):
        _write(tmp_path, "login.php", DB_DERIVED_SESSION)
        keys = sast._collect_corpus_session_keys(tmp_path)
        assert "id" not in keys, keys
        findings = scan_file(str(_write(tmp_path, "high.php", HIGH_PHP)))
        assert "PHP_SQL_INTERMEDIATE_QUERY" not in _ids(findings)

    def test_scan_directory_runs_corpus_prepass(self, tmp_path):
        _write(tmp_path, "session-input.php", PROVEN_SESSION)
        _write(tmp_path, "sqli/source/high.php", HIGH_PHP)
        scan_directory(str(tmp_path), workers=1)
        assert "id" in sast._CORPUS_SESSION_SOURCE_KEYS


class TestAdjudicatedControlsStayDark:
    def test_config_interpolated_query_stays_dark(self, tmp_path):
        """DVWA includes/DBMS/MySQL.php shape: $_DVWA config interpolation
        carries no attacker control (adjudicated divergence from CNAP)."""
        code = """<?php
$drop_db = "DROP DATABASE `{$_DVWA['db_database']}`";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $drop_db );
"""
        findings = scan_file(str(_write(tmp_path, "MySQL.php", code)))
        assert "PHP_SQL_INTERMEDIATE_QUERY" not in _ids(findings)

    def test_parameterized_statement_stays_dark(self, tmp_path):
        code = """<?php
$stmt = $conn->prepare("SELECT first_name FROM users WHERE user_id = ?");
$result = mysqli_query($conn, $stmt );
"""
        findings = scan_file(str(_write(tmp_path, "prepared.php", code)))
        assert "PHP_SQL_INTERMEDIATE_QUERY" not in _ids(findings)
