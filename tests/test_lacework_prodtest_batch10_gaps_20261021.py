"""Red-first tests: batch-10 remaining batch-9 gaps (G9, G15-G20).

Every positive fixture mirrors a real prodtest shape validated against the
CNAP reports (DVWA-master / WebGoat-main / railsgoat-main); every control
mirrors a real non-vulnerable or CNAP-FP shape adjudicated at source.
G9  java/php SQL sink fed by an intermediate query variable.
G15 rails secret_key_base + the main.py seeds.rb evidence-gate carve-out.
G16 php XSS via request-derived echo (jsonp callback, interpolated echo).
G17 php file-read via request-derived variable (view_source shape).
G18 php predictable session identifier (weak_id low/medium/high shapes).
G19 php open redirect via header("location: " . $_GET).
G20 php command injection via intermediate variable (str_replace/2-hop).
"""
import pytest
from scanner.sast import scan_file


def _sast(tmp_path, name, code, language=None):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    return scan_file(str(p), language=language) if language else scan_file(str(p))


def _ids(findings):
    return {str(f.get("rule_id")) for f in findings}


# ---------------------------------------------------------------------------
# G9a/b -- Java JDBC SQL via intermediate variable / multiline prepareStatement
# ---------------------------------------------------------------------------

class TestJavaSqlIntermediate:
    def test_intermediate_query_fires(self, tmp_path):
        """WebGoat SqlInjectionLesson10.java:49+56 -- query built 7 lines
        above the sink, param arrives via @RequestParam."""
        findings = _sast(tmp_path, "Lesson10.java", """
  @GetMapping
  public AttackResult run(@RequestParam String action) {
    String query = "SELECT * FROM access_log WHERE action LIKE '%" + action + "%'";
    try (Connection connection = dataSource.getConnection()) {
      Statement statement = connection.createStatement();
      ResultSet results = statement.executeQuery(query);
    }
    return null;
  }
""")
        assert "JAVA_JDBC_SQL_INTERMEDIATE_QUERY" in _ids(findings), _ids(findings)

    def test_prepared_concat_multiline_fires(self, tmp_path):
        """WebGoat Assignment5.java:43-49 -- concat spans lines inside
        prepareStatement, operands are @RequestParam vars."""
        findings = _sast(tmp_path, "Assignment5.java", """
  public AttackResult run(@RequestParam String username_login,
      @RequestParam String password_login) throws Exception {
    try (var connection = dataSource.getConnection()) {
      PreparedStatement statement =
          connection.prepareStatement(
              "select password from challenge_users where userid = '"
                  + username_login
                  + "' and password = '"
                  + password_login
                  + "'");
      ResultSet resultSet = statement.executeQuery();
    }
    return null;
  }
""")
        assert "JAVA_JDBC_SQL_PREPARED_CONCAT" in _ids(findings), _ids(findings)

    def test_literal_query_var_stays_quiet(self, tmp_path):
        """Control: query variable holding a pure literal is not injectable
        (the pre-existing JAVA_JDBC_SQL_CONCAT 'bare createStatement()' posture
        signal may still fire; the new injection rule must not)."""
        findings = _sast(tmp_path, "Ok.java", """
  public List row() throws Exception {
    String query = "SELECT * FROM access_log";
    Statement statement = connection.createStatement();
    ResultSet results = statement.executeQuery(query);
    return null;
  }
""")
        ids = _ids(findings)
        assert "JAVA_JDBC_SQL_INTERMEDIATE_QUERY" not in ids, ids
        assert "JAVA_JDBC_SQL_PREPARED_CONCAT" not in ids, ids

    def test_prepare_placeholders_stays_quiet(self, tmp_path):
        """Control: parameterised '?' placeholders are the secure shape."""
        findings = _sast(tmp_path, "Prep.java", """
  public void run(@RequestParam String id) throws Exception {
    PreparedStatement ps = connection.prepareStatement("SELECT * FROM t WHERE id = ?");
    ps.setString(1, id);
  }
""")
        ids = _ids(findings)
        assert "JAVA_JDBC_SQL_INTERMEDIATE_QUERY" not in ids, ids
        assert "JAVA_JDBC_SQL_PREPARED_CONCAT" not in ids, ids

    def test_non_jdbc_execute_stays_quiet(self, tmp_path):
        """Control: executor.execute(task) is not a SQL sink (no JDBC
        context anywhere in the file)."""
        findings = _sast(tmp_path, "Pool.java", """
  public void submit(Runnable task) {
    executor.execute(task);
  }
""")
        ids = _ids(findings)
        assert "JAVA_JDBC_SQL_INTERMEDIATE_QUERY" not in ids, ids
        assert "JAVA_JDBC_SQL_PREPARED_CONCAT" not in ids, ids

    def test_reassigned_query_var_fires(self, tmp_path):
        """WebGoat SqlInjectionLesson5a.java:45-52 -- `String query = ""` is
        re-assigned the concatenated SQL before executeQuery(query); the
        validator must judge the LAST assignment, not the empty
        initializer."""
        findings = _sast(tmp_path, "Lesson5a.java", """
  public AttackResult completed(@RequestParam String accountName) {
    return injectableQuery(accountName);
  }

  protected AttackResult injectableQuery(String accountName) {
    String query = "";
    try (Connection connection = dataSource.getConnection()) {
      query =
          "SELECT * FROM user_data WHERE first_name = 'John' and last_name = '" + accountName + "'";
      try (Statement statement =
          connection.createStatement(
              ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
        ResultSet results = statement.executeQuery(query);
      }
    }
    return null;
  }
""")
        assert "JAVA_JDBC_SQL_INTERMEDIATE_QUERY" in _ids(findings), _ids(findings)

    def test_bare_prepare_statement_var_fires(self, tmp_path):
        """WebGoat SqlInjectionLesson5b.java:45-49 -- the query lives in a
        variable passed as prepareStatement's first argument."""
        findings = _sast(tmp_path, "Lesson5b.java", """
  public AttackResult completed(@RequestParam String userid, @RequestParam String login_count) {
    return injectableQuery(login_count, userid);
  }

  protected AttackResult injectableQuery(String login_count, String accountName) {
    String queryString = "SELECT * From user_data WHERE Login_Count = ? and userid= " + accountName;
    try (Connection connection = dataSource.getConnection()) {
      PreparedStatement query =
          connection.prepareStatement(
              queryString, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    }
    return null;
  }
""")
        assert "JAVA_JDBC_SQL_INTERMEDIATE_QUERY" in _ids(findings), _ids(findings)

    def test_reassigned_to_literal_stays_quiet(self, tmp_path):
        """Control: a query variable whose LAST assignment is a literal is
        safe at the sink regardless of earlier concatenations."""
        findings = _sast(tmp_path, "Reassign.java", """
  public void run(@RequestParam String id) throws Exception {
    String query = "SELECT * FROM t WHERE id = '" + id + "'";
    query = "SELECT * FROM t WHERE id = 1";
    Statement statement = connection.createStatement();
    ResultSet results = statement.executeQuery(query);
  }
""")
        assert "JAVA_JDBC_SQL_INTERMEDIATE_QUERY" not in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G9c -- PHP SQL via intermediate variable
# ---------------------------------------------------------------------------

class TestPhpSqlIntermediate:
    def test_php_interpolated_query_var_fires(self, tmp_path):
        """DVWA sqli/source/high.php shape: $id from GET, query string built
        with interpolation, sink receives the bare variable."""
        findings = _sast(tmp_path, "high.php", """<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE user_id = '$id'";
$result = mysql_query($query) or die(mysql_error());
""")
        assert "PHP_SQL_INTERMEDIATE_QUERY" in _ids(findings), _ids(findings)

    def test_php_config_interpolated_query_stays_quiet(self, tmp_path):
        """Divergence from CNAP (adjudicated): DVWA includes/DBMS/MySQL.php
        interpolates the CONFIG array $_DVWA, not request input -- no
        attacker control, so V11 stays quiet by design."""
        findings = _sast(tmp_path, "MySQL.php", """<?php
$drop_db = "DROP DATABASE `{$_DVWA['db_database']}`";
mysqli_query($GLOBALS["___DVWA"], $drop_db);
""")
        assert "PHP_SQL_INTERMEDIATE_QUERY" not in _ids(findings), _ids(findings)

    def test_php_literal_query_var_stays_quiet(self, tmp_path):
        findings = _sast(tmp_path, "ok.php", """<?php
$query = "SELECT * FROM users";
$result = mysqli_query($connection, $query);
""")
        assert "PHP_SQL_INTERMEDIATE_QUERY" not in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G16 -- PHP XSS via request-derived echo
# ---------------------------------------------------------------------------

class TestPhpXssTaintedEcho:
    def test_jsonp_callback_fires(self, tmp_path):
        """DVWA csp/source/jsonp.php:5+12 -- callback from GET concatenated
        into an echoed response (JSONP callback injection)."""
        findings = _sast(tmp_path, "jsonp.php", """<?php
header("Content-Type: application/json; charset=UTF-8");
if (array_key_exists ("callback", $_GET)) {
	$callback = $_GET['callback'];
}
$outp = array ("answer" => "15");
echo $callback . "(".json_encode($outp).")";
""")
        assert "PHP_XSS_TAINTED_ECHO" in _ids(findings), _ids(findings)

    def test_direct_interpolated_echo_fires(self, tmp_path):
        findings = _sast(tmp_path, "xss.php", """<?php
echo "<div class=\\"name\\">$_GET[name]</div>";
""")
        assert "PHP_XSS_TAINTED_ECHO" in _ids(findings), _ids(findings)

    def test_print_of_processed_body_output_quiet(self, tmp_path):
        """DVWA check_token_high.php:14+24 adjudication: $ret derives from
        check_token(php://input) processing -- one hop, not request echo."""
        findings = _sast(tmp_path, "check_token_high.php", """<?php
$token = $jsonData = file_get_contents('php://input');
$ret = check_token ($token);
print $ret;
exit;
""")
        assert "PHP_XSS_TAINTED_ECHO" not in _ids(findings), _ids(findings)

    def test_echo_htmlspecialchars_quiet(self, tmp_path):
        findings = _sast(tmp_path, "safe.php", """<?php
echo htmlspecialchars($_GET['name'], ENT_QUOTES);
""")
        assert "PHP_XSS_TAINTED_ECHO" not in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G17 -- PHP file read via request-derived variable
# ---------------------------------------------------------------------------

class TestPhpPathUserInputVar:
    def test_view_source_shape_fires(self, tmp_path):
        """DVWA vulnerabilities/view_source.php:12+63 -- $id/$security from
        GET interpolated into a file_get_contents path."""
        findings = _sast(tmp_path, "view_source.php", """<?php
if (array_key_exists ("id", $_GET) && array_key_exists ("security", $_GET)) {
	$id       = $_GET[ 'id' ];
	$security = $_GET[ 'security' ];
	$source = @file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php" );
}
""")
        assert "PHP_PATH_USER_INPUT_VAR" in _ids(findings), _ids(findings)

    def test_view_source_all_shape_fires(self, tmp_path):
        """DVWA vulnerabilities/view_source_all.php:12+14."""
        findings = _sast(tmp_path, "view_source_all.php", """<?php
if (array_key_exists("id", $_GET)) {
	$id = $_GET['id'];
	$lowsrc = @file_get_contents("./{$id}/source/low.php");
}
""")
        assert "PHP_PATH_USER_INPUT_VAR" in _ids(findings), _ids(findings)

    def test_whitelisted_lookup_stays_quiet(self, tmp_path):
        """DVWA instructions.php:20-26 adjudication (CNAP FP): $selectedDocId
        is whitelisted against a fixed $docs map before use, so $readFile can
        only ever be one of four literal paths. One-hop taint must not
        propagate through the map lookup."""
        findings = _sast(tmp_path, "instructions.php", """<?php
$docs = array(
	'readme' => array( 'file' => 'README.md' ),
	'PDF'    => array( 'file' => 'docs/pdf.html' ),
);
$selectedDocId = isset( $_GET[ 'doc' ] ) ? $_GET[ 'doc' ] : '';
if( !array_key_exists( $selectedDocId, $docs ) ) {
	$selectedDocId = 'readme';
}
$readFile = $docs[ $selectedDocId ][ 'file' ];
$instructions = file_get_contents( DVWA_WEB_PAGE_TO_ROOT.$readFile );
""")
        assert "PHP_PATH_USER_INPUT_VAR" not in _ids(findings), _ids(findings)

    def test_basename_wrap_stays_quiet(self, tmp_path):
        findings = _sast(tmp_path, "dl.php", """<?php
echo file_get_contents("docs/" . basename($_GET['doc']));
""")
        assert "PHP_PATH_USER_INPUT_VAR" not in _ids(findings), _ids(findings)

    def test_php_input_stream_read_stays_quiet(self, tmp_path):
        """DVWA api/src/*Controller.php: file_get_contents('php://input') is
        the standard JSON body read -- the PATH is a fixed stream wrapper,
        not attacker-controlled. Measured: the first implementation flagged
        every api controller endpoint as path traversal."""
        findings = _sast(tmp_path, "ctrl.php", """<?php
$input = (array) json_decode(file_get_contents('php://input'), TRUE);
$payload = (array) json_decode(file_get_contents("php://input"), TRUE);
""")
        assert "PHP_PATH_USER_INPUT_VAR" not in _ids(findings), _ids(findings)

    def test_param_name_include_stays_quiet(self, tmp_path):
        """DVWA csp/source/high.php adjudication: 'include' is a PARAMETER
        NAME inside $_POST['include'], not an include() sink. The match
        started inside the string literal -- php string-position guard."""
        findings = _sast(tmp_path, "high.php", """<?php
if (isset ($_POST['include'])) {
\t$callback = $_POST['include'];
}
if (isset ($_POST['callback'])) {
\t$callback = $_POST['callback'];
}
""")
        assert "PHP_PATH_USER_INPUT_VAR" not in _ids(findings), _ids(findings)

    def test_real_include_of_get_still_fires(self, tmp_path):
        """Control: the classic include($_GET['page']) shape must stay
        detected through the string-position guard."""
        findings = _sast(tmp_path, "page.php", """<?php
include($_GET['page']);
""")
        assert "PHP_PATH_USER_INPUT_VAR" in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G18 -- PHP predictable session identifiers (DVWA weak_id low/medium/high)
# ---------------------------------------------------------------------------

class TestPhpSessionPredictable:
    def test_time_based_session_cookie_fires(self, tmp_path):
        """weak_id/source/medium.php:6-7 -- session cookie = time()."""
        findings = _sast(tmp_path, "medium.php", """<?php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$cookie_value = time();
	setcookie("dvwaSession", $cookie_value);
}
""")
        assert "PHP_SESSION_ID_PREDICTABLE" in _ids(findings), _ids(findings)

    def test_counter_session_cookie_fires(self, tmp_path):
        """weak_id/source/low.php:6-11 -- session cookie = incrementing
        counter from $_SESSION."""
        findings = _sast(tmp_path, "low.php", """<?php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (!isset ($_SESSION['last_session_id'])) {
		$_SESSION['last_session_id'] = 0;
	}
	$_SESSION['last_session_id']++;
	$cookie_value = $_SESSION['last_session_id'];
	setcookie("dvwaSession", $cookie_value);
}
""")
        assert "PHP_SESSION_ID_PREDICTABLE" in _ids(findings), _ids(findings)

    def test_md5_of_counter_session_fires(self, tmp_path):
        """weak_id/source/high.php:9-11 -- hashing a counter is not
        unpredictability."""
        findings = _sast(tmp_path, "high.php", """<?php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$_SESSION['last_session_id_high']++;
	$cookie_value = md5($_SESSION['last_session_id_high']);
	setcookie("dvwaSession", $cookie_value, time()+3600, "/", $_SERVER['HTTP_HOST'], false, false);
}
""")
        assert "PHP_SESSION_ID_PREDICTABLE" in _ids(findings), _ids(findings)

    def test_random_session_cookie_quiet(self, tmp_path):
        findings = _sast(tmp_path, "ok.php", """<?php
setcookie("PHPSESSID", bin2hex(random_bytes(32)));
""")
        assert "PHP_SESSION_ID_PREDICTABLE" not in _ids(findings), _ids(findings)

    def test_session_create_id_quiet(self, tmp_path):
        findings = _sast(tmp_path, "ok2.php", """<?php
session_start();
setcookie("session", session_create_id());
""")
        assert "PHP_SESSION_ID_PREDICTABLE" not in _ids(findings), _ids(findings)

    def test_non_session_cookie_from_get_quiet(self, tmp_path):
        """DVWA sqli_blind/cookie-input.php:12 adjudication: a preference
        cookie named 'lang' from GET is not a session-identifier defect
        (CNAP's AUTH-SESSION-001 over-reached here; V11 stays quiet)."""
        findings = _sast(tmp_path, "pref.php", """<?php
setcookie("lang", $_GET['lang']);
""")
        assert "PHP_SESSION_ID_PREDICTABLE" not in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G19 -- PHP open redirect
# ---------------------------------------------------------------------------

class TestPhpOpenRedirect:
    def test_get_redirect_header_fires(self, tmp_path):
        """DVWA open_redirect/source/low.php:4 -- header concat of $_GET."""
        findings = _sast(tmp_path, "low.php", """<?php
if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
	header ("location: " . $_GET['redirect']);
	exit;
}
""")
        assert "PHP_OPEN_REDIRECT_HEADER" in _ids(findings), _ids(findings)

    def test_static_location_quiet(self, tmp_path):
        findings = _sast(tmp_path, "ok.php", """<?php
header("Location: /dashboard");
""")
        assert "PHP_OPEN_REDIRECT_HEADER" not in _ids(findings), _ids(findings)

    def test_config_url_location_quiet(self, tmp_path):
        findings = _sast(tmp_path, "cfg.php", """<?php
$home = $config['home_url'];
header("Location: " . $home);
""")
        assert "PHP_OPEN_REDIRECT_HEADER" not in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G20 -- PHP command injection via intermediate variable
# ---------------------------------------------------------------------------

class TestPhpCmdIntermediate:
    def test_str_replace_blacklist_fires(self, tmp_path):
        """DVWA exec/source/medium.php:6+19 -- $target from GET passes a
        bypassable str_replace blacklist into shell_exec."""
        findings = _sast(tmp_path, "medium.php", """<?php
$target = $_REQUEST[ 'ip' ];
$substitutions = array( '&&' => '', ';' => '' );
$target = str_replace( array_keys( $substitutions ), $substitutions, $target );
if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
	$cmd = shell_exec( 'ping  ' . $target );
}
""")
        assert "PHP_CMD_INJECTION_INTERMEDIATE" in _ids(findings), _ids(findings)

    def test_json_body_two_hop_fires(self, tmp_path):
        """DVWA api/src/HealthController.php:84-88 -- php://input decoded,
        one hop later concatenated into exec."""
        findings = _sast(tmp_path, "HealthController.php", """<?php
private function checkConnectivity() {
	$input = (array) json_decode(file_get_contents('php://input'), TRUE);
	if (array_key_exists ("target", $input)) {
		$target = $input['target'];
		exec ("ping -c 4 " . $target, $output, $ret_var);
	}
}
""")
        assert "PHP_CMD_INJECTION_INTERMEDIATE" in _ids(findings), _ids(findings)

    def test_validated_octets_stay_quiet(self, tmp_path):
        """DVWA exec/source/impossible.php adjudication (CNAP FP): every
        octet is ctype_digit-checked before reassembly -- the hardened
        variant must stay quiet."""
        findings = _sast(tmp_path, "impossible.php", """<?php
$target = $_REQUEST[ 'ip' ];
$octet = explode('.', $target);
if( count( $octet ) != 4 ) { exit; }
for ($i = 0; $i < 4; $i++) {
	if( !ctype_digit( $octet[$i] ) ) { exit; }
}
$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
$cmd = shell_exec( 'ping  ' . $target );
""")
        assert "PHP_CMD_INJECTION_INTERMEDIATE" not in _ids(findings), _ids(findings)

    def test_escapeshellarg_stays_quiet(self, tmp_path):
        findings = _sast(tmp_path, "safe.php", """<?php
$target = $_GET['target'];
$cmd = shell_exec( 'ping ' . escapeshellarg($target) );
""")
        assert "PHP_CMD_INJECTION_INTERMEDIATE" not in _ids(findings), _ids(findings)

    def test_fixed_command_stays_quiet(self, tmp_path):
        findings = _sast(tmp_path, "fixed.php", """<?php
$cmd = shell_exec('ping -c 4 127.0.0.1');
""")
        assert "PHP_CMD_INJECTION_INTERMEDIATE" not in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G15 -- Ruby secrets: rails secret_key_base rule + main.py evidence gate
# ---------------------------------------------------------------------------

class TestRubySecrets:
    def test_rails_secret_key_base_fires(self, tmp_path):
        """railsgoat config/initializers/secret_token.rb:8 -- committed
        session-signing key."""
        findings = _sast(tmp_path, "secret_token.rb", """# Be sure to restart your server when you modify this file.
Railsgoat::Application.config.secret_key_base = "2f1d90a26236c3245d96f5606c201a780dc9ca687e5ed82b45e211bb5dc84c1870f61ca9e002dad5dd8a149c9792d8f07f31a9575065cca064bd6af44bb1e87c"
""")
        assert "RUBY_RAILS_SECRET_TOKEN" in _ids(findings), _ids(findings)

    def test_env_referenced_secret_quiet(self, tmp_path):
        findings = _sast(tmp_path, "prod.rb", """MyApp::Application.config.secret_key_base = ENV["SECRET_KEY_BASE"]
""")
        assert "RUBY_RAILS_SECRET_TOKEN" not in _ids(findings), _ids(findings)

    def test_short_non_hex_value_quiet(self, tmp_path):
        findings = _sast(tmp_path, "dev.rb", """MyApp::Application.config.secret_key_base = "dev-secret"
""")
        assert "RUBY_RAILS_SECRET_TOKEN" not in _ids(findings), _ids(findings)

    def test_ruby_seed_credentials_survive_evidence_gate(self):
        """main.py _prune_unsupported_occurrences: Rails db/seeds.rb holds
        DEPLOYMENT seed data (production default accounts), not JS test
        fixtures -- the hardcoded_secret fixture/seed suppression must not
        sweep it away (railsgoat had 7 findings silently deleted)."""
        import importlib
        main = importlib.import_module("main")
        payload = {"findings": [{
            "vuln_type": "hardcoded_secret",
            "instances": 1,
            "occurrences": [{
                "file": r"D:\code\railsgoat-main\db\seeds.rb",
                "snippet": 'password: "admin1234",',
                "taint_path": "",
            }],
        }]}
        removed = main._prune_unsupported_occurrences(payload)
        assert removed == 0, payload["findings"][0]["occurrences"]
        assert payload["findings"][0]["occurrences"], "seeds.rb occurrence was pruned"

    def test_js_fixture_data_still_pruned(self):
        """Control: the original suppression intent -- fixture DATA files --
        must keep working."""
        import importlib
        main = importlib.import_module("main")
        payload = {"findings": [{
            "vuln_type": "hardcoded_secret",
            "instances": 1,
            "occurrences": [{
                "file": r"D:\app\__fixtures__\users.json",
                "snippet": '"password": "fixturepass1",',
                "taint_path": "",
            }],
        }]}
        removed = main._prune_unsupported_occurrences(payload)
        assert removed == 1, payload["findings"][0]["occurrences"]


class TestReportPipelineSurvival:
    """The batch-10 rules must survive the report intake that previously
    deleted them: EVIDEX's expected-vs-candidate sink intersection (regex
    findings carried no sink_category, so candidates were empty) and
    main.py's path_traversal occurrence gate (demands '->' taint evidence).
    Measured pre-fix: scan_directory produced 35 batch-10 rows on DVWA and
    clean_report.json contained 16."""

    def _payload_ids(self, tmp_path, name, code):
        import copy
        from scanner.sast import scan_file
        from core.analyzer import build_report_payload
        p = tmp_path / name
        p.write_text(code, encoding="utf-8")
        raw = scan_file(str(p))
        payload = build_report_payload(copy.deepcopy(raw), [], str(p))
        return {str(f.get("rule_id")) for f in payload.get("findings") or []}, raw

    def test_path_xss_redirect_survive_report_intake(self, tmp_path):
        code = """<?php
$id = $_GET['id'];
$source = @file_get_contents( "vulnerabilities/{$id}/source/low.php" );
$callback = $_GET['callback'];
echo $callback . "(" . json_encode(array("ok" => 1)) . ")";
header ("location: " . $_GET['redirect']);
"""
        ids, raw = self._payload_ids(tmp_path, "mixed.php", code)
        for rid in ("PHP_PATH_USER_INPUT_VAR", "PHP_XSS_TAINTED_ECHO",
                    "PHP_OPEN_REDIRECT_HEADER"):
            assert rid in {str(f.get("rule_id")) for f in raw}, rid
            assert rid in ids, (rid, sorted(ids))

    def test_taint_chain_recorded_on_findings(self, tmp_path):
        from scanner.sast import scan_file
        p = tmp_path / "chain.php"
        p.write_text("""<?php
$id = $_GET['id'];
$source = @file_get_contents( "docs/{$id}" );
""", encoding="utf-8")
        rows = [f for f in scan_file(str(p))
                if str(f.get("rule_id")) == "PHP_PATH_USER_INPUT_VAR"]
        assert rows, "rule did not fire"
        assert "->" in str(rows[0].get("taint_path")), rows[0].get("taint_path")
        assert rows[0].get("sink_category") == "file", rows[0].get("sink_category")
