"""Red-first tests: batch-9 CNAP gaps (DVWA/wrongsecrets/WebGoat joins).

G10 PHP md5/sha1 weak hash (DVWA 20x CNAP CRYPTO-WEAK-003).
G12 generic CORS wildcard origin (DVWA INTEG-ORIGIN-001, gen_openapi.php:6).
G13 Java AES/CBC static-IV cipher (wrongsecrets CRYPTO-WEAK-002, Challenge54/63).
G14 pom.xml ${property} version resolution (WebGoat 4 maven pins).
G11 PHP setcookie flag positions (DVWA DATA-COOKIE-001/002).
"""
import pytest
from scanner.sast import scan_file
from scanner.sbom import generate_sbom


def _sast(tmp_path, name, code, language=None):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    return scan_file(str(p), language=language) if language else scan_file(str(p))


def _ids(findings):
    return {str(f.get("rule_id")) for f in findings}


# ---------------------------------------------------------------------------
# G10 -- PHP weak hash
# ---------------------------------------------------------------------------

class TestPhpWeakHash:
    def test_php_md5_password_hash_fires(self, tmp_path):
        """DVWA mysql.php shape: md5($password) -- CNAP CRYPTO-WEAK-003."""
        findings = _sast(tmp_path, "hash.php", """<?
function login($password) {
    $hash = md5($password);
    return $hash;
}
""")
        assert "MD5_USAGE" in _ids(findings), _ids(findings)

    def test_php_sha1_fires(self, tmp_path):
        findings = _sast(tmp_path, "sha.php", """<?
$digest = sha1($_POST['pw']);
""")
        assert "SHA1_USAGE" in _ids(findings), _ids(findings)

    def test_python_bare_md5_without_hashlib_import_stays_quiet(self, tmp_path):
        """Control: the import gate must not weaken for python (local helper)."""
        findings = _sast(tmp_path, "helper.py", """
        def md5(data):
            return data

        def run(x):
            return md5(x)
        """)
        assert "MD5_USAGE" not in _ids(findings), _ids(findings)

    def test_python_aliased_import_still_fires(self, tmp_path):
        findings = _sast(tmp_path, "go.py", "from hashlib import md5\nx = md5(b'a')\n")
        assert "MD5_USAGE" in _ids(findings), _ids(findings)


# ---------------------------------------------------------------------------
# G12 -- CORS wildcard (generic, cross-language)
# ---------------------------------------------------------------------------

class TestCorsWildcard:
    def test_php_header_wildcard_fires(self, tmp_path):
        """DVWA vulnerabilities/api/gen_openapi.php:6."""
        findings = _sast(tmp_path, "api.php", """<?
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json");
""")
        assert any("CORS" in i for i in _ids(findings)), _ids(findings)

    def test_node_setheader_wildcard_fires(self, tmp_path):
        findings = _sast(tmp_path, "app.js", """
        res.setHeader('Access-Control-Allow-Origin', '*');
        """)
        assert any("CORS" in i for i in _ids(findings)), _ids(findings)

    def test_python_add_header_wildcard_fires(self, tmp_path):
        """Flask/Django response.add_header shape -- call-anchored match."""
        findings = _sast(tmp_path, "routes.py", """
        response.add_header("Access-Control-Allow-Origin", "*")
""")
        assert any("CORS" in i for i in _ids(findings)), _ids(findings)

    def test_reflected_origin_echo_is_quiet_here(self, tmp_path):
        """Control: Origin-reflection is a different (worse) defect handled by
        other families; the wildcard rule must not claim it."""
        findings = _sast(tmp_path, "app.js", """
        res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
        """)
        assert not any("CORS" in i for i in _ids(findings)), _ids(findings)


# ---------------------------------------------------------------------------
# G13 -- Java AES/CBC static IV
# ---------------------------------------------------------------------------

class TestAesCbcStaticIv:
    def test_challenge54_shape_fires(self, tmp_path):
        """wrongsecrets Challenge54.java:42 -- IV literal assigned one line up."""
        findings = _sast(tmp_path, "Challenge54.java", """
    byte[] ivBytes = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
""")
        assert any("CBC" in i or "STATIC_IV" in i for i in _ids(findings)), _ids(findings)

    def test_challenge63_constant_iv_fires(self, tmp_path):
        """Challenge63.java -- the real file: IV constant in the class-constant
        block, IvParameterSpec two lines above the sink (~580 chars below)."""
        findings = _sast(tmp_path, "Challenge63.java", """
  private static final String HARDCODED_KEY = "SuperSecretKey12";
  private static final String HARDCODED_IV = "InitVector123456";

  public String decrypt(String cipherText) {
      byte[] keyBytes = HARDCODED_KEY.getBytes(StandardCharsets.UTF_8);
      byte[] ivBytes = HARDCODED_IV.getBytes(StandardCharsets.UTF_8);
      SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
      IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
  }
""")
        assert any("CBC" in i or "STATIC_IV" in i for i in _ids(findings)), _ids(findings)

    def test_gcm_or_random_iv_stays_quiet(self, tmp_path):
        """Control: AES/GCM with SecureRandom IV is the secure shape."""
        findings = _sast(tmp_path, "Ok.java", """
    SecureRandom rnd = new SecureRandom();
    byte[] iv = new byte[12];
    rnd.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
""")
        assert not any("CBC" in i or "STATIC_IV" in i for i in _ids(findings)), _ids(findings)


# ---------------------------------------------------------------------------
# G14 -- pom.xml property version resolution
# ---------------------------------------------------------------------------

class TestPomPropertyVersions:
    def test_property_referenced_versions_resolve(self, tmp_path):
        """WebGoat pom.xml shape: <xstream.version>1.4.5</xstream.version>
        then <version>${xstream.version}</version>."""
        (tmp_path / "pom.xml").write_text("""<?xml version="1.0"?>
<project>
  <properties>
    <xstream.version>1.4.5</xstream.version>
    <jsoup.version>1.23.1</jsoup.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.thoughtworks.xstream</groupId>
      <artifactId>xstream</artifactId>
      <version>${xstream.version}</version>
    </dependency>
    <dependency>
      <groupId>org.jsoup</groupId>
      <artifactId>jsoup</artifactId>
      <version>${jsoup.version}</version>
    </dependency>
  </dependencies>
</project>
""", encoding="utf-8")
        sbom = generate_sbom(str(tmp_path))
        pkgs = {(str(p.get("name")).lower(), str(p.get("version"))) for p in sbom}
        assert ("com.thoughtworks.xstream:xstream", "1.4.5") in pkgs, sorted(pkgs)
        assert ("org.jsoup:jsoup", "1.23.1") in pkgs, sorted(pkgs)

    def test_versionless_dep_uses_artifactid_version_property(self, tmp_path):
        """WebGoat real shape: <commons-lang3.version>3.14.0</...> exists,
        the dependency omits <version> entirely (managed by the property by
        convention). CNAP resolved 3.14.0; V11 said 'unknown'."""
        (tmp_path / "pom.xml").write_text("""<?xml version="1.0"?>
<project>
  <properties>
    <commons-lang3.version>3.14.0</commons-lang3.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
    </dependency>
  </dependencies>
</project>
""", encoding="utf-8")
        sbom = generate_sbom(str(tmp_path))
        rows = {str(p.get("name")).lower(): str(p.get("version")) for p in sbom}
        assert rows.get("org.apache.commons:commons-lang3") == "3.14.0", rows

    def test_versionless_dep_without_property_stays_unknown(self, tmp_path):
        """Control: no matching '<artifactId>.version' property -> unknown,
        never an invented literal (WebGoat jackson-databind shape)."""
        (tmp_path / "pom.xml").write_text("""<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>
""", encoding="utf-8")
        sbom = generate_sbom(str(tmp_path))
        rows = {str(p.get("name")).lower(): str(p.get("version")) for p in sbom}
        assert rows.get("com.fasterxml.jackson.core:jackson-databind") in (
            "unknown", "None"), rows

    def test_unresolvable_property_not_invented(self, tmp_path):
        """Control: a property that is never defined must not become a literal."""
        (tmp_path / "pom.xml").write_text("""<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>mystery</artifactId>
      <version>${undefined.version}</version>
    </dependency>
  </dependencies>
</project>
""", encoding="utf-8")
        sbom = generate_sbom(str(tmp_path))
        versions = {str(p.get("version")) for p in sbom
                    if "mystery" in str(p.get("name")).lower()}
        assert "undefined.version" not in versions, versions


# ---------------------------------------------------------------------------
# G11 -- PHP setcookie flag positions
# ---------------------------------------------------------------------------

class TestPhpCookieFlags:
    def test_short_setcookie_missing_both_flags(self, tmp_path):
        """DVWA shape: setcookie('sid', $val) -- positional args 6/7 absent."""
        findings = _sast(tmp_path, "login.php", """<?
setcookie("session", $value);
setcookie("session2", $v, time()+3600, "/\\.example.com", "", true, true);
""")
        php_cookie = {i for i in _ids(findings) if "PHP_COOKIE" in i}
        assert any("SECURE" in i for i in php_cookie), _ids(findings)
        assert any("HTTPONLY" in i for i in php_cookie), _ids(findings)

    def test_full_positional_call_is_quiet(self, tmp_path):
        findings = _sast(tmp_path, "ok.php", """<?
setcookie("session", $value, time()+3600, "/", ".example.com", true, true, "Lax");
""")
        assert not any("PHP_COOKIE" in i for i in _ids(findings)), _ids(findings)

    def test_array_options_form_missing_httponly(self, tmp_path):
        """PHP 7.3+ options array: secure present, httponly absent."""
        findings = _sast(tmp_path, "arr.php", """<?
setcookie("session", $value, ["expires" => time()+3600, "secure" => true, "path" => "/"]);
""")
        php_cookie = {i for i in _ids(findings) if "PHP_COOKIE" in i}
        assert any("HTTPONLY" in i for i in php_cookie), _ids(findings)
        assert not any("SECURE" in i for i in php_cookie), _ids(findings)
