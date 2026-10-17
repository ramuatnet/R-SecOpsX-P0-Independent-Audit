"""F2 (Benchmark precision batch): property-driven weak-hash resolution.

All 40 remaining BenchmarkJava hash misses read their algorithm from a
co-located .properties resource:

    benchmarkprops.load(...getResourceAsStream("benchmark.properties"));
    String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
    MessageDigest.getInstance(algorithm);

benchmark.properties carries hashAlg1=MD5 (the vulnerable tests) while
hashAlg2=SHA-256 covers the negative tests.  The J2 layer resolves a
simple `String x = "MD5"` assignment but never looked through the
properties resource, so `getInstance(algorithm)` stayed dark for every
property-driven test.

This fix resolves -- never guesses: the resource file is looked up near
the scanning file (src/main/resources and siblings), the key is read
from the file, and the code default is used only when the file or key is
absent (the runtime fallback).  Unresolvable stays unreported.

Red-first protocol: test_tpd_props_md5_fires is RED before the resolver;
both controls PASS in both phases.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.taint_engine import _scan_java_security_api_semantics  # noqa: E402

RULE = "JAVA_J2_WEAK_HASH"

JAVA = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        java.util.Properties props = new java.util.Properties();
        props.load(
                this.getClass().getClassLoader().getResourceAsStream("%(res)s"));
        String algorithm = props.getProperty("%(key)s", "%(default)s");
        java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
        md.update(request.getParameter("x").getBytes());
    }
}
"""


def j2_hits(java_source: str, rule: str = RULE) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f2_hash_") as tmp:
        p = pathlib.Path(tmp, "T.java")
        p.write_text(java_source, encoding="utf-8")
        return [f for f in _scan_java_security_api_semantics(str(p),
                                                             java_source)
                if f.get("rule_id") == rule]


def _fixture_dir(res_name: str, key: str, default: str,
                 res_content: str | None):
    tmp = tempfile.TemporaryDirectory(prefix="rsx_f2_hash_")
    p = pathlib.Path(tmp.name)
    src = JAVA % {"res": res_name, "key": key, "default": default}
    (p / "T.java").write_text(src, encoding="utf-8")
    if res_content is not None:
        (p / res_name).write_text(res_content, encoding="utf-8")
    return tmp, p, src


def test_tpd_props_md5_fires():
    """hashAlg1=MD5 in the resource -> weak-hash finding at getInstance."""
    tmp, p, src = _fixture_dir("test-hash.properties", "hashAlg1",
                               "SHA512", "hashAlg1=MD5\nhashAlg2=SHA-256\n")
    try:
        hits = [f for f in _scan_java_security_api_semantics(str(p / "T.java"),
                                                             src)
                if f.get("rule_id") == RULE]
        assert len(hits) == 1
        assert hits[0].get("cwe", "").lower() == "cwe-328"
    finally:
        tmp.cleanup()


def test_control_props_strong_value_stays_dark():
    """hashAlg2=SHA-256 (the negative tests' key) must not report."""
    tmp, p, src = _fixture_dir("test-hash.properties", "hashAlg2",
                               "SHA512", "hashAlg1=MD5\nhashAlg2=SHA-256\n")
    try:
        hits = [f for f in _scan_java_security_api_semantics(str(p / "T.java"),
                                                             src)
                if f.get("rule_id") == RULE]
        assert hits == []
    finally:
        tmp.cleanup()


def test_control_no_file_uses_strong_default():
    """No resource on disk -> the code default (SHA512) is the value."""
    tmp, p, src = _fixture_dir("missing-props.properties", "hashAlg1",
                               "SHA512", None)
    try:
        hits = [f for f in _scan_java_security_api_semantics(str(p / "T.java"),
                                                             src)
                if f.get("rule_id") == RULE]
        assert hits == []
    finally:
        tmp.cleanup()


def test_control_literal_weak_hash_still_fires():
    """The pre-existing literal path must survive untouched."""
    src = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        java.security.MessageDigest md =
                java.security.MessageDigest.getInstance("MD5");
        md.update(request.getParameter("x").getBytes());
    }
}
"""
    assert len(j2_hits(src)) == 1
