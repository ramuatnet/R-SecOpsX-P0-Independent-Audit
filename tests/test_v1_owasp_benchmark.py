"""V1.4: OWASP BenchmarkJava differential harness.

The real benchmark (2740 labelled tests) is NOT vendored -- it is cloned
on demand and passed via --benchmark-dir. These tests therefore pin the
machinery (CSV parsing, per-test scoring, CWE alignment, off-target
handling, the --min-recall gate) with synthetic labels, plus the one
benchmark-calibrated scanner fix measured against it: an XML parser the
file already hardens against XXE must not be reported as XXE (all 35
parser files in BenchmarkJava carry disallow-doctype-decl, and every XXE
finding the rule produced against that benchmark was against a file
carrying the canonical mitigation).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.validation.owasp_benchmark import (  # noqa: E402
    GroundTruth,
    load_ground_truth,
    main,
    score,
)

TRUTH = {
    "benchmarktest00001": GroundTruth("BenchmarkTest00001", "sqli", True, "89"),
    "benchmarktest00002": GroundTruth("BenchmarkTest00002", "sqli", False, "89"),
    "benchmarktest00003": GroundTruth("BenchmarkTest00003", "xss", True, "79"),
    "benchmarktest00004": GroundTruth("BenchmarkTest00004", "xss", False, "79"),
}


def _finding(rule="R", cwe="CWE-89", file="x/BenchmarkTest00001.java"):
    return {"rule_id": rule, "cwe": cwe, "file": file}


def test_score_counts_detections_alignments_and_false_positives():
    findings = [
        _finding("A", "CWE-89", "t/BenchmarkTest00001.java"),    # aligned TP
        _finding("B", "CWE-79", "t/BenchmarkTest00001.java"),    # TP test, wrong family
        _finding("C", "CWE-79", "t/BenchmarkTest00003.java"),    # aligned TP
        _finding("D", "CWE-79", "t/BenchmarkTest00004.java"),    # negative test -> FP
        _finding("E", "CWE-89", "t/HelperService.java"),         # no test id -> off-target
    ]
    res = score(findings, TRUTH)
    sqli = res["categories"]["sqli"]
    assert sqli["true_total"] == 1 and sqli["detected"] == 1
    assert sqli["detected_cwe_aligned"] == 1
    assert sqli["false_total"] == 1 and sqli["fp_tests"] == 0  # FP is in xss
    xss = res["categories"]["xss"]
    assert xss["detected"] == 1 and xss["detected_cwe_aligned"] == 1
    assert xss["false_total"] == 1 and xss["fp_tests"] == 1 and xss["fp_findings"] == 1
    assert res["off_target_findings"] == 1
    assert res["tests_with_findings"] == 3  # 00001, 00003, 00004


def test_wrong_family_finding_detects_but_does_not_align():
    # A CWE-79 finding inside a CWE-89 test proves something was reported,
    # but must not masquerade as detection of the labelled defect family.
    findings = [_finding("B", "CWE-79", "t/BenchmarkTest00001.java")]
    res = score(findings, TRUTH)
    sqli = res["categories"]["sqli"]
    assert sqli["detected"] == 1
    assert sqli["detected_cwe_aligned"] == 0
    assert res["overall"]["recall"] > res["overall"]["recall_cwe_aligned"]


def test_cwe_comparison_is_case_and_prefix_insensitive():
    # Expected values come from the CSV as bare numbers ("89"); findings
    # carry "CWE-89", "cwe-89" or "89" -- every form must align, and the
    # counting is per test, so two aligned findings in one test = one.
    truth = dict(TRUTH)
    truth["benchmarktest00005"] = GroundTruth("BenchmarkTest00005", "eval", True, "94")
    findings = [
        _finding("A", "CWE-89", "t/BenchmarkTest00001.java"),
        _finding("A", "cwe-94", "t/BenchmarkTest00005.java"),
        _finding("A", "94", "t/BenchmarkTest00005.java"),
    ]
    res = score(findings, truth)
    assert res["overall"]["detected_cwe_aligned"] == 2


def test_load_ground_truth_parses_commented_header(tmp_path):
    (tmp_path / "expectedresults-1.2.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,hash,false,328\n",
        encoding="utf-8")
    truth = load_ground_truth(tmp_path)
    assert truth["BenchmarkTest00001"] == GroundTruth(
        "BenchmarkTest00001", "pathtraver", True, "22")
    assert truth["BenchmarkTest00002"].real_vulnerability is False


def test_missing_benchmark_dir_raises_with_guidance(tmp_path):
    with pytest.raises(FileNotFoundError, match="BenchmarkJava"):
        load_ground_truth(tmp_path)


def test_min_recall_gate_and_json_output(tmp_path, capsys):
    (tmp_path / "expectedresults-1.2.csv").write_text(
        "# header\nBenchmarkTest00001,sqli,true,89\n", encoding="utf-8")
    dump = tmp_path / "findings.json"
    dump.write_text(json.dumps([
        {"rule_id": "X", "cwe": "CWE-89", "file": "t/BenchmarkTest00001.java"}]),
        encoding="utf-8")

    assert main(["--benchmark-dir", str(tmp_path),
                 "--reuse-findings", str(dump)]) == 0
    assert main(["--benchmark-dir", str(tmp_path),
                 "--reuse-findings", str(dump),
                 "--min-recall", "0.9"]) == 0
    # A finding-less dump must trip the gate when one is demanded.
    dump.write_text("[]", encoding="utf-8")
    assert main(["--benchmark-dir", str(tmp_path),
                 "--reuse-findings", str(dump),
                 "--min-recall", "0.5"]) == 1

    out = capsys.readouterr().out
    assert "OVERALL" in out


# ---------------------------------------------------------------------------
# Benchmark-calibrated scanner fix (JAVA_XXE_PARSER vs hardened parsers)
# ---------------------------------------------------------------------------

_HARDENED = '''import javax.xml.parsers.DocumentBuilderFactory;

class HardenedReader {
    void read() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.newDocumentBuilder().parse(stream);
    }
}
'''

_UNHARDENED = '''import javax.xml.parsers.DocumentBuilderFactory;

class CarelessReader {
    void read() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.newDocumentBuilder().parse(stream);
    }
}
'''


def _xxe_findings_in(tmp: Path):
    from scanner.sast import scan_directory
    return [f for f in scan_directory(str(tmp))
            if f.get("rule_id") == "JAVA_XXE_PARSER"]


def test_hardened_xml_parser_is_not_reported_as_xxe(tmp_path):
    # Measured against BenchmarkJava: every parser file there carries
    # disallow-doctype-decl, and the constructor-only rule flagged all
    # 35 of them -- 20 on tests the oracle labels negative.
    (tmp_path / "HardenedReader.java").write_text(_HARDENED, encoding="utf-8")
    (tmp_path / "CarelessReader.java").write_text(_UNHARDENED, encoding="utf-8")
    hits = _xxe_findings_in(tmp_path)
    files = {Path(f["file"]).name for f in hits}
    assert files == {"CarelessReader.java"}, (
        "hardened parser must not be reported; unhardened must be: %s" % files)


def test_xxe_hardening_idioms_all_suppress(tmp_path):
    idioms = {
        "disallow": 'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
        "dtd": 'f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);',
        "secure": 'f.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);',
        "expand": 'f.setExpandEntityReferences(false);',
        "input": 'in.setProperty(javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);',
    }
    for name, line in idioms.items():
        d = tmp_path / name
        d.mkdir()
        (d / "Reader.java").write_text(
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            "class Reader { void r() throws Exception {\n"
            "  DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
            "  %s\n} }\n" % line, encoding="utf-8")
        assert _xxe_findings_in(d) == [], "idiom %r failed to suppress" % name
