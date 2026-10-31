"""T-9.6 D-2 triage SPA -- airgap single-file triage UI (opencodetask D-2).

Gates pinned here (opencodetask.md D-2):

* browser smoke tests -- list render, filters, evidence expand,
  suppression stub download, embedded mode loads offline via file://,
  fetch mode works over HTTP and fails HONESTLY over file://;
* determinism of the generated file (same report -> same bytes);
* size budget CI check (template <= 250 KB);
* no server / no build tools: the asset is one vanilla HTML+JS string.

Contract details pinned alongside:
* embedded JSON cannot break out of its script tag (stored-XSS guard);
* the ``--html-embedded`` CLI writes triage.html byte-identical to a
  rebuild from the written clean_report.json (page == report), and
  flag-off writes nothing;
* triage.html is in BOTH self-scan exclusion sets (set agreement);
* the module has no banned top-level imports (offline).

Browser smoke tests use playwright+chromium when available and skip
with a machine-readable reason otherwise (dev-only optional dep -- the
runtime artifact stays pure stdlib).
"""
from __future__ import annotations

import ast
import functools
import http.server
import json
import pathlib
import re
import subprocess
import sys
import threading

import pytest

from reporting.triage_spa import (
    ASSET_BUDGET_BYTES, SCHEMA, build, build_asset, main, triage_subset,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
MAIN = REPO / "main.py"


def _finding(**over):
    base = {
        "finding_id": "f-000",
        "rule_id": "GENERIC_RULE",
        "title": "generic title",
        "severity": "Medium",
        "cwe": None,
        "owasp": None,
        "accuracy": {"verdict": "NEEDS_REVIEW"},
        "disposition": "NEEDS_REVIEW",
        "file": "pkg/mod.py",
        "line": 1,
        "confidence": "HIGH",
        "vuln_type": "generic",
        "snippet": "x = 1",
        "evidence": ["validated sink"],
        "description": "desc",
    }
    base.update(over)
    return base


@pytest.fixture(scope="module")
def report():
    return {
        "metadata": {
            "tool": "R-SecOpsX SAST v2.1",
            "scan_date": "2026-10-31T00:00:00Z",
            "total_findings": 5,
            "sast_findings": 5,
            "sca_findings": 0,
        },
        "findings": [
            _finding(finding_id="f-001", rule_id="TAINT_SQL_INJECTION",
                     title="SQL injection reaches sink", severity="High",
                     cwe="CWE-89", owasp="A03:2021 - Injection",
                     accuracy={"verdict": "TRUE_POSITIVE"},
                     disposition="CONFIRMED", file="app/db.py", line=42,
                     vuln_type="sql_injection",
                     evidence=["validated sink", "req -> q -> cur"]),
            _finding(finding_id="f-002", rule_id="MD5_USAGE",
                     title="MD5 used for password", severity="Medium",
                     cwe="CWE-327", owasp="A02:2021 - Cryptographic Failures",
                     accuracy={"verdict": "NEEDS_REVIEW"},
                     disposition="CONFIRMED", file="lib/crypto.py", line=7),
            _finding(finding_id="f-003", rule_id="XSS_SINK",
                     title="reflected XSS", severity="Low",
                     cwe="CWE-79", owasp="A03:2021 - Injection",
                     accuracy={"verdict": "LIKELY_FALSE_POSITIVE"},
                     disposition="REJECTED_FALSE_POSITIVE",
                     file="web/view.py", line=12),
            # honest nulls: no accuracy block, no cwe
            _finding(finding_id="f-004", rule_id="DEBUG_ENDPOINT",
                     title="debug endpoint exposed", severity="Medium",
                     cwe=None, owasp="A05:2021 - Security Misconfiguration",
                     accuracy=None, disposition=None, file="cfg.py",
                     line=None, evidence=[], description=None),
            _finding(finding_id="f-005", rule_id="HARDCODED_SECRET",
                     title="hardcoded API key", severity="High",
                     cwe="CWE-798", owasp="A07:2021 - Identification failures",
                     accuracy={"verdict": "NEEDS_REVIEW"},
                     disposition="LIKELY", file="conf/settings.py", line=3),
        ],
    }


# ---------------------------------------------------------------------------
# A. module contracts (no browser)
# ---------------------------------------------------------------------------


def test_embedded_build_is_deterministic(report):
    a = build(report, embedded=True)
    b = build(report, embedded=True)
    assert a == b
    assert a == build(dict(report), embedded=True)   # fresh object, same bytes
    assert SCHEMA.encode() in a


def test_embedded_json_cannot_break_out_of_script_tag():
    evil = {"metadata": {}, "findings": [
        _finding(title='</script><script>alert(1)</script>')]}
    html = build(evil, embedded=True).decode("utf-8")
    assert "</script><script>alert(1)" not in html
    assert "\\u003c/script" in html


def test_subset_shape_nulls_and_coercions(report):
    sub = triage_subset(report)
    assert sub["schema"] == SCHEMA
    assert sub["report"]["tool"] == "R-SecOpsX SAST v2.1"
    # subset rows carry the resolved identity under "id"
    # (finding_id or fingerprint or rule:file:line composite)
    rows = {r["id"]: r for r in sub["findings"]}
    assert len(rows) == 5
    r1 = rows["f-001"]
    assert r1["verdict"] == "TRUE_POSITIVE"
    assert r1["line"] == 42
    r4 = rows["f-004"]
    assert r4["verdict"] is None and r4["cwe"] is None
    assert r4["line"] is None and r4["evidence"] == []
    assert r4["disposition"] is None
    # line coerces from digit strings, stays null otherwise
    coerce = triage_subset({"findings": [
        {"rule_id": "R", "file": "a.py", "line": "17"},
        {"rule_id": "R", "file": "b.py", "line": "NaN"},
    ]})
    assert coerce["findings"][0]["line"] == 17
    assert coerce["findings"][1]["line"] is None
    # minimal report: everything honest, never fabricated
    empty = triage_subset({})
    assert empty["report"]["tool"] is None
    assert empty["findings"] == []


def test_fetch_asset_budget_determinism_and_empty_data_tag():
    a, b = build_asset(), build_asset()
    assert a == b
    assert len(a) <= ASSET_BUDGET_BYTES, (
        f"asset is {len(a)} bytes; D-2 budget is 250 KB")
    text = a.decode("utf-8")
    assert 'fetch("./clean_report.json"' in text
    assert "__DATA__" not in text
    # fetch-mode data tag is EMPTY (no report subset smuggled in)
    assert re.search(
        r'id="rsx-triage-data" type="application/json"></script>', text)
    # no framework / CDN / build-tool references (airgap)
    for token in ("https://", "http://cdn", "<script src=", "require(",
                  "import react"):
        assert token not in text, token


def test_cli_report_mode_writes_byte_identical_html(report, tmp_path,
                                                    capsys):
    src = tmp_path / "clean_report.json"
    src.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out = tmp_path / "triage.html"
    rc = main(["--report", str(src), "--out", str(out)])
    assert rc == 0
    assert out.read_bytes() == build(report, embedded=True)
    assert "triage spa" not in capsys.readouterr().out


def test_cli_asset_mode_writes_fetch_asset(tmp_path):
    out = tmp_path / "asset.html"
    assert main(["--asset", "--out", str(out)]) == 0
    assert out.read_bytes() == build_asset()


def test_cli_errors_are_loud(tmp_path, capsys):
    # usage: exactly one of --report/--asset (rc2 via argparse)
    with pytest.raises(SystemExit) as eu:
        main(["--out", str(tmp_path / "x.html")])
    assert eu.value.code == 2
    with pytest.raises(SystemExit) as eu:
        main(["--asset", "--report", "r.json",
              "--out", str(tmp_path / "x.html")])
    assert eu.value.code == 2
    # unreadable report -> rc1 with a machine-readable line, no partial file
    out = tmp_path / "x.html"
    rc = main(["--report", str(tmp_path / "missing.json"), "--out",
               str(out)])
    assert rc == 1 and not out.exists()
    assert "triage spa error:" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    rc = main(["--report", str(bad), "--out", str(out)])
    assert rc == 1 and not out.exists()
    assert "triage spa error:" in capsys.readouterr().out
    arr = tmp_path / "arr.json"
    arr.write_text("[1,2]", encoding="utf-8")
    rc = main(["--report", str(arr), "--out", str(out)])
    assert rc == 1 and not out.exists()
    assert "not a JSON object" in capsys.readouterr().out


def test_module_has_no_banned_top_level_imports():
    src = (REPO / "reporting" / "triage_spa.py").read_text(
        encoding="utf-8")
    tree = ast.parse(src)
    banned = {"urllib", "socket", "requests", "boto3", "http", "os",
              "subprocess"}
    top = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top.append(node.module)
    assert not (set(top) & banned), top
    for token in ("urllib", "boto3", "requests", "os.environ",
                  "http.client", "socket."):
        assert token not in src, token


def test_triage_html_excluded_from_self_scan_in_both_sets():
    from core.file_index import EXCLUDED_FILES
    from scanner.taint_engine import ARTIFACT_FILE_NAMES
    assert "triage.html" in EXCLUDED_FILES
    assert "triage.html" in ARTIFACT_FILE_NAMES
    assert set(ARTIFACT_FILE_NAMES) == set(EXCLUDED_FILES)


def test_main_write_site_is_discovered_by_the_exclusion_regex():
    # tests/test_v11_self_scan_exclusions.py derives artifacts from
    # `output_dir / "Name.ext"` -- the triage write must stay visible
    src = MAIN.read_text(encoding="utf-8")
    assert re.search(r'output_dir\s*/\s*"triage\.html"', src), (
        "the --html-embedded write site no longer matches the "
        "self-scan discovery regex")


# ---------------------------------------------------------------------------
# B. CLI: --html-embedded writes triage.html; flag-off is invariant
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scan_with_flag(tmp_path_factory):
    proj = tmp_path_factory.mktemp("rsx_t96_proj_on")
    (proj / "vuln.py").write_text(
        "import subprocess\n"
        "def handler(request):\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n",
        encoding="utf-8")
    outdir = tmp_path_factory.mktemp("rsx_t96_out_on")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--html-embedded", "--workers", "1"],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


@pytest.fixture(scope="module")
def scan_without_flag(tmp_path_factory):
    proj = tmp_path_factory.mktemp("rsx_t96_proj_off")
    (proj / "vuln.py").write_text(
        "import subprocess\n"
        "def handler(request):\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n",
        encoding="utf-8")
    outdir = tmp_path_factory.mktemp("rsx_t96_out_off")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--workers", "1"],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


def _assert_ok(proc, label):
    assert proc.returncode == 0, (
        f"{label}: main.py exited {proc.returncode}.\n"
        f"--- stdout tail ---\n{(proc.stdout or '')[-3000:]}\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}")


def test_cli_scan_exits_zero(scan_with_flag):
    _assert_ok(scan_with_flag[0], "--html-embedded scan")


def test_cli_writes_triage_html_matching_the_report(scan_with_flag):
    _proc, outdir = scan_with_flag
    triage = outdir / "triage.html"
    assert triage.exists(), "--html-embedded must write triage.html"
    report = json.loads((outdir / "clean_report.json").read_text(
        encoding="utf-8"))
    # the page and the report can never disagree: rebuilding the SPA
    # from the written clean_report.json is byte-identical
    assert triage.read_bytes() == build(report, embedded=True)
    html = triage.read_text(encoding="utf-8")
    assert 'id="rsx-triage-data"' in html
    assert json.loads  # report itself is valid JSON (sanity)
    assert report.get("findings") is not None


def test_cli_flag_off_writes_no_triage_html(scan_without_flag):
    proc, outdir = scan_without_flag
    _assert_ok(proc, "flag-off scan")
    assert not (outdir / "triage.html").exists(), (
        "without --html-embedded no triage.html may appear")


# ---------------------------------------------------------------------------
# C. browser smoke (playwright; skipped with reason when unavailable)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed (dev-only optional dep)")
    with sync_playwright() as p:
        try:
            b = p.chromium.launch(headless=True)
        except Exception as exc:  # noqa: BLE001 -- browser binary absent
            pytest.skip(f"chromium unavailable: {type(exc).__name__}")
        yield b
        b.close()


def _goto_embedded(browser, tmp_path, report, name="triage.html"):
    out = tmp_path / name
    out.write_bytes(build(report, embedded=True))
    page = browser.new_page()
    page.goto(out.as_uri())
    page.wait_for_function(
        "document.getElementById('counts').textContent.length > 0")
    return page


def _row_count(page):
    return page.locator("#rows tr.row").count()


def _counts_text(page):
    return page.locator("#counts").inner_text()


def test_browser_embedded_file_url_renders_all_rows(browser, report,
                                                     tmp_path):
    page = _goto_embedded(browser, tmp_path, report)
    assert _row_count(page) == 5
    assert _counts_text(page) == "5 / 5 findings"
    assert "R-SecOpsX SAST v2.1" in page.locator("#provenance").inner_text()
    page.close()


def test_browser_filters_narrow_and_reset(browser, report, tmp_path):
    page = _goto_embedded(browser, tmp_path, report)
    # severity: High -> 2, reset -> 5
    page.select_option("#f-severity", "High")
    assert _row_count(page) == 2
    assert _counts_text(page) == "2 / 5 findings"
    page.click("#reset")
    assert _row_count(page) == 5
    # rule: TAINT_SQL_INJECTION -> 1
    page.select_option("#f-rule", "TAINT_SQL_INJECTION")
    assert _row_count(page) == 1
    page.click("#reset")
    # CWE: CWE-79 -> 1 ; OWASP: A03 -> 2 ; verdict: TRUE_POSITIVE -> 1
    page.select_option("#f-cwe", "CWE-79")
    assert _row_count(page) == 1
    page.click("#reset")
    page.select_option("#f-owasp", "A03:2021 - Injection")
    assert _row_count(page) == 2
    page.click("#reset")
    page.select_option("#f-verdict", "TRUE_POSITIVE")
    assert _row_count(page) == 1
    page.click("#reset")
    # free-text search over title/rule/file
    page.fill("#q", "db.py")
    assert _row_count(page) == 1
    page.click("#reset")
    assert _row_count(page) == 5
    # honest null rendering: the no-verdict row shows an em dash, never
    # a fabricated verdict, and vanishes when a verdict filter is chosen
    page.select_option("#f-verdict", "NEEDS_REVIEW")
    assert _row_count(page) == 2     # f-002 + f-005 (f-004 null excluded)
    page.click("#reset")
    page.close()


def test_browser_evidence_expand_shows_evidence_snippet_disposition(
        browser, report, tmp_path):
    page = _goto_embedded(browser, tmp_path, report)
    page.locator("#rows tr.row").first.click()
    detail = page.locator("tr.detail").first
    assert detail.is_visible()
    body = detail.inner_text()
    assert "req -> q -> cur" in body          # evidence list item
    assert "disposition: CONFIRMED" in body
    assert "confidence: HIGH" in body
    # collapse again
    page.locator("#rows tr.row").first.click()
    assert not page.locator("tr.detail").first.is_visible()
    page.close()


def test_browser_suppression_stub_download(browser, report, tmp_path):
    page = _goto_embedded(browser, tmp_path, report)
    # stub bar starts disabled at zero
    assert page.locator("#stub").is_disabled()
    # select one row
    page.locator("#rows tr.row").nth(0).click()
    page.locator("tr.detail").nth(0).locator(
        "button:text-is('suppress')").click()
    assert "download baseline stub (1)" in page.locator("#stub").inner_text()
    assert page.locator("#stub").is_enabled()
    with page.expect_download() as dl:
        page.click("#stub")
    path = tmp_path / "stub_one.json"
    dl.value.save_as(str(path))
    stub = json.loads(path.read_text(encoding="utf-8"))
    assert stub == {"TAINT_SQL_INJECTION": [{"file": "app/db.py",
                                             "line": 42}]}
    # second selection merges, rules sorted
    page.locator("#rows tr.row").nth(4).click()
    page.locator("tr.detail").nth(4).locator(
        "button:text-is('suppress')").click()
    with page.expect_download() as dl2:
        page.click("#stub")
    path2 = tmp_path / "stub_two.json"
    dl2.value.save_as(str(path2))
    stub2 = json.loads(path2.read_text(encoding="utf-8"))
    assert sorted(stub2.keys()) == ["HARDCODED_SECRET",
                                    "TAINT_SQL_INJECTION"]
    assert stub2["HARDCODED_SECRET"] == [
        {"file": "conf/settings.py", "line": 3}]
    page.close()


def test_browser_fetch_mode_works_over_http(browser, report, tmp_path):
    (tmp_path / "triage.html").write_bytes(build_asset())
    (tmp_path / "clean_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")

    class _Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    handler = functools.partial(_Quiet, directory=str(tmp_path))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        page = browser.new_page()
        page.goto(f"http://127.0.0.1:{port}/triage.html")
        page.wait_for_function(
            "document.getElementById('counts').textContent.length > 0")
        assert _row_count(page) == 5
        page.select_option("#f-severity", "Medium")
        assert _row_count(page) == 2
        page.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_browser_fetch_mode_file_url_fails_honestly(browser, tmp_path):
    out = tmp_path / "triage.html"
    out.write_bytes(build_asset())      # no embedded data, file:// page
    page = browser.new_page()
    page.goto(out.as_uri())
    page.wait_for_selector("#error:not([hidden])")
    msg = page.locator("#error").inner_text()
    assert "could not load ./clean_report.json" in msg
    assert "--html-embedded" in msg
    assert page.locator("#rows tr.row").count() == 0   # no silent half-render
    page.close()
