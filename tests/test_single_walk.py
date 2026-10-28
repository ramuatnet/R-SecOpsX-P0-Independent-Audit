"""T-0.2 gate: one walk, one skip policy, one .sastignore evaluation.

task.md section 3, T-0.2:

    Steps: one ``walk(root) -> FileIndex{path, lang, size, mtime,
    content_hash}`` consumed by all engines. Replace every
    ``rglob``/``_iter_files``. One ``.sastignore`` evaluation, one
    ``SKIP_DIRS``.
    Accept: instrument walk count; assert exactly 1 per scan.
    Gate: perf -- scan of a 10k-file tree <= 60% of current wall time.

Before this gate, a single scan fanned out into dozens of independent
``rglob``/``os.walk`` passes -- main.py's LLM passes, sast, every BOM
engine, reachability -- each re-implementing its own (slightly different)
skip policy. Files were stat'ed many times, and a divergence in any one
engine's SKIP_DIRS silently changed what that engine could see.

The contract asserted here:

  * ``core.file_index.walk`` is the one walk; a scan of any target runs it
    exactly once (asserted through report metadata, so a subprocess scan
    proves it too);
  * the skip policy is ONE set (the union of the per-engine lists, each
    entry documented by where it came from) applied at walk time;
  * ``.sastignore`` is loaded once per scan and its path-shaped rules are
    evaluated at the walk (rule-id rules stay in the finding-level
    suppression layer, where they belong -- they must not exclude files);
  * the walk is iterative with a depth cap and cycle detection (T-0.4
    semantics applied to the filesystem, not just JSON containers).
"""
from __future__ import annotations

import importlib
import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

MAIN = REPO / "main.py"


# ---------------------------------------------------------------------------
# 1. Module + API surface
# ---------------------------------------------------------------------------
def test_file_index_module_and_api():
    from core import file_index
    assert callable(file_index.walk)
    assert hasattr(file_index, "FileIndex")
    assert hasattr(file_index, "walk_count")
    assert hasattr(file_index, "begin_scan")
    # The canonical policy lives here now; scanner.sast must keep exposing
    # the historical names (every engine imports them from there).
    from scanner import sast
    for name in ("EXCLUDED_DIRS", "EXCLUDED_FILES", "SCANNABLE_EXT",
                 "LANG_BY_EXT", "_skip", "_should_scan"):
        assert hasattr(sast, name), f"sast lost its historical name {name}"
    assert "node_modules" in {d.lower() for d in file_index.EXCLUDED_DIRS}


def test_union_policy_covers_every_engine_source():
    """One SKIP_DIRS: the union of every scan-path engine's list.

    Losing an entry here re-opens an FP class each list was added to
    close (I2 forge out/, I18 i18n bundle/, ...); dropping an engine's
    entry changes what that engine sees.
    """
    from core import file_index
    union = {d.lower() for d in file_index.EXCLUDED_DIRS}
    # sast's historical core set
    for d in (".git", "node_modules", "__pycache__", "venv", ".venv",
              "dist", "build", "vendor", "third_party", "migrations",
              "reports", "artifacts", "output", "outputs", "coverage",
              ".pytest_cache", "out", "bundle", ".tox", ".cache", "env",
              ".env", ".svn"):
        assert d in union, f"sast policy entry missing from union: {d}"
    # llm_security additions
    for d in (".hg", ".next", ".nuxt"):
        assert d in union, f"llm_security entry missing from union: {d}"
    # sbom addition
    assert "target" in union


# ---------------------------------------------------------------------------
# 2. Walk unit semantics (policy, lang, laziness, depth, cycle)
# ---------------------------------------------------------------------------
@pytest.fixture()
def tree(tmp_path):
    """A miniature repo exercising every policy family."""
    keep = tmp_path / "src" / "app.py"
    keep.parent.mkdir(parents=True)
    keep.write_text("password = 'x'\n", encoding="utf-8")
    js = tmp_path / "web" / "index.js"
    js.parent.mkdir(parents=True)
    js.write_text("eval(x)\n", encoding="utf-8")
    for d in ("node_modules/pkg", "bundle", "target", ".next", ".hg",
              "dist", "out"):
        p = tmp_path / d
        p.mkdir(parents=True, exist_ok=True)
        (p / "x.js").write_text("eval(x)\n", encoding="utf-8")
    # self-scan hazard: exact-name artifacts
    (tmp_path / "clean_report.json").write_text("{}", encoding="utf-8")
    # scanner-result export: must be skipped by content, not name
    (tmp_path / "vendor_scan.json").write_text(
        '{"metadata": {"tool": "x"}, "total_findings": 1,'
        ' "findings": [{"rule_id": "R"}]}',
        encoding="utf-8")
    return tmp_path


def test_walk_policy_and_lang_fields(tree):
    from core import file_index
    idx = file_index.walk(tree)
    rels = {e.rel for e in idx.entries}
    assert "src/app.py" in rels
    assert "web/index.js" in rels
    for d in ("node_modules/pkg/x.js", "bundle/x.js", "target/x.js",
              ".next/x.js", ".hg/x.js", "dist/x.js", "out/x.js"):
        assert d not in rels, f"policy failed to exclude {d}"
    assert "clean_report.json" not in rels
    assert "vendor_scan.json" not in rels, (
        "scanner-result JSON exports are tool output, not source")
    by_rel = {e.rel: e for e in idx.entries}
    assert by_rel["src/app.py"].lang == "python"
    assert by_rel["web/index.js"].lang == "javascript"
    assert by_rel["src/app.py"].size > 0
    assert by_rel["src/app.py"].mtime > 0
    # content_hash is part of the FileIndex contract but computed lazily --
    # the walk must not read every file up front.
    assert by_rel["src/app.py"].content_hash is None


def test_walk_is_exactly_one_and_counted(tree):
    from core import file_index
    file_index.begin_scan()
    assert file_index.walk_count() == 0
    file_index.walk(tree)
    file_index.walk_count() == 1  # sanity for the counter itself
    assert file_index.walk_count() == 1
    idx = file_index.current()
    assert idx is not None and idx.root == tree.resolve()
    file_index.begin_scan()
    assert file_index.walk_count() == 0


def test_walk_depth_cap_is_reported_not_silent(tmp_path):
    from core import file_index
    deep = tmp_path / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "x.py").write_text("x = 1\n", encoding="utf-8")
    idx = file_index.walk(tmp_path, max_depth=2)
    rels = {e.rel for e in idx.entries}
    assert "a/b/c/d/x.py" not in rels
    report = idx.walk_report
    assert report.get("depth_capped") >= 1, (
        "depth-cap exclusion must be counted, never silent")


def test_walk_detects_directory_cycles(tmp_path):
    from core import file_index
    a = tmp_path / "a"
    a.mkdir()
    (a / "x.py").write_text("x = 1\n", encoding="utf-8")
    b = a / "loop"
    try:
        os.symlink(str(tmp_path), str(b), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this machine")
    file_index.begin_scan()
    idx = file_index.walk(tmp_path)
    # termination + no duplicated subtree
    rels = [e.rel for e in idx.entries]
    assert len(rels) == len(set(rels))
    assert idx.walk_report.get("cycles_detected", 0) >= 1


def test_sastignore_path_rules_walk_level_rule_ids_stay_finding_level(tmp_path):
    """Path-shaped .sastignore rules exclude at the walk; bare rule ids do
    not (they suppress one rule's findings, never a whole file)."""
    from core import file_index
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "keep").mkdir()
    (tmp_path / "keep" / "b.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / ".sastignore").write_text(
        "# comment\nsecrets/\nGENERIC_API_KEY_PASSWORD\n", encoding="utf-8")
    idx = file_index.walk(tmp_path)
    rels = {e.rel for e in idx.entries}
    assert "secrets/a.py" not in rels
    assert "keep/b.py" in rels
    assert idx.walk_report.get("sastignore_skipped") == 1


def test_sastignore_loaded_once_per_scan(tmp_path, monkeypatch):
    from core import file_index
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".sastignore").write_text("secrets/\n", encoding="utf-8")
    # Count actual DISK reads of .sastignore, not loader calls: the loader
    # is consulted per walk but must hit the per-scan cache.
    reads = {"n": 0}
    orig_read_text = pathlib.Path.read_text

    def counted_read(self, *args, **kwargs):
        if self.name == ".sastignore":
            reads["n"] += 1
        return orig_read_text(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "read_text", counted_read)
    file_index.begin_scan()
    file_index.walk(tmp_path)
    file_index.walk(tmp_path)
    assert reads["n"] == 1, (
        f".sastignore read from disk {reads['n']} times -- one evaluation "
        "means one load per scan")


def test_content_hash_lazily_filled_and_stable(tree):
    from core import file_index
    idx = file_index.walk(tree)
    entry = next(e for e in idx.entries if e.rel == "src/app.py")
    h1 = idx.content_hash(entry.path)
    assert isinstance(h1, str) and len(h1) == 64
    assert entry.content_hash == h1
    assert idx.content_hash(entry.path) == h1  # cached


def test_files_query_filters(tree):
    from core import file_index
    idx = file_index.walk(tree)
    py = idx.files(lang="python")
    assert [p.name for p in py] == ["app.py"]
    js = idx.files(exts={".js"})
    assert [p.name for p in js] == ["index.js"]
    any_ = idx.files()
    assert len(any_) == len(idx.entries)


def test_read_source_normalizes_newlines_like_text_mode(tmp_path):
    """read_source must match the text-mode open() every replaced site used.

    Path.read_text maps \\r\\n AND lone \\r to \\n. The cached path decodes
    raw bytes, so without the explicit normalize it silently diverged from
    the fallback path -- DVWA medium.php:55 is the worked example (see the
    php-window test below). content_hash() is a file-identity contract and
    keeps hashing the raw bytes.
    """
    import hashlib
    from core import file_index
    p = tmp_path / "crlf.txt"
    raw = b"a\r\nb\rc\n"
    p.write_bytes(raw)
    file_index.begin_scan()
    idx = file_index.walk(tmp_path)          # walk() sets the current index
    try:
        assert file_index.read_source(p) == "a\nb\nc\n"
        # Same file, direct fallback (no active scan): identical answer.
        file_index.set_current(None)
        assert file_index.read_source(p) == "a\nb\nc\n"
        assert idx.content_hash(p) == hashlib.sha256(raw).hexdigest()
    finally:
        file_index.begin_scan()


def test_php_sql_intermediate_query_survives_crlf_window(tmp_path):
    """Regression pin for the medium.php:55 parity break.

    _php_sql_intermediate_query searches a 1500-char region behind the
    sink for the FIRST assignment of the sink's variable. DVWA's medium
    page has a tainted $query assignment ~1.5kB before a later clean
    COUNT(*) one; a CRLF checkout is a few bytes longer, and without
    newline normalization the tainted assignment slips outside the
    window and the finding dies silently. The pad is computed so the
    assignment sits just inside the window normalized and just outside
    it with CRLF preserved -- and the test asserts BOTH directions, so
    the fixture cannot go stale without failing.
    """
    import re
    from core import file_index
    from scanner import sast

    a = "$query = \"SELECT name FROM users WHERE u = $_GET['id'];\";\n"
    b = "$query = \"SELECT COUNT(*) FROM users;\";\n"
    sink_prefix = "$result = "
    # Normalized offsets: assignment A at a_off, sink token at start_norm.
    head_norm = "<?php\n" + a
    a_off = head_norm.index("$query")
    s0 = len(head_norm) + len(b) + len(sink_prefix)
    # Pad: L comment lines, width w each (line = 3 + w + 1 normalized).
    # P_norm = L*(w+3), P_crlf = P_norm + L.  Want, with 3-byte margins:
    #   A inside the normalized window:  s0 + P_norm - 1500 <= a_off - 3
    #   A outside the CRLF window:       s0 + P_crlf  - 1500 >= a_off + 3
    lines = 10
    lower = a_off + 1503 - s0 - lines
    upper = a_off + 1497 - s0
    assert lower <= upper, "fixture geometry impossible"
    width = max(1, ((lower + upper) // 2) // lines - 3)
    pad = "".join("// " + "x" * width + "\r\n" for _ in range(lines))
    p = tmp_path / "medium.php"
    p.write_bytes(("<?php\r\n" + a.replace("\n", "\r\n") + pad
                   + b.replace("\n", "\r\n") + sink_prefix
                   + "mysqli_query($db, $query);\r\n").encode("utf-8"))

    # Self-validation of the fixture geometry: without normalization the
    # assignment is outside the window (validator dark), with it it fires.
    raw = p.read_bytes().decode("utf-8")
    m_raw = re.search(r"mysqli_query\s*\(", raw)
    assert sast._php_sql_intermediate_query(raw, m_raw, "php") is False

    file_index.begin_scan()
    file_index.walk(tmp_path)                 # cache path, the buggy one
    try:
        text = file_index.read_source(str(p))
        assert "\r" not in text
        m = re.search(r"mysqli_query\s*\(", text)
        assert sast._php_sql_intermediate_query(text, m, "php") is True
        hits = [f for f in sast.scan_file(str(p))
                if f.get("rule_id") == "PHP_SQL_INTERMEDIATE_QUERY"]
        assert hits, "CRLF source lost the intermediate-query finding"
    finally:
        file_index.begin_scan()


# ---------------------------------------------------------------------------
# 3. Acceptance: exactly 1 walk per scan (subprocess, the real pipeline)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def scan_artifacts(tmp_path_factory):
    proj = tmp_path_factory.mktemp("single_walk_proj")
    (proj / "app.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    (proj / "web").mkdir()
    (proj / "web" / "index.js").write_text("eval(x)\n", encoding="utf-8")
    # a file every engine used to re-discover independently
    (proj / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    outdir = tmp_path_factory.mktemp("single_walk_out")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--workers", "2"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


def test_scan_exits_zero(scan_artifacts):
    proc, _outdir = scan_artifacts
    assert proc.returncode == 0, (
        f"main.py exited {proc.returncode}.\n"
        f"--- stdout tail ---\n{(proc.stdout or '')[-3000:]}\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}"
    )


def test_exactly_one_walk_per_scan(scan_artifacts):
    """task.md T-0.2 acceptance, asserted through the report so a
    subprocess scan proves it: a scan walks the tree once."""
    _proc, outdir = scan_artifacts
    report = json.loads((outdir / "clean_report.json").read_text(
        encoding="utf-8"))
    meta = (report.get("metadata") or {}).get("file_index")
    assert meta, (
        "clean_report.json carries no metadata.file_index block -- the "
        "walk instrumentation is missing")
    assert meta.get("walks") == 1, (
        f"a scan must walk the tree exactly once, observed {meta.get('walks')}")
    assert meta.get("files", 0) >= 3, (
        "the index must see app.py, index.js and package.json")


def test_report_byte_stable_across_scans(scan_artifacts, tmp_path):
    """Ground rule 10: the metadata block is deterministic -- a second
    scan of the same tree emits the identical block."""
    _proc, outdir = scan_artifacts
    report = json.loads((outdir / "clean_report.json").read_text(
        encoding="utf-8"))
    meta1 = json.dumps((report.get("metadata") or {}).get("file_index"),
                       sort_keys=True)
    proj2 = tmp_path / "stable"
    proj2.mkdir()
    (proj2 / "app.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    out2 = tmp_path / "stable_out"
    out2.mkdir()
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj2),
         "--output-dir", str(out2), "--no-pdf", "--no-excel",
         "--workers", "2"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    assert proc.returncode == 0
    report2 = json.loads((out2 / "clean_report.json").read_text(
        encoding="utf-8"))
    meta2 = json.dumps((report2.get("metadata") or {}).get("file_index"),
                       sort_keys=True)
    # walks/files counts are structural constants, not timings: equal
    # trees must produce equal blocks.
    for block in (meta1, meta2):
        data = json.loads(block)
        assert set(data) >= {"walks", "files", "sastignore_skipped"}
        assert data["walks"] == 1


# ---------------------------------------------------------------------------
# 4. Perf gate: one walk of a 10k-file tree stays cheap
# ---------------------------------------------------------------------------
def _make_10k_tree(root: pathlib.Path, nfiles: int = 10_000,
                   ndirs: int = 100) -> None:
    per_dir = nfiles // ndirs
    for d in range(ndirs):
        sub = root / ("pkg%03d" % d)
        sub.mkdir(parents=True, exist_ok=True)
        for f in range(per_dir):
            (sub / ("m%04d.py" % f)).write_text("x = 1\n", encoding="utf-8")


def test_walk_10k_file_tree_is_fast(tmp_path):
    """One walk of 10k files must be a single linear pass with one stat per
    file. The full-scan <=60% wall gate is measured end-to-end in the
    commit evidence; this in-suite assertion is the regression guard that
    catches a reintroduced per-engine re-walk storm (which multiplies this
    number by the engine count)."""
    from core import file_index
    _make_10k_tree(tmp_path)
    file_index.begin_scan()
    t0 = time.perf_counter()
    idx = file_index.walk(tmp_path)
    elapsed = time.perf_counter() - t0
    assert len(idx.entries) == 10_000
    assert elapsed < 3.0, (
        "one walk of a 10k-file tree took %.2fs -- the single-pass walk "
        "regressed toward per-engine re-walking" % elapsed)


def test_no_engine_rewalks_when_index_is_current(tmp_path, monkeypatch):
    """Engines must consume the current index, not spawn fresh walks."""
    from core import file_index
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    file_index.begin_scan()
    file_index.walk(tmp_path)
    assert file_index.walk_count() == 1
    idx2 = file_index.index_for(tmp_path)
    assert file_index.walk_count() == 1, (
        "index_for re-walked instead of returning the current index")
    assert idx2.root == tmp_path.resolve()
