"""T-15 (task.md section 15 Definition of Done): machine-checkable DoD pins.

The §15 checklist has six bullets. Four of them can be asserted from
the suite; the other two (baselines same-commit, gates green) are
process/measurement claims verified in the commit body:

* **Offline/airgap scan mode works with zero network** -- behavioural:
  with the documented air-gap switches set, no transport in the scan
  path may open a socket. Ground defect this file caught:
  ``scanner/sbom.py``'s Maven Central POM fetch ignored
  ``RSECOPSX_LIVE_FEEDS`` entirely while every other live client
  honours a switch.
* **No absolute paths** (repo convention, task.md section 2) --
  executable string constants in the product scan path, plus the
  repo-root ``sys.path`` bootstraps that made the "known exception"
  disclosures necessary.
* **No new in-source backups** (ground rule 8) -- no tracked
  ``*.bak_*`` / ``*.before_*`` siblings and no tracked ``backup/``
  files.
* **``--explain-drops`` / ``--explain-score`` / ``--explain-verdict``
  functional** -- declared on the CLI surface the DoD names, with the
  functional coverage living in test_no_silent_drops /
  test_explain_verdict / test_t71_scoring (run in this batch's blast).

Plus one harness calibration pin: the v0 unit gate carries a timeout
measured against its real runtime (the default 300s cap turned a
healthy 173-test gate into a chronic matrix red).

No pinned counts anywhere: every assertion is emptiness of an offender
set or a behavioural outcome, never a number of findings.
"""
from __future__ import annotations

import ast
import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------------
# helpers (each has a teeth check -- a synthetic input that MUST be caught)
# --------------------------------------------------------------------------

_NETWORK_BANNED_TOPS = {
    "socket", "requests", "boto3", "aiohttp", "httpx", "ftplib",
    "telnetlib", "smtplib", "xmlrpc",
}
# urllib.parse / urllib.error are offline string work; urllib.request is not.
_SAFE_URILIB = {"urllib.parse", "urllib.error"}

# The only scan-path modules allowed to import a network transport, and
# only because each one's egress is behind an operator switch (T-15
# verified: HF=RSX_HF_ENRICH, NVD=RSX_NVD_ENRICH, Maven+OSV=
# RSECOPSX_LIVE_FEEDS, intel feeds=RSECOPSX_LIVE_FEEDS).
_NETWORK_ALLOWLIST = {
    "scanner/aibom.py",
    "scanner/nvd_client.py",
    "scanner/sbom.py",
    "scanner/vulnerability_intel.py",
}

_SCAN_PATH_ROOTS = ("main.py", "core", "scanner", "reporting")

_DRIVE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\s`\"')]*")
_UNC = re.compile(r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+")
_HOME = re.compile(r"/home/[A-Za-z0-9._-]+")


def _is_network_module(mod: str) -> bool:
    top = mod.split(".")[0]
    if top in _NETWORK_BANNED_TOPS:
        return True
    if mod == "http.client":
        return True
    if top == "urllib":
        return mod not in _SAFE_URILIB
    return False


def _net_import_hits(source: str, name: str = "synthetic.py") -> list[str]:
    """Network-capable imports in *source* (AST, comments invisible)."""
    hits: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [f"{name}: <unparseable>"]
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level:
            mods = [node.module or ""]
        for mod in mods:
            if _is_network_module(mod):
                hits.append(f"{name}:{node.lineno} {mod}")
    return hits


def _scan_path_py_files() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for root in _SCAN_PATH_ROOTS:
        p = REPO / root
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(sorted(p.rglob("*.py")))
    return out


def _executable_abs_hits(source: str, name: str = "synthetic.py") -> list[str]:
    """Absolute paths inside executable string constants (not docstrings).

    Comments never reach the AST; module/class/function docstrings are
    ``Expr(Constant)`` statements and are skipped as prose.
    """
    hits: list[str] = []
    tree = ast.parse(source)
    parent: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    lines = source.splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if isinstance(parent.get(node), ast.Expr):
            continue  # docstring / bare string expression = prose
        for rx in (_DRIVE, _UNC, _HOME):
            m = rx.search(node.value)
            if m:
                line = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                hits.append(f"{name}:{node.lineno} {m.group(0)[:60]} | {line[:80]}")
                break
    return hits


def _backup_sibling(name: str) -> bool:
    """Ground rule 8 matcher: in-source backup artefacts."""
    base = name.rsplit("/", 1)[-1]
    if name.startswith("backup/"):
        return True
    return bool(re.search(r"\.(bak|before|orig|rej)_", base)) or bool(
        re.search(r"\.(bak|before)\.", base)
    )


def _tracked_files() -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            capture_output=True, text=True, encoding="utf-8",
            cwd=str(REPO), timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git unavailable -- tracked-file pins cannot run")
    if proc.returncode != 0:
        pytest.skip("git ls-files failed -- not a checkout?")
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


# --------------------------------------------------------------------------
# bullet: offline/airgap scan mode works with zero network
# --------------------------------------------------------------------------

def test_airgap_maven_fetch_honours_the_master_switch(monkeypatch, tmp_path):
    """RSECOPSX_LIVE_FEEDS=0 must stop the Maven POM transport too.

    Every other live client in the tree honours a switch; this fetch
    used to go straight to urlopen, so an operator who set the
    documented air-gap switches still had repo1.maven.org contacted for
    any dependency whose version the parent-pom chain had to resolve.
    Local cache reads above the gate stay legal offline.
    """
    from scanner import sbom as sbom_mod

    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "0")
    monkeypatch.setattr(
        sbom_mod, "_MAVEN_POM_CACHE_PATH", tmp_path / ".maven_pom_cache.json"
    )
    calls: list[tuple] = []

    def _spy(*args, **kwargs):
        calls.append(args)
        raise AssertionError("egress attempted while RSECOPSX_LIVE_FEEDS=0")

    monkeypatch.setattr("urllib.request.urlopen", _spy)

    text = sbom_mod._fetch_maven_pom("com.rsx.t15", "never-cached", "1.0.0")

    assert text is None, "airgap mode must degrade to unknown, not fetch"
    assert calls == [], (
        f"Maven POM fetch ignored RSECOPSX_LIVE_FEEDS=0 and opened the "
        f"transport {len(calls)} time(s) -- section 15 offline invariant"
    )


def test_airgap_hf_enrichment_honours_its_switch(monkeypatch, tmp_path):
    """RSX_HF_ENRICH=0 must keep the hub transport untouched (regression
    pin for the gate; honestly green at ground -- the gate predates T-15)."""
    from scanner import aibom

    monkeypatch.setenv("RSX_HF_ENRICH", "0")
    calls: list[tuple] = []

    def _spy(*args, **kwargs):
        calls.append(args)
        raise AssertionError("egress attempted while RSX_HF_ENRICH=0")

    monkeypatch.setattr(aibom, "urlopen", _spy)

    # model_value (not "model") is what _hf_model_id reads -- a wrong
    # key skips the fetch entirely and the gate mutation would survive
    items = [{"provider": "HuggingFace", "model_value": "rsx/t15-fake"}]
    out = aibom.enrich_hf_metadata(items, cache_path=tmp_path / ".hf_cache.json")

    assert calls == [], "HF enrichment ignored RSX_HF_ENRICH=0"
    assert not any((i.get("hf_enrichment") or {}).get("status") == "ok" for i in out)


def test_nvd_stays_opt_in_when_the_env_is_unset(monkeypatch):
    """RSX_NVD_ENRICH unset -> the secondary pass returns before any
    transport (opt-in by default; regression pin)."""
    from scanner import vulnerability_intel as vi

    monkeypatch.delenv("RSX_NVD_ENRICH", raising=False)
    calls: list[tuple] = []

    def _spy(*args, **kwargs):
        calls.append(args)
        raise AssertionError("egress attempted with RSX_NVD_ENRICH unset")

    monkeypatch.setattr("urllib.request.urlopen", _spy)
    out = vi._query_nvd_secondary(
        [{"name": "t15", "version": "1.0", "ecosystem": "PyPI"}], {}
    )
    assert out == {}
    assert calls == []


def test_scan_path_network_imports_are_allowlisted():
    """Only the four switch-gated clients may import a transport in the
    scan path; a new module reaching for socket/urllib.request directly
    reopens the offline hole."""
    offenders: list[str] = []
    for path in _scan_path_py_files():
        rel = path.relative_to(REPO).as_posix()
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        for hit in _net_import_hits(text, rel):
            if rel not in _NETWORK_ALLOWLIST:
                offenders.append(hit)
    assert not offenders, (
        "un-gated network imports in the scan path (section 15 offline "
        f"invariant): {offenders}"
    )


def test_net_import_detector_has_teeth():
    assert _net_import_hits("import socket\n"), "detector missed import socket"
    assert _net_import_hits("from urllib.request import urlopen\n")
    assert _net_import_hits("import http.client\n")
    assert not _net_import_hits("from urllib.parse import quote\n")
    assert not _net_import_hits("import json\n")


# --------------------------------------------------------------------------
# bullet: no absolute paths (executable context, product scan path)
# --------------------------------------------------------------------------

def test_product_scan_path_has_no_executable_absolute_paths():
    offenders: list[str] = []
    for path in _scan_path_py_files():
        rel = path.relative_to(REPO).as_posix()
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        offenders.extend(_executable_abs_hits(text, rel))
    assert not offenders, (
        "executable absolute paths in the product scan path (repo "
        f"convention, task.md section 2): {offenders}"
    )


def test_abs_path_detector_has_teeth():
    assert _executable_abs_hits('X = r"D:\\evil\\path"\n'), "assignment missed"
    assert _executable_abs_hits('f("C:/evil")\n'), "call literal missed"
    # forward slashes: a backslash form here would make ast.parse itself
    # emit a SyntaxWarning for the invalid \e escape
    assert not _executable_abs_hits('"""prose D:/evil/path"""\n'), (
        "docstrings are prose and must be skipped"
    )
    assert not _executable_abs_hits("# comment D:\\evil\\path\nX = 1\n")
    assert not _executable_abs_hits("from urllib.parse import quote\n")


_BOOTSTRAP_ABS = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\"'\n]*R-SecOpsX_V11"
)


def test_tests_do_not_bootstrap_from_an_absolute_repo_root():
    """The sys.path/ROOT bootstraps that hardcode this machine's checkout
    are the reason two 'known exception' disclosures existed; each file
    now derives the root from __file__."""
    offenders: list[str] = []
    for path in sorted((REPO / "tests").glob("*.py")):
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if _BOOTSTRAP_ABS.search(text):
            offenders.append(path.name)
    assert not offenders, (
        "tests still bootstrap from an absolute repo root "
        f"(portable-root convention): {offenders}"
    )


def test_bootstrap_detector_has_teeth():
    # root is concatenated so this file's own offender scan (which greps
    # test sources for the literal drive+root pattern) stays clean while
    # the synthetic needle still exercises the full regex
    root = "R-SecOpsX" + "_V11"
    evil = 'sys.path.insert(0, r"D:\\data\\Code test\\' + root + '")\n'
    assert _BOOTSTRAP_ABS.search(evil), "detector missed a drive+root bootstrap"
    assert not _BOOTSTRAP_ABS.search(
        'sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))\n'
    )


# --------------------------------------------------------------------------
# bullet: no new in-source backups (ground rule 8)
# --------------------------------------------------------------------------

def test_no_tracked_in_source_backup_siblings():
    offenders = [f for f in _tracked_files() if _backup_sibling(f)]
    assert not offenders, (
        "tracked in-source backup artefacts (ground rule 8 -- untracked "
        f"legacy backup/ copies are a separate disclosed set): {offenders}"
    )


def test_backup_matcher_has_teeth():
    assert _backup_sibling("core/finding_model.bak_20260101.py")
    assert _backup_sibling("scanner/abom.py.before_canonical_2026.py")
    assert _backup_sibling("backup/abom.py.before_x.py")
    assert not _backup_sibling("core/finding_model.py")
    assert not _backup_sibling("tools/emit_corpus_manifest.py")


# --------------------------------------------------------------------------
# bullet: --explain-drops / --explain-score / --explain-verdict declared
# --------------------------------------------------------------------------

def test_explain_flags_are_declared_on_their_cli_surfaces():
    main_src = (REPO / "main.py").read_text(encoding="utf-8-sig", errors="replace")
    assert "--explain-drops" in main_src, "main.py lost --explain-drops"
    assert "--explain-verdict" in main_src, "main.py lost --explain-verdict"
    scoring_src = (REPO / "analysis" / "scoring" / "connect.py").read_text(
        encoding="utf-8-sig", errors="replace"
    )
    assert "--explain-score" in scoring_src, (
        "the scoring CLI (not main.py -- T-7.1) must declare --explain-score"
    )


# --------------------------------------------------------------------------
# bullet (harness): the v0 gate's timeout is measured, not a stale default
# --------------------------------------------------------------------------

def test_ci_matrix_v0_gate_has_a_measured_timeout():
    src = (REPO / "analysis" / "validation" / "ci_matrix.py").read_text(
        encoding="utf-8-sig", errors="replace"
    )
    anchor = src.find('"v0_unit_tests"')
    assert anchor != -1, "v0_unit_tests gate disappeared from ci_matrix"
    block = src[anchor:anchor + 700]
    assert "timeout=600" in block, (
        "v0_unit_tests must carry its measured timeout=600 (healthy run "
        "374.2s > the 300s default cap turned a green gate into a "
        "chronic matrix red -- T-15 calibration, section 15)"
    )


# --------------------------------------------------------------------------
# README documents the air-gap switches the invariant depends on
# --------------------------------------------------------------------------

def test_readme_documents_the_airgap_switches():
    text = (REPO / "README.md").read_text(encoding="utf-8", errors="replace")
    for needle in ("RSECOPSX_LIVE_FEEDS", "RSX_HF_ENRICH"):
        assert needle in text, (
            f"README.md must document the {needle} air-gap switch -- "
            "section 15 offline invariant is operator-visible"
        )
