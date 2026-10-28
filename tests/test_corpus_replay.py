"""T-3.1 + T-3.2 gate: content-addressed corpus manifest and deterministic replay.

task.md section 3:

    T-3.1 Content-addressed corpus -- Immutable entries:
    {id, lang, source, rule_id, expected: TP|FP|FN, line, cwe,
    provenance}. Cover SAST/SCA/IaC now; DAST/cloud later. Extend the
    existing 380 pinned SCA pairs.

    T-3.2 Deterministic replay runner -- Replays the whole corpus,
    requires byte-identical output, diffs against golden. Runs on every
    rule change in CI.

The contract asserted here:

  * tools/emit_corpus_manifest.py derives tests/replay/manifest.json from
    the labels; every entry id is content-addressed (sha256 over the
    fixture bytes plus the claim), so an edited fixture re-addresses
    itself and the manifest cannot silently keep describing the old file;
  * the manifest covers every labelled fixture -- TP entries per expected
    finding, one FP entry per safe fixture, FN entries for the pinned
    known misses (tests/replay/known_misses.json, annotate-never-delete);
  * tests/replay/vuln_cache_pinned.json covers every (package, version,
    CVE) the SCA labels claim, so the replay can answer every corpus
    question from a committed store with live feeds off;
  * analysis/validation/replay.py replays the corpus twice, requires the
    two dumps byte-identical, then diffs against tests/replay/golden.json;
  * the manifest assertions are load-bearing: a TP the engines stop
    finding, an FN they start finding, or any finding on a safe fixture
    fails the replay with a machine-readable reason.

The full-corpus replay itself (~80s double-run) is the ci_matrix
``corpus_replay`` gate, not a pytest case; the tests below use a
synthetic corpus in tmp_path for the runner's logic and the committed
artifacts for structural checks that need no engine time.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

REPLAY_DIR = REPO / "tests" / "replay"


# ---------------------------------------------------------------------------
# 1. Committed artifacts are in sync with the corpus (emitter --check)
# ---------------------------------------------------------------------------
def test_emitter_check_passes_on_committed_artifacts():
    """Rebuilding the manifest in memory must reproduce the committed bytes.

    This is the freshness gate: a label or fixture edited without
    re-running the emitter fails here rather than letting the replay
    compare against an index that no longer describes the corpus. Run
    through the CLI so the --check code path itself is what CI will use.
    """
    import subprocess
    tools = REPO / "tools" / "emit_corpus_manifest.py"
    assert tools.is_file(), "emitter missing: %s" % tools
    proc = subprocess.run(
        [sys.executable, str(tools), "--check"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        "emitter --check failed:\n%s\n%s"
        % (proc.stdout, proc.stderr))


def test_manifest_entries_are_content_addressed():
    """Every id recomputes from the entry's own fields plus fixture bytes."""
    from analysis.validation.manifest import entry_id

    doc = json.loads((REPLAY_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "rsecopsx.corpus_manifest/v1"
    seen: set[str] = set()
    for entry in doc["entries"]:
        prov = entry.get("provenance") or {}
        recomputed = entry_id(entry["source"], entry["fixture_sha256"],
                              entry["rule_id"], entry["expected"],
                              entry["line"], entry["cwe"],
                              prov.get("cve"), prov.get("package"),
                              prov.get("version"))
        assert entry["id"] == recomputed, entry
        assert entry["id"] not in seen, "duplicate entry id %s" % entry["id"]
        seen.add(entry["id"])
        assert entry["expected"] in ("TP", "FP", "FN"), entry
        assert set(entry) >= {"id", "lang", "source", "rule_id", "expected",
                              "line", "cwe", "provenance", "fixture_sha256"}


def test_manifest_covers_every_labelled_fixture():
    from analysis.validation.corpus import iter_labelled

    doc = json.loads((REPLAY_DIR / "manifest.json").read_text(encoding="utf-8"))
    by_source: dict[str, list[dict]] = {}
    for entry in doc["entries"]:
        by_source.setdefault(entry["source"], []).append(entry)

    corpus = REPO / "tests" / "vuln-test-corpus"
    labelled = 0
    for path, truth in iter_labelled(corpus):
        labelled += 1
        rel = path.relative_to(corpus).as_posix()
        assert rel in by_source, "fixture missing from manifest: %s" % rel
        expected = truth.get("expected_findings") or []
        if expected:
            tp_or_fn = [e for e in by_source[rel] if e["expected"] in ("TP", "FN")]
            assert len(tp_or_fn) == len(expected), rel
        else:
            fp = [e for e in by_source[rel] if e["expected"] == "FP"]
            assert len(fp) == 1, "%s: safe fixture must carry one FP entry" % rel
    assert labelled > 0
    # No manifest entry may point at a file that is not a labelled fixture.
    for source in by_source:
        assert (corpus / source).is_file(), "manifest entry for missing file: %s" % source


def test_known_misses_are_pinned_as_fn_with_reasons():
    """The slack_webhook gap stays annotated, not deleted (ground rule)."""
    misses = json.loads(
        (REPLAY_DIR / "known_misses.json").read_text(encoding="utf-8"))
    assert misses["schema"] == "rsecopsx.known_misses/v1"
    assert misses["misses"], "known-miss table is empty; the corpus has a pinned miss"

    doc = json.loads((REPLAY_DIR / "manifest.json").read_text(encoding="utf-8"))
    fn_entries = {(e["source"], e["rule_id"], e["line"]): e
                  for e in doc["entries"] if e["expected"] == "FN"}
    from analysis.validation.manifest import build_manifest
    for miss in misses["misses"]:
        key = (miss["source"], miss["rule_id"], miss["line"])
        assert key in fn_entries, "known miss not in manifest as FN: %s" % (key,)
        assert miss.get("reason", "").strip(), "known miss without a reason: %s" % (key,)
        assert fn_entries[key]["provenance"]["kind"] == "known-miss"
        assert fn_entries[key]["provenance"]["reason"] == miss["reason"]

    # Each known miss must still be claimed by its label: a miss whose
    # label disappeared (or whose fixture changed) must be re-pinned or
    # removed deliberately, and this is where that surfaces.
    corpus = REPO / "tests" / "vuln-test-corpus"
    for miss in misses["misses"]:
        path = corpus / miss["source"]
        truth = json.loads(path.with_name(path.name + ".ground_truth.json")
                           .read_text(encoding="utf-8"))
        claim = [f for f in truth.get("expected_findings") or []
                 if f.get("rule_id") == miss["rule_id"]
                 and int(f.get("line") or 0) == miss["line"]]
        assert claim, "known miss no longer claimed by its label: %s" % (miss,)


def test_pinned_cache_answers_every_sca_label():
    """Every (package, version, CVE) the SCA labels claim is in the pin.

    This is the "extend the existing 380 pinned SCA pairs" clause made
    checkable: the replay runs with live feeds off, so a label whose CVE
    is absent from the committed pin could never be scored.
    """
    pin = json.loads(
        (REPLAY_DIR / "vuln_cache_pinned.json").read_text(encoding="utf-8"))
    assert isinstance(pin.get("entries"), dict), "pinned cache has no entries"
    pinned_cves: dict[tuple[str, str], set[str]] = {}
    for key, records in pin["entries"].items():
        _eco, name, version = key.split("|", 2)
        cves = {str(r.get("cve")).lower() for r in records
                if isinstance(r, dict) and r.get("cve")}
        pinned_cves[(name.strip().lower(), str(version).strip())] = cves

    from analysis.validation.corpus import iter_labelled
    corpus = REPO / "tests" / "vuln-test-corpus"
    checked = 0
    for path, truth in iter_labelled(corpus):
        try:
            rel_parts = path.relative_to(corpus).parts
        except ValueError:
            continue
        if not rel_parts or rel_parts[0] != "sca":
            continue
        for finding in truth.get("expected_findings") or []:
            pkg = str(finding.get("package") or "").strip().lower()
            ver = str(finding.get("version") or "").strip()
            cve = str(finding.get("cve") or "").strip().lower()
            assert pkg and ver and cve, finding
            assert cve in pinned_cves.get((pkg, ver), set()), (
                "SCA label %s:%s@%s claims %s but the pinned cache does not"
                " answer it -- re-run tools/emit_corpus_manifest.py after"
                " refreshing data/.vuln_cache.json" % (path.name, pkg, ver, cve))
            checked += 1
    assert checked > 0, "no SCA labels checked"


# ---------------------------------------------------------------------------
# 2. Replay runner behaviour, on a synthetic corpus (no engine time in CI)
# ---------------------------------------------------------------------------
# The vulnerable fixture mirrors the shape the taint engine actually
# recognises (a Flask request source feeding a shell=True sink) -- the
# first draft used os.environ.get + os.system, which produced zero
# findings because os.environ is not a registered taint source. Labels
# name the CANONICAL rule (SAST-CMDI), not the shipping rule id.
_VULN = """\
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "")  # source
    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return output.decode()
"""

_SAFE = """\
import subprocess
subprocess.run(["echo", "static"], check=True)
"""


def _write_corpus(root: pathlib.Path) -> pathlib.Path:
    """A two-fixture corpus: one sast vulnerable, one sast safe."""
    sast = root / "sast" / "python"
    sast.mkdir(parents=True)
    (sast / "vuln_cmd.py").write_text(_VULN, encoding="utf-8")
    (sast / "vuln_cmd.py.ground_truth.json").write_text(json.dumps({
        "fixture": "vuln_cmd.py",
        "expected_count": 1,
        "expected_findings": [{
            "rule_id": "SAST-CMDI", "file": "vuln_cmd.py", "line": 9,
            "severity": "Critical", "cwe": "CWE-78",
            "evidence": "subprocess.check_output(cmd, shell=True",
        }],
    }), encoding="utf-8")
    (sast / "safe_run.py").write_text(_SAFE, encoding="utf-8")
    (sast / "safe_run.py.ground_truth.json").write_text(json.dumps({
        "fixture": "safe_run.py",
        "expected_count": 0,
        "expected_findings": [],
    }), encoding="utf-8")
    return root


def test_replay_synthetic_corpus_is_deterministic_and_updates_golden(tmp_path):
    """Double-run identical, golden written by --update, second run passes."""
    from analysis.validation import replay

    corpus = _write_corpus(tmp_path / "corpus")
    out = tmp_path / "out"
    out.mkdir()
    manifest_path = out / "manifest.json"
    golden_path = out / "golden.json"

    from analysis.validation.manifest import write_manifest
    write_manifest(corpus, manifest_path, out / "vuln_cache_pinned.json",
                   known_misses_path=None)

    result = replay.replay(corpus=corpus, manifest_path=manifest_path,
                           golden_path=golden_path, update=True)
    assert result["exit_code"] == 0, result
    assert result["deterministic"], "replay output differed between two runs"
    assert golden_path.is_file()

    golden_bytes = golden_path.read_bytes()
    result2 = replay.replay(corpus=corpus, manifest_path=manifest_path,
                            golden_path=golden_path, update=False)
    assert result2["exit_code"] == 0, result2
    assert golden_path.read_bytes() == golden_bytes


def test_replay_detects_golden_drift(tmp_path):
    """Tampering with the golden makes the byte-compare fail with a diff."""
    from analysis.validation import replay

    corpus = _write_corpus(tmp_path / "corpus")
    out = tmp_path / "out"
    out.mkdir()
    manifest_path = out / "manifest.json"
    golden_path = out / "golden.json"
    from analysis.validation.manifest import write_manifest
    write_manifest(corpus, manifest_path, out / "vuln_cache_pinned.json",
                   known_misses_path=None)
    replay.replay(corpus=corpus, manifest_path=manifest_path,
                  golden_path=golden_path, update=True)

    doc = json.loads(golden_path.read_text(encoding="utf-8"))
    for fixture in doc["fixtures"]:
        for finding in fixture["findings"]:
            finding["line"] = 999
    golden_path.write_text(json.dumps(doc, sort_keys=True, indent=1,
                                      ensure_ascii=True) + "\n",
                           encoding="utf-8", newline="\n")

    result = replay.replay(corpus=corpus, manifest_path=manifest_path,
                           golden_path=golden_path, update=False)
    assert result["exit_code"] == 1, result
    assert any("drift" in p for p in result["problems"]), result["problems"]


def test_replay_flags_a_tp_the_engines_stopFinding(tmp_path):
    """A manifest TP with no matching finding fails with a machine reason."""
    from analysis.validation import replay

    corpus = _write_corpus(tmp_path / "corpus")
    out = tmp_path / "out"
    out.mkdir()
    manifest_path = out / "manifest.json"
    golden_path = out / "golden.json"
    from analysis.validation.manifest import write_manifest
    write_manifest(corpus, manifest_path, out / "vuln_cache_pinned.json",
                   known_misses_path=None)
    replay.replay(corpus=corpus, manifest_path=manifest_path,
                  golden_path=golden_path, update=True)

    # Lie in the manifest: claim a TP the fixture never supports.
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    doc["entries"].append({
        "id": "0" * 16,
        "lang": "python",
        "source": "sast/python/safe_run.py",
        "rule_id": "SAST-SQLI",
        "expected": "TP",
        "line": 1,
        "cwe": "CWE-89",
        "fixture_sha256": "0" * 64,
        "provenance": {"kind": "fixture-semantics"},
    })
    manifest_path.write_text(json.dumps(doc, sort_keys=True, indent=1,
                                        ensure_ascii=True) + "\n",
                             encoding="utf-8", newline="\n")

    result = replay.replay(corpus=corpus, manifest_path=manifest_path,
                           golden_path=golden_path, update=False)
    assert result["exit_code"] == 1, result
    assert any("TP not detected" in p for p in result["problems"]), \
        result["problems"]


def test_replay_flags_a_known_miss_that_became_detected(tmp_path):
    """An FN that the engines start finding forces a deliberate re-pin."""
    from analysis.validation import replay

    corpus = _write_corpus(tmp_path / "corpus")
    out = tmp_path / "out"
    out.mkdir()
    manifest_path = out / "manifest.json"
    golden_path = out / "golden.json"
    from analysis.validation.manifest import write_manifest
    write_manifest(corpus, manifest_path, out / "vuln_cache_pinned.json",
                   known_misses_path=None)
    replay.replay(corpus=corpus, manifest_path=manifest_path,
                  golden_path=golden_path, update=True)

    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    # Pin the vuln fixture's TP as a known miss: replay will FIND it, which
    # is exactly the "miss got fixed" flip the gate must catch.
    for entry in doc["entries"]:
        if entry["source"].endswith("vuln_cmd.py"):
            entry["expected"] = "FN"
            entry["provenance"] = {"kind": "known-miss",
                                   "reason": "synthetic flip"}
    manifest_path.write_text(json.dumps(doc, sort_keys=True, indent=1,
                                        ensure_ascii=True) + "\n",
                             encoding="utf-8", newline="\n")

    result = replay.replay(corpus=corpus, manifest_path=manifest_path,
                           golden_path=golden_path, update=False)
    assert result["exit_code"] == 1, result
    assert any("known miss now detected" in p for p in result["problems"]), \
        result["problems"]


def test_replay_flags_a_finding_on_a_safe_fixture(tmp_path):
    """A safe-fixture FP entry with an actual finding fails the replay."""
    from analysis.validation import replay

    corpus = _write_corpus(tmp_path / "corpus")
    out = tmp_path / "out"
    out.mkdir()
    manifest_path = out / "manifest.json"
    golden_path = out / "golden.json"
    from analysis.validation.manifest import write_manifest
    write_manifest(corpus, manifest_path, out / "vuln_cache_pinned.json",
                   known_misses_path=None)
    replay.replay(corpus=corpus, manifest_path=manifest_path,
                  golden_path=golden_path, update=True)

    # Make the "safe" fixture genuinely vulnerable WITHOUT re-emitting the
    # manifest: the manifest still pins it FP, the engine will now find
    # the sink, and the assertion -- not the golden diff -- must fire.
    (corpus / "sast" / "python" / "safe_run.py").write_text(
        _VULN, encoding="utf-8")

    result = replay.replay(corpus=corpus, manifest_path=manifest_path,
                           golden_path=golden_path, update=False)
    assert result["exit_code"] == 1, result
    assert any("false positive" in p for p in result["problems"]), \
        result["problems"]


def test_replay_pins_live_feeds_off_and_uses_the_committed_cache(tmp_path, monkeypatch):
    """Replay must not depend on working-copy cache churn or the network."""
    from analysis.validation import replay
    from scanner import vulnerability_intel

    monkeypatch.delenv("RSECOPSX_LIVE_FEEDS", raising=False)
    pin = tmp_path / "pinned.json"
    pin.write_text(json.dumps({"schema_version": 4, "source": "test",
                               "entries": {}, "fetched": {}}),
                   encoding="utf-8")
    before = vulnerability_intel.CACHE_FILE
    try:
        replay._pin_advisory_state(pin)
        import os
        assert os.environ.get("RSECOPSX_LIVE_FEEDS") == "0"
        assert vulnerability_intel.CACHE_FILE == pin
    finally:
        vulnerability_intel.CACHE_FILE = before
