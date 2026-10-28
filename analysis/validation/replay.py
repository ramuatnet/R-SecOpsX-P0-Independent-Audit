"""T-3.2: deterministic corpus replay runner.

    python -m analysis.validation.replay                # check vs golden
    python -m analysis.validation.replay --update       # re-pin golden
    python -m analysis.validation.replay --corpus PATH --golden PATH

WHAT IT GUARANTEES
------------------
Three checks, in order, all of them fail-closed:

1. DETERMINISM. The whole corpus is scanned TWICE in one process and the
   two dumps must be byte-identical before either is compared to the
   golden. A rule whose output order depends on set iteration, or a
   validator whose answer depends on a temp path, fails here instead of
   producing a golden file that only matches on the machine that wrote
   it.

2. GOLDEN DIFF. The dump is diffed byte-for-byte against
   ``tests/replay/golden.json``. Any rule change that touches a finding
   shows up as an explicit diff; the baseline is updated with ``--update``
   in the SAME commit as the change that caused it (ground rule:
   baselines update together, never pinned counts).

3. MANIFEST ASSERTIONS. The content-addressed manifest (T-3.1) is
   load-bearing, not decorative: every TP entry must appear in the dump,
   every FN (pinned known miss) must NOT -- a rule change that starts
   finding a known miss fails until the miss is re-pinned deliberately --
   and any finding on a safe fixture (FP entry) fails with the word
   "false positive" in the reason.

OFFLINE BY CONTRACT
-------------------
Live feeds are forced off and the advisory cache is redirected to the
committed pin ``tests/replay/vuln_cache_pinned.json`` before any engine
imports run. The working copy's ``data/.vuln_cache.json`` churns with
every live scan (it is a cache, by design); a golden that depended on it
would diff on every machine that had scanned anything. The pin is the
committed subset that answers every SCA question the corpus asks.

EXIT CODES (mirror analysis.validation.run)
-------------------------------------------
    0   replayed, byte-identical, all manifest assertions hold
    1   determinism failure, golden drift, or an assertion violation
    2   nothing replayed (no labelled fixtures) -- never a pass
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_LOG = logging.getLogger("rsx.analysis.validation.replay")

REPO = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO / "tests" / "vuln-test-corpus"
DEFAULT_MANIFEST = REPO / "tests" / "replay" / "manifest.json"
DEFAULT_GOLDEN = REPO / "tests" / "replay" / "golden.json"
DEFAULT_PIN = REPO / "tests" / "replay" / "vuln_cache_pinned.json"

_GOLDEN_SCHEMA = "rsecopsx.corpus_replay/v1"

# The stable projection written to the golden. Everything excluded here is
# either machine-dependent (absolute temp paths, _source_finding) or pure
# duplication of fields the comparator never reads. Keeping the projection
# minimal is what makes "byte-identical" achievable across platforms.
_FINDING_FIELDS = ("rule_id", "class", "basename", "line", "severity",
                   "cwe", "evidence", "cve", "package", "version")


def _pin_advisory_state(pin_path: Path) -> None:
    """Force offline mode and repoint the advisory cache at the commit pin.

    Must run before any engine call. Sets the env var the product reads
    (``live_feeds_enabled``) and the module global ``query_osv_batch``
    loads its cache from. Also clears the module's cache memo so a
    previously imported tree cannot leak its state into the replay.
    """
    os.environ["RSECOPSX_LIVE_FEEDS"] = "0"
    from scanner import vulnerability_intel
    vulnerability_intel.CACHE_FILE = Path(pin_path)
    if hasattr(vulnerability_intel, "_CACHE_FETCHED"):
        vulnerability_intel._CACHE_FETCHED.clear()
    if hasattr(vulnerability_intel, "_CACHE_LOAD_FAILED"):
        vulnerability_intel._CACHE_LOAD_FAILED = False


def _scan_all(corpus_root: Path) -> dict:
    """Replay every labelled fixture through its own family engine.

    Dispatch is copied from ``run_corpus`` deliberately rather than
    imported: that function scores, this one collects. Sharing the
    dispatch table would couple a measurement loop to a serialization
    loop for no gain; the parity that matters is the engine calls, and
    those ARE shared (``_scan_*`` below are the same functions).
    """
    from analysis.validation import run as run_mod
    from analysis.validation.normalize import (
        normalize_finding, normalize_corpus_finding)  # noqa: F401 (parity)
    from analysis.validation.normalize import normalize_findings
    from analysis.validation.corpus import GroundTruthError

    root = Path(corpus_root)
    out: dict[str, dict] = {}
    problems: list[str] = []

    for family, case_dir, path in run_mod._iter_case_dirs(root):
        source = path.relative_to(root).as_posix()
        truth = run_mod._load_truth(path)
        if isinstance(truth, GroundTruthError):
            problems.append("%s: unparseable label: %s" % (source, truth))
            continue
        for problem in run_mod.validate_ground_truth(truth, path, root):
            problems.append("%s: invalid label: %s" % (source, problem))

        if family == "sca":
            actual = run_mod._scan_sca(case_dir)
        elif family in run_mod._SAST_FAMILIES:
            actual = normalize_findings(
                run_mod._scan_sast(case_dir, path.name), "rsecopsx")
        elif family == "secrets":
            actual = normalize_findings(
                run_mod._scan_secrets(case_dir, path.name), "rsecopsx")
        elif family == "iac":
            actual = normalize_findings(
                run_mod._scan_iac(case_dir, path.name), "rsecopsx")
        elif family == "cbom":
            actual = normalize_findings(
                run_mod._scan_cbom(case_dir, path.name), "cbom")
        elif family == "sbom":
            actual = run_mod._scan_sbom(case_dir, path.name)
        else:
            problems.append("%s: no engine for family %r" % (source, family))
            continue

        findings = sorted(
            (_project(f) for f in actual or []),
            key=lambda f: (f.get("basename") or "", f.get("line") or 0,
                           f.get("rule_id") or "", f.get("cve") or "",
                           f.get("package") or "", f.get("version") or "",
                           f.get("evidence") or ""),
        )
        out[source] = {"family": family, "findings": findings}

    if problems:
        raise ValueError("corpus is not replayable:\n" + "\n".join(problems))
    return out


def _project(finding: dict) -> dict:
    """Reduce a normalized finding to the golden's stable field set."""
    return {k: finding.get(k) for k in _FINDING_FIELDS}


def _dump(scan: dict, manifest_sha256: str) -> bytes:
    """Byte-stable golden document: sorted, LF, no timestamps."""
    import hashlib
    fixtures = [
        {"source": source,
         "family": scan[source]["family"],
         "findings": scan[source]["findings"]}
        for source in sorted(scan)
    ]
    doc = {
        "schema": _GOLDEN_SCHEMA,
        "manifest_sha256": manifest_sha256,
        "fixture_count": len(fixtures),
        "finding_count": sum(len(f["findings"]) for f in fixtures),
        "fixtures": fixtures,
    }
    from analysis.validation.manifest import canonical_json
    return canonical_json(doc)


def _manifest_assertions(scan: dict, manifest_doc: dict) -> list[str]:
    """Check TP/FN/FP claims against the replayed findings."""
    from analysis.validation.compare import identity

    problems: list[str] = []
    by_source: dict[str, list[dict]] = {}
    for entry in manifest_doc.get("entries") or []:
        by_source.setdefault(entry["source"], []).append(entry)

    for source, entries in sorted(by_source.items()):
        fixture = scan.get(source)
        if fixture is None:
            problems.append("%s: manifest entry for a fixture the replay"
                            " did not scan" % source)
            continue
        actual = fixture["findings"]

        for entry in entries:
            expected = entry["expected"]
            claim = {
                "rule_id": entry["rule_id"],
                "file": entry["source"].rsplit("/", 1)[-1],
                "line": entry["line"],
                "cwe": entry["cwe"],
                "class": None,
                "cve": entry.get("provenance", {}).get("cve"),
                "package": entry.get("provenance", {}).get("package"),
                "version": entry.get("provenance", {}).get("version"),
                "basename": entry["source"].rsplit("/", 1)[-1],
            }
            from analysis.validation.normalize import normalize_corpus_finding
            claim = normalize_corpus_finding(
                claim, claim["file"])
            claim_id = identity(claim)

            matched = [
                a for a in actual
                if identity(a) == claim_id
                and (entry["line"] == 0
                     or a.get("line") == entry["line"]
                     # SCA claims are line-less: identity is the CVE triple.
                     or claim_id[0] != "location")
            ]

            if expected == "TP" and not matched:
                problems.append(
                    "TP not detected: %s %s line %s (entry %s) -- the"
                    " engines no longer find a labelled expectation;"
                    " fix the rule or re-pin the miss in"
                    " tests/replay/known_misses.json" %
                    (source, entry["rule_id"], entry["line"], entry["id"]))
            elif expected == "FN" and matched:
                problems.append(
                    "known miss now detected: %s %s line %s (entry %s) --"
                    " the pinned miss got fixed; remove it from"
                    " tests/replay/known_misses.json and re-emit the"
                    " manifest + golden in this commit" %
                    (source, entry["rule_id"], entry["line"], entry["id"]))
            elif expected == "FP" and actual:
                problems.append(
                    "false positive on safe fixture: %s reports %d"
                    " finding(ies) but the manifest pins it FP (entry %s)"
                    % (source, len(actual), entry["id"]))
    return problems


def _first_diff(a: bytes, b: bytes, limit: int = 12) -> list[str]:
    lines_a = a.decode("utf-8", "replace").splitlines()
    lines_b = b.decode("utf-8", "replace").splitlines()
    out: list[str] = []
    for i in range(max(len(lines_a), len(lines_b))):
        la = lines_a[i] if i < len(lines_a) else "<EOF>"
        lb = lines_b[i] if i < len(lines_b) else "<EOF>"
        if la != lb:
            out.append("  line %d:\n    committed: %s\n    replayed:  %s"
                       % (i + 1, la[:160], lb[:160]))
            if len(out) >= limit:
                out.append("  ... (more differences elided)")
                break
    return out


def replay(corpus: Path | str = DEFAULT_CORPUS,
           manifest_path: Path | str = DEFAULT_MANIFEST,
           golden_path: Path | str = DEFAULT_GOLDEN,
           pin_path: Path | str = DEFAULT_PIN,
           update: bool = False) -> dict:
    """Run the full replay and return a machine-readable result dict."""
    import hashlib
    from analysis.validation.manifest import canonical_json

    corpus = Path(corpus)
    manifest_path = Path(manifest_path)
    golden_path = Path(golden_path)
    pin_path = Path(pin_path)

    result: dict = {
        "exit_code": 0,
        "problems": [],
        "deterministic": None,
        "counts": {},
    }

    if not corpus.is_dir():
        result["exit_code"] = 2
        result["problems"].append("corpus root does not exist: %s" % corpus)
        return result
    if not manifest_path.is_file():
        result["exit_code"] = 2
        result["problems"].append(
            "manifest missing: %s -- run tools/emit_corpus_manifest.py"
            % manifest_path)
        return result

    _pin_advisory_state(pin_path)

    manifest_bytes = manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    import json
    manifest_doc = json.loads(manifest_bytes.decode("utf-8"))

    try:
        scan_a = _scan_all(corpus)
        scan_b = _scan_all(corpus)
    except ValueError as exc:
        result["exit_code"] = 1
        result["problems"].append(str(exc))
        return result

    if not scan_a:
        result["exit_code"] = 2
        result["problems"].append(
            "NOTHING REPLAYED -- no labelled fixtures under %s."
            " This is not a pass." % corpus)
        return result

    dump_a = _dump(scan_a, manifest_sha256)
    dump_b = _dump(scan_b, manifest_sha256)
    result["deterministic"] = dump_a == dump_b
    if dump_a != dump_b:
        result["exit_code"] = 1
        result["problems"].append(
            "replay is not deterministic: two in-process runs produced"
            " different bytes")
        result["problems"].extend(_first_diff(dump_a, dump_b))
        return result

    result["counts"] = {
        "fixtures": len(scan_a),
        "findings": sum(len(f["findings"]) for f in scan_a.values()),
    }

    # 3. manifest assertions (independent of the golden, so a stale golden
    # cannot mask a TP the engines stopped finding).
    result["problems"].extend(_manifest_assertions(scan_a, manifest_doc))

    # 2. golden byte-diff.
    if update:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_bytes(dump_a)
        _LOG.info("updated golden: %s (%d fixtures, %d findings)",
                  golden_path, result["counts"]["fixtures"],
                  result["counts"]["findings"])
    elif not golden_path.is_file():
        result["problems"].append(
            "golden missing: %s -- run"
            " `python -m analysis.validation.replay --update` and commit"
            " the result" % golden_path)
    else:
        want = golden_path.read_bytes()
        if want != dump_a:
            result["problems"].append(
                "golden drift: %s differs from the replayed corpus (%d"
                " committed bytes vs %d replayed) -- if the change is"
                " intended, run --update and commit the golden with the"
                " change" % (golden_path, len(want), len(dump_a)))
            result["problems"].extend(_first_diff(want, dump_a))

    if result["problems"]:
        result["exit_code"] = 1
    return result


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(
        prog="python -m analysis.validation.replay",
        description="Deterministic corpus replay (T-3.2): scan the whole"
                    " corpus twice, require byte-identical output, diff"
                    " against the committed golden, and enforce the"
                    " content-addressed manifest's TP/FN/FP assertions.")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--golden", default=str(DEFAULT_GOLDEN))
    parser.add_argument("--pin", default=str(DEFAULT_PIN))
    parser.add_argument("--update", action="store_true",
                        help="rewrite the golden from this replay"
                             " (commit it with the change that caused it)")
    args = parser.parse_args(argv)

    result = replay(corpus=args.corpus, manifest_path=args.manifest,
                    golden_path=args.golden, pin_path=args.pin,
                    update=args.update)

    counts = result.get("counts") or {}
    print("replay: %d fixtures, %d findings, deterministic=%s"
          % (counts.get("fixtures", 0), counts.get("findings", 0),
             result.get("deterministic")))
    for problem in result["problems"]:
        print("PROBLEM: %s" % problem, file=sys.stderr)
    if result["exit_code"] == 0:
        print("replay OK -- byte-identical to golden, manifest holds")
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
