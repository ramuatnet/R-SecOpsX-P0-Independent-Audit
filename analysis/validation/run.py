"""Run the golden corpus through the real engines and score it (Phase V0.2).

    python -m analysis.validation.run --corpus tests/vuln-test-corpus/sast/python
    python -m analysis.validation.run --corpus tests/vuln-test-corpus --tolerance 1

WHAT THIS DOES AND DOES NOT DO
------------------------------
It measures. It does not fix, and it does not adjust a label to match a tool.

That distinction is the whole point of the phase, so it is worth being blunt
about the failure this is designed to prevent. If scoring a corpus could
rewrite the corpus, then every detection gap would close itself: the tool
misses it, the label drops it, the next run is clean. A harness that does
that is not measuring anything -- it is recording what the tool happened to
do and calling it ground truth. Labels here are read-only, and a miss is
reported as a miss.

EACH FAMILY IS SCORED BY ITS OWN ENGINE
---------------------------------------
This is the correction that changed the V0.1 headline from 33% to 44%.

SAST and AI/ML findings come from ``scanner.sast.scan_directory``. SCA
findings do not exist in that engine at all -- they come from
``scanner.sbom.generate_sbom`` plus ``scanner.vulnerability_intel.query_osv_batch``.
Scanning a manifest with the SAST engine and reporting "no advisory found" is
true for every tool ever written, including a perfect one, so it measures
nothing. Two of the first measurement's four SCA "misses" were exactly that,
and the fixtures had to be renamed before the SBOM path could even see them.

EXIT CODES
----------
    0   scored something, gate passed
    1   scored something, gate failed
    2   scored nothing

Exit 2 exists so an empty corpus cannot read as a passing run. A gate that
returns success because it found nothing to check is worse than no gate.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_20, WINDOW_6, WINDOW_TOP_5
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_20, WINDOW_6, WINDOW_TOP_5

import argparse
import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

_LOG = logging.getLogger("rsx.analysis.validation.run")

if __package__ in (None, ""):  # allow `python -m analysis.validation.run`
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from analysis.validation import compare, metrics as _metrics  # noqa: E402
from analysis.validation.corpus import (  # noqa: E402
    CORPUS_ROOT, iter_labelled, validate_ground_truth)

# Families scored by the SAST engine. secrets, iac and cbom each have their
# OWN engines -- grouping them here scored those families against a scanner
# that does not implement them, which reports a coverage gap as a detection
# gap and is the same category error as scanning a manifest with the SAST
# engine to decide whether it has vulnerable dependencies.
_SAST_FAMILIES = {"sast", "ai_ml"}


def _setup_logging(verbose: bool) -> None:
    """Console handler only, at WARNING unless asked for more.

    The harness prints its table to stdout; logging to the console as well
    would interleave and make the table unreadable. File handlers are not
    added here because this is a measurement tool, not a scan -- it should
    leave no artefacts behind.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


# Families the corpus is organised into. Used to recognise a fixture's family
# from its own location, however deeply --corpus is nested.
FAMILIES = ("sast", "sca", "ai_ml", "secrets", "iac", "sbom", "cbom")


def _family_of(path: Path) -> str | None:
    """The family a fixture belongs to, found by name rather than by position.

    Two earlier attempts both looked right and were wrong:

    * ``rel.parts[0]`` relative to --corpus. With
      ``--corpus tests/vuln-test-corpus/sast/python`` the first component of
      a fixture's relative path is its own filename, so every fixture was
      reported as family "safe_app.py", matched no engine, and the run scored
      nothing while still printing a table of zeros. V0.4's acceptance
      criterion names that exact command.
    * the same thing after realising the filename problem -- because the
      relative path strips whatever --corpus already consumed, so with that
      root the family "sast" is not in the relative path at all.

    The family is a property of where the fixture lives on disk, so the
    search walks the full path, deepest-first. Deepest-first matters: a
    caller whose directory tree happens to contain a folder named "sca"
    somewhere above the corpus still resolves correctly, because the real
    family directory is nearer the fixture.
    """
    for part in reversed(path.parts):
        if part in FAMILIES:
            return part
    return None


def _iter_case_dirs(root: Path):
    """Yield (family, case_dir, fixture_path) for every labelled fixture.

    SCA cases are directories: each holds one manifest under its canonical
    filename, because ``generate_sbom`` locates manifests by glob and a file
    named ``vulnerable_package.json`` matches no glob at all.
    """
    for path, truth in iter_labelled(root):
        rel = path.relative_to(root)
        family = _family_of(path)
        yield family, path.parent, path


def _scan_sast(case_dir: Path, fixture_name: str) -> list[dict]:
    """Run the SAST engine over one case directory, in a temp copy.

    A temp copy is used so the scan cannot see the label files or anything
    else in the corpus that a real target would not contain. Scanning the
    corpus in place would let a fixture's own neighbour change its result.

    ``fixture_name`` restricts the result to that fixture. Without it, a
    directory holding both a safe and a vulnerable fixture scores each one
    against the other's findings: the safe fixture inherits every real bug
    beside it as a false positive, and the vulnerable fixture inherits the
    safe one's clean results as credit. One case directory holds two files,
    so this filter is load-bearing, not cosmetic.
    """
    from scanner.sast import scan_directory
    from scanner.walk import walk

    tmp = Path(tempfile.mkdtemp(prefix="rsx_val_"))
    try:
        for p, _s, _m in walk(case_dir, exts=None, ignore=frozenset(),
                              max_bytes=None):
            if not p.is_file() or p.name.endswith(".ground_truth.json"):
                continue
            # Copy only the fixture under test. Scanning the whole directory
            # and filtering afterwards would work too, but then the scan has
            # seen a neighbour file that a real target would not contain, and
            # any directory-wide rule could fire because of it.
            shutil.copy2(p, tmp / p.name)
        findings = scan_directory(str(tmp))
        return [f for f in findings
                if Path(str(f.get("file", ""))).name == fixture_name]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _scan_sca(case_dir: Path) -> list[dict]:
    """Run the SBOM + OSV path over one case directory.

    Returns canonical-shaped findings carrying package, version and CVE.
    Those three are the identity for SCA comparisons: an advisory is a claim
    about a component, not about a line, so ``line`` is deliberately left as
    whatever the manifest parser reports rather than being forced to match.
    """
    from scanner.sbom import generate_sbom
    from scanner.vulnerability_intel import query_osv_batch

    packages = generate_sbom(str(case_dir))
    if not packages:
        _LOG.warning("generate_sbom found no packages in %s", case_dir)
        return []

    findings: list[dict] = []
    # OSV mirrors one claim through several records: the same CVE arrives as
    # a GHSA and a PYSEC entry (prodtest measured 141 advisories for 136
    # CVEs). The product's report rows are one per vulnerable package keyed to
    # its primary CVE, so a mirrored record must not become a second finding
    # here -- the comparator counts it as a duplicate false positive that the
    # product never emits. Claims are collapsed by (package, version, CVE)
    # only: a CVE is a claim identifier, while two CVE-less records assert two
    # separate things and keep their existing per-record treatment.
    seen_claims: set[tuple[str, str, str]] = set()
    results = query_osv_batch(packages)
    if not isinstance(results, dict):
        _LOG.warning("query_osv_batch returned %s, expected a dict",
                     type(results).__name__)
        return []

    for key, vulns in results.items():
        if not vulns:
            continue
        try:
            _eco, name, version = key.split("|", 2)
        except ValueError:
            continue
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve = v.get("cve")
            if cve:
                claim = (name.strip().lower(), str(version).strip(),
                         str(cve).strip().lower())
                if claim in seen_claims:
                    continue
                seen_claims.add(claim)
            findings.append({
                "rule_id": v.get("id"),
                "class": None,
                "file": None,
                "basename": None,
                "line": None,
                "severity": v.get("severity"),
                "cwe": None,
                "evidence": v.get("summary") or v.get("id"),
                "cve": v.get("cve"),
                "package": name,
                "version": version,
                "_source": "rsecopsx",
                "_source_finding": v,
            })
    return findings


def _scan_secrets(case_dir: Path, fixture_name: str) -> list[dict]:
    """Run the secret-intelligence engine over one fixture, from a temp copy.

    TWO REASONS FOR THE TEMP COPY
    -----------------------------
    The same one ``_scan_sast`` uses: the scan must not see the label files or
    a neighbour fixture that a real target would not contain.

    The second is specific to this engine and is not cosmetic. The secrets
    engine gates its 13 known-signature rules (AWS_ACCESS_KEY, GITHUB_TOKEN,
    STRIPE_SECRET_KEY, SLACK_WEBHOOK, ...) behind
    ``not _is_nonproduction_context(path)``, and that predicate is true for
    any path containing a component named test, tests, fixture, fixtures,
    mock, spec, docs, example or their plurals -- case-insensitively. The
    corpus lives under ``tests/``, so from its own location not one
    provider-specific rule runs, and every fixture is scored as a miss for a
    reason that has nothing to do with whether the rule works.

    Proven, not assumed: scanning the identical bytes from a temp directory
    found AWS_ACCESS_KEY at line 2, GITHUB_TOKEN at 4, SLACK_WEBHOOK at 2,
    GITLAB_TOKEN at 1, HUGGINGFACE_TOKEN at 2, NPM_TOKEN at 2 and PYPI_TOKEN
    at 3 -- exactly the lines the labels name.

    WHAT THIS DOES NOT HIDE
    -----------------------
    Copying to temp scores the engine's DETECTION capability, which is what
    this corpus exists to measure. The gate itself is a real behaviour with a
    real consequence and is reported separately rather than being laundered
    away here: a genuine repository containing a ``tests/`` directory with a
    leaked AWS key in it will not have that key reported by the
    known-signature rules. That is a finding about the product, and this
    function must not be the place where it quietly stops existing.
    """
    from scanner.secret_intelligence import scan_secret_intelligence

    tmp = Path(tempfile.mkdtemp(prefix="rsx_secret_"))
    try:
        source = case_dir / fixture_name
        if not source.is_file():
            _LOG.warning("fixture %s not found in %s", fixture_name, case_dir)
            return []
        shutil.copy2(source, tmp / fixture_name)
        findings = scan_secret_intelligence(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if isinstance(findings, dict):
        findings = findings.get("secret_intelligence_findings") or []
    return list(findings or [])


def _scan_iac(case_dir: Path, fixture_name: str) -> list[dict]:
    """Run the IaC engine that matches the fixture's file type.

    Three separate scanners exist and none of them accepts the other's
    inputs: a Dockerfile is not Terraform and neither is a Kubernetes
    manifest. Dispatching on extension rather than calling all three keeps
    each fixture scored by the engine that is actually responsible for it --
    running the Kubernetes scanner over a Dockerfile and reporting "no
    privileged container found" would be true of every Dockerfile ever
    written.
    """
    from scanner.iac_docker import scan_docker
    from scanner.iac_kubernetes import scan_kubernetes
    from scanner.iac_terraform import scan_terraform

    name = fixture_name.lower()
    if name.endswith(".tf") or name.endswith(".tfvars"):
        scanner = scan_terraform
    elif "dockerfile" in name:
        # Matched as a substring, not a prefix: real Dockerfiles are routinely
        # named prod.Dockerfile or app.dockerfile, and a prefix test would
        # route those to the Kubernetes scanner, which would find no
        # privileged container in a Dockerfile and report a clean result.
        scanner = scan_docker
    elif name.endswith((".yaml", ".yml")):
        scanner = scan_kubernetes
    else:
        _LOG.warning("no IaC engine for %s; skipping", fixture_name)
        return []

    return [f for f in scanner(str(case_dir)) or []
            if Path(str(f.get("file", ""))).name == fixture_name]


def _scan_cbom(case_dir: Path, fixture_name: str) -> list[dict]:
    """Run the crypto-asset engine over one fixture.

    Returned unnormalized: CBOM records carry ``component`` and ``category``
    with no ``cwe`` and no ``rule_id``, so they are normalized through the
    dedicated ``cbom`` source rather than the rsecopsx one. Through
    ``rsecopsx`` every record would get the identity ``('location', (file,
    ''))`` and MD5 would be indistinguishable from RC4.
    """
    from scanner.cbom import generate_cbom

    return [f for f in generate_cbom(str(case_dir)) or []
            if Path(str(f.get("file", ""))).name == fixture_name]


def _scan_sbom(case_dir: Path, fixture_name: str) -> list[dict]:
    """Inventory every component ``generate_sbom`` derives from one manifest.

    This is a different question from the SCA family's. SCA asks "does this
    dependency have an advisory?"; SBOM asks "is this dependency reported at
    all?". Mixing them would score an inventory tool against a vulnerability
    corpus, and a component with no advisory -- correctly absent from an SCA
    run -- would then read as a miss.

    The CVE is therefore deliberately NOT copied through, even though
    ``generate_sbom`` has already resolved one for most packages. Carrying it
    would switch the finding's identity from component to CVE, while the label
    for an inventory entry carries no CVE at all; the two sides would then key
    on different things and every entry would score as both a miss and an
    extra. The advisory itself is measured by the sca family, which keeps it.

    ``manifest_line`` is where the declaration sits, but it is deliberately
    NOT carried into the finding. The comparator's line check would then
    compare a transitive dependency against the line its PARENT happens to be
    declared on -- ``generate_sbom`` reports jinja2 and werkzeug at line 1 of
    a requirements.txt whose line 1 reads ``flask==3.0.0`` -- and a correct
    inventory entry would fail for a line it has no business being on. Line 0
    is the schema's spelling for "not line-addressable", which is the honest
    description of an inventory entry: identity comes from the component, and
    two components declared on one line stay distinct without a line to tell
    them apart.
    """
    from scanner.sbom import generate_sbom

    packages = generate_sbom(str(case_dir))
    out: list[dict] = []
    for pkg in packages or []:
        if not isinstance(pkg, dict):
            continue
        manifest = Path(str(pkg.get("manifest_file") or "")).name
        if manifest != fixture_name:
            # A case directory may hold more than one manifest. Counting a
            # neighbour's components against this fixture would credit it with
            # findings it does not contain.
            continue
        out.append({
            "rule_id": "SBOM-COMPONENT-INVENTORY",
            "class": "SBOM-COMPONENT-INVENTORY",
            "file": fixture_name,
            "basename": fixture_name,
            "line": 0,
            "severity": None,
            "cwe": None,
            "evidence": pkg.get("name"),
            "cve": None,
            "package": pkg.get("name"),
            "version": pkg.get("version"),
        })
    return out


def run_corpus(corpus_root: Path, tolerance: int = 0,
               families: list[str] | None = None) -> dict:
    """Measure the corpus and return the aggregated result.

    Returns the metrics dict plus a ``details`` list carrying one entry per
    fixture, so the CLI can print misses and the caller can inspect them
    without re-running the engines.
    """
    root = Path(corpus_root)
    if not root.is_dir():
        raise FileNotFoundError("corpus root does not exist: %s" % root)

    comparisons: list[dict] = []
    details: list[dict] = []
    problems: list[str] = []

    for family, case_dir, path in _iter_case_dirs(root):
        if families and family not in families:
            continue

        truth = dict(_load_truth(path))
        for problem in validate_ground_truth(truth, path, root):
            problems.append(problem)
            _LOG.error("invalid label: %s", problem)

        expected_raw = truth.get("expected_findings") or []
        from analysis.validation.normalize import normalize_corpus_finding
        expected = [normalize_corpus_finding(f, path.name) for f in expected_raw]

        if family == "sca":
            # _scan_sca already emits canonical records; re-normalizing them
            # through "rsecopsx" would be harmless but would drop the package
            # and version fields that SCA identity depends on.
            actual = _scan_sca(case_dir)
        elif family in _SAST_FAMILIES:
            from analysis.validation.normalize import normalize_findings
            # The SAST engine returns its own rich finding shape: absolute
            # Windows paths, `snippet` rather than `evidence`, and no
            # canonical `class`. Passing those to the comparator raw is what
            # dropped measured recall from 44% to 11% -- the labels bucket by
            # canonical class (SAST-SQLI) while raw findings bucket by their
            # CWE (CWE-89), so the two sides never shared an identity and
            # every actual finding was counted as a false positive.
            actual = normalize_findings(
                _scan_sast(case_dir, path.name), "rsecopsx")
        elif family == "secrets":
            from analysis.validation.normalize import normalize_findings
            actual = normalize_findings(
                _scan_secrets(case_dir, path.name), "rsecopsx")
        elif family == "iac":
            from analysis.validation.normalize import normalize_findings
            actual = normalize_findings(
                _scan_iac(case_dir, path.name), "rsecopsx")
        elif family == "cbom":
            from analysis.validation.normalize import normalize_findings
            actual = normalize_findings(
                _scan_cbom(case_dir, path.name), "cbom")
        elif family == "sbom":
            # Inventory, not vulnerability matching. _scan_sca would report
            # only packages WITH advisories, so a component that is correctly
            # present but currently unvulnerable would read as a miss.
            actual = _scan_sbom(case_dir, path.name)
        else:
            _LOG.warning("no engine for family %r; skipping %s", family, path.name)
            continue

        result = compare.compare_findings(actual, expected,
                                          line_tolerance=tolerance)
        fp_split = compare.classify_false_positives(result)
        result["fp_classification"] = fp_split
        result["fixture"] = path.name
        result["family"] = family
        result["language"] = _metrics.language_of(expected[0]) if expected \
            else _metrics.language_of(actual[0] if actual else {})

        sevs = {e.get("severity") for e in expected if e.get("severity")}
        result["severity_context"] = sorted(sevs)[0] if len(sevs) == 1 else None

        comparisons.append(result)
        details.append({
            "fixture": path.name,
            "family": family,
            "expected": len(expected),
            "actual": len(actual),
            "tp": result["counts"]["tp"],
            "fp": result["counts"]["fp"],
            "fn": result["counts"]["fn"],
            "missed": [
                {"line": e.get("line"), "cwe": e.get("cwe"),
                 "rule_id": e.get("rule_id"), "package": e.get("package"),
                 "cve": e.get("cve")}
                for e in expected
                if not any(compare.identity(e) == compare.identity(a)
                           and (compare._distance(e, a) is None
                                or compare._distance(e, a) <= tolerance)
                           for a in actual)
            ],
            "extra": [
                {"line": a.get("line"), "rule_id": a.get("rule_id"),
                 "cwe": a.get("cwe"), "severity": a.get("severity")}
                for a in actual
                if not any(compare.identity(e) == compare.identity(a)
                           and (compare._distance(e, a) is None
                                or compare._distance(e, a) <= tolerance)
                           for e in expected)
            ],
            "duplicates": fp_split["duplicates"],
            "spurious": fp_split["spurious"],
            "duplicate_count": fp_split["duplicate_count"],
            "spurious_count": fp_split["spurious_count"],
        })

    result = _metrics.metrics(comparisons)
    result["details"] = details
    result["problems"] = problems
    result["tolerance"] = tolerance
    return result


def _load_truth(path: Path) -> dict:
    label = path.with_name(path.name + ".ground_truth.json")
    if not label.is_file():
        label = path.with_name("ground_truth.json")
    if not label.is_file():
        return {}
    try:
        data = json.loads(label.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.error("cannot read %s: %s", label, exc)
        return {}
    if isinstance(data, dict) and "expected_findings" not in data:
        return data.get(path.name) or {}
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="analysis.validation.run",
        description="Score the golden corpus against the real engines.")
    parser.add_argument("--corpus", default=str(CORPUS_ROOT),
                        help="corpus root, or a subdirectory of it")
    parser.add_argument("--tolerance", type=int, default=0,
                        help="line tolerance for location matches (default 0)")
    parser.add_argument("--family", action="append", dest="families",
                        help="restrict to a family; repeatable")
    parser.add_argument("--json", action="store_true",
                        help="emit the full result as JSON")
    parser.add_argument("--max-gaps", type=int, default=12,
                        help="how many gap classes to name")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--triage", metavar="REPORT",
                        help="triage a clean_report.json instead of scoring "
                             "the corpus: classify every finding as "
                             "LIKELY_FP / NEEDS_REVIEW / LIKELY_REAL from "
                             "the FP families the live test suite documents")
    parser.add_argument("--brain", action="store_true",
                        help="run the security brain instead of scoring the "
                             "corpus: six levels of self-validation "
                             "(static integrity, control gates, loop "
                             "invariants, shape invariants, adversarial, "
                             "meta) against the scanner's own controls")
    parser.add_argument("--brain-levels", default=None,
                        help="comma-separated subset for --brain, e.g. L1,L4")
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    if args.triage:
        from .triage_report import main as _triage_main

        return _triage_main(["--report", args.triage])

    if args.brain:
        from .brain import main as _brain_main

        extra = ["--levels", args.brain_levels] if args.brain_levels else []
        return _brain_main(extra)

    root = Path(args.corpus)
    if not root.is_absolute():
        root = (Path.cwd() / root).resolve()

    try:
        result = run_corpus(root, tolerance=args.tolerance,
                            families=args.families)
    except FileNotFoundError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(_jsonable(result), indent=2, default=str))
        return _exit_code(result)

    print("Golden corpus: %s" % root)
    if result["problems"]:
        print("\n%d INVALID LABELS -- these are corpus defects, not detection"
              " gaps:" % len(result["problems"]))
        for p in result["problems"][:WINDOW_20]:
            print("  %s" % p)

    print()
    print(_metrics.format_table(result))

    gaps = _metrics.summarise_gaps(result, max_items=args.max_gaps)
    if gaps:
        print()
        print(gaps)

    dup_total = sum(d.get("duplicate_count", 0) for d in result["details"])
    spur_total = sum(d.get("spurious_count", 0) for d in result["details"])
    print()
    print("false positives, split by cause:")
    if not (dup_total or spur_total):
        # A clean corpus still gets the section: silence reads like the
        # report forgot to look, and the split IS the actionable part.
        print("  none        0   every finding matches a label and no")
        print("               %s   defect is reported twice" % "")
    else:
        print("  duplicates   %3d   the defect WAS found; a second rule or a" % dup_total)
        print("               %3s   second line reports it again" % "")
        print("  spurious     %3d   the rule fired where the defect is not" % spur_total)
        print()
        print("  duplicates are a reporting problem -- the detection was")
        print("  right. Spurious findings are a rule problem -- deduplication")
        print("  would not make them correct.")
        for d in result["details"]:
            if not d.get("duplicate_count") and not d.get("spurious_count"):
                continue
            print()
            print("  %s" % d["fixture"])
            for dup in d.get("duplicates", [])[:WINDOW_TOP_5]:
                print("    duplicate L%-4s %-42s same as L%s (%s apart)"
                      % (dup.get("line"), dup.get("rule_id"),
                         dup.get("duplicates_line"), dup.get("line_delta")))
            for spur in d.get("spurious", [])[:WINDOW_TOP_5]:
                print("    spurious  L%-4s %-42s %s"
                      % (spur.get("line"), spur.get("rule_id"), spur.get("cwe")))

    if result["details"]:
        missed = [d for d in result["details"] if d["fn"]]
        if missed:
            print()
            print("misses by fixture:")
            for d in missed:
                print("  %-30s %d of %d missed" % (d["fixture"], d["fn"],
                                                   d["expected"]))
                for m in d["missed"][:WINDOW_6]:
                    if m.get("package"):
                        print("      %-30s %s" % (m["package"], m.get("cve")))
                    else:
                        print("      L%-5s %-10s %s"
                              % (m.get("line"), m.get("cwe"), m.get("rule_id")))

    return _exit_code(result)


def _exit_code(result: dict) -> int:
    """2 when nothing was scored, 1 when the gate failed, 0 otherwise.

    An empty run exits 2 rather than 0. A gate that succeeds because it found
    nothing to check is worse than no gate: it reports health that was never
    established, and it keeps reporting it after the corpus breaks.
    """
    if not _metrics.has_expectations(result):
        print("\nNOTHING SCORED -- the corpus root contains no labelled"
              " fixtures. This is not a pass.", file=sys.stderr)
        return 2
    if result["problems"]:
        return 1
    return 0


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj


if __name__ == "__main__":
    raise SystemExit(main())
