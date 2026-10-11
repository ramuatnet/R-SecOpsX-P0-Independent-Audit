"""Golden-corpus contract for technique validation (Phase V0.1).

WHY THIS EXISTS
---------------
Before this package there was no way to ask "does the scanner find what is
actually there?". ``tests/vuln-test-corpus/`` held 16 hand-written fixtures
that pair a safe and a vulnerable implementation, and not one of them carried
a single label. A fixture without ground truth is an illustration: it reads
convincingly, and it proves nothing.

The label file turns each fixture into an assertion. ``ground_truth.json``
states what the scanner MUST find in the adjacent input file, keyed to an
exact line, so a missed detection becomes a measurable false negative instead
of an opinion.

WHAT COUNTS AS GROUND TRUTH HERE
--------------------------------
A label is only admissible when its truth does not come from the scanner.
Three of the four families below take their truth from outside this repo:

    sca/       OSV. ``reports/.vuln_cache.json`` carries 380 pinned
               package/version pairs with real advisories attached
               (112 PyPI, 261 npm, 7 Maven). The labels are copied from
               those records, so the corpus is anchored to a database that
               published its answer before the scanner existed.
    sast/      The fixture itself. Each vulnerable line is stated by the
               code's own behaviour (a query built by f-string, a sink
               taking request data). ``rule_id`` is a real shipped
               identifier -- JAVA_JDBC_SQL_CONCAT, GO_EXEC_SH_C,
               PHP_COMMAND_INJECTION -- not a name invented for the label.
    iac/       The configuration's own semantics (privileged: true, a
               0.0.0.0/0 ingress, an unpinned base image), matched to the
               rule that exists to detect exactly that condition.

The fourth family, secrets/, is the one that cannot be sourced externally and
is therefore labelled with the *format* rule the detector itself claims to
implement -- which makes it a test of the implementation, not of the world.

WHAT THIS MODULE GUARDS AGAINST
-------------------------------
The failure mode of a golden corpus is rot: fixtures drift, line numbers
move, and the labels quietly stop describing the file beside them. Every
check here exists because a label that no longer matches its fixture is worse
than no label at all, since it manufactures a clean bill of health from a
stale claim.

So validation is structural AND textual:

    * ``expected_count`` must equal ``len(expected_findings)`` -- a corpus
      that counts 5 findings and lists 3 cannot be scored.
    * every ``line`` must exist in the fixture -- a label pointing at line
      118 of a 45-line file is rot, not a false negative.
    * every ``evidence`` string must actually appear on the line it names.
      This is the load-bearing check. It means a label cannot describe
      code that is not there, and it fails loudly the moment someone edits
      a fixture without re-deriving its truth.

``evidence`` is a substring, deliberately: requiring the whole line would
make labels brittle against whitespace, while requiring nothing would let a
label survive a rewrite that changed the vulnerability itself.

USAGE
-----
    from analysis.validation.corpus import (
        CORPUS_ROOT, iter_fixtures, validate_ground_truth)

    for fixture, truth in iter_fixtures():
        problems = validate_ground_truth(truth, fixture)
        ...
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CORPUS_ROOT = Path(__file__).resolve().parents[2] / "tests" / "vuln-test-corpus"

# The technique families the scanner actually implements. A fixture outside
# these is not ignored -- it is a layout error worth surfacing.
FAMILIES = ("sast", "sca", "secrets", "iac", "sbom", "cbom", "ai_ml")

# Canonical severities. Title case is not cosmetic: group_by_severity and the
# security gate both key on the exact spelling, so a label spelling it
# "HIGH" would never match the finding it is meant to score.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

GROUND_TRUTH_NAME = "ground_truth.json"

# Per-fixture label files are named "<fixture>.ground_truth.json", because one
# directory holds both a safe and a vulnerable fixture and a bare
# ground_truth.json would have to name its fixture anyway.
LABEL_SUFFIX = "." + GROUND_TRUTH_NAME

# Canonical rule vocabulary.
#
# Labels name the VULNERABILITY CLASS, not the rule that happens to detect it.
# The two are not interchangeable: a corpus whose labels carry shipped rule IDs
# is silently coupled to the scanner, so adding or renaming a rule rewrites what
# the corpus says is true about the code. SAST-SQLI means "this line executes
# SQL built from untrusted input" whether JAVA_TAINT_SQL_INJECTION, TAINT_SQL_INJECTION
# or nothing at all reports it -- which is what makes an undetected class show up
# as a false negative instead of disappearing.
#
# Mapping shipped rule IDs onto this vocabulary is V0.2's normalizer job.
CANONICAL_RULES = frozenset({
    # SAST / CBOM / AI-ML
    "SAST-SQLI",        # CWE-89   SQL built from untrusted input, then executed
    "SAST-CMDI",        # CWE-78   a shell or process spawned with untrusted args
    "SAST-PATH",        # CWE-22   a filesystem path assembled from untrusted input
    "SAST-DESER",       # CWE-502  untrusted data deserialised into objects/code
    "SAST-CODEINJ",     # CWE-94   eval/exec or a template built from untrusted input
    "SAST-HARDCRED",    # CWE-798  a credential literal committed to source
    "SAST-XSS",         # CWE-79   untrusted data written into a response unsafely
    "SAST-DEBUG",       # CWE-215  a debug/verbose switch left on for production
    # SCA
    "SCA-VULN-DEP",     # a pinned dependency version carrying a known advisory
    # Secrets
    "SECRET-PROVIDER-KEY",  # a key whose format identifies its provider
    "SECRET-CONFIG-PASSWORD",  # a credential literal in a config/connection string
    "SECRET-DECOY",     # a placeholder that must NOT be reported as a live secret
    # IaC -- named by the CONDITION, not by the rule that detects it, for the
    # same reason the SAST classes are. Several rules detect one condition
    # (TF_OPEN_SECURITY_GROUP_INGRESS and TF_OPEN_IPV6_INGRESS are both
    # "reachable from the internet"), so a vocabulary of rule IDs would report
    # them as separate classes and hide that the condition is covered twice.
    # Each class below groups the rules that share a CWE, and the CWE is what
    # the shipped rules already carry -- so the grouping is read off the
    # scanner's own table rather than invented here.
    "IAC-PUBLIC-EXPOSURE",        # CWE-284  resource reachable from the internet
    "IAC-UNENCRYPTED-STORAGE",    # CWE-311  data at rest not encrypted
    "IAC-OVERBROAD-PERMISSIONS",  # CWE-732/266  grant wider than the task needs
    "IAC-PRIVILEGED-CONTAINER",   # CWE-250/269  runs elevated, or as root
    "IAC-UNPINNED-IMAGE",         # CWE-1104  base image not fixed to a version
    "IAC-INSECURE-DOWNLOAD",      # CWE-494  remote content fetched unchecked
    "IAC-HOST-NAMESPACE-SHARING", # CWE-668  pod shares the host network/PID/IPC
    "IAC-EXPOSED-SERVICE",        # CWE-1008/200  a management service in the image
    "IAC-RESOURCE-EXHAUSTION",    # CWE-770  no CPU/memory limits on the container
    # CBOM -- the engine reports a crypto component and a CATEGORY, with no
    # CWE and no rule id at all, so these classes are the only identity a CBOM
    # finding has. Without them every CBOM finding in a file would share one
    # empty identity and the comparator could not tell MD5 from RC4.
    "CBOM-WEAK-HASH",             # a broken hash (MD5, SHA-1)
    "CBOM-WEAK-CIPHER",           # a broken cipher (DES/3DES, RC4)
    "CBOM-APPROVED-CIPHER",       # a healthy cipher, inventoried not flagged
    "CBOM-ASYMMETRIC-KEY",        # an asymmetric algorithm in use
    "CBOM-TRANSPORT-CRYPTO",      # a TLS/SSL configuration in use
    "CBOM-HARDCODED-KEY",         # key material embedded in the source
    "CBOM-HARDCODED-CERT",        # a certificate embedded in the source
    # SBOM -- an inventory entry is a claim that a component is present, which
    # is neither a weakness nor a line. Without a class of its own every
    # inventory label would have to borrow a vulnerability class and assert a
    # defect the manifest does not have.
    "SBOM-COMPONENT-INVENTORY",   # a declared component, reported as present
})

# Families whose findings are anchored to a source line. SCA and SBOM findings
# are properties of a manifest or of the dependency graph, so line 0 legitimately
# means "not line-addressable" for them.
LINE_ANCHORED_FAMILIES = frozenset({"sast", "iac", "secrets", "cbom", "ai_ml"})

# A label is not allowed to name a fixture that does not exist, and an
# evidence string of "" matches every line by accident.
REQUIRED_KEYS = ("fixture", "expected_findings", "expected_count")
FINDING_KEYS = ("rule_id", "file", "line", "severity", "cwe", "evidence")


class GroundTruthError(ValueError):
    """Raised only by strict callers; the normal path returns problem lists."""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def iter_fixtures(root: Path | None = None):
    """Yield ``(fixture_path, ground_truth_dict)`` for every labelled fixture.

    A fixture is any file under the corpus that is not itself a label, a
    README, or a ``__pycache__`` entry. Fixtures with no ``ground_truth.json``
    beside them are yielded with ``None`` so the caller can decide whether
    "unlabelled" is acceptable. Silently skipping them is how a corpus ends
    up measuring a shrinking subset while reporting the same totals.
    """
    root = Path(root or CORPUS_ROOT)
    if not root.is_dir():
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts:
            continue
        # Two label spellings are accepted, and BOTH must be skipped here or
        # the labels are counted as fixtures they belong to. That is not a
        # cosmetic slip: it makes every fixture appear unlabelled while the
        # corpus is in fact fully labelled, which reads as a coverage gap
        # rather than as the bookkeeping error it is.
        if path.name == GROUND_TRUTH_NAME:
            continue
        if path.name.endswith(LABEL_SUFFIX):
            continue
        if path.name.upper().startswith("README"):
            continue

        label = path.with_name(LABEL_SUFFIX.join([path.name, ""]))
        if not label.is_file():
            # The aggregate-per-directory spelling, kept so a corpus written
            # that way is still discovered rather than silently dropped.
            label = path.with_name(GROUND_TRUTH_NAME)
        truth = None
        if label.is_file():
            try:
                truth = json.loads(label.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                truth = GroundTruthError(f"{label.name}: unparseable JSON: {exc}")
            else:
                # An aggregate maps fixture name -> truth doc. Resolve it to
                # this fixture's own document so callers never see the map.
                if (isinstance(truth, dict) and "expected_findings" not in truth
                        and path.name in truth):
                    truth = truth[path.name]

        yield path, truth


def iter_labelled(root: Path | None = None):
    """Yield ``(fixture_path, ground_truth_dict)`` for labelled fixtures only."""
    for path, truth in iter_fixtures(root):
        if truth is not None:
            yield path, truth


def family_of(path: Path, root: Path | None = None) -> str | None:
    """Technique family a fixture belongs to, from its position in the tree.

    Derived from the path rather than declared in the label, so a fixture
    filed under ``sca/`` cannot claim to be a SAST case.
    """
    root = Path(root or CORPUS_ROOT)
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    parts = rel.parts
    return parts[0] if parts and parts[0] in FAMILIES else None


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_RE = re.compile(r"^CWE-\d+$")


def validate_ground_truth(truth, fixture: Path, root: Path | None = None) -> list[str]:
    """Return a list of problems. An empty list means the label is sound.

    Every message names the fixture so a failing corpus test points at a file
    rather than at an assertion deep in a loop.
    """
    where = fixture.name
    problems: list[str] = []

    if isinstance(truth, GroundTruthError):
        return [str(truth)]
    if not isinstance(truth, dict):
        return [f"{where}: ground truth must be a JSON object, got "
                f"{type(truth).__name__}"]

    for key in REQUIRED_KEYS:
        if key not in truth:
            problems.append(f"{where}: missing required key '{key}'")
    if problems:
        return problems

    declared = truth["fixture"]
    if declared != fixture.name:
        problems.append(
            f"{where}: label names fixture '{declared}' but sits beside "
            f"'{fixture.name}'")

    findings = truth["expected_findings"]
    if not isinstance(findings, list):
        problems.append(
            f"{where}: expected_findings must be a list, got "
            f"{type(findings).__name__}")
        return problems

    count = truth["expected_count"]
    if count != len(findings):
        problems.append(
            f"{where}: expected_count={count} but {len(findings)} findings "
            f"are listed -- the corpus cannot be scored against both")

    if not isinstance(count, int) or count < 0:
        problems.append(f"{where}: expected_count must be a non-negative int")
        return problems

    try:
        lines = fixture.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        problems.append(f"{where}: cannot read fixture: {exc}")
        return problems

    family = family_of(fixture, root)

    seen_keys: set[tuple] = set()
    for i, f in enumerate(findings):
        tag = f"{where}#findings[{i}]"

        if not isinstance(f, dict):
            problems.append(f"{tag}: must be an object, got {type(f).__name__}")
            continue

        for key in FINDING_KEYS:
            if key not in f:
                problems.append(f"{tag}: missing '{key}'")
        if any(p.startswith(tag) for p in problems):
            continue

        if not str(f["rule_id"]).strip():
            problems.append(f"{tag}: rule_id is empty")
        elif f["rule_id"] not in CANONICAL_RULES:
            problems.append(
                f"{tag}: rule_id {f['rule_id']!r} is not in the canonical "
                f"vocabulary. Labels name the vulnerability class, not the "
                f"shipping rule -- see analysis.validation.corpus.CANONICAL_RULES")

        sev = f["severity"]
        if sev not in SEVERITIES:
            problems.append(
                f"{tag}: severity {sev!r} is not one of {SEVERITIES}")

        cwe = f["cwe"]
        if cwe is not None and not _CWE_RE.match(str(cwe)):
            problems.append(f"{tag}: cwe {cwe!r} is not a CWE identifier")

        cve = f.get("cve")
        if cve is not None and not _CVE_RE.match(str(cve)):
            problems.append(f"{tag}: cve {cve!r} is not a CVE identifier")

        line_no = f["line"]
        if not isinstance(line_no, int) or line_no < 0:
            problems.append(f"{tag}: line must be a non-negative int, got "
                            f"{line_no!r}")
            continue

        declared_file = str(f["file"])
        if family != "sca" and Path(declared_file).name != fixture.name:
            problems.append(
                f"{tag}: file {declared_file!r} does not match the fixture "
                f"it labels")

        # A SAST/secrets/iac label names a line in source it must be able to
        # point at. SCA and SBOM findings are properties of a manifest or of
        # the dependency graph as a whole, so line 0 legitimately means
        # "not line-addressable" -- see the schema note in the module
        # docstring.
        #
        # The fixture-name check above deliberately runs BEFORE this branch.
        # It used to sit after, so a line-0 label -- which every SCA and SBOM
        # label is -- skipped it along with the evidence and duplicate checks.
        # A label could then name a file that does not exist beside it and be
        # reported as sound, because the only check that would have caught it
        # was unreachable for exactly the families that use line 0.
        if line_no == 0:
            if family in LINE_ANCHORED_FAMILIES:
                problems.append(
                    f"{tag}: line 0 is not valid for the {family} family")
            continue

        if line_no > len(lines):
            problems.append(
                f"{tag}: line {line_no} does not exist "
                f"(fixture has {len(lines)} lines)")
            continue

        evidence = str(f["evidence"]).strip()
        if not evidence:
            problems.append(f"{tag}: evidence is empty")
            continue

        actual = lines[line_no - 1]
        if evidence not in actual:
            problems.append(
                f"{tag}: evidence {evidence!r} is not present on line "
                f"{line_no} of {fixture.name}, which reads {actual.strip()!r}"
                " -- the label no longer describes this fixture")

        key = (f["rule_id"], f["file"], line_no)
        if key in seen_keys:
            problems.append(
                f"{tag}: duplicate label for {key} -- one vulnerable line "
                f"must not be counted twice")
        seen_keys.add(key)

    expected_cves = truth.get("expected_cves", [])
    if not isinstance(expected_cves, list):
        problems.append(f"{where}: expected_cves must be a list")
    else:
        for cve in expected_cves:
            if not _CVE_RE.match(str(cve)):
                problems.append(
                    f"{where}: expected_cves holds {cve!r}, not a CVE identifier")
        listed = {f.get("cve") for f in findings if isinstance(f, dict)}
        listed.discard(None)
        missing = set(expected_cves) - listed
        if missing:
            problems.append(
                f"{where}: expected_cves claims {sorted(missing)} but no "
                f"finding carries them")

    return problems


def corpus_summary(root: Path | None = None) -> dict:
    """Counts per family, and how many fixtures carry no label at all."""
    root = Path(root or CORPUS_ROOT)
    per_family: dict[str, dict[str, int]] = {}
    unlabelled: list[str] = []

    for path, truth in iter_fixtures(root):
        fam = family_of(path, root) or "(unfiled)"
        bucket = per_family.setdefault(fam, {"fixtures": 0, "labelled": 0,
                                             "findings": 0})
        bucket["fixtures"] += 1
        if truth is None:
            unlabelled.append(str(path.relative_to(root)))
            continue
        bucket["labelled"] += 1
        if isinstance(truth, dict):
            findings = truth.get("expected_findings") or []
            if isinstance(findings, list):
                bucket["findings"] += len(findings)

    return {"families": per_family, "unlabelled": unlabelled}
