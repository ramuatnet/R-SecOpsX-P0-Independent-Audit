"""Compare normalized findings against ground truth (Phase V0.2).

THE PROBLEM THIS SOLVES
----------------------
V0.1 measured the scanner with an ad-hoc script that required line-exact
matches. That was honest but crude, and it surfaced the cost in the results:
four findings on VulnerableServlet.java scored as extras even though the
scanner had found the correct vulnerability, anchored one line away from the
sink the label names. The label anchors at ``stmt.executeQuery(sql)``; the
rule fires at ``conn.createStatement()`` two lines above. Same defect, same
CWE, different line.

Neither side is wrong. The label chose the sink because that is where the
dangerous operation happens. The rule chose the statement construction
because that is where its pattern matches. Reporting those as four separate
misses would overstate the gap; matching them silently would understate it
and would also start crediting a rule that merely sat NEAR a real finding.

So matching is two-tiered, and the tolerance is explicit and reported.

HOW A FINDING IS IDENTIFIED
---------------------------
Two identities, chosen by what the finding is about:

    CVE      ``(package, version, cve)``     -- SCA findings are claims about
                                                a component, not about a line
    location ``(basename, CWE or class)``    -- SAST/secret/IaC findings are
                                                claims about a place in code

Rule ID is never the primary key. ``TAINT_SQL_INJECTION``,
``JAVA_JDBC_SQL_CONCAT`` and semgrep's ``java.lang.security.audit.sqli`` all
name the same defect, so a comparator keyed on their literal spelling would
report three detections of one finding. CWE is shared vocabulary; rule ID is
kept for reporting only.

For location matches the LINE is then compared within a tolerance. At the
default of 0 the comparator reproduces V0.1's strict behaviour exactly, so
nothing is hidden by the upgrade. At 1 it absorbs the anchor difference
above. The result of both is reported, because the difference between them
is itself the finding: a scanner that is right one line away from the sink
is not the same as a scanner that is right, and conflating them would hide a
real property of the rules.

WHY A MISS IS NEVER "FIXED" BY LOOSENING
----------------------------------------
A tolerance is not a scoring knob. Raising it until the numbers improve
would make the corpus agree with the tool, which is precisely the failure
V0.1 was built to prevent. The default is 0, tolerance is reported alongside
the strict figure, and neither is ever written back into a label.
"""
from __future__ import annotations

import logging
from typing import Any

_LOG = logging.getLogger("rsx.analysis.validation.compare")

# Identity kinds. A finding is either a claim about a component (CVE-backed)
# or a claim about a place in code (location-backed).
_KIND_CVE = "cve"
_KIND_COMPONENT = "component"
_KIND_LOCATION = "location"


def _norm(value: Any) -> str:
    """Lowercase and strip, so identity comparison is case-insensitive.

    Package names in particular differ in case across ecosystems and tools
    (``Django`` vs ``django``), and a case-sensitive comparison would report
    the same component twice.
    """
    return str(value).strip().lower() if value is not None else ""


def identity(finding: dict) -> tuple[str, tuple]:
    """The thing a finding claims to be true about.

    Returns ``(kind, key)``. Two findings with equal identities describe the
    same issue; the line then decides whether they are the SAME occurrence.

    A CVE-backed finding takes precedence over its location, because an SCA
    label may point at line 4 of a manifest while the tool reports no line at
    all. Requiring a line match there would score every SCA finding a miss
    against a tool that simply does not report lines -- which is what the
    first measurement did, and it was wrong for that reason.

    A package WITHOUT a CVE is a component inventory entry, and it gets its
    own kind rather than falling through to location. Location identity is
    ``(basename, class)``, so every component declared in one manifest shares
    a single key: ten packages would collapse to one identity, the dict below
    would keep only the last, and a nine-package manifest would be scored as
    one finding with eight unexplained extras. Two versions of the same
    package are separate claims too, which is why the version is in the key.
    """
    cve = _norm(finding.get("cve"))
    package = _norm(finding.get("package"))
    if cve and package:
        return (_KIND_CVE, (package, _norm(finding.get("version")), cve))
    if package and finding.get("version"):
        return (_KIND_COMPONENT,
                (package, _norm(finding.get("version"))))

    anchor = _norm(finding.get("class")) or _norm(finding.get("cwe")) \
        or _norm(finding.get("rule_id"))
    return (_KIND_LOCATION, (_norm(finding.get("basename")), anchor))


def _line_of(finding: dict) -> int | None:
    line = finding.get("line")
    if isinstance(line, int):
        return line
    return None


def _distance(a: dict, b: dict) -> int | None:
    """Line distance between two findings, or None if either has no line.

    None is distinct from a large number: "no line to compare" and "far
    apart" are different states, and treating the former as the latter would
    let a line-less tool finding match anything.
    """
    la, lb = _line_of(a), _line_of(b)
    if la is None or lb is None:
        return None
    return abs(la - lb)


def _matchable(expected: dict, actual: dict, line_tolerance: int) -> bool:
    """Whether one actual finding satisfies one expected finding."""
    if identity(expected) != identity(actual):
        return False

    dist = _distance(expected, actual)
    if dist is None:
        # One side carries no line. For a location-backed identity that is a
        # weaker match, not a free pass -- accept it, but only at the stated
        # tolerance, so a caller who wants line-exactness can set 0 and see
        # these fail rather than being quietly credited.
        return True
    return dist <= line_tolerance


def compare_findings(actual: list[dict], expected: list[dict],
                     line_tolerance: int = 0) -> dict:
    """Compare normalized actual findings against normalized ground truth.

    Returns ``tp`` / ``fp`` / ``fn`` plus precision, recall and F1.

    Matching is greedy on closeness: when several actual findings could
    satisfy one expected finding, the nearest line wins. That is deliberate.
    A first-come matcher would let an early far-away match consume the
    expectation, leaving the correct near match to be counted as a false
    positive -- reporting the scanner as both wrong and right for one finding.

    ``line_tolerance`` defaults to 0, which reproduces strict line-exact
    matching. Passing 1 absorbs the anchor difference between a rule's
    match site and a label's sink; the caller is expected to report both
    figures rather than only the flattering one.
    """
    actual = list(actual or [])
    expected = list(expected or [])

    pairs: list[tuple[int, dict, dict]] = []
    for exp_idx, exp in enumerate(expected):
        for act in actual:
            if not _matchable(exp, act, line_tolerance):
                continue
            dist = _distance(exp, act)
            # Sort key: matched pairs first by distance, then line-less pairs,
            # so a nearby hit always beats a distant one.
            pairs.append((0 if dist is not None else 1, dist or 0,
                          exp_idx, exp, act))

    pairs.sort(key=lambda p: (p[0], p[1]))

    used_actual: set[int] = set()
    matched_expected: set[int] = set()
    tp: list[dict] = []
    id_actual = [id(a) for a in actual]

    for _kind, _dist, exp_idx, exp, act in pairs:
        if exp_idx in matched_expected:
            continue
        act_slot = None
        for i, a in enumerate(actual):
            if id(a) == id(act) and i not in used_actual:
                act_slot = i
                break
        if act_slot is None:
            continue
        used_actual.add(act_slot)
        matched_expected.add(exp_idx)
        tp.append({
            "expected": exp,
            "actual": actual[act_slot],
            "identity": identity(exp),
            "line_delta": _distance(exp, actual[act_slot]),
        })

    fn = [e for i, e in enumerate(expected) if i not in matched_expected]
    fp = [a for i, a in enumerate(actual) if i not in used_actual]

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": _precision(len(tp), len(actual)),
        "recall": _recall(len(tp), len(expected)),
        "f1": _f1(_precision(len(tp), len(actual)), _recall(len(tp), len(expected))),
        "line_tolerance": line_tolerance,
        "counts": {
            "expected": len(expected),
            "actual": len(actual),
            "tp": len(tp),
            "fp": len(fp),
            "fn": len(fn),
        },
    }


def _precision(tp: int, actual: int) -> float:
    """tp / (tp + fp).

    Zero actual findings scores 0.0, not 1.0. Returning 1.0 for a tool that
    reported nothing would score perfect precision on silence, and a corpus
    whose "vulnerable" fixtures are all missed would then look well-tuned.
    """
    denom = tp + (actual - tp)
    return (tp / denom) if denom else 0.0


def _recall(tp: int, expected: int) -> float:
    """tp / (tp + fn). Zero expectations scores 0.0 for the same reason."""
    return (tp / expected) if expected else 0.0


def _f1(precision: float, recall: float) -> float:
    """Harmonic mean. Zero when either term is zero."""
    if not precision or not recall:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def classify_false_positives(result: dict,
                             max_duplicate_delta: int = 3) -> dict:
    """Split false positives into duplicates and spurious findings.

    WHY THIS EXISTS
    ---------------
    "18 false positives" is one number describing at least two unrelated
    problems, and they need different responses. Measuring
    VulnerableServlet.java showed why the distinction is not academic:

      L22  JAVA_JDBC_SQL_CONCAT              CWE-89   one line above L23
      L39  JAVA_TAINT_PATH_TRAVERSAL         CWE-22   one line below L38
      L48  JAVA_OBJECTINPUTSTREAM_DESERIAL.  CWE-502  two lines above L50
      L23  JAVA_J5_CMD                       CWE-78   nine lines from L32
      L23  JAVA_J5_PATH                      CWE-22   fifteen from L38
      L23  JAVA_J5_XSS                       CWE-79   no XSS label anywhere

    The first three report a vulnerability that IS already matched -- the
    same defect, found by a second rule or fired at the construction line as
    well as the sink. They are a DUPLICATION problem: the detection is right
    and the report should collapse them.

    The last three are different. They place a finding on a line that is not
    where that class occurs -- a CWE-78 attributed to the SQL injection line,
    a CWE-22 attributed to it as well, and an XSS finding on a file with no
    XSS at all. Those are SPURIOUS: the rule is firing somewhere it should
    not, and no amount of deduplication makes them correct.

    Both count as false positives in the metrics. Reporting them separately
    is what turns "47% precision" into an action.

    HOW A DUPLICATE IS DECIDED
    --------------------------
    A false positive is a duplicate when its identity matches a finding that
    WAS counted as a true positive AND its line is within
    ``max_duplicate_delta`` of that finding's line.

    The delta bound is the whole substance of the distinction and is not
    optional. Two CWE-89 findings fifteen lines apart in one method may be
    two separate injections, and calling the second a "duplicate" of the
    first would file a real missed finding under a heading that says the
    detection was already right. The default of 3 comfortably contains the
    observed same-defect cases (deltas of 1, 1 and 2) while sitting well
    clear of the spurious ones (9 and 15).
    """
    tp = result.get("tp") or []
    fp = result.get("fp") or []

    duplicates, spurious = [], []
    for act in fp:
        nearest, nearest_dist = None, None
        for pair in tp:
            matched_actual = pair.get("actual") or {}
            if identity(matched_actual) != identity(act):
                continue
            dist = _distance(matched_actual, act)
            if dist is None:
                continue
            if nearest_dist is None or dist < nearest_dist:
                nearest, nearest_dist = pair, dist

        if nearest is not None and nearest_dist <= max_duplicate_delta:
            duplicates.append({
                "finding": act,
                "line": _line_of(act),
                "rule_id": act.get("rule_id"),
                "cwe": act.get("cwe"),
                "duplicates_line": _line_of(nearest.get("actual") or {}),
                "duplicates_rule": (nearest.get("actual") or {}).get("rule_id"),
                "line_delta": nearest_dist,
            })
        else:
            # Either no finding of this identity was matched at all, or the
            # nearest one is too far to be the same defect. Both mean the
            # rule fired somewhere it should not have.
            spurious.append({
                "finding": act,
                "line": _line_of(act),
                "rule_id": act.get("rule_id"),
                "cwe": act.get("cwe"),
                "nearest_matched_delta": nearest_dist,
            })

    return {
        "duplicates": duplicates,
        "spurious": spurious,
        "duplicate_count": len(duplicates),
        "spurious_count": len(spurious),
        "max_duplicate_delta": max_duplicate_delta,
    }


def anchor_analysis(actual: list[dict], expected: list[dict]) -> dict:
    """Explain the gap between strict and tolerant matching.

    Every finding that fails a line-exact match but succeeds at a small
    tolerance is listed with its distance. That set is the useful output of
    this phase: it separates "the scanner did not find it" from "the scanner
    found it one line from where the label points", which are different
    findings and call for different responses.

    A large tolerance matching a lot of findings would be alarming rather
    than reassuring, since it would mean the rules fire anywhere near the
    vulnerability rather than at it, so distances are returned rather than
    summarised away.
    """
    strict = compare_findings(actual, expected, line_tolerance=0)
    tolerant = compare_findings(actual, expected, line_tolerance=2)

    strict_pairs = {(id(t["expected"]), id(t["actual"])) for t in strict["tp"]}
    recovered = [
        t for t in tolerant["tp"]
        if (id(t["expected"]), id(t["actual"])) not in strict_pairs
    ]

    return {
        "strict_recall": strict["recall"],
        "tolerant_recall": tolerant["recall"],
        "recovered_by_tolerance": len(recovered),
        "recoveries": [
            {
                "expected_line": _line_of(t["expected"]),
                "actual_line": _line_of(t["actual"]),
                "line_delta": t["line_delta"],
                "expected_rule": t["expected"].get("rule_id"),
                "actual_rule": t["actual"].get("rule_id"),
                "cwe": t["expected"].get("cwe"),
            }
            for t in recovered
        ],
    }
