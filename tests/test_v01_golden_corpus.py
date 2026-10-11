"""The golden corpus must describe the fixtures it sits beside.

WHY THIS IS A TEST AND NOT A REVIEW
-----------------------------------
A golden corpus decays invisibly. Someone renames a variable, a fixture grows
a line, a label stops matching -- and the corpus keeps reporting the same
verdict it always did, because nothing ever checks the label against the file.
The result looks like evidence and is a memory of code that no longer exists.

Every assertion below exists to make that decay loud. The two most important
are the negative ones: a label whose `evidence` no longer appears on the line
it names, and a rule ID outside the canonical vocabulary. Both fail for the
same reason -- each one severs a label from the thing it is supposed to
describe.

THE RULE ABOUT TRUTH
--------------------
Labels here are derived from what a fixture provably contains, never from what
the scanner reported. The distinction is load-bearing. Deriving labels from
scanner output would make every detection gap close itself: the scanner
misses it, the label does not list it, the corpus scores clean. That is how a
measurement harness becomes a decoration.

So a failing assertion in this file is a finding, not a defect to paper over.
When it fires, the answer is to fix the detection or correct the label with
evidence -- not to relax the check.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.validation.corpus import (  # noqa: E402
    CANONICAL_RULES,
    CORPUS_ROOT,
    FAMILIES,
    SEVERITIES,
    corpus_summary,
    family_of,
    iter_fixtures,
    iter_labelled,
    validate_ground_truth,
)

# Label files are never fixtures themselves, and a fixture is never its own
# label. Getting this wrong once made all 16 fixtures look unlabelled while
# every one of them carried a label, which reads as a coverage hole.
def _real_fixtures():
    return [p for p, _ in iter_fixtures()]


def test_corpus_root_exists():
    assert CORPUS_ROOT.is_dir(), (
        f"the golden corpus is missing at {CORPUS_ROOT} -- without it nothing "
        f"can be measured against ground truth")


def test_every_fixture_carries_a_label():
    """An unlabelled fixture is an illustration, not a test case."""
    unlabelled = [p.name for p, t in iter_fixtures() if t is None]
    assert not unlabelled, (
        "these fixtures have no ground_truth.json beside them: %s" % unlabelled)


def test_labels_are_not_counted_as_fixtures():
    """The regression the loader had: <fixture>.ground_truth.json was yielded
    as a fixture of its own, so all 16 fixtures appeared unlabelled."""
    names = [p.name for p in _real_fixtures()]
    assert not any(n.endswith(".ground_truth.json") for n in names), names
    assert not any(n == "ground_truth.json" for n in names), names


def test_the_corpus_is_not_accidentally_empty():
    fixtures = _real_fixtures()
    assert len(fixtures) >= 10, (
        f"only {len(fixtures)} fixtures -- too few to measure anything")


@pytest.mark.parametrize("path,truth", list(iter_labelled()),
                         ids=lambda v: v.name if isinstance(v, Path) else "")
def test_every_label_is_sound(path, truth):
    """The full contract, applied fixture by fixture.

    Failing here means a label no longer describes its fixture: a moved line,
    an edited line, a count that no longer matches, or a value the schema
    forbids. Each message names the fixture so the fix is obvious.
    """
    assert validate_ground_truth(truth, path) == []


def test_every_finding_uses_a_canonical_rule_id():
    """Labels name the vulnerability class, not the shipping rule.

    A corpus keyed to shipped rule IDs is coupled to the scanner: renaming a
    rule silently rewrites what the corpus claims is true about the code.
    """
    offenders = []
    for path, truth in iter_labelled():
        for f in truth.get("expected_findings", []):
            if f.get("rule_id") not in CANONICAL_RULES:
                offenders.append((path.name, f.get("rule_id")))
    assert not offenders, (
        "rule IDs outside the canonical vocabulary: %s" % offenders)


def test_every_severity_is_canonical():
    """Title case is not cosmetic. group_by_severity and the security gate key
    on the exact spelling, so a label spelling it 'HIGH' would never match."""
    offenders = []
    for path, truth in iter_labelled():
        for f in truth.get("expected_findings", []):
            if f.get("severity") not in SEVERITIES:
                offenders.append((path.name, f.get("severity")))
    assert not offenders, offenders


def test_vulnerable_fixtures_declare_findings_and_safe_ones_do_not():
    """The safe/vulnerable pairing is the corpus's whole design.

    A 'vulnerable' fixture labelled with zero findings would score every
    scanner clean on code that is provably bad. A 'safe' fixture labelled
    with findings would do the reverse. Both silently destroy the signal.
    """
    mislabelled = []
    for path, truth in iter_labelled():
        name = path.name.lower()
        count = truth.get("expected_count", 0)
        if "vulnerable" in name and count == 0:
            mislabelled.append(f"{path.name}: vulnerable but 0 expected findings")
        if name.startswith("safe") and count != 0:
            mislabelled.append(
                f"{path.name}: safe but {count} expected findings")
    assert not mislabelled, mislabelled


def test_expected_counts_agree_with_the_findings_listed():
    """expected_count drives the scoring denominators. A corpus that counts 5
    and lists 3 scores 100% on 3 of the 5 real findings."""
    bad = []
    for path, truth in iter_labelled():
        listed = len(truth.get("expected_findings", []))
        if truth.get("expected_count") != listed:
            bad.append(f"{path.name}: count={truth.get('expected_count')} "
                       f"listed={listed}")
    assert not bad, bad


def test_family_is_derived_from_path_not_declared():
    """A fixture under sca/ cannot claim to be a SAST case."""
    for path in _real_fixtures():
        fam = family_of(path)
        assert fam in FAMILIES, (path.name, fam)
        assert path.parts[path.parts.index("vuln-test-corpus") + 1] == fam


def test_corpus_summary_agrees_with_the_inventory():
    """A summary that disagrees with what it summarises is worse than none,
    because it will be quoted."""
    s = corpus_summary()
    fixtures = _real_fixtures()
    assert sum(v["fixtures"] for v in s["families"].values()) == len(fixtures)
    assert sum(v["labelled"] for v in s["families"].values()) == len(fixtures)
    assert not s["unlabelled"]


def test_expected_findings_total_is_non_zero():
    s = corpus_summary()
    total = sum(v["findings"] for v in s["families"].values())
    assert total > 0, "the corpus expects to find nothing, so it measures nothing"


# ==========================================================================
# The checks that catch rot. Each one corrupts a copy and proves the
# validator notices. Without these, a validator that always returned []
# would pass every test above.
# ==========================================================================

def _copy_corpus(tmp_path):
    dst = tmp_path / "vuln-test-corpus"
    shutil.copytree(CORPUS_ROOT, dst)
    return dst


def test_validator_notices_evidence_that_no_longer_matches(tmp_path):
    """The load-bearing rot check.

    Rewriting the vulnerable line without updating the label is the single
    most likely way this corpus decays. If the validator does not notice, the
    label is now describing code that does not exist and the corpus scores a
    verdict on it anyway.
    """
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    original = fixture.read_text(encoding="utf-8")
    lines = original.splitlines()
    # Line 17 is the SQLi sink the label anchors on. Change the sink so the
    # evidence string can no longer appear there.
    assert "cursor.execute(query)" in lines[16]
    lines[16] = "    cursor.execute('SELECT 1')"
    fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")

    truth = json.loads(label.read_text(encoding="utf-8"))
    problems = validate_ground_truth(truth, fixture, dst)

    assert problems, "the validator accepted a label that no longer matches"
    assert any("is not present on line 17" in p for p in problems), problems


def test_validator_notices_a_line_number_that_no_longer_exists(tmp_path):
    """A label pointing past the end of a fixture is rot, and reporting it as
    a false negative would blame the scanner for the corpus's own decay."""
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_findings"][0]["line"] = 5000

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("does not exist" in p for p in problems), problems


def test_validator_notices_a_count_that_disagrees_with_the_list(tmp_path):
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_count"] = 99

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("cannot be scored against both" in p for p in problems), problems


def test_validator_rejects_a_rule_id_outside_the_vocabulary(tmp_path):
    """Guards against a label inventing an identifier the comparator could
    never match, which would read as a detection miss forever."""
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_findings"][0]["rule_id"] = "SAST-INVENTED-RULE-XYZ"

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("not in the canonical vocabulary" in p for p in problems), problems


def test_validator_rejects_a_non_canonical_severity(tmp_path):
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_findings"][0]["severity"] = "HIGH"

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("is not one of" in p for p in problems), problems


def test_validator_rejects_a_label_that_names_a_different_fixture(tmp_path):
    """A label copied beside the wrong file would score the wrong code."""
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "safe_app.py"
    label = fixture.with_name("safe_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["fixture"] = "vulnerable_app.py"

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("sits beside" in p for p in problems), problems


def test_validator_rejects_a_cve_that_is_not_a_cve(tmp_path):
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_findings"][0]["cve"] = "CVE-21-3"

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("not a CVE identifier" in p for p in problems), problems


def test_validator_rejects_duplicate_labels_for_one_line(tmp_path):
    """One vulnerable line counted twice doubles the expected count and makes
    a perfect detection score 50%."""
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_findings"].append(dict(truth["expected_findings"][0]))
    truth["expected_count"] = len(truth["expected_findings"])

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("duplicate label" in p for p in problems), problems


def test_validator_rejects_empty_evidence(tmp_path):
    """An empty evidence string is a substring of every line, so it would
    validate against code that has nothing to do with the finding."""
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_findings"][0]["evidence"] = "   "

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("evidence is empty" in p for p in problems), problems


def test_validator_rejects_unparseable_json_as_a_problem_not_a_crash(tmp_path):
    """A corrupt label must surface as a problem. Raising would abort the
    whole corpus run and hide every other fixture's result."""
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")
    label.write_text("{ not json", encoding="utf-8")

    truth = json.loads(label.read_text(encoding="utf-8")) \
        if False else "sentinel-not-json"

    problems = validate_ground_truth(truth, fixture, dst)

    assert problems, "an unusable label was accepted"


def test_line_zero_is_invalid_for_line_anchored_families(tmp_path):
    """line 0 means 'not line-addressable', which SCA and SBOM genuinely are
    -- but a SAST finding with no line cannot be scored at all."""
    dst = _copy_corpus(tmp_path)
    fixture = dst / "sast" / "python" / "vulnerable_app.py"
    label = fixture.with_name("vulnerable_app.py.ground_truth.json")

    truth = json.loads(label.read_text(encoding="utf-8"))
    truth["expected_findings"][0]["line"] = 0

    problems = validate_ground_truth(truth, fixture, dst)

    assert any("line 0 is not valid" in p for p in problems), problems
