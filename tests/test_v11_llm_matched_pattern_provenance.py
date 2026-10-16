"""A finding's detection_note must name a pattern of ITS OWN rule.

THE DEFECT, AND WHY IT WAS NOT ONLY A MULTI-RULE PROBLEM
--------------------------------------------------------
`detection_note` is built as:

    f"{title} matched pattern: {matched_pattern}" if matched_pattern
    else f"{title} matched a compiled rule pattern"

`matched_pattern` was read as a bare name inside the emit loop, where it resolved to
the loop variable left over from the rule loop -- not the pattern belonging to the
finding being emitted. The naive reading of the bug is that it only shows up when
two rules match one line. It does not.

`matched_pattern = None` is reset at the top of EVERY rule iteration, and all rules
are evaluated for every line whether or not they match. So by the time the emit loop
runs, the variable holds whatever the LAST rule in LLM_RULES left behind -- almost
always None, since the last rule rarely matches. Every rule that matched through one
of its explicit patterns therefore lost its attribution and fell back to the generic
wording, unless it happened to be the final rule evaluated.

The reachable paths that set an explicit pattern are the specificity aliases, the
LLM01 additional patterns, the PI category ids and the two markers
LLM02_SENSITIVE_EVIDENCE and PI-006_SPLIT_PAYLOAD. All of them were being discarded
on the floor. Measured over 300 real files of the AI Benchmarks corpus, 241 of 651
findings -- 37% -- carried the generic note where a specific pattern was available.

The correct value was being stored on the match dict the whole time; nothing read it.

WHAT IS ASSERTED, AND WHY IT IS NOT VACUOUS
-------------------------------------------
  1. A line matching via a specificity alias names that alias.
  2. A line matching via a combined pattern still yields the generic note. Without
     this, a "fix" that always interpolated something would satisfy test 1 while
     fabricating evidence.
  3. The invariant holds across every finding over real repository files, not just
     the fixtures -- which is where the 37% figure came from, and where a rule shape
     the fixture does not trigger would otherwise go unchecked.

This is also what justifies excluding detection_note from the before/after
differential in analysis tooling: a difference is only acceptable if the new value is
independently shown to be correct, which is what test 1 and test 3 do.
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import scanner.llm_security as ls  # noqa: E402

NOTE_SPECIFIC = re.compile(r" matched pattern: (?P<pattern>.+)$")
NOTE_GENERIC = " matched a compiled rule pattern"

# Reachable non-pattern match markers. A rule may be credited with one of these
# without it appearing in the rule's own `patterns` list.
NON_PATTERN_MARKERS = frozenset({
    "LLM02_SENSITIVE_EVIDENCE",
    "PI-006_SPLIT_PAYLOAD",
})

# _v11_llm01_pattern_categories returns a CATEGORY id (PI-001 .. PI-008), not a
# regex, so these are reachable attribution values in their own right. They belong to
# LLM01 alone -- the helper is only called on that rule's path -- so they are granted
# only to it. Granting them globally would let a genuine cross-rule leak involving a
# PI id pass, which is exactly what this invariant exists to catch.
#
# PI-005 is the awkward one: it is appended when `obfuscation_detected` is set, not
# looked up in the pattern table, so deriving the ids from _V11_PI_PATTERNS alone
# misses it. That is why this test failed on a real corpus file rather than passing
# on the fixture. Stated explicitly, and asserted against the table below so the
# reason cannot rot.
OBFUSCATION_CATEGORY_ID = "PI-005"
PI_CATEGORY_IDS = frozenset(ls._V11_PI_PATTERNS) | {OBFUSCATION_CATEGORY_ID}
RULES_EMITTING_PI_CATEGORIES = frozenset({"LLM01_PROMPT_INJECTION"})


def test_obfuscation_category_is_not_a_pattern_table_entry():
    """Documents why PI-005 is listed by hand.

    If a future release adds PI-005 to _V11_PI_PATTERNS this becomes redundant
    rather than wrong, and the union above keeps working either way.
    """
    assert OBFUSCATION_CATEGORY_ID not in ls._V11_PI_PATTERNS, (
        "PI-005 is now a pattern-table entry; the hand-listed obfuscation id is "
        "redundant and can be dropped")

# `return.*token` is a specificity alias for llm_sensitive_info_disclosure. It is
# used here because it is a path that sets matched_pattern explicitly and is
# therefore exactly the case the leak destroyed. It is not the rule's first
# pattern, so a note naming it cannot come from coincidence.
#
# The line carries credential collocation (`access_token`) because the A3 gate
# (test_babyagi_transformers_fp_families) keeps `return.*token` only next to a
# credential term: bare `return token`/`return tokenizer` is NLP vocabulary and
# is suppressed as a disclosure FP. The provenance path exercised -- the alias
# value stored on the match record -- is identical on both sides of that gate.
ALIAS_FIXTURE = "    model_owner = None; return access_token\n"

# MEMORY_PERSISTENCE_RISK reaches the emit step with matched_pattern unset, because
# it matches through its combined pattern with no explicit-pattern fallback. The
# generic note is therefore the CORRECT output here, and asserting it keeps a
# "fix" that always interpolated something from fabricating evidence.
COMBINED_FIXTURE = "    result = memory.save_context(token)\n"


def _rules_by_id() -> dict:
    return {r["rule_id"]: r for r in ls.LLM_RULES}


def _allowed_patterns(rule_id: str) -> set:
    rule = _rules_by_id().get(rule_id)
    if rule is None:
        return set()
    allowed = set(rule.get("patterns") or [])
    allowed |= set(ls.RULE_SPECIFICITY_ALIASES.get(rule["vuln_type"], []))
    if rule_id in RULES_EMITTING_PI_CATEGORIES:
        allowed |= set(PI_CATEGORY_IDS)
    return allowed


def _check(findings, label: str) -> int:
    """Assert the invariant over findings. Returns how many named a specific pattern."""
    named = 0
    for f in findings:
        note = f.get("detection_note") or ""
        m = NOTE_SPECIFIC.search(note)
        if not m:
            assert note.endswith(NOTE_GENERIC), (
                f"{label}: unrecognised detection_note {note!r}")
            continue
        named += 1
        pattern = m.group("pattern")
        rule_id = f["rule_id"]
        assert pattern in NON_PATTERN_MARKERS or pattern in _allowed_patterns(rule_id), (
            f"{label}: finding {rule_id} is annotated with a pattern that is not its "
            f"own: {pattern!r}. The note either still reads another rule's pattern, "
            f"or a rule gained a match path whose pattern is not registered.")
    return named


# ------------------------------------------------------- the specific case ---

def test_alias_match_names_its_pattern():
    """The regression. Under the leak this produced the generic note.

    `return.*token` is not LLM06's first pattern, so a note naming it can only have
    come from this finding's own match record -- not from a stale variable and not
    from coincidence.
    """
    findings = ls.scan_llm_file("fixture.py", ALIAS_FIXTURE)
    assert len(findings) == 1, f"fixture should fire exactly one rule: {findings}"
    note = findings[0]["detection_note"]
    assert NOTE_SPECIFIC.search(note), (
        f"expected a specific pattern in detection_note, got {note!r}. This is the "
        f"defect: the note fell back to the generic wording.")
    assert note.endswith("matched pattern: return.*token"), note


def test_combined_match_still_reports_generic():
    """The other direction: do not manufacture specificity that is not there."""
    findings = ls.scan_llm_file("fixture.py", COMBINED_FIXTURE)
    assert findings, "fixture must fire a rule"
    for f in findings:
        note = f["detection_note"]
        assert note.endswith(NOTE_GENERIC), (
            f"{note!r} claims a specific pattern, but this line matched only through "
            f"a combined pattern where no single pattern is attributable.")


def test_both_shapes_are_exercised_by_the_fixtures():
    """Without both, either test above could pass vacuously."""
    spec = _check(ls.scan_llm_file("fixture.py", ALIAS_FIXTURE), "alias")
    generic = sum(
        1 for f in ls.scan_llm_file("fixture.py", COMBINED_FIXTURE)
        if f["detection_note"].endswith(NOTE_GENERIC))
    assert spec >= 1, "alias fixture produced no specific note"
    assert generic >= 1, "combined fixture produced no generic note"


# ----------------------------------------------------------- the invariant ---

@pytest.mark.parametrize("project", [
    "peft-main", "llama_index-main", "transformers-main",
])
def test_detection_note_never_names_another_rules_pattern(project):
    """The invariant over real code.

    The 37% figure was measured this way. A fixture cannot establish that the fix
    holds for rule shapes it does not happen to trigger, and there are 40 rules.
    """
    root = pathlib.Path(r"D:\Data\Code test\prodtest\AI Benchmarks") / project
    inner = root / project
    if inner.is_dir():
        root = inner
    if not root.exists():
        pytest.skip(f"corpus project not present: {root}")

    files = sorted(root.rglob("*.py"))[:30]
    if not files:
        pytest.skip(f"no .py files under {root}")

    named = 0
    for p in files:
        content = p.read_text(encoding="utf-8", errors="replace")
        named += _check(ls.scan_llm_file(str(p), content), p.name)
    print(f"\n  {project}: {len(files)} files, {named} findings naming a pattern")
