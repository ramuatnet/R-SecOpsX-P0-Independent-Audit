"""Tests for mojibake removal and for the restored attack-path content.

Two defects, both found by reading generated output rather than source:

MOJIBAKE. `Security_Report.pdf` and `Security_Executive_Report.pdf` both carried
`(U+00C3 U+00A2 U+00C5 U+201C U+00C2 U+00A6; triple-encoded U+2726)` three times, in the top-root-causes remediation note. Unravelling the
round trips gives U+2726 BLACK FOUR POINTED STAR -- a decorative list marker that
was UTF-8-decoded as cp1252 and re-encoded three times. Three layers were wrong:

  1. the literal in reporting/pdf_report.py, plus 62 more occurrences in 7 files
  2. `clean_mojibake`, a 9-entry lookup table that only handled
     single-round-trip forms and so could not have fixed a triple-encoded token
     -- and which was imported by two renderers and called ZERO times
  3. nothing at the render boundary to catch anything slipping through

ATTACK-PATH CONTENT. Fixing the publication defect (G-106) removed three things
the old report genuinely had: the risk score column vanished, the narrative went
empty, and the title degraded to a rule identifier. `get_attack_paths` never
propagated the finding's own fields -- which were all present and already
computed -- so the view correctly reported "absent" and the renderer correctly
omitted the column. Omitting was honest; leaving it absent when the number was one
lookup away was not.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.attack_graph import (  # noqa: E402
    _ap_narrative,
    _ap_risk,
    _ap_weakness,
    get_attack_paths,
)
from reporting.report_mappings import clean_mojibake, mojibake_score  # noqa: E402

TRIPLE = "\u00c3\u00a2\u00c5\u201c\u00c2\u00a6"        # decodes to U+2726
DOUBLE_QUOTE = "\u00e2\u0080\u0099"                      # decodes to U+2019

# Signatures that indicate a UTF-8 -> cp1252 -> UTF-8 round trip.
SIGNATURES = ("\ufffd", "\u00c3\u0082", "\u00c3\u0083", "\u00c2\u00a2",
              "\u00e2\u0080", "\u00e2\u20ac", "\u00c3\u00a2", "\u00c2\u00ac",
              "\u00f0\u017e")


def looks_dirty(text: str) -> bool:
    return any(sig in text for sig in SIGNATURES)


# ===========================================================================
# 1. Source is clean
# ===========================================================================

def test_no_production_source_contains_mojibake():
    """NEGATIVE and load-bearing: the corruption started in the source."""
    SKIP = {"backup", "dump", "quarantine", "__pycache__", ".git",
            "node_modules", ".venv", "venv", "build", "dist",
            "Working folder"}
    offenders = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in {".py", ".json", ".md"}:
            continue
        if any(seg in SKIP for seg in p.parts):
            continue
        try:
            t = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if looks_dirty(t):
            offenders.append(p.relative_to(ROOT).as_posix())
    assert not offenders, f"mojibake in: {offenders[:10]}"


def test_the_offending_literal_is_gone():
    src = (ROOT / "reporting" / "pdf_report.py").read_text(encoding="utf-8")
    assert TRIPLE not in src
    assert "- Fixing this root cause" in src or \
        "Fixing this root cause" in src


# ===========================================================================
# 2. The cleaner actually works, and is SAFE
# ===========================================================================

def test_cleaner_repairs_a_triple_encoded_token():
    """The 9-entry table this replaced could not have handled this."""
    dirty = TRIPLE + " Fixing this root cause"
    assert mojibake_score(dirty) > 0
    out = clean_mojibake(dirty)
    assert mojibake_score(out) == 0
    assert looks_dirty(out) is False
    assert "Fixing this root cause" in out


def test_cleaner_repairs_single_and_double_round_trips():
    for dirty in (DOUBLE_QUOTE + "it" + DOUBLE_QUOTE + "s",
                  "\u00e2\u20ac\u0153 dash",
                  "\u00c3\u00a2\u00c2\u00a2 arrow"):
        out = clean_mojibake(dirty)
        assert mojibake_score(out) < mojibake_score(dirty) or \
            not looks_dirty(out), dirty


@pytest.mark.parametrize("text", [
    "plain ascii",
    "caf\u00e9 na\u00efve r\u00e9sum\u00e9",       # legitimate accents
    "\u4e2d\u6587\u6587\u4ef6\u540d",               # CJK filename
    "\u0440\u0443\u0441\u0441\u043a\u0438\u0439",   # Cyrillic
    "100% \u2265 90 \u00b1 5",
])
def test_cleaner_leaves_legitimate_non_ascii_alone(text):
    """NEGATIVE and load-bearing.

    A cleaner that mangles real non-ASCII is worse than no cleaner: it would
    corrupt legitimate filenames in an inventory. The acceptance test -- only
    accept a decode that strictly reduces the signature count -- is what makes
    this safe, so it is asserted directly rather than assumed.
    """
    assert clean_mojibake(text) == text


def test_cleaner_is_idempotent():
    dirty = TRIPLE + " x " + DOUBLE_QUOTE
    once = clean_mojibake(dirty)
    assert clean_mojibake(once) == once


@pytest.mark.parametrize("bad", [None, 42, [], {}])
def test_cleaner_tolerates_non_strings(bad):
    assert clean_mojibake(bad) == bad


def test_cleaner_is_actually_called_at_the_render_boundary():
    """It was imported by two renderers and called ZERO times, which is how a
    triple-encoded token reached a finished PDF."""
    src = (ROOT / "reporting" / "pdf_report.py").read_text(encoding="utf-8")
    assert "clean_mojibake(" in src
    calls = [ln for ln in src.splitlines()
             if "clean_mojibake(" in ln and not ln.lstrip().startswith("def ")]
    assert calls, "clean_mojibake is imported/defined but never called"


# ===========================================================================
# 3. Attack-path content is restored, not invented
# ===========================================================================

FINDING = {
    "finding_id": "abc", "rule_id": "TAINT_SQL_INJECTION",
    "title": "SQL Injection", "severity": "Medium", "risk_score": 70.5,
    "cwe": "CWE-89", "vuln_type": "sql_injection", "confidence": "HIGH",
    "exploitability": "High", "file": "app/api/__init__.py", "line": 68,
    "evidence_valid": True,
    "taint_path": "route parameter {x} -> query -> db.find(",
}


def test_risk_is_read_from_the_finding_not_defaulted():
    """`finding.get("risk_score", 0)` is how a fabricated "Risk: 0" shipped."""
    assert _ap_risk(FINDING) == 70.5
    assert _ap_risk({**FINDING, "risk_score": "70.5"}) == 70.5
    assert _ap_risk({**FINDING, "risk_score": None}) is None
    assert _ap_risk({}) is None
    assert _ap_risk({"risk_score": ""}) is None
    assert _ap_risk({"risk_score": True}) is None, "a bool is not a score"


def test_title_prefers_the_human_readable_finding_title():
    assert _ap_weakness(FINDING) == "SQL Injection"
    assert _ap_weakness({"rule_id": "X_Y"}) == "X_Y"
    assert _ap_weakness({}) == "Unclassified weakness"


def test_emitted_path_carries_the_findings_own_fields():
    out = get_attack_paths([FINDING])[0]
    assert out["title"] == "Attack Path: SQL Injection"
    assert out["severity"] == "Medium"
    assert out["risk_score"] == 70.5
    assert out["cwe"] == "CWE-89"
    assert out["file"] == "app/api/__init__.py"
    assert out["line"] == 68
    assert len(out["narrative"]) > 80


def test_rule_id_stays_traceable_as_a_field():
    """The title becomes human-readable; the rule id must remain available.

    Asserted as a FIELD rather than as a substring of the title, because the
    point is traceability, not that the title should keep showing raw ids. An
    earlier version asserted `"TAINT_SQL_INJECTION" in out`, which checks dict KEYS
    -- a dict-membership mistake that passed for the wrong reason and then failed
    when read correctly.
    """
    out = get_attack_paths([FINDING])[0]
    assert out["rule_id"] == "TAINT_SQL_INJECTION"


def test_narrative_quotes_only_observed_fields():
    n = get_attack_paths([FINDING])[0]["narrative"]
    assert "SQL Injection" in n
    assert "CWE-89" in n
    assert "route parameter {x}" in n            # the real source
    assert "db.find(" in n                       # the real sink
    assert "app/api/__init__.py:68" in n         # the real location


def test_confirmed_narrative_does_not_claim_live_exploitability():
    n = _ap_narrative(FINDING, ["a", "b"], True)
    assert "does NOT assert that the chain is exploitable" in n
    assert "reachability of this chain is established" in n


def test_candidate_narrative_says_reachability_is_not_established():
    n = _ap_narrative(FINDING, ["a", "b"], False)
    assert "Reachability is NOT established" in n
    assert "not an observed data flow" in n


def test_narrative_is_not_a_fabricated_scenario():
    """NEGATIVE: no invented exploit narrative.

    A per-vulnerability prose table would describe outcomes this scan never
    observed. Every clause must be traceable to a field, so the assertion is that
    the sink and source actually appear rather than that the prose reads well.
    """
    f = {**FINDING, "title": "SQL Injection", "sinkless": True}
    n = _ap_narrative(f, ["request param", "cursor.execute"], True)
    assert "request param" in n and "cursor.execute" in n
    # No claim about an outcome the record does not carry.
    for invented in ("database was accessed", "credentials were stolen",
                     "data was exfiltrated", "attacker gained"):
        assert invented not in n.lower(), invented


def test_no_zero_risk_score_is_ever_emitted():
    for f in (FINDING, {**FINDING, "risk_score": None}, {}):
        out = get_attack_paths([f])
        for a in out:
            assert a.get("risk_score") is None or a.get("risk_score") != 0


def test_title_never_degrades_to_a_bare_rule_id():
    out = get_attack_paths([FINDING])[0]
    assert out["title"] == "Attack Path: SQL Injection"
    assert not out["title"].endswith(out["rule_id"])
    # Traceability is carried as a FIELD. An earlier version asserted
    # `"TAINT_SQL_INJECTION" in out`, which tests dict KEYS -- it was checking
    # membership in the record's keys, not the value of a field, so it neither
    # tested what it claimed nor would have caught a dropped rule id.
    assert out["rule_id"] == "TAINT_SQL_INJECTION"


# ===========================================================================
# 4. Against the real artifact, when present
# ===========================================================================

ART = pathlib.Path(
    r"D:\Data\Code test\prodtest\reports\ai_benchmarks\babyagi-main"
    r"\clean_report.json")


@pytest.mark.skipif(not ART.exists(), reason="babyagi artifact not present")
def test_real_artifact_paths_are_complete():
    payload = json.loads(ART.read_text(encoding="utf-8", errors="replace"))
    paths = payload.get("attack_paths") or []
    assert paths, "no attack paths in the artifact"
    for p in paths:
        for key in ("title", "severity", "risk_score", "narrative", "cwe",
                    "file", "line", "path"):
            assert p.get(key) not in (None, ""), (key, p)
        assert p.get("risk_score") != 0
        assert len(p["path"]) >= 2


@pytest.mark.skipif(not ART.exists(), reason="babyagi artifact not present")
def test_real_artifact_has_no_junk_characters():
    """The artifact was already clean; the corruption was in the renderer. This
    guards the data side so a future change cannot introduce it there either."""
    text = ART.read_text(encoding="utf-8", errors="replace")
    assert not looks_dirty(text)