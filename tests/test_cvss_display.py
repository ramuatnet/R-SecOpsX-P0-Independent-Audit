"""The CVSS cell must say which version spoke, and never invent that it did.

Five display outcomes are reachable from real advisory data and all five are
pinned here so a later refactor cannot quietly collapse two of them. The one
collapse that would actually mislead a reader is ``--``: it means no
vulnerability exists, whereas "score unavailable" means one exists and its
severity is simply not published. Rendering the second as the first would
understate a live finding.
"""

import pytest

from reporting.report_mappings import format_cvss_assessment


# ------------------------------------------------------------ the five rules --
def test_no_vulnerability_is_a_dash():
    assert format_cvss_assessment("4.0", 6.9, has_vulnerability=False) == "--"


def test_version_and_score_together():
    assert format_cvss_assessment("4.0", 6.9) == "CVSS 4.0 — 6.9"
    assert format_cvss_assessment("3.1", 9.8) == "CVSS 3.1 — 9.8"
    assert format_cvss_assessment("3.0", 7.5) == "CVSS 3.0 — 7.5"


def test_number_published_without_a_version():
    assert format_cvss_assessment(None, 7.5) == "CVSS version unknown — 7.5"


def test_version_stated_but_no_score():
    assert format_cvss_assessment("4.0", None) == "CVSS 4.0 — score unavailable"


def test_neither_version_nor_score():
    assert format_cvss_assessment(None, None) == "CVSS score unavailable"


# ------------------------------------------------- unavailable is not a dash --
@pytest.mark.parametrize("version,score", [
    ("4.0", None),
    ("3.1", None),
    (None, None),
])
def test_a_live_finding_is_never_rendered_as_nothing(version, score):
    """Collapsing these two would understate a real vulnerability."""
    text = format_cvss_assessment(version, score, has_vulnerability=True)
    assert text != "--"
    assert "score unavailable" in text


def test_only_a_missing_vulnerability_earns_a_dash():
    assert format_cvss_assessment(None, None, has_vulnerability=False) == "--"
    assert format_cvss_assessment(None, None, has_vulnerability=True) != "--"


# ------------------------------------------------------------- no false version --
def test_unknown_is_not_a_version():
    """"UNKNOWN" is a truthy string; treating it as a version would print
    'CVSS UNKNOWN — 7.5', which reads as though a version had been named."""
    assert format_cvss_assessment("UNKNOWN", 7.5) == "CVSS version unknown — 7.5"
    assert format_cvss_assessment("", 7.5) == "CVSS version unknown — 7.5"
    assert format_cvss_assessment("N/A", 7.5) == "CVSS version unknown — 7.5"


def test_a_version_is_never_guessed_from_the_number():
    """A 7.5 could be 3.1 or 4.0. Only a stated version may be printed."""
    for score in (2.0, 7.5, 9.8, 10.0):
        assert format_cvss_assessment(None, score).startswith(
            "CVSS version unknown"
        )


def test_version_is_trimmed_but_not_invented():
    assert format_cvss_assessment(" 4.0 ", 6.9) == "CVSS 4.0 — 6.9"


# ------------------------------------------------------------------ real scores --
@pytest.mark.parametrize("version", ["4.0", "3.1", "3.0"])
def test_every_legal_score_renders_with_its_own_digits(version):
    """CVSS scores are defined to one decimal place, so formatting may only
    restate a value. Checked across the entire legal domain 0.0-10.0 rather
    than a sample: ':.1f' must never move a digit."""
    for step in range(0, 101):
        value = step / 10.0
        assert format_cvss_assessment(version, value) == f"CVSS {version} — {value:.1f}"


def test_zero_is_a_score_not_a_missing_value():
    assert format_cvss_assessment("4.0", 0.0) == "CVSS 4.0 — 0.0"
    assert format_cvss_assessment("4.0", 0.0) != "CVSS 4.0 — score unavailable"


def test_negative_and_out_of_range_numbers_are_not_scores():
    assert format_cvss_assessment("4.0", -1) == "CVSS 4.0 — score unavailable"
    assert format_cvss_assessment("4.0", 42) == "CVSS 4.0 — score unavailable"


@pytest.mark.parametrize("garbage", ["n/a", True, object(), b"7.5"])
def test_non_numeric_scores_are_not_scores(garbage):
    assert format_cvss_assessment("4.0", garbage) == (
        "CVSS 4.0 — score unavailable"
    )


def test_a_numeric_string_is_accepted():
    """Advisory feeds publish scores as strings as often as numbers."""
    assert format_cvss_assessment("3.1", "7.5") == "CVSS 3.1 — 7.5"


# ------------------------------------------------------------------- the glyph --
@pytest.mark.parametrize("version,score,expected", [
    ("4.0", 6.9, "CVSS 4.0 — 6.9"),
    (None, 7.5, "CVSS version unknown — 7.5"),
    ("4.0", None, "CVSS 4.0 — score unavailable"),
])
def test_uses_the_em_dash_the_report_glyph_set_covers(version, score, expected):
    assert format_cvss_assessment(version, score) == expected
    assert "\u2014" in expected
