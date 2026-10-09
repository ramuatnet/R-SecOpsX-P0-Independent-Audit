"""A CVSS score must never be shown under a version that did not produce it.

The platform prefers CVSS 4.0 when an advisory publishes it, but the number
printed next to that label has to be *4.0's* number. Advisory sources make
this easy to get wrong: an OSV record can publish a 4.0 vector and a 3.1
vector together, with a single numeric that belongs to the 3.1 one (measured
227/227 in the cached corpus). Pairing that numeric with the "4.0" label is a
relabel, not a formatting choice.

Reference vectors below were cross-checked three ways -- published fixture,
FIRST's official cvss_score.js, and this platform's port -- and only vectors
all three agree on are used as expected values.
"""

import pytest

from scanner.cvss4 import cvss_v4_base_score
from scanner.package_intelligence import (
    _normalize_vulnerability_record,
    enrich_package,
)
from scanner.vulnerability_intel import (
    extract_cvss_assessments,
    extract_cvss_metadata,
    preferred_cvss_score,
    score_cvss_vector,
)

V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# (vector, expected) -- fixture == FIRST official JS == our port.
REFERENCE_VECTORS = [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/CR:H/IR:L/AR:M", 0.0),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 2.3),
    ("CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:L/SC:N/SI:H/SA:H", 2.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 6.9),
    ("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:L/SC:N/SI:L/SA:N", 5.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L", 8.8),
    ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:N/VA:H/SC:H/SI:N/SA:L", 7.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:H/SA:N", 9.5),
]


# --------------------------------------------------------------- reference --
@pytest.mark.parametrize("vector,expected", REFERENCE_VECTORS)
def test_v4_reference_vectors_score_exactly(vector, expected):
    assert cvss_v4_base_score(vector) == expected


def test_rejects_a_non_40_vector():
    """The 4.0 formula must never be applied to a 3.x vector."""
    assert cvss_v4_base_score(V31) is None
    assert cvss_v4_base_score("not a vector") is None
    assert cvss_v4_base_score(None) is None


# ---------------------------------------------------------- version routing --
def test_each_version_uses_its_own_formula():
    assert score_cvss_vector(V4, "4.0") == 9.3
    assert score_cvss_vector(V31, "3.1") == 9.8
    assert score_cvss_vector(V30, "3.0") == 9.8


def test_unsupported_version_scores_nothing():
    assert score_cvss_vector(V4, "9.9") is None
    assert score_cvss_vector(V4, None) is None
    assert score_cvss_vector(None, "4.0") is None


# ------------------------------------------------------------- assessments --
def _both_versions_raw():
    return {
        "severity": [
            {"type": "CVSS_V4", "score": V4},
            {"type": "CVSS_V3", "score": V31},
        ],
        "cvss": 9.8,
    }


def test_40_is_preferred_over_31_and_each_keeps_its_own_score():
    assessments = extract_cvss_assessments(_both_versions_raw())
    assert [a["version"] for a in assessments] == ["4.0", "3.1"]
    assert [a["score"] for a in assessments] == [9.3, 9.8]
    assert [a["vector"] for a in assessments] == [V4, V31]


def test_primary_metadata_is_the_40_assessment():
    meta = extract_cvss_metadata(_both_versions_raw())
    assert meta == {"cvss_version": "4.0", "cvss_vector": V4}


# ---------------------------------------------------------- preferred score --
def test_40_primary_never_shows_the_31_number():
    meta = extract_cvss_metadata(_both_versions_raw())
    got = preferred_cvss_score(
        meta["cvss_version"], meta["cvss_vector"], _both_versions_raw()["cvss"]
    )
    assert got == 9.3, "the 3.1 numeric (9.8) must not be relabelled 4.0"


def test_40_stated_without_a_computable_score_is_refused():
    assert preferred_cvss_score("4.0", None, 9.8) is None


def test_version_unknown_keeps_the_bare_number():
    assert preferred_cvss_score(None, None, 7.5) == 7.5


def test_31_without_a_vector_keeps_its_own_number():
    assert preferred_cvss_score("3.1", None, 7.5) == 7.5


def test_zero_is_a_score_not_a_missing_value():
    assert preferred_cvss_score(None, None, 0.0) == 0.0


@pytest.mark.parametrize("garbage", ["n/a", 42, -1, True, "", object()])
def test_non_scores_become_none(garbage):
    assert preferred_cvss_score(None, None, garbage) is None


# ------------------------------------------------------------- propagation --
def test_record_level_propagation():
    rec = _normalize_vulnerability_record({
        "id": "GHSA-xxxx-yyyy-zzzz",
        "cvss": 9.8,
        "cvss_version": "4.0",
        "cvss_vector": V4,
        "severity": "Critical",
        "summary": "demo",
    })
    assert rec["cvss_version"] == "4.0"
    assert rec["cvss_preferred_score"] == 9.3
    assert rec["cvss"] == 9.8, "the legacy scalar drives severity and risk"


def test_package_level_40_primary_keeps_its_own_score():
    item = enrich_package({
        "name": "demo",
        "version": "1.2.3",
        "ecosystem": "npm",
        "vulnerabilities": [{
            "id": "GHSA-xxxx-yyyy-zzzz",
            "cve": "CVE-2024-0001",
            "cvss": 9.8,
            "cvss_version": "4.0",
            "cvss_vector": V4,
            "severity": "Critical",
            "summary": "demo",
        }],
    })
    assert item["cvss_version"] == "4.0"
    assert item["cvss_preferred_score"] == 9.3
    assert item["cvss"] == 9.8


def test_package_level_version_unknown_still_shows_its_number():
    item = enrich_package({
        "name": "demo",
        "version": "1.2.3",
        "ecosystem": "npm",
        "vulnerabilities": [{
            "id": "GHSA-xxxx-yyyy-zzzz",
            "cvss": 7.5,
            "severity": "High",
            "summary": "demo",
        }],
    })
    assert item["cvss_version"] is None
    assert item["cvss_preferred_score"] == 7.5


def test_extract_cvss_metadata_still_returns_exactly_two_keys():
    """The payload contract pins this shape; other data lives elsewhere."""
    assert extract_cvss_metadata({"cvss": 9.1}) == {
        "cvss_version": None,
        "cvss_vector": None,
    }
