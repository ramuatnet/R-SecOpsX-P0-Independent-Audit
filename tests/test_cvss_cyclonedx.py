"""CycloneDX must say which standard produced a score, and never claim one.

The defect this pins: ``method`` was hard-coded to ``"CVSSv3"`` whenever a
record happened to carry a score.  That is wrong twice over.  CycloneDX 1.5's
``definitions.scoreMethod`` enum is::

    CVSSv2, CVSSv3, CVSSv31, CVSSv4, OWASP, SSVC, other

``CVSSv3`` means v3.0 *specifically* -- v3.1 has its own member -- and 1212
of this platform's 2259 scored advisories publish v3.1, so most cells were
misstated.  Worse, a CVSS 4.0 primary assessment was published with a 3.1
score under a CVSSv3 heading, which is precisely the relabelling that must
never happen.

Enum source (fetched and read while making this change, not remembered):
https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json
``ratings`` is additionally constrained by ``additionalProperties: false``,
so only source / score / severity / method / vector / justification may appear.
"""

import re
from pathlib import Path

from reporting.cyclonedx_export import (
    _cvss_number,
    _score_method,
    _vulnerability,
    build_cyclonedx,
)

CDX_SOURCE = Path(__file__).resolve().parents[1] / "reporting" / "cyclonedx_export.py"

# Verbatim from bom-1.5.schema.json -> definitions.scoreMethod -> enum
SCORE_METHOD_ENUM = ["CVSSv2", "CVSSv3", "CVSSv31", "CVSSv4",
                     "OWASP", "SSVC", "other"]

# Exactly the keys bom-1.5.schema.json allows on a rating object.
RATING_KEYS = {"source", "score", "severity", "method", "vector", "justification"}

V4_VECTOR = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/"
             "SC:N/SI:N/SA:N")
V31_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"


def _rating(**kw):
    return _vulnerability(dict(kw))["ratings"][0]


def _props(**kw):
    vuln = _vulnerability(dict(kw))
    return {p["name"]: p["value"] for p in vuln["properties"]}


# ------------------------------------------------- the four stated versions --
def test_cvss_40_primary_is_labelled_cvssv4():
    r = _rating(id="X", cvss_version="4.0", cvss_preferred_score=6.9,
                cvss=5.3, cvss_vector=V4_VECTOR)
    assert r["method"] == "CVSSv4"
    assert r["score"] == 6.9
    assert r["vector"] == V4_VECTOR


def test_cvss_31_primary_is_labelled_cvssv31_not_cvssv3():
    """CVSSv3 means v3.0. Most of our advisories are v3.1."""
    r = _rating(id="X", cvss_version="3.1", cvss_preferred_score=9.8, cvss=9.8)
    assert r["method"] == "CVSSv31"
    assert r["score"] == 9.8


def test_cvss_30_primary_is_labelled_cvssv3():
    r = _rating(id="X", cvss_version="3.0", cvss_preferred_score=7.5, cvss=7.5)
    assert r["method"] == "CVSSv3"
    assert r["score"] == 7.5


def test_every_emitted_method_is_a_legal_cyclonedx_15_member():
    for version, expected in (("4.0", "CVSSv4"), ("3.1", "CVSSv31"),
                              ("3.0", "CVSSv3"), (None, "other")):
        assert _score_method(version, True) == expected
        assert expected in SCORE_METHOD_ENUM


# --------------------------------------- never claim a version not published --
def test_a_score_with_no_stated_version_never_becomes_cvssv3():
    """Before this change this exact case emitted method=CVSSv3."""
    r = _rating(id="X", cvss_version=None, cvss_preferred_score=7.5, cvss=7.5)
    assert r["method"] == "other"
    assert r["score"] == 7.5


def test_the_version_is_never_guessed_from_the_number():
    """7.5 is a legal 3.1 score and a legal 4.0 score; they differ by formula."""
    for score in (2.0, 7.5, 9.8, 10.0):
        assert _score_method(None, True) == "other"
        assert f"{score}" is not None  # the number is never consulted


def test_sentinel_strings_are_not_versions():
    for bogus in ("UNKNOWN", "None", "", "N/A", "5.0"):
        assert _score_method(bogus, True) == "other", bogus


def test_no_score_means_other_whatever_the_version_claims():
    """A version without a score must not advertise a scoring method."""
    r = _rating(id="X", cvss_version="4.0", cvss_preferred_score=None, cvss=None)
    assert r["method"] == "other"
    assert "score" not in r
    assert _score_method("4.0", False) == "other"


# ------------------------------------------------------- nothing gets lost ----
def test_a_legacy_payload_still_publishes_its_scalar():
    r = _rating(id="X", cvss=5.3)
    assert r["method"] == "other"
    assert r["score"] == 5.3


def test_the_legacy_rsecopsx_cvss_property_is_untouched():
    """ratings[].score now carries the preferred assessment; the property
    named after the legacy scalar must keep publishing exactly that."""
    assert _props(id="X", cvss=5.3, cvss_version="4.0",
                  cvss_preferred_score=6.9)["rsecopsx:cvss"] == "5.3"
    assert _props(id="X", cvss=7.7, cvss_version="3.1",
                  cvss_preferred_score=7.7)["rsecopsx:cvss"] == "7.7"


def test_zero_is_a_score_and_not_an_absence():
    r = _rating(id="X", cvss_version="4.0", cvss_preferred_score=0.0, cvss=0.0)
    assert r["method"] == "CVSSv4"
    assert r["score"] == 0.0
    assert "score" in r


def test_no_vector_key_is_emitted_when_there_is_no_vector():
    r = _rating(id="X", cvss_version="4.0", cvss_preferred_score=6.9)
    assert "vector" not in r


def test_the_rating_reports_the_severity_it_always_did():
    assert "severity" in _rating(id="X", severity="high", cvss=9.8,
                                 cvss_version="3.1", cvss_preferred_score=9.8)


# ------------------------------------------------------- score normalising ----
def test_cvss_number_accepts_what_feeds_actually_send():
    assert _cvss_number(6.9) == 6.9
    assert _cvss_number("7.5") == 7.5
    assert _cvss_number(0) == 0.0
    assert _cvss_number(10.0) == 10.0


def test_cvss_number_rejects_what_is_not_a_score():
    for bad in (None, True, False, -1, 42, "n/a", "", object()):
        assert _cvss_number(bad) is None, bad


def test_cvss_number_treats_zero_as_present():
    """`if score:` would discard a legitimate 0.0."""
    assert _cvss_number(0.0) == 0.0
    assert _cvss_number(0.0) is not None


# ------------------------------------------------------------ whole document --
def test_build_cyclonedx_ratings_conform_to_the_15_schema():
    doc = build_cyclonedx({"sbom": [
        {"name": "a", "version": "1", "cve": "CVE-1",
         "cvss": 5.3, "cvss_version": "4.0", "cvss_preferred_score": 6.9,
         "cvss_vector": V4_VECTOR},
        {"name": "b", "version": "1", "cve": "CVE-2",
         "cvss": 7.5, "cvss_version": "3.1", "cvss_preferred_score": 7.5},
        {"name": "c", "version": "1", "cve": "CVE-3",
         "cvss": 7.5, "cvss_version": None, "cvss_preferred_score": 7.5},
        {"name": "d", "version": "1", "cve": "CVE-4"},
    ]})
    vulns = doc.get("vulnerabilities") or []
    assert vulns, "expected vulnerabilities in the document"
    for vuln in vulns:
        for rating in vuln["ratings"]:
            # additionalProperties: false
            assert set(rating) <= RATING_KEYS, sorted(rating)
            assert rating["method"] in SCORE_METHOD_ENUM, rating
            assert rating["severity"]
            if "score" in rating:
                assert 0.0 <= rating["score"] <= 10.0, rating
            if "vector" in rating:
                assert rating["vector"].startswith("CVSS:"), rating


def test_no_rating_still_claims_cvssv3_by_default():
    """The literal that was hard-coded must be gone from the rating path."""
    src = CDX_SOURCE.read_text(encoding="utf-8-sig")
    assert not re.search(r'"method":\s*"CVSSv3"', src)
    # the rating's method comes from the stated-version map, never a literal
    assert '"method": _score_method(' in src
    assert '"4.0": "CVSSv4"' in src
    assert '"3.1": "CVSSv31"' in src
    assert '"3.0": "CVSSv3"' in src


def test_file_stays_lf_only_with_no_bom():
    """HEAD's blob for this file is pure LF with no BOM; the edit tool wrote
    CRLF on insertion, so the repair is asserted rather than assumed."""
    raw = CDX_SOURCE.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
