"""SPDX must name the standard behind a score without breaking its evidence.

SPDX 2.3 has no structured CVSS field, so the score travels inside a
free-text evidence annotation.  Two things could go wrong and both are
pinned here:

* the existing ``cvss:`` scalar must survive byte-for-byte, and must stay
  absent when no score was published -- a contract already asserted by
  tests/test_v11_spdx_export.py and re-asserted here;
* a version added alongside that scalar would let a reader pair
  "cvss version: 4.0" with "cvss: 5.3", which are different assessments.
  The version therefore ships as ONE self-contained clause that carries its
  own score and vector.
"""

from reporting.spdx_export import _cvss_assessment_bits, build_spdx

V4_VECTOR = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/"
             "SC:N/SI:N/SA:N")


def _comment(**pkg) -> str:
    pkg.setdefault("name", "x")
    pkg.setdefault("version", "1")
    pkg.setdefault("ecosystem", "npm")
    pkg.setdefault("cve", "CVE-2020-1")
    doc = build_spdx({"sbom": [pkg]})
    return doc["packages"][0]["annotations"][0]["comment"]


# ------------------------------------------------- the existing contract ----
def test_no_score_means_no_cvss_text_at_all():
    assert "cvss" not in _comment()


def test_the_legacy_scalar_is_still_reported_when_that_is_all_there_is():
    assert "cvss: 7.5" in _comment(cvss_score=7.5)


def test_a_stated_version_alone_adds_no_scalar():
    """A version with no published score must not conjure a number."""
    text = _comment(cvss_version="4.0")
    assert "cvss: " not in text
    assert "score unavailable" in text


# ------------------------------------------- one self-contained clause -------
def test_version_and_score_travel_together_so_they_cannot_be_split():
    text = _comment(cvss=5.3, cvss_version="4.0", cvss_preferred_score=6.9,
                     cvss_vector=V4_VECTOR)
    clause = next(b for b in text.split("; ") if "cvss assessment:" in b)
    # the version, its own score and the vector are all in ONE clause
    assert "CVSS 4.0" in clause
    assert "6.9" in clause
    assert V4_VECTOR in clause
    # and the legacy scalar still ships unchanged beside it
    assert "cvss: 5.3" in text


def test_the_assessment_clause_never_reuses_the_legacy_number():
    """6.9 belongs to the 4.0 assessment; 5.3 is its 3.1 sibling's score."""
    text = _comment(cvss=5.3, cvss_version="4.0", cvss_preferred_score=6.9,
                     cvss_vector=V4_VECTOR)
    clause = next(b for b in text.split("; ") if "cvss assessment:" in b)
    assert "5.3" not in clause
    assert "6.9" in clause


def test_a_31_primary_reports_its_own_version_and_score():
    text = _comment(cvss_version="3.1", cvss_preferred_score=9.8, cvss=9.8)
    assert "cvss assessment: CVSS 3.1 — 9.8" in text


def test_a_30_primary_is_not_called_31():
    text = _comment(cvss_version="3.0", cvss_preferred_score=7.5, cvss=7.5)
    assert "cvss assessment: CVSS 3.0 — 7.5" in text


# ------------------------------------------------- never a false version ----
def test_unknown_is_not_reported_as_a_version():
    """"UNKNOWN" is a truthy *string*. It must never become "CVSS UNKNOWN".

    With no version and no vector there is no standard to name, so no clause
    is added -- the legacy ``cvss: 7.5`` already carries the number, and
    appending "version unknown" beside it would only duplicate it. What must
    never happen is a fabricated version.
    """
    text = _comment(cvss_version="UNKNOWN", cvss_preferred_score=7.5, cvss=7.5)
    assert "CVSS UNKNOWN" not in text
    assert "cvss version: UNKNOWN" not in text
    assert "cvss: 7.5" in text
    assert "cvss assessment:" not in text


def test_the_version_is_never_inferred_from_the_number():
    """7.5 is legal for 3.1 and for 4.0; only a stated version may be shown."""
    text = _comment(cvss=7.5, cvss_preferred_score=7.5)
    assert "cvss version: 3.1" not in text
    assert "cvss version: 4.0" not in text
    assert "cvss: 7.5" in text


def test_no_version_and_no_vector_yields_no_clause():
    assert _cvss_assessment_bits({"cvss_preferred_score": 6.9}) == []
    assert _cvss_assessment_bits({"cvss": 6.9}) == []


# ------------------------------------------------------- score semantics -----
def test_zero_is_a_score_and_not_an_absence():
    bits = _cvss_assessment_bits({"cvss_version": "4.0",
                                  "cvss_preferred_score": 0.0})
    assert bits == ["cvss assessment: CVSS 4.0 — 0.0"]


def test_a_live_finding_is_never_rendered_as_nothing():
    bits = _cvss_assessment_bits({"cvss_version": "4.0",
                                  "cvss_preferred_score": None})
    assert bits == ["cvss assessment: CVSS 4.0 — score unavailable"]


def test_a_vector_is_printed_verbatim_and_in_full():
    bits = _cvss_assessment_bits({"cvss_version": "4.0",
                                  "cvss_preferred_score": 6.9,
                                  "cvss_vector": V4_VECTOR})
    assert bits == [f"cvss assessment: CVSS 4.0 — 6.9, vector {V4_VECTOR}"]


def test_a_vector_without_a_version_field_still_reports_honestly():
    """The vector states its own version, so no version is invented for it."""
    bits = _cvss_assessment_bits({"cvss_vector": V4_VECTOR,
                                  "cvss_preferred_score": 6.9})
    assert "version unknown" in bits[0]
    assert V4_VECTOR in bits[0]
    assert "6.9" in bits[0]


# ------------------------------------------------------------- the contract --
def test_the_annotation_is_only_added_where_evidence_exists():
    """A clean package must still earn no annotation at all."""
    doc = build_spdx({"sbom": [
        {"name": "clean", "version": "1", "ecosystem": "npm"},
        {"name": "vuln", "version": "1", "ecosystem": "npm",
         "cve": "CVE-2020-1", "cvss_version": "4.0",
         "cvss_preferred_score": 6.9, "cvss_vector": V4_VECTOR},
    ]})
    by_name = {p["name"]: p for p in doc["packages"]}
    assert not by_name["clean"].get("annotations")
    assert "cvss assessment:" in by_name["vuln"]["annotations"][0]["comment"]
