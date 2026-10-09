"""The two machine-readable surfaces that still needed a CVSS version.

VEX publishes the legacy scalar under ``properties.cvss`` with no way to say
which standard it came from, so it now carries the preferred assessment's
version, vector and score beside it.  ``cvss`` itself must not move: a
consumer that reads only that key has to see exactly what it saw before.

SARIF is the opposite case and is pinned for the record.  Its
``security-severity`` is a bare numeric string by specification (GitHub Code
Scanning parses it as a float), so it must never become a versioned label --
and measured on the shipped payload, 0 of 102 findings carry a CVSS value at
all, so SARIF has no CVSS surface to version in the first place.
"""

import re

from reporting.sarif_export import _security_severity
from reporting.vex_export import build_vex

V4_VECTOR = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/"
             "SC:N/SI:N/SA:N")


def _statement_props(doc: dict) -> dict:
    """The properties of the first statement, whatever container holds it."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict) and "cvss" in props:
                found.append(props)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    assert found, "no VEX statement carrying a cvss property"
    return found[0]


def _props(**pkg) -> dict:
    pkg.setdefault("name", "x")
    pkg.setdefault("version", "1")
    pkg.setdefault("ecosystem", "npm")
    pkg.setdefault("cve", "CVE-2020-1")
    return _statement_props(build_vex({"sbom": [pkg]}))


# ------------------------------------------------------------------- VEX -----
def test_vex_publishes_the_preferred_assessment_beside_the_legacy_scalar():
    props = _props(cvss=5.3, cvss_version="4.0", cvss_preferred_score=6.9,
                   cvss_vector=V4_VECTOR)
    assert props["cvss"] == 5.3, "the legacy scalar must not move"
    assert props["cvss_version"] == "4.0"
    assert props["cvss_preferred_score"] == 6.9
    assert props["cvss_vector"] == V4_VECTOR


def test_vex_does_not_relabel_a_31_number_as_a_40_one():
    """4.0 is the assessment shown; 5.3 stays under the key that owned it."""
    props = _props(cvss=5.3, cvss_version="4.0", cvss_preferred_score=6.9,
                   cvss_vector=V4_VECTOR)
    assert props["cvss"] == 5.3
    assert props["cvss_preferred_score"] == 6.9
    assert props["cvss_preferred_score"] != props["cvss"]


def test_vex_carries_the_keys_even_for_a_payload_that_lacks_them():
    """A payload written before this change gets explicit nulls, not a
    missing key -- so a consumer can tell 'absent' from 'not carried'."""
    props = _props(cvss=7.5)
    assert props["cvss"] == 7.5
    assert props["cvss_version"] is None
    assert props["cvss_vector"] is None
    assert props["cvss_preferred_score"] is None


def test_vex_never_invents_a_version_for_a_legacy_scalar():
    """Only a stated version may be published."""
    props = _props(cvss=7.5)
    assert props["cvss_version"] is None
    assert props["cvss_preferred_score"] is None


def test_vex_keeps_the_scalar_when_there_is_no_score_at_all():
    props = _props(cvss_version="4.0")
    assert props["cvss"] is None
    assert props["cvss_version"] == "4.0"
    assert props["cvss_preferred_score"] is None


# ------------------------------------------------------------------ SARIF ----
def test_sarif_security_severity_stays_a_bare_numeric_string():
    """SARIF/GitHub parse this as a float; a versioned label would break it."""
    for finding in ({"cvss": 7.5}, {"severity": "critical"},
                    {"severity": "high"}, {"severity": "medium"},
                    {"severity": "low"}, {}, {"cvss": "9.8"}):
        value = _security_severity(finding)
        assert re.fullmatch(r"\d+\.\d", value), (finding, value)


def test_sarif_does_not_fabricate_a_score_it_was_not_given():
    """With no CVSS it falls back to the severity mapping -- a score derived
    from severity, not a CVSS. It is never dressed up as one: SARIF carries
    no version field, and none is added, because measured on the shipped
    payload 0 of 102 findings have a CVSS value to name a version for."""
    assert _security_severity({"severity": "critical"}) == "9.5"
    assert _security_severity({"severity": "medium"}) == "5.0"
    assert _security_severity({}) == "0.0"
