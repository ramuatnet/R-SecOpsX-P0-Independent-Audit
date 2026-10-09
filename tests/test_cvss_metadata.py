from scanner.package_intelligence import _extract_cvss_metadata


def test_cvss_31_vector():
    result = _extract_cvss_metadata({
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }]
    })
    assert result["cvss_version"] == "3.1"
    assert result["cvss_vector"].startswith("CVSS:3.1/")


def test_cvss_40_vector():
    result = _extract_cvss_metadata({
        "severity": [{
            "type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        }]
    })
    assert result["cvss_version"] == "4.0"
    assert result["cvss_vector"].startswith("CVSS:4.0/")


def test_numeric_only_score_has_unknown_version():
    result = _extract_cvss_metadata({"cvss": 9.1})
    assert result == {"cvss_version": None, "cvss_vector": None}


def test_unrecognized_version_is_not_inferred():
    result = _extract_cvss_metadata({"cvss_version": "5.0", "cvss": 9.1})
    assert result["cvss_version"] is None
    assert result["cvss_vector"] is None


def test_direct_vector_field():
    result = _extract_cvss_metadata({
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    })
    assert result["cvss_version"] == "3.1"
