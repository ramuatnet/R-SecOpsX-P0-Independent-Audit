"""An accessor names a field; PII typing must see it.

Every identifier pattern in the engine is a field or variable name --
``user.email``, ``email_address``, ``phone``. A Java or TypeScript accessor
is therefore invisible: there is no word boundary inside ``getEmail``,
because ``t`` and ``E`` are both word characters. A file whose only PII
evidence is ``user.getEmail()`` produced no PII type at all, so the exposure
layer downgraded a real log sink to ``PII_PATTERN_OBSERVED``:

    log.info(user.getEmailAddress())       LOW PII_PATTERN_OBSERVED
    System.out.println(user.getEmail())    LOW PII_PATTERN_OBSERVED

Only ``get`` is treated as an accessor. ``isEmail()`` is a boolean flag and a
setter can be an assignment target; neither proves the value is read. The
match is an exact identifier lookup, so ``getEmailVerified`` stays invisible.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from analysis.privacy_data_exposure_engine import (
    _PRIVACY_PII_GETTER_META,
    _PRIVACY_PII_GETTER_NAMES,
    _privacy_pii_getter_hits,
    _privacy_semantic_pii_fallback,
    enrich_privacy_data_exposure,
)


def _types(text):
    return [entry[0] for entry in _privacy_semantic_pii_fallback(text)]


@pytest.mark.parametrize("call, expected", [
    ("user.getEmail()", "EMAIL"),
    ("user.getEmailAddress()", "EMAIL"),
    ("account.getCustomerEmail()", "EMAIL"),
    ("user.getPhoneNumber()", "PHONE"),
    ("user.getMobileNumber()", "PHONE"),
    ("customer.getMsisdn()", "PHONE"),
    ("user.getHomeAddress()", "ADDRESS"),
    ("user.getDateOfBirth()", "DOB"),
    ("user.getSsn()", "SSN"),
    ("user.getPanNumber()", "PAN"),
    ("user.getAadhaarNumber()", "AADHAAR"),
    ("user.getCardNumber()", "PAYMENT_CARD"),
    ("account.getCreditCardNumber()", "PAYMENT_CARD"),
])
def test_accessor_is_typed(call, expected):
    assert _types(call) == [expected]


@pytest.mark.parametrize("text", [
    "user.isEmail()",              # boolean flag, not the value
    "user.setEmail(value)",        # assignment target
    "user.getEmailVerified()",     # exact identifier lookup, not a prefix
    "user.getAddress()",           # bare "address" is too generic by design
    "user.getCard()",              # no card noun, and no number either
    "target.getLabel()",           # "get" inside a longer identifier
])
def test_non_accessor_shapes_stay_invisible(text):
    assert _types(text) == []


def test_accessor_table_is_exact_identifiers():
    assert "getemailverified" not in _PRIVACY_PII_GETTER_NAMES
    assert _PRIVACY_PII_GETTER_NAMES["getemail"] == "EMAIL"
    assert _PRIVACY_PII_GETTER_NAMES["getuseremail"] == "EMAIL"


def test_accessor_does_not_duplicate_an_identifier_already_found():
    # Both the field and the accessor name the same email address.
    assert _types("user.email = user.getEmail()") == ["EMAIL"]


def test_getter_hits_reports_each_type_once_in_order():
    assert _privacy_pii_getter_hits(
        "user.getEmail() user.getPhoneNumber() user.getEmail()"
    ) == ["EMAIL", "PHONE", "EMAIL"]


def test_phone_accessor_still_respects_the_sbom_exclusion():
    metadata = ('{"Name": "MIT", "MatchType": "header"}\n'
                "user.getPhoneNumber()")
    assert _types(metadata) == []
    # A numeric value is independent evidence, so the same text reports.
    assert _types(metadata + '\n"phone": "+91 98765 43210"') == ["PHONE"]


def test_accessor_metadata_matches_the_existing_identifiers():
    assert _PRIVACY_PII_GETTER_META["EMAIL"] == ("MEDIUM", "Email address")
    assert _PRIVACY_PII_GETTER_META["AADHAAR"] == ("HIGH", "Aadhaar identifier")
    assert _PRIVACY_PII_GETTER_META["PAYMENT_CARD"][0] == "CRITICAL"


def _scan(relative: str, body: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_getter_") as raw:
        target = pathlib.Path(raw) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return enrich_privacy_data_exposure(
            raw, findings=[], live_progress=False).get("indicators") or []


def test_java_getter_in_a_log_call_is_a_high_exposure():
    rows = _scan("src/main/java/corp/B.java", (
        "public class B {\n"
        "  public void audit(User user) {\n"
        "    log.info(user.getEmailAddress());\n"
        "  }\n}\n"))
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["indicator"] == "PII_LOGGING"
    assert row["risk_level"] == "HIGH"
    assert row["privacy_evidence_state"] == "EXPOSED"
    assert row["pii_types"] == ["EMAIL"]


def test_java_system_out_getter_is_a_high_exposure():
    rows = _scan("src/main/java/corp/C.java", (
        "public class C {\n"
        "  public void dump(User user) {\n"
        "    System.out.println(user.getEmail());\n"
        "  }\n}\n"))
    assert [r["indicator"] for r in rows] == ["PII_LOGGING"]
    assert rows[0]["risk_level"] == "HIGH"
    assert rows[0]["pii_types"] == ["EMAIL"]


def test_java_phone_getter_in_a_log_call_is_a_high_exposure():
    rows = _scan("src/main/java/corp/D.java", (
        "public class D {\n"
        "  public void audit(User user) {\n"
        "    LOGGER.info(user.getPhoneNumber());\n"
        "  }\n}\n"))
    assert [r["indicator"] for r in rows] == ["PII_LOGGING"]
    assert rows[0]["pii_types"] == ["PHONE"]


def test_getter_without_a_sink_stays_an_observation():
    rows = _scan("src/main/java/corp/Person.java", (
        "public class Person {\n"
        "  private String email;\n"
        "  public String getEmail() { return email; }\n"
        "}\n"))
    assert rows, rows
    assert all(r["privacy_evidence_state"] == "OBSERVED_ONLY" for r in rows)
    assert rows[0]["risk_level"] == "LOW"


def test_password_accessor_is_not_pii_but_the_log_row_is_kept():
    # HibernateUtil.java line 264 in the OWASP tree: a real console write.
    rows = _scan("src/main/java/corp/HibernateUtil.java", (
        "public class HibernateUtil {\n"
        "  public static void main(User user) {\n"
        "    System.out.println(user.getPassword());\n"
        "  }\n}\n"))
    assert [r["indicator"] for r in rows] == ["PII_PATTERN_OBSERVED"]
    assert rows[0]["privacy_evidence_state"] == "OBSERVED_ONLY"
    assert rows[0]["pii_types"] == []
