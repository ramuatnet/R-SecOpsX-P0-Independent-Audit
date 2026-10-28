"""A card number must pass its check digit; an expiry month is not a card.

The legacy gate accepted any 13-19 digit run, so ``4111111111111112`` (one
digit off a valid Visa test number) was reported exactly like
``4111111111111111``. It also accepted the bare token ``expiry`` as payment
data: all 4 PAYMENT_CARD rows in the STR delivery came from
jquery.countdown.js on that word, with no card number in the evidence.

The change is additive -- keyword-only evidence (cvv, cvc, cardholder) keeps
the legacy decision, and ``_looks_like_payment_data`` is left untouched so
"card-shaped" and "card data" stay separable.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from analysis.privacy_data_exposure_engine import (
    _looks_like_card_number,
    _looks_like_payment_data,
    _luhn_valid,
    _payment_data_is_concrete,
    enrich_privacy_data_exposure,
)


@pytest.mark.parametrize("number", [
    "4111111111111111",      # Visa 16
    "5500005555555559",      # Mastercard 16
    "6011111111111117",      # Discover 16
    "378282246310005",       # Amex 15
    "30569309025904",        # Diners 14
    "4222222222222",         # Visa 13
])
def test_known_valid_cards_pass_the_check_digit(number):
    assert _luhn_valid(number) is True


@pytest.mark.parametrize("number", [
    "4111111111111112",      # valid Visa with one digit changed
    "1234567890123456",      # a common test placeholder
    "411111111111111",
])
def test_other_numbers_do_not_pass_the_check_digit(number):
    assert _luhn_valid(number) is False


def test_all_zero_run_satisfies_luhn_but_is_not_a_card():
    # Pure checksum: every digit is zero, so the total is zero.
    assert _luhn_valid("0000000000000000") is True
    assert _looks_like_card_number("0000000000000000") is False
    assert _looks_like_card_number("4111111111111111") is True
    assert _looks_like_card_number("4111111111111112") is False


def test_non_digits_are_not_validated():
    assert _luhn_valid("4111-1111-1111-1111") is False
    assert _luhn_valid("") is False


def test_invalid_check_digit_is_not_payment_data():
    assert _payment_data_is_concrete('{cardNumber:"4111111111111112"}') is False
    assert _payment_data_is_concrete('card_number = "1234567890123456"') is False


def test_valid_check_digit_is_payment_data_in_every_common_notation():
    for body in (
        'cardNumber:"4111111111111111"',
        'card_number = "4111111111111111"',
        'card_number = "4111 1111 1111 1111"',
        'card_number = "4111-1111-1111-1111"',
        '"card_number": "4111111111111111"',
        'const n = 4111111111111111;',
        'credit_card = "5500005555555559"',
        'const pay={cardNumber:"378282246310005"}',
    ):
        assert _payment_data_is_concrete(body) is True, body


def test_keyword_only_evidence_keeps_the_legacy_decision():
    for body in ('cvv = "123"', 'cvc: "456"', "cardholder = full_name",
                 'card_number -> record.number', 'cardNum: null'):
        assert _payment_data_is_concrete(body) is True, body


def test_expiry_alone_is_not_payment_data():
    for body in ('var expiry = new Date();', 'expiry = "2027-01"',
                 'const t={exp_month: 12, exp_year: 2027}',
                 'expiry -> config.cacheTtl'):
        assert _payment_data_is_concrete(body) is False, body


def test_expiry_next_to_a_valid_card_nearby_is_still_payment_data():
    # The number, not the word, carries the finding.
    body = 'const p={expiry:"2027-01",cardNumber:"4111111111111111"};'
    assert _payment_data_is_concrete(body) is True


def test_card_shaped_helper_is_unchanged():
    """Additivity: "card-shaped" still answers the old question."""
    for body in ('cardNumber:"4111111111111112"', 'expiry = "2027-01"',
                 'cardNumber:"4111111111111111"'):
        assert _looks_like_payment_data(body) is True, body


def _scan(files: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="rsx_card_gate_") as raw:
        base = pathlib.Path(raw)
        for rel, body in files.items():
            target = base / "src" / "pay" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        rows = enrich_privacy_data_exposure(
            str(base), findings=[], live_progress=False).get("indicators") or []
    return {str(r.get("file")).replace("\\", "/"): r for r in rows}


def test_engine_reports_a_valid_card_and_drops_an_invalid_one():
    rows = _scan({
        "good.js": 'const pay={cardNumber:"4111111111111111"};\n',
        "bad.js": 'const pay={cardNumber:"4111111111111112"};\n',
        "masked.js": 'const pay={cardNumber:"0000 0000 0000 0000"};\n',
        "expiry.js": 'var expiry = new Date();\n',
        "cvv.py": 'cvv = "123"\n',
    })
    assert "PAYMENT_CARD" in (rows["src/pay/good.js"]["pii_types"])
    assert "src/pay/bad.js" not in rows
    assert "src/pay/masked.js" not in rows
    assert "src/pay/expiry.js" not in rows
    assert "PAYMENT_CARD" in (rows["src/pay/cvv.py"]["pii_types"])
