"""T-3.4 payload pack: load, encode, validate.

Every class document must load offline (mini_yaml fallback path
exercised by construction -- the pack files are in the mini_yaml
subset), every encoder must round-trip through its implementation, and
a document outside the v1 shape must raise rather than half-load.
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from core.payload_pack import (
    ENCODERS, PayloadPackError, encode, encode_payload, load_all, load_class,
)


def test_load_all_returns_expected_classes():
    classes = load_all()
    expected = {
        "shell_injection", "code_injection", "sql_injection",
        "path_traversal", "xss", "ssrf", "insecure_deserialization", "xxe",
    }
    assert expected <= set(classes)
    for cls in classes.values():
        assert cls["cwe"].startswith("CWE-")
        assert cls["payloads"] and all(isinstance(p, str) and p
                                       for p in cls["payloads"])
        assert set(cls["encoders"]) <= set(ENCODERS)


def test_load_class_and_unknown_class():
    cls = load_class("shell_injection")
    assert cls["cwe"] == "CWE-78"
    with pytest.raises(PayloadPackError, match="unknown payload class"):
        load_class("not_a_class")


def test_encoders_are_total_and_deterministic():
    s = "; id"
    for name in ENCODERS:
        a, b = encode(s, name), encode(s, name)
        assert a == b, f"encoder {name} is non-deterministic"
        if name != "case_flip":
            assert a != s or name == "polyglot"  # polyglot wraps, differs


def test_encode_specific_behaviours():
    assert encode("a b", "url") == "a%20b"
    assert encode("x", "base64") == base64.b64encode(b"x").decode()
    assert encode("ab", "double_encode") == encode(encode("ab", "url"), "url")
    assert encode("x", "null_byte") == "x\x00"
    assert encode("Ab", "case_flip") == "aB"
    assert encode("<b>", "html") == "&#60;&#98;&#62;"
    assert encode("a", "js") == "\\u0061"
    assert encode("a", "polyglot") == "/*x*/a/**/"


def test_unknown_encoder_raises():
    with pytest.raises(PayloadPackError, match="unknown encoder"):
        encode("x", "rot13")


def test_encode_payload_requires_declared_encoder():
    # shell_injection declares url; xxe does not.
    out = encode_payload("shell_injection", "; id", "url")
    assert "%20" in out or out != "; id"
    with pytest.raises(PayloadPackError, match="does not declare"):
        encode_payload("xxe", "<x/>", "base64")
    with pytest.raises(PayloadPackError, match="unknown payload class"):
        encode_payload("nope", "x", "url")


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_validate_rejects_bad_shapes(tmp_path, monkeypatch):
    from core import payload_pack as pp

    bad_schema = _write(tmp_path, "bad1.yaml",
                        "schema: 'nope/v1'\nclasses: []\n")
    with pytest.raises(PayloadPackError, match="schema"):
        pp._validate(pp._load_doc(bad_schema), "bad1.yaml")

    no_payloads = _write(
        tmp_path, "bad2.yaml",
        "schema: 'rsecopsx.payloads/v1'\nclasses:\n"
        "  - id: 'x'\n    cwe: 'CWE-1'\n    payloads: []\n")
    with pytest.raises(PayloadPackError, match="payloads"):
        pp._validate(pp._load_doc(no_payloads), "bad2.yaml")

    bad_cwe = _write(
        tmp_path, "bad3.yaml",
        "schema: 'rsecopsx.payloads/v1'\nclasses:\n"
        "  - id: 'x'\n    cwe: '78'\n    payloads: ['a']\n")
    with pytest.raises(PayloadPackError, match="cwe"):
        pp._validate(pp._load_doc(bad_cwe), "bad3.yaml")

    bad_encoder = _write(
        tmp_path, "bad4.yaml",
        "schema: 'rsecopsx.payloads/v1'\nclasses:\n"
        "  - id: 'x'\n    cwe: 'CWE-1'\n    payloads: ['a']\n"
        "    encoders: ['rot13']\n")
    with pytest.raises(PayloadPackError, match="unknown encoders"):
        pp._validate(pp._load_doc(bad_encoder), "bad4.yaml")


def test_load_all_rejects_duplicate_class_ids(tmp_path, monkeypatch):
    from core import payload_pack as pp

    doc = ("schema: 'rsecopsx.payloads/v1'\nclasses:\n"
           "  - id: 'dup'\n    cwe: 'CWE-1'\n    payloads: ['a']\n")
    _write(tmp_path, "a.yaml", doc)
    _write(tmp_path, "b.yaml", doc)
    monkeypatch.setattr(pp, "_PAYLOADS_DIR", tmp_path)
    monkeypatch.setattr(pp, "_CACHE", None)
    with pytest.raises(PayloadPackError, match="duplicate payload class"):
        pp.load_all()
