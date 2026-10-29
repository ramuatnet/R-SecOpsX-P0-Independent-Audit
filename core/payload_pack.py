"""T-3.4 payload pack: per-class injection sets + encoders.

``payloads/<class>.yaml`` is the single source of truth (same offline
discipline as rules/: PyYAML when importable, core.mini_yaml otherwise).
The pack is shared by the T-3.3 variant hunter (encoding variants +
reverse-mode injection) and any DAST layer; nothing here is scanned --
it is input vocabulary, not detection logic.

A class document that a consumer cannot fully understand raises at
load: a half-understood payload set would be the "silent drops"
failure class applied to the attack vocabulary itself.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from core import mini_yaml

_PAYLOADS_DIR = Path(__file__).resolve().parents[1] / "payloads"

# Encoder names a class may declare. Each has an implementation in
# ENCODERS; a class naming anything else fails validation.
ENCODERS: dict[str, object] = {}


def _enc_url(s: str) -> str:
    return quote(s, safe="")


def _enc_html(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _enc_js(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _enc_base64(s: str) -> str:
    import base64

    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _enc_unicode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _enc_double_encode(s: str) -> str:
    return _enc_url(_enc_url(s))


def _enc_polyglot(s: str) -> str:
    # A payload that is also a comment in C-style languages: inert in a
    # comment position, live when the sink evaluates it as code.
    return f"/*x*/{s}/**/"


def _enc_null_byte(s: str) -> str:
    return s + "\x00"


def _enc_case_flip(s: str) -> str:
    return s.swapcase()


ENCODERS.update(
    url=_enc_url,
    html=_enc_html,
    js=_enc_js,
    base64=_enc_base64,
    unicode=_enc_unicode,
    double_encode=_enc_double_encode,
    polyglot=_enc_polyglot,
    null_byte=_enc_null_byte,
    case_flip=_enc_case_flip,
)


class PayloadPackError(ValueError):
    """A payload file outside the v1 shape (or unknown encoder)."""


def encode(payload: str, encoder: str) -> str:
    fn = ENCODERS.get(encoder)
    if fn is None:
        raise PayloadPackError(
            f"unknown encoder {encoder!r} (known: {sorted(ENCODERS)})")
    return fn(payload)  # type: ignore[operator]


def _load_doc(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return mini_yaml.loads(text)


def _validate(doc, where: str) -> list[dict]:
    if not isinstance(doc, dict) or doc.get("schema") != "rsecopsx.payloads/v1":
        raise PayloadPackError(f"{where}: schema must be rsecopsx.payloads/v1")
    classes = doc.get("classes")
    if not isinstance(classes, list) or not classes:
        raise PayloadPackError(f"{where}: classes must be a non-empty list")
    out = []
    for cls in classes:
        if not isinstance(cls, dict):
            raise PayloadPackError(f"{where}: class entry must be a mapping")
        cid = cls.get("id")
        if not isinstance(cid, str) or not cid:
            raise PayloadPackError(f"{where}: class needs a string id")
        cwe = cls.get("cwe")
        if not isinstance(cwe, str) or not cwe.startswith("CWE-"):
            raise PayloadPackError(f"{where}:{cid}: cwe must look like CWE-N")
        payloads = cls.get("payloads")
        if (not isinstance(payloads, list) or not payloads
                or not all(isinstance(p, str) and p for p in payloads)):
            raise PayloadPackError(
                f"{where}:{cid}: payloads must be a non-empty list of strings")
        enc = cls.get("encoders", [])
        if not isinstance(enc, list):
            raise PayloadPackError(f"{where}:{cid}: encoders must be a list")
        unknown = [e for e in enc if e not in ENCODERS]
        if unknown:
            raise PayloadPackError(
                f"{where}:{cid}: unknown encoders {unknown} "
                f"(known: {sorted(ENCODERS)})")
        out.append({
            "id": cid,
            "cwe": cwe,
            "description": str(cls.get("description") or ""),
            "payloads": list(payloads),
            "encoders": list(enc),
        })
    return out


_CACHE: dict[str, dict] | None = None


def load_all() -> dict[str, dict]:
    """Every class, keyed by id. One parse of the whole pack."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    classes: dict[str, dict] = {}
    for path in sorted(_PAYLOADS_DIR.glob("*.yaml")):
        if path.name.startswith("schema"):
            continue
        for cls in _validate(_load_doc(path), path.name):
            if cls["id"] in classes:
                raise PayloadPackError(
                    f"duplicate payload class {cls['id']!r} "
                    f"({path.name} and {classes[cls['id']]['_source']})")
            cls["_source"] = path.name
            classes[cls["id"]] = cls
    if not classes:
        raise PayloadPackError(f"no payload classes found under {_PAYLOADS_DIR}")
    _CACHE = classes
    return classes


def load_class(class_id: str) -> dict:
    cls = load_all().get(class_id)
    if cls is None:
        raise PayloadPackError(
            f"unknown payload class {class_id!r} "
            f"(known: {sorted(load_all())})")
    return cls


def encode_payload(class_id: str, payload: str, encoder: str) -> str:
    """Validate that the class actually declares the encoder, then encode.

    Encoding a payload a class does not advertise would build a probe
    the pack never claimed to cover.
    """
    cls = load_class(class_id)
    if encoder not in cls["encoders"]:
        raise PayloadPackError(
            f"{class_id} does not declare encoder {encoder!r} "
            f"(declared: {cls['encoders']})")
    return encode(payload, encoder)
