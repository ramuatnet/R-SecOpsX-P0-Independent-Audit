from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List

# R-SecOpsX privacy scanner: single-line live progress output.
def _privacy_live(*args, **kwargs):
    import sys
    msg = " ".join(str(x) for x in args)
    width = 150
    if len(msg) > width - 1:
        msg = msg[:width - 1] + "â€¦"
    sys.stdout.write("\r" + msg.ljust(width))
    sys.stdout.flush()

def _privacy_live_finish():
    import sys
    sys.stdout.write("\r" + (" " * 150) + "\r\n")
    sys.stdout.flush()

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".rb", ".cs",
    ".json", ".yml", ".yaml", ".xml", ".properties", ".env", ".txt", ".md",
}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".next"}

PII_PATTERNS = [
    ("AADHAAR", r"\b(?:aadhaar|aadhar|uidai)\b|\b\d{4}[ -]?\d{4}[ -]?\d{4}\b", "CRITICAL", "India national identifier"),
    ("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b|\bpan(?:_?number)?\b", "HIGH", "India tax identifier"),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b|\bssn\b|social_security", "CRITICAL", "US social security number"),
    ("PAYMENT_CARD", r"\b(?:card_number|cardnumber|credit_card_number|debit_card_number|cardholder|cvv|cvc|expiry|exp_month|exp_year)\b|\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b", "CRITICAL", "Payment card data"),
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b(?:email|email_address|user_email|mail_address)\b", "MEDIUM", "Email address"),
    ("PHONE", r"\b(?:phone|phone_number|mobile|mobile_number|msisdn|telephone)\b|\b(?:\+?91[- ]?)?[6-9]\d{9}\b|\+\d{1,3}(?:[- .]?\d){8,14}\b", "MEDIUM", "Phone number"),
    ("DOB", r"\b(date_of_birth|dob|birth_date|birthdate)\b", "MEDIUM", "Date of birth"),
    ("ADDRESS", r"\b(?:postal_address|street_address|home_address|billing_address|shipping_address|postal_code|zipcode|zip_code|geo_location)\b", "MEDIUM", "Location/address data"),
    ("HEALTH", r"\b(?:patient_id|patient_record|diagnosis|medical_record|health_record|prescription|health_data)\b", "HIGH", "Health data"),
    ("BIOMETRIC", r"\b(?:biometric|fingerprint_template|face_template|facial_template|iris_template)\b", "CRITICAL", "Biometric data"),
]

# Keyword-only matches are intentionally weak. A word such as ``card``,
# ``email`` or ``phone`` in documentation, localization text, URLs, Git
# metadata, fixtures, or product descriptions is not proof of PII.
TEXT_ONLY_EXTENSIONS = {".json", ".md", ".txt", ".yml", ".yaml", ".xml", ".properties"}
LOCALIZATION_MARKERS = ("/i18n/", "/locales/", "/locale/", "/translations/", "/translation/")
SYNTHETIC_MARKERS = ("fake", "faker", "mock", "fixture", "seed", "dummy", "synthetic", "testdata", "test-data", "sample", "challenge", "codefix", "hacking-instructor")

# Repository metadata/contact strings are not application PII exposure.
EMAIL_METADATA_RE = re.compile(r"(?:git\+https?://[^\s/@]+@github\.com/|git@github\.com/|mailto:)", re.I)
DOCUMENTATION_CONTACT_MARKERS = ("mailto:", "code of conduct", "contact", "project leads", "maintainers", "contributors")


def _path_context(path: Path, target: str) -> str:
    return _rel(path, target).replace("\\", "/").lower()


def _is_non_production_text(path: Path, text: str, target: str) -> bool:
    p = _path_context(path, target)
    if any(marker in p for marker in LOCALIZATION_MARKERS):
        return True
    if "/docs/" in p or "/documentation/" in p or p.startswith(("docs/", "documentation/")):
        return True
    # Repository reference/readme content is documentation, not application PII.
    if p.endswith(("/references.md", "references.md", "/readme.md", "readme.md", "/changelog.md", "changelog.md")):
        return True
    # Localization/catalogue content is presentation data, not application data.
    if "/i18n/" in p or "/locale/" in p or "/locales/" in p:
        return True
    if p.endswith(("/bom.json", "bom.json", "/sbom.json", "sbom.json")):
        return True
    if any(marker in p for marker in ("/fixtures/", "/fixture/", "/test/", "/tests/", "/__tests__/", "/spec/", "/seed/", "/seeds/", "/data/static/codefixes/", "/hacking-instructor/")) or p.startswith(("data/static/codefixes/", "hacking-instructor/")):
        return True
    if re.search(r"(?:^|/)[^/]+\.spec\.(?:js|ts|jsx|tsx)$", p, re.I) or "/challenge" in p:
        return True
    low = text.lower()
    if "git+ssh://git@" in low or "github.com/" in low and "git@github.com" in low:
        return True
    return False


def _has_real_email(text: str) -> bool:
    return bool(re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text))


def _looks_like_payment_data(text: str) -> bool:
    low = text.lower()
    if re.search(r"\b(?:\d{4}[ -]?){3}\d{4}\b", text):
        return True
    return bool(re.search(r"(?:card[_ -]?(?:number|num)|credit[_ -]?card|debit[_ -]?card|cardholder|cvv|cvc|exp(?:iry|_month|_year))\s*[:=]", low))



# V20: cached semantic PII context regexes
_V20_EMAIL_METADATA_RE = re.compile(
    r"mailto:|code of conduct|project leads|maintainers|contributors",
    re.I,
)

_V20_EMAIL_FIELD_RE = re.compile(
    r"(?:email|user_email|email_address)\s*(?:[:=]|\(|\[|\.|->)",
    re.I,
)


# V24: cached EMAIL semantic candidate regexes.
# These preserve V21 semantics while avoiding repeated compilation.
_V24_EMAIL_VALUE_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.I,
)

_V24_EMAIL_FIELD_CANDIDATE_RE = re.compile(
    r"(?:"
    r"email|user_email|email_address|mail_address"
    r")\s*(?:[:=]|\(|\[|\.|->)",
    re.I,
)

_V24_EMAIL_METADATA_CANDIDATE_RE = re.compile(
    r"mailto:|git\+https?://[^\s/@]+@github\.com/|git@github\.com/",
    re.I,
)

_V24_EMAIL_DOCUMENTATION_RE = re.compile(
    r"mailto:|code of conduct|contact|project leads|maintainers|contributors",
    re.I,
)

_V20_OBJECT_EMAIL_RE = re.compile(
    r"\b(?:user|customer|account|record|profile)\.email\b",
    re.I,
)

_V20_PHONE_VALUE_RE = re.compile(
    r"(?:\+?\d[\d ()-]{8,}\d)",
)

_V20_IDENTIFIER_CONTEXT_RE = re.compile(
    r"(?:aadhaar|aadhar|uidai|pan(?:_?number)?|ssn|social_security)\s*[:=]",
    re.I,
)

_V20_NUMERIC_IDENTIFIER_RE = re.compile(
    r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"
    r"|\b\d{3}-\d{2}-\d{4}\b"
    r"|\b[A-Z]{5}\d{4}[A-Z]\b",
    re.I,
)

_V20_GENERIC_SEMANTIC_RE = re.compile(
    r"(?:[:=]|\(|\[|\.|->|return\s+|jsonify\s*\(|res\.json)",
    re.I,
)

def _semantic_pii_hits(text: str, path: Path, target: str):
    """Return PII hits only when the line has semantic evidence of data.

    V17.9.25/V19 performance hardening:
    non-production content is gated before the expensive PII regex family
    is evaluated. Exposure analysis is performed at most once and its result
    is reused below.

    This prevents enterprise privacy risk from being driven by natural-language
    content, localization strings, Git transport usernames, product names, and
    other repository metadata.
    """
    low = text.lower()
    non_prod_text = _is_non_production_text(path, text, target)

    # V19: perform the expensive exposure analysis once for non-production
    # content. If there is no exposure candidate, there is no reason to run
    # the ten full-document PII regexes.
    exposure_hits = []
    if non_prod_text:
        exposure_hits = _privacy_exposure_hits_fast(text)
        if not exposure_hits:
            return []

    synthetic_context = any(marker in low for marker in SYNTHETIC_MARKERS)
    hits = []

    # V27: candidate-first PII family gating.
    #
    # The lexical gate is intentionally conservative. A family is evaluated
    # only when one of its semantic indicator tokens exists in the document.
    # Existing regex and semantic validation remain unchanged after gating.
    _V27_PII_FAMILY_TOKENS = {
        "AADHAAR": ("aadhaar", "aadhar", "uidai"),
        "PAN": ("pan", "pan_number", "pan number"),
        "SSN": ("ssn", "social_security", "social security"),
        "PAYMENT_CARD": (
            "card", "card_number", "credit_card",
            "debit_card", "cardholder", "cvv", "cvc",
            "expiry", "expiry_month", "expiry_year"
        ),
        "EMAIL": (
            "email", "user_email", "email_address", "mail_address"
        ),
        "PHONE": (
            "phone", "phone_number", "mobile",
            "mobile_number", "telephone", "msisdn"
        ),
        "DOB": (
            "dob", "date_of_birth", "birth_date", "date of birth"
        ),
        "ADDRESS": (
            "address", "street", "postal", "zip_code"
        ),
        "HEALTH": (
            "patient", "diagnosis", "medical", "health", "disease"
        ),
        "BIOMETRIC": (
            "biometric", "fingerprint",
            "face_template", "iris"
        ),
    }

    _V27_CANDIDATE_FAMILIES = {
        family
        for family, tokens in _V27_PII_FAMILY_TOKENS.items()
        if any(token in low for token in tokens)
    }

    for pii_type, pattern, risk, description in _V17925_COMPILED_PII_PATTERNS:

        # V27: skip the full-document regex when the family has no
        # lexical evidence anywhere in the source.
        if pii_type not in _V27_CANDIDATE_FAMILIES:
            continue

        matched = bool(pattern.search(text))
        if not matched:
            continue

        concrete = False
        if pii_type == "EMAIL":
            # V24: A bare "email" keyword is not PII.
            # Evaluate the semantic candidate once using cached regexes.
            #
            # Preserve V21 behavior:
            #   * actual email address -> eligible
            #   * application email field -> eligible
            #   * bare documentation/keyword "email" -> rejected
            email_value_candidate = bool(
                _V24_EMAIL_VALUE_RE.search(text)
            )

            email_field_candidate = bool(
                _V24_EMAIL_FIELD_CANDIDATE_RE.search(text)
                or _V20_OBJECT_EMAIL_RE.search(text)
            )

            if not email_value_candidate and not email_field_candidate:
                continue

            # Metadata/documentation checks are only necessary when an
            # actual email value exists. Application field references are
            # still treated as concrete application PII semantics.
            metadata_email = False
            documented_contact = False

            if email_value_candidate:
                metadata_email = bool(
                    _V24_EMAIL_METADATA_CANDIDATE_RE.search(text)
                )

                documented_contact = bool(
                    _V24_EMAIL_DOCUMENTATION_RE.search(text)
                ) or (
                    path.suffix.lower() in {".md", ".txt"}
                )

                if documented_contact:
                    continue

                # V21 _has_real_email() uses the same semantic address
                # pattern. email_value_candidate already proves that
                # condition, so do not rescan the entire document.
                concrete = not metadata_email
            else:
                concrete = True
        elif pii_type == "PHONE":
            concrete = bool(_V20_PHONE_VALUE_RE.search(text)) or bool(re.search(r"(?:phone_number|mobile_number|msisdn|telephone)\s*(?:[:=]|\(|\[|\.|->)", text, re.I))
        elif pii_type == "PAYMENT_CARD":
            concrete = _looks_like_payment_data(text)
        elif pii_type in {"AADHAAR", "PAN", "SSN", "DOB", "ADDRESS", "HEALTH", "BIOMETRIC"}:
            concrete = bool(_V20_GENERIC_SEMANTIC_RE.search(text))
            if pii_type in {"AADHAAR", "PAN", "SSN"} and _V20_NUMERIC_IDENTIFIER_RE.search(text):
                # Do not treat numeric tokens embedded in URLs/event IDs as PII.
                url_like = bool(re.search(r"https?://|www\.|eventbrite\.com", text, re.I))
                identifier_context = bool(_V20_IDENTIFIER_CONTEXT_RE.search(text))
                concrete = (not url_like) or identifier_context
        if non_prod_text:
            # V19: exposure was already evaluated once before the PII regex
            # loop. Reuse that result rather than rescanning the full document.
            if not exposure_hits:
                continue
        if synthetic_context and not _is_challenge_context(text) and pii_type in {"EMAIL", "PHONE", "ADDRESS"} and not _has_real_email(text) and not re.search(r"\b(?:\+?\d[\d ()-]{8,}\d)\b", text):
            continue
        if concrete:
            hits.append((pii_type, risk, description))
    return hits


EXPOSURE_PATTERNS = [
    # A privacy exposure requires a concrete sink. Do not use a bare ``return``
    # token: challenge predicates commonly ``return req.body.email === ...``
    # and are observations/comparisons, not disclosures.
    ("PII_LOGGING", r"\b(?:print|logger\.|console\.log|log\.)\s*\([^\n]*(?:\b(?:user|req(?:uest)?|body|data|payload|record|customer|account)\.(?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)\b|[\"'](?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)[\"']\s*[:=])", "HIGH", "PII or sensitive data may be written to logs."),
    ("PII_API_RESPONSE", r"(?:\bres\.(?:json|send|end)\s*\(|\bresponse\.(?:json|send|end)\s*\(|\breply\.(?:send|json)\s*\(|\bjsonify\s*\(|\bJSONResponse\s*\(|\breturn\s+Response\s*\(|\breturn\s+JsonResponse\s*\(|\breturn\s+jsonify\s*\()[^\n]*?(?:\b(?:user|req(?:uest)?|body|data|payload|record|customer|account)\.(?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)\b|[\"'](?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)[\"']\s*:)", "HIGH", "PII may be returned in an API response."),
    ("PII_THIRD_PARTY_TRANSFER", r"(?:\brequests\.(?:post|put)\s*\(|\bfetch\s*\(|\baxios\.(?:post|put)\s*\(|\bhttp\.post\s*\()[^\n]*?(?:\b(?:user|req(?:uest)?|body|data|payload|record|customer|account)\.(?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)\b|[\"'](?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)[\"']\s*:)", "HIGH", "PII may be sent to an external or third-party endpoint."),
    ("PII_UNENCRYPTED_STORAGE", r"\b(?:insert|save|write|put_item|setItem)\s*\([^\n]*(?:\b(?:user|req(?:uest)?|body|data|payload|record|customer|account)\.(?:ssn|pan|aadhaar|card|cvv|dob|address|phone)\b|[\"'](?:ssn|pan|aadhaar|card|cvv|dob|address|phone)[\"']\s*:)", "HIGH", "PII may be stored without visible encryption or tokenization."),
    ("PROMPT_PII_EXPOSURE", r"\b(?:prompt|message|chat|llm|openai|anthropic)\b[^\n]*(?:\b(?:user|req(?:uest)?|body|data|payload|record|customer|account)\.(?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)\b|[\"'](?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)[\"']\s*:)", "HIGH", "PII may be sent to an AI prompt/model context."),
    ("NO_RETENTION_CONTROL", r"\b(retention|ttl|expire|delete_after|purge_after)\s*=\s*(None|False|0|\"\")", "MEDIUM", "Retention or deletion control appears disabled or undefined."),
    ("CONSENT_BYPASS", r"\b(consent_required|privacy_check|purpose_check)\s*=\s*False\b|skip_consent\s*=\s*True", "HIGH", "Consent or purpose limitation check may be bypassed."),
]

# V17.9.25 performance hardening.
# These are the same detection rules, compiled once instead of per source line.
_V17925_COMPILED_PII_PATTERNS = tuple(
    (pii_type, re.compile(pattern, re.IGNORECASE), risk, description)
    for pii_type, pattern, risk, description in PII_PATTERNS
)
_V17925_COMPILED_EXPOSURE_PATTERNS = tuple(
    (indicator, re.compile(pattern, re.IGNORECASE), risk, impact)
    for indicator, pattern, risk, impact in EXPOSURE_PATTERNS
)


THIRD_PARTY_HINTS = ["openai", "anthropic", "googleapis", "segment", "mixpanel", "analytics", "hubspot", "stripe", "sendgrid", "slack", "telegram", "discord"]


def _iter_files(target: str):
    root = Path(target)
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if path.suffix.lower() in SCAN_EXTENSIONS:
                yield path


def _safe_read(path: Path):
    # V17.9.25: stream source lines rather than materializing the entire file.
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                yield line.rstrip("\\r\\n")
    except Exception:
        return


def _rel(path: Path, target: str) -> str:
    try:
        return str(path.relative_to(Path(target)))
    except Exception:
        return str(path)


def _risk_rank(level: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(level).upper(), 0)


# V17.9.3 sink-driven privacy semantics. These helpers intentionally remain
# lightweight and language-aware rather than pretending regex alone proves a
# complete interprocedural data-flow path.
CHALLENGE_CONTEXT_PATTERNS = (
    r"\bchallengeUtils\.solveIf\s*\(",
    r"\bchallengeUtils\.(?:notSolved|isSolved|solve)\s*\(",
    r"\bchallenges\.[A-Za-z0-9_]+Challenge\b",
    r"\b(?:challenge|codefix|hacking-instructor)\b",
)

REQUEST_SIDE_PII_PATTERNS = (
    r"\breq(?:uest)?\.(?:body|query|params)\b",
    r"\brequest\.(?:body|query|params|args|form|json|GET|POST)\b",
    r"\b(?:body|query|params)\.(?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)\b",
)

RESPONSE_SINK_PATTERNS = (
    r"\bres\.(?:json|send|end)\s*\(",
    r"\bresponse\.(?:json|send|end)\s*\(",
    r"\breply\.(?:send|json)\s*\(",
    r"\bjsonify\s*\(",
    r"\bJSONResponse\s*\(",
    r"\breturn\s+(?:Response|JsonResponse)\s*\(",
    r"\breturn\s+jsonify\s*\(",
)

PII_VALUE_PATTERNS = (
    r"\b(?:user|req(?:uest)?|body|data|payload|record|customer|account)\.(?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)\b",
    r"[\"'](?:email|phone|address|dob|ssn|pan|aadhaar|card|cvv|token|password)[\"']\s*:",
)

def _regex_any(patterns, text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _is_challenge_context(text: str) -> bool:
    return _regex_any(CHALLENGE_CONTEXT_PATTERNS, text)


def _is_request_side_only(text: str) -> bool:
    return _regex_any(REQUEST_SIDE_PII_PATTERNS, text) and not _regex_any(RESPONSE_SINK_PATTERNS, text)


def _has_response_sink(text: str) -> bool:
    return _regex_any(RESPONSE_SINK_PATTERNS, text)


def _has_pii_value(text: str) -> bool:
    return _regex_any(PII_VALUE_PATTERNS, text)


def _classify_exposure(text: str, exposure_hits) -> tuple[bool, str]:
    """Classify an exposure only when a concrete sink and data-bearing value coexist.

    Challenge predicates and request-side comparisons are observations unless a
    real disclosure/transfer/storage/logging sink is independently established.
    """
    if not exposure_hits:
        return False, "OBSERVED_ONLY"

    has_response = _has_response_sink(text)
    has_value = _has_pii_value(text)

    # ``challengeUtils.solveIf(... return req.body.email === ...)`` is a data
    # usage/comparison construct, not an exposure. Do not suppress a challenge
    # line if it contains a genuine response sink with a data-bearing payload.
    if _is_challenge_context(text) and not (has_response and has_value):
        return False, "OBSERVED_ONLY"

    # Request-side collection/comparison is not disclosure by itself.
    if _is_request_side_only(text):
        return False, "OBSERVED_ONLY"

    # For API response findings, require both the concrete response sink and a
    # PII-bearing expression on the same logical line. Other exposure types keep
    # their explicit sink pattern semantics.
    api_hits = [h for h in exposure_hits if h[0] == "PII_API_RESPONSE"]
    if api_hits and not (has_response and has_value):
        exposure_hits[:] = [h for h in exposure_hits if h[0] != "PII_API_RESPONSE"]

    return bool(exposure_hits), ("EXPOSED" if exposure_hits else "OBSERVED_ONLY")


def _recommended_action(indicator: str) -> List[str]:
    base = [
        "Classify the data element and confirm whether it is regulated, confidential, or customer-identifiable.",
        "Minimize collection and exposure; return or transmit only fields required for the business purpose.",
        "Apply masking, tokenization, or strong encryption for storage, logs, prompts, and outbound transfers.",
    ]
    if indicator == "PII_LOGGING":
        return [
            "Remove PII from application, debug, prompt, and access logs.",
            "Apply irreversible redaction for Aadhaar/PAN/SSN/card/email/phone before log write.",
            "Restrict log access, shorten retention, and scan historical logs for exposed PII.",
        ]
    if indicator == "PII_API_RESPONSE":
        return [
            "Use explicit response DTOs/schemas and deny-list sensitive fields from serialized objects.",
            "Mask identifiers and return only the minimum fields required by the caller.",
            "Add authorization checks before returning customer or account-level data.",
        ]
    if indicator == "PII_THIRD_PARTY_TRANSFER":
        return [
            "Validate lawful basis, consent, DPA, and approved vendor status before transfer.",
            "Redact or tokenize PII before sending to third-party APIs or model providers.",
            "Add egress allow-listing and audit logging for sensitive data transfers.",
        ]
    if indicator == "PROMPT_PII_EXPOSURE":
        return [
            "Do not send raw PII to LLM/model context unless explicitly approved and contractually protected.",
            "Redact identifiers before prompt construction and disable prompt/response logging for PII.",
            "Add policy checks for purpose limitation, retention, and cross-border transfer constraints.",
        ]
    return base




# V17.9.25 privacy large-record performance V3.
# Aho-style literal candidate prefilter: only run expensive exposure regexes
# when their required literal families occur in the text. This preserves
# all existing regexes and detection semantics.

_PRIVACY_EXPOSURE_LITERAL_FAMILIES = (
    ("PII_LOGGING", ("log", "logger", "console.log", "print(")),
    ("PII_API_RESPONSE", ("res.", "response.", "reply.", "jsonify(", "jsonresponse", "jsonresponse(", "jsonresponse ")),
    ("PII_THIRD_PARTY_TRANSFER", ("requests.", "fetch(", "axios.", "http.")),
    ("PII_UNENCRYPTED_STORAGE", ("insert(", "save(", "write(", "put_item(", "setitem(")),
    ("PROMPT_PII_EXPOSURE", ("prompt", "message", "chat", "llm", "openai", "anthropic")),
)

def _privacy_candidate_lower(text):
    return text.lower()

def _privacy_exposure_candidate(indicator, low_text):
    for name, literals in _PRIVACY_EXPOSURE_LITERAL_FAMILIES:
        if name == indicator:
            return any(token in low_text for token in literals)
    return True


# V30 exposure-correlation constants
_V30_PII_VALUE_PATTERNS = (
    re.compile(
        r'(?<![A-Za-z0-9])\b\d{3}-\d{2}-\d{4}\b(?![A-Za-z0-9])'
    ),
    re.compile(
        r'(?<![A-Za-z0-9])\b[A-Z]{5}\d{4}[A-Z]\b(?![A-Za-z0-9])'
    ),
    re.compile(
        r'(?<![A-Za-z0-9])\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b(?![A-Za-z0-9])'
    ),
    re.compile(
        r'(?<![A-Za-z0-9])'
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
        r'(?![A-Za-z0-9])'
    ),
)

_V30_LOG_SINK_RE = re.compile(
    r'\b(?:logger|logging|log|audit|print|println|printf|'
    r'printStackTrace|write|append)\s*[\.(]',
    re.I,
)

_V30_STORAGE_SINK_RE = re.compile(
    r'\b(?:insert|update|save|persist|store|write|append|'
    r'put|set|execute|executeUpdate|executeQuery)\s*[\.(]',
    re.I,
)

_V30_PROMPT_SINK_RE = re.compile(
    r'\b(?:prompt|messages|chat|completion|generate|invoke|'
    r'predict|llm|openai|anthropic|model)\s*[\.(]',
    re.I,
)

_V30_PII_FIELD_RE = re.compile(
    r'\b(?:email|e-mail|ssn|social\s+security|aadhaar|aadhar|'
    r'pan(?:\s+number)?|phone|mobile|telephone|dob|date\s+of\s+birth|'
    r'passport|card\s+number|account\s+number)\b',
    re.I,
)




def _v34_has_storage_correlation(text):
    """
    V34 storage-specific correlation.

    A storage sink is considered privacy-relevant only when:
      1. a concrete PII value is present in the same bounded statement, OR
      2. a PII field identifier is explicitly passed to the storage call.

    A nearby standalone PII keyword is insufficient.
    """

    if not text:
        return False

    # Split into conservative statement/expression units.
    statements = re.split(
        r'[;\r\n]+',
        text,
    )

    for statement in statements:
        statement = statement.strip()

        if not statement:
            continue

        # Storage operation must occur in this statement.
        sink_match = _V30_STORAGE_SINK_RE.search(statement)

        if not sink_match:
            continue

        # ------------------------------------------------------------
        # Rule 1: concrete PII value in the same statement.
        # Example:
        #   ssn=123-45-6789; save(ssn)
        #
        # The assignment and sink may be separated by the statement
        # boundary, so Rule 2 handles variable propagation.
        # ------------------------------------------------------------

        if any(
            pattern.search(statement)
            for pattern in _V30_PII_VALUE_PATTERNS
        ):
            return True

        # ------------------------------------------------------------
        # Rule 2: explicit PII field passed to the storage sink.
        #
        # Examples accepted:
        #   save(email)
        #   store(ssn)
        #   insert(customer_email)
        #
        # Avoid accepting merely:
        #   email; save(data)
        # ------------------------------------------------------------

        sink_tail = statement[sink_match.start():]

        if not _V30_PII_FIELD_RE.search(
            sink_tail
        ):
            continue

        # Require the PII field to occur as an argument/value rather
        # than merely before the sink.
        open_pos = sink_tail.find("(")

        if open_pos < 0:
            continue

        args = sink_tail[open_pos + 1:]

        close_pos = args.find(")")

        if close_pos >= 0:
            args = args[:close_pos]

        if _V30_PII_FIELD_RE.search(args):
            return True

    return False



def _privacy_exposure_hits_fast(text):
    """
    V30 correlation-gated privacy exposure detection.

    Generic exposure vocabulary is not sufficient. Each indicator requires
    concrete PII evidence within a bounded semantic context.
    """

    hits = []

    if not text:
        return hits

    if _v30_has_exposure_correlation(
        text,
        _V30_LOG_SINK_RE,
    ):
        hits.append((
            "PII_LOGGING",
            None,
            "HIGH",
            "PII or sensitive data may be written to logs.",
        ))

    if _v34_has_storage_correlation(text):
        hits.append((
            "PII_UNENCRYPTED_STORAGE",
            None,
            "HIGH",
            "PII may be stored without visible encryption or tokenization.",
        ))

    if _v30_has_exposure_correlation(
        text,
        _V30_PROMPT_SINK_RE,
    ):
        hits.append((
            "PROMPT_PII_EXPOSURE",
            None,
            "HIGH",
            "PII may be sent to an AI prompt/model context.",
        ))

    return hits
def _v30_has_concrete_pii(context):
    """Return True only for an actual PII value or a PII-bearing field."""
    if not context:
        return False

    for pattern in _V30_PII_VALUE_PATTERNS:
        if pattern.search(context):
            return True

    return bool(_V30_PII_FIELD_RE.search(context))


def _v30_has_exposure_correlation(text, sink_re):
    """
    Require PII evidence and an exposure sink within the same bounded
    semantic window. This intentionally avoids whole-document correlation.
    """
    if not text:
        return False

    window = 1200
    matches = list(sink_re.finditer(text))

    for match in matches:
        start = max(0, match.start() - window)
        end = min(len(text), match.end() + window)
        context = text[start:end]

        if _v30_has_concrete_pii(context):
            return True

    return False


def _privacy_pii_hits_fast(text, path, target):
    """
    V25 lexical family-gated PII detection.

    Performance strategy:
      1. Lowercase the document once.
      2. Identify PII families that have lexical evidence.
      3. Run expensive PII regexes only for those families.
      4. Preserve existing semantic validation through
         _semantic_pii_hits().
    """

    # V25: lexical family gating.
    low = text.lower()

    family_tokens = {
        "AADHAAR": (
            "aadhaar",
            "aadhar",
            "uidai",
        ),
        "PAN": (
            "pan",
            "pan_number",
            "pan number",
        ),
        "SSN": (
            "ssn",
            "social_security",
            "social security",
        ),
        "PAYMENT_CARD": (
            "card",
            "card_number",
            "credit_card",
            "debit_card",
            "cvv",
            "cvc",
            "expiry",
        ),
        "EMAIL": (
            "email",
            "user_email",
            "email_address",
            "mail_address",
        ),
        "PHONE": (
            "phone",
            "phone_number",
            "mobile",
            "mobile_number",
            "telephone",
            "msisdn",
        ),
        "DOB": (
            "dob",
            "date_of_birth",
            "birth_date",
            "date of birth",
        ),
        "ADDRESS": (
            "address",
            "street",
            "postal",
            "zip_code",
        ),
        "HEALTH": (
            "patient",
            "diagnosis",
            "medical",
            "health",
            "disease",
        ),
        "BIOMETRIC": (
            "biometric",
            "fingerprint",
            "face_template",
            "iris",
        ),
    }

    candidate_families = {
        name
        for name, tokens in family_tokens.items()
        if any(token in low for token in tokens)
    }

    # Numeric-only PII patterns need a digit gate.
    if any(ch.isdigit() for ch in text):
        candidate_families.update({
            "AADHAAR",
            "PAN",
            "SSN",
            "PAYMENT_CARD",
            "PHONE",
            "DOB",
        })

    if not candidate_families:
        return []

    # Preserve the existing semantic implementation while preventing
    # irrelevant PII families from invoking their expensive regex.
    original_patterns = globals().get(
        "_V17925_COMPILED_PII_PATTERNS"
    )

    if not original_patterns:
        return _semantic_pii_hits(text, path, target)

    filtered_patterns = tuple(
        item
        for item in original_patterns
        if item[0] in candidate_families
    )

    if not filtered_patterns:
        return []

    # Temporarily expose only the candidate families to the semantic
    # evaluator. The semantic evaluator itself remains unchanged.
    global _V17925_COMPILED_PII_PATTERNS

    saved_patterns = _V17925_COMPILED_PII_PATTERNS

    try:
        _V17925_COMPILED_PII_PATTERNS = filtered_patterns
        return _semantic_pii_hits(text, path, target)
    finally:
        _V17925_COMPILED_PII_PATTERNS = saved_patterns


# V17.9.25 privacy large-record bounded matching.
_V17925_PRIVACY_V3_MARKER = True
_PRIVACY_LARGE_TEXT_THRESHOLD = 64 * 1024
_PRIVACY_CHUNK_SIZE = 64 * 1024
_PRIVACY_CHUNK_OVERLAP = 2048

def _privacy_text_windows(text):
    if len(text) <= _PRIVACY_LARGE_TEXT_THRESHOLD:
        yield text
        return
    step = _PRIVACY_CHUNK_SIZE - _PRIVACY_CHUNK_OVERLAP
    start = 0
    n = len(text)
    while start < n:
        end = min(start + _PRIVACY_CHUNK_SIZE, n)
        yield text[start:end]
        if end >= n:
            break
        start += step

def _privacy_pii_hits_bounded(text, path, target):
    if len(text) <= _PRIVACY_LARGE_TEXT_THRESHOLD:
        return _semantic_pii_hits(text, path, target)
    merged = []
    seen = set()
    for window in _privacy_text_windows(text):
        for item in _semantic_pii_hits(window, path, target):
            key = repr(item)
            if key not in seen:
                seen.add(key)
                merged.append(item)
    return merged

def _redact_pii_evidence(text: str) -> str:
    """
    Redact PII only at the evidence/report presentation boundary.

    Detection input is never modified by this helper.

    D-02 design:
      1. Structured PII detectors run first.
      2. Generic PII-field fallback runs second.
      3. Existing REDACTED markers are immutable.
      4. Generic-field prefix whitespace is possessive so regex
         backtracking cannot consume part of an existing marker.
      5. Replacement is callback-based rather than replacement-string
         backreferences.
      6. The resulting transformation is idempotent.

    OWASP alignment:
      - deterministic structured patterns are kept separate from
        contextual qualification and risk logic;
      - this helper performs evidence sanitization only;
      - entropy/statistical analysis belongs to secret/high-entropy
        detection and is intentionally not mixed into PII redaction.
    """
    if not isinstance(text, str) or not text:
        return text

    redacted = text

    # ------------------------------------------------------------
    # D-02 structured detectors
    # ------------------------------------------------------------

    # Email.
    redacted = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        redacted,
    )

    # US SSN.
    redacted = re.sub(
        r"\b\d{3}-\d{2}-\d{4}\b",
        "[REDACTED_SSN]",
        redacted,
    )

    # Payment cards MUST precede Aadhaar because a 16-digit card
    # can otherwise partially match the Aadhaar pattern.
    redacted = re.sub(
        r"\b(?:\d[ -]?){13,19}\b",
        "[REDACTED_PAYMENT_CARD]",
        redacted,
    )

    # Aadhaar-like identifier.
    redacted = re.sub(
        r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b",
        "[REDACTED_AADHAAR]",
        redacted,
    )

    # PAN.
    redacted = re.sub(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "[REDACTED_PAN]",
        redacted,
    )

    # ------------------------------------------------------------
    # D-02 generic PII-field fallback
    # ------------------------------------------------------------

    field_names = (
        r"email|phone|phone_number|mobile|mobile_number|ssn|pan|aadhaar|"
        r"card_number|cardnumber|credit_card_number|debit_card_number|cvv|cvc"
    )

    marker = re.compile(
        r"\[REDACTED_[A-Z0-9_]+\]",
        flags=re.I,
    )

    # IMPORTANT:
    #
    # The whitespace after [: =] is possessive (\s*+).
    #
    # Without this, Python regex can backtrack through the whitespace
    # and evaluate the REDACTED-marker guard at the wrong position.
    # That was the root cause of:
    #
    #     [REDACTED_PII]]
    #
    # Possessive whitespace makes the field prefix atomic with respect
    # to that whitespace and prevents the corruption.

    quoted_pattern = re.compile(
        r"(?P<prefix>(?:" + field_names + r")\s*[:=]\s*+)"
        r"(?P<quote>[\x22\x27])"
        r"(?P<value>[^\r\n]*?)"
        r"(?P=quote)"
        r"(?=\s*(?:[,;}\]]|$))",
        flags=re.I,
    )

    def _redact_quoted(match):
        value = match.group("value").strip()
        if marker.fullmatch(value):
            return match.group(0)
        return match.group("prefix") + match.group("quote") + "[REDACTED_PII]" + match.group("quote")

    redacted = quoted_pattern.sub(_redact_quoted, redacted)

    unquoted_pattern = re.compile(
        r"(?P<prefix>(?:" + field_names + r")\s*[:=]\s*+)"
        r"(?!\[REDACTED_[A-Z0-9_]+\])"
        r"(?P<value>[^\r\n,;}\]]+?)"
        r"(?=\s*(?:[,;}\]]|$))",
        flags=re.I,
    )

    def _redact_unquoted(match):
        value = match.group("value").strip()
        if marker.fullmatch(value):
            return match.group(0)
        return (
        match.group("prefix")
        + match.group("quote")
        + "[REDACTED_PII]"
        + match.group("quote")
    )

    redacted = unquoted_pattern.sub(_redact_unquoted, redacted)

    return redacted
def _privacy_exposure_hits_bounded(text):
    hits = []
    seen = set()
    for window in _privacy_text_windows(text):
        for indicator, pattern, risk, impact in _V17925_COMPILED_EXPOSURE_PATTERNS:
            if pattern.search(window):
                key = (indicator, risk, impact)
                if key not in seen:
                    seen.add(key)
                    hits.append((indicator, pattern, risk, impact))
    return hits



_V17925_PRIVACY_STREAMING_V5_MARKER = True
_PRIVACY_V5_CHUNK_SIZE = 128 * 1024
_PRIVACY_V5_OVERLAP = 4096

def _privacy_v5_stream_chunks(path):
    import codecs
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    with open(path, "rb") as fh:
        carry = ""
        while True:
            block = fh.read(_PRIVACY_V5_CHUNK_SIZE)
            if not block:
                break
            data = carry + decoder.decode(block, final=False)
            while len(data) > _PRIVACY_V5_CHUNK_SIZE + _PRIVACY_V5_OVERLAP:
                yield data[:_PRIVACY_V5_CHUNK_SIZE]
                data = data[_PRIVACY_V5_CHUNK_SIZE:]
            if len(data) > _PRIVACY_V5_OVERLAP:
                yield data[:-_PRIVACY_V5_OVERLAP]
                carry = data[-_PRIVACY_V5_OVERLAP:]
            else:
                carry = data
        data = carry + decoder.decode(b"", final=True)
        while len(data) > _PRIVACY_V5_CHUNK_SIZE:
            yield data[:_PRIVACY_V5_CHUNK_SIZE]
            data = data[_PRIVACY_V5_CHUNK_SIZE:]
        if data:
            yield data

def enrich_privacy_data_exposure(target: str, findings: List[Dict[str, Any]] | None = None, api_bom: List[Dict[str, Any]] | None = None, data_flow_summary: Dict[str, Any] | None = None, live_progress: bool = True) -> Dict[str, Any]:
    indicators: List[Dict[str, Any]] = []
    pii_type_counts: Dict[str, int] = {}

    _privacy_v5_files = list(_iter_files(target))
    _privacy_v5_total = len(_privacy_v5_files)
    _privacy_v5_global_start = time.perf_counter()
    _privacy_v5_index = 0
    _privacy_v5_last_report = _privacy_v5_global_start - 1.0
    if live_progress:
        print(
            f"[PRIVACY] Start Date/Time: {time.strftime('%d-%m-%Y %H:%M:%S')}",
            flush=True,
        )
        print(f"[PRIVACY] Files discovered: {_privacy_v5_total}", flush=True)

    for path in _privacy_v5_files:
        _privacy_v5_index += 1

        # V17.9 throttled privacy progress: maximum one update per second.
        # Chunk processing remains completely silent.
        _privacy_v5_now = time.perf_counter()
        if live_progress and (
            (_privacy_v5_now - _privacy_v5_last_report) >= 1.0
            or _privacy_v5_index == _privacy_v5_total
        ):
            _privacy_live(
                f"[PRIVACY] {_privacy_v5_index}/{_privacy_v5_total} "
                f"({(_privacy_v5_index / _privacy_v5_total * 100.0) if _privacy_v5_total else 100.0:5.1f}%) "
                f"| Indicators: {len(indicators):,} "
                f"| Exposed: {sum(1 for i in indicators if i.get('privacy_exposure_confirmed')):,} "
                f"| Observed: {sum(1 for i in indicators if i.get('privacy_evidence_state') == 'OBSERVED_ONLY'):,} "
                f"| Critical: {sum(1 for i in indicators if i.get('risk_level') == 'CRITICAL'):,} "
                f"| High: {sum(1 for i in indicators if i.get('risk_level') == 'HIGH'):,} "
                f"| Elapsed: {_privacy_v5_now - _privacy_v5_global_start:.1f}s",
                flush=True,
            )
            _privacy_v5_last_report = _privacy_v5_now

        _privacy_v5_file_start = time.perf_counter()
        try:
            _privacy_v5_size = path.stat().st_size
        except OSError:
            _privacy_v5_size = 0
        _privacy_v5_done = 0

        _privacy_v5_chunk_no = 0
        for _privacy_v5_chunk in _privacy_v5_stream_chunks(path):
            _privacy_v5_chunk_no += 1
            line_no = _privacy_v5_chunk_no
            line = _privacy_v5_chunk
            text = _privacy_v5_chunk.strip()

            _privacy_v5_done = min(
                _privacy_v5_size,
                _privacy_v5_done + len(_privacy_v5_chunk.encode("utf-8", "replace"))
            )
            _privacy_v5_pct = (
                (_privacy_v5_done / _privacy_v5_size * 100.0)
                if _privacy_v5_size else 100.0
            )
            _privacy_v5_file_elapsed = time.perf_counter() - _privacy_v5_file_start
            _privacy_v5_total_elapsed = time.perf_counter() - _privacy_v5_global_start

            
            if not text:
                continue
            if not text:
                continue
            # Privacy analysis is intentionally production-oriented. Benchmark
            # challenge/code-fix assets, tests, fixtures, documentation and
            # localization content remain visible to SAST but are excluded from
            # privacy exposure telemetry to prevent known training material from
            # inflating enterprise privacy risk.
            if _is_non_production_text(path, text, target):
                continue

            pii_matches = _privacy_pii_hits_fast(text, path, target)
            pii_hits = [m[0] for m in pii_matches]
            max_risk = "LOW"
            descriptions = [m[2] for m in pii_matches]
            for pii_type, risk, _description in pii_matches:
                pii_type_counts[pii_type] = pii_type_counts.get(pii_type, 0) + 1
                if _risk_rank(risk) > _risk_rank(max_risk):
                    max_risk = risk

            # D-02: supplement the optimized fast path with bounded semantic
            # exposure detection for sink/data correlation.
            exposure_hits = _privacy_exposure_hits_fast(text)

            bounded_exposure_hits = _privacy_exposure_hits_bounded(text)

            existing_exposure_indicators = {
                item[0] for item in exposure_hits
            }

            for bounded_hit in bounded_exposure_hits:
                if bounded_hit[0] not in existing_exposure_indicators:
                    exposure_hits.append(bounded_hit)
                    existing_exposure_indicators.add(bounded_hit[0])

            for indicator, _pattern, risk, impact in exposure_hits:
                if _risk_rank(risk) > _risk_rank(max_risk):
                    max_risk = risk

            # Contact/metadata text must not become a privacy indicator merely
            # because it contains an email address.
            if not pii_hits and not exposure_hits:
                continue
            if pii_hits == ["EMAIL"] and (bool(EMAIL_METADATA_RE.search(text)) or bool(_V20_EMAIL_METADATA_RE.search(text))):
                pii_hits = []
                pii_matches = []
                max_risk = "LOW"
                if not exposure_hits:
                    continue

            third_party = any(h in text.lower() for h in THIRD_PARTY_HINTS)
            if third_party and pii_hits and _risk_rank(max_risk) < _risk_rank("HIGH"):
                max_risk = "HIGH"

            # A privacy exposure must be tied to an observed PII data element.
            # Control-pattern matches such as consent/retention checks are
            # privacy governance observations, not PII disclosures by themselves.
            if exposure_hits and not pii_hits:
                exposed, evidence_state = False, "OBSERVED_ONLY"
            else:
                exposed, evidence_state = _classify_exposure(text, exposure_hits)
            indicator_name = exposure_hits[0][0] if exposed else "PII_PATTERN_OBSERVED"
            impact = exposure_hits[0][2] if exposed else "PII-like data element observed in source code; no exposure sink was established by static analysis."
            # Observation of a PII-shaped field is not itself a privacy exposure.
            # Only a matched exposure sink may retain HIGH/CRITICAL semantics.
            if not exposed:
                max_risk = "LOW"

            indicators.append({
                "indicator": indicator_name,
                "risk_level": max_risk,
                "severity": "Critical" if max_risk == "CRITICAL" else ("High" if max_risk == "HIGH" else "Low"),
                "privacy_evidence_state": evidence_state,
                # Static analysis establishes the PII-to-sink relationship only.
                # It does not prove that a runtime request actually disclosed the data.
                "static_exposure_confirmed": bool(exposed),
                "runtime_exposure_confirmed": False,
                "privacy_exposure_status": "STATIC_EXPOSURE_ESTABLISHED" if exposed else "OBSERVED_ONLY",
                # Backward-compatible field: means static exposure correlation, not runtime proof.
                "privacy_exposure_confirmed": bool(exposed),
                "file": _rel(path, target),
                "line": line_no,
                "snippet": _redact_pii_evidence(text[:240]),
                "pii_types": sorted(set(pii_hits)),
                "privacy_domain": "Data Privacy / PII Exposure",
                "third_party_transfer_hint": third_party,
                "description": impact,
                "business_impact": "Potential exposure of regulated or customer-identifiable data may trigger privacy, contractual, and compliance obligations.",
                "recommended_actions": _recommended_action(indicator_name),
                "framework_mappings": {
                    "gdpr": ["Art. 5 Data minimisation", "Art. 32 Security of processing"],
                    "dpdp_india": ["Purpose limitation", "Reasonable security safeguards"],
                    "nist_privacy": ["CT.PO-P", "DM.PD-P"],
                },
                "confidence": "HIGH" if exposure_hits and pii_hits else ("MEDIUM" if pii_hits else "LOW"),
                "context_validated": bool(pii_hits or exposure_hits),
                "false_positive_controls": [
                    "localization/documentation content excluded",
                    "Git transport usernames excluded from email detection",
                    "keyword-only payment-card matches excluded",
                    "synthetic/test fixture paths excluded unless concrete data evidence exists",
                ],
            })

    # Add contextual signal from data-flow engine if it already found sensitive flows.
    dfs = data_flow_summary or {}
    sensitive_count = int(dfs.get("total_data_flow_sensitivity_indicators", 0) or dfs.get("total_indicators", 0) or 0)
    if sensitive_count:
        indicators.append({
            "indicator": "SENSITIVE_DATA_FLOW_CONTEXT",
            "risk_level": "LOW",
            "severity": "Low",
            "privacy_evidence_state": "OBSERVED_ONLY",
            "static_exposure_confirmed": False,
            "runtime_exposure_confirmed": False,
            "privacy_exposure_status": "OBSERVED_ONLY",
            "privacy_exposure_confirmed": False,
            "file": "DATA_FLOW_CORRELATION",
            "line": 0,
            "snippet": f"{sensitive_count} sensitive data-flow indicators observed by data-flow engine.",
            "pii_types": [],
            "privacy_domain": "Data Privacy / Data Flow",
            "third_party_transfer_hint": False,
            "description": "Existing data-flow indicators suggest sensitive data handling paths that require privacy review.",
            "business_impact": "Sensitive data movement may expand breach impact and regulatory exposure.",
            "recommended_actions": [
                "Review correlated sensitive data flows and confirm data classification for each source/sink.",
                "Add masking/encryption at sinks and enforce data minimisation in API responses.",
                "Map each sensitive flow to owner, purpose, retention, and approved processing basis.",
            ],
            "confidence": "MEDIUM",
            "context_validated": True,
            "false_positive_controls": [
                "data-flow context is telemetry only and does not establish privacy exposure",
                "requires independent privacy source-to-sink evidence before EXPOSED classification",
            ],
        })

    # Every privacy indicator must have an explicit evidence state.  This is a
    # report-integrity invariant: OBSERVED_ONLY + EXPOSED + other explicit
    # states must reconcile exactly to total_privacy_indicators.
    for _indicator in indicators:
        if not _indicator.get("privacy_evidence_state"):
            _indicator["privacy_evidence_state"] = "OBSERVED_ONLY"
        if "static_exposure_confirmed" not in _indicator:
            _indicator["static_exposure_confirmed"] = _indicator.get("privacy_evidence_state") == "EXPOSED"
        if "runtime_exposure_confirmed" not in _indicator:
            _indicator["runtime_exposure_confirmed"] = False
        if "privacy_exposure_status" not in _indicator:
            _indicator["privacy_exposure_status"] = (
                "STATIC_EXPOSURE_ESTABLISHED" if _indicator.get("static_exposure_confirmed") else "OBSERVED_ONLY"
            )
        if "privacy_exposure_confirmed" not in _indicator:
            _indicator["privacy_exposure_confirmed"] = bool(_indicator.get("static_exposure_confirmed"))

    critical = sum(1 for i in indicators if i.get("risk_level") == "CRITICAL" and i.get("privacy_exposure_confirmed"))
    high = sum(1 for i in indicators if i.get("risk_level") == "HIGH" and i.get("privacy_exposure_confirmed"))
    observed_only = sum(1 for i in indicators if i.get("privacy_evidence_state") == "OBSERVED_ONLY")
    exposed_count = sum(1 for i in indicators if i.get("privacy_evidence_state") == "EXPOSED")
    vulnerability_count = sum(1 for i in indicators if i.get("privacy_exposure_confirmed") and i.get("risk_level") in {"HIGH", "CRITICAL"})
    third_party_count = sum(1 for i in indicators if i.get("third_party_transfer_hint") and i.get("privacy_exposure_confirmed"))

    _privacy_finding_keys = set()
    deduplicated_privacy_findings = []
    for _indicator in indicators:
        _key = (
            str(_indicator.get("indicator") or ""),
            str(_indicator.get("file") or ""),
            tuple(sorted(_indicator.get("pii_types") or [])),
            str(_indicator.get("description") or ""),
        )
        if _key not in _privacy_finding_keys:
            _privacy_finding_keys.add(_key)
            deduplicated_privacy_findings.append(_indicator)

    raw_privacy_evidence_count = len(indicators)
    deduplicated_privacy_finding_count = len(deduplicated_privacy_findings)
    unclassified_privacy_indicators = sum(
        1 for i in indicators if i.get("privacy_evidence_state") not in {"OBSERVED_ONLY", "EXPOSED"}
    )
    classification_complete = unclassified_privacy_indicators == 0 and (
        observed_only + exposed_count == raw_privacy_evidence_count
    )
    potential_executive_review_indicators = critical + high
    confirmed_executive_exposures = 0

    if live_progress:
        _privacy_live_finish()
    return {
        "summary_status": "PRIVACY_DATA_EXPOSURE_IDENTIFIED" if exposed_count else ("PRIVACY_DATA_ELEMENTS_OBSERVED_REVIEW_REQUIRED" if observed_only else "NO_PRIVACY_DATA_EXPOSURE_INDICATORS_IDENTIFIED"),
        "total_privacy_indicators": len(indicators),
        "total_privacy_evidence": len(indicators),
        "privacy_observed_only_indicators": observed_only,
        "privacy_exposure_indicators": exposed_count,
        "privacy_static_exposure_indicators": exposed_count,
        "privacy_runtime_exposure_confirmed": sum(1 for i in indicators if i.get("runtime_exposure_confirmed") is True),
        "privacy_vulnerability_indicators": vulnerability_count,
        "privacy_unclassified_indicators": unclassified_privacy_indicators,
        "privacy_classification_complete": classification_complete,
        "critical_privacy_indicators": critical,
        "high_privacy_indicators": high,
        "third_party_transfer_indicators": third_party_count,
        "pii_type_counts": pii_type_counts,
        # V17.9 PRIVACY EVIDENCE SEMANTICS
        "raw_privacy_evidence_count": raw_privacy_evidence_count,
        "deduplicated_privacy_finding_count": deduplicated_privacy_finding_count,
        "deduplicated_privacy_findings": deduplicated_privacy_findings[:500],
        "potential_executive_review_indicators": potential_executive_review_indicators,
        "confirmed_executive_exposures": confirmed_executive_exposures,
        "executive_relevant": confirmed_executive_exposures,
        "indicator_semantics": "PII_OBSERVED_SEPARATE_FROM_EXPOSURE;_EXPOSURE_REQUIRES_STATIC_SINK_CORRELATION;_RUNTIME_NOT_CONFIRMED",
        "exposure_semantics": "STATIC_EXPOSURE_REQUIRES_PII_TO_DISCLOSURE_SINK_CORRELATION;_RUNTIME_DISCLOSURE_IS_NOT_CONFIRMED_BY_STATIC_ANALYSIS",
        "static_exposure_semantics": "STATIC_EXPOSURE_ESTABLISHED_MEANS_A_PII_BEARING_EXPRESSION_WAS_CORRELATED_TO_A_DISCLOSURE_SINK",
        "runtime_exposure_semantics": "RUNTIME_EXPOSURE_CONFIRMED_REQUIRES_RUNTIME_EVIDENCE_AND_IS_FALSE_FOR_STATIC_ONLY_SCANS",
        "exposure_classifier": "SINK_DRIVEN_V17_9_3",
        "challenge_context_semantics": "CHALLENGE_PREDICATE_OBSERVATION_ONLY_UNLESS_INDEPENDENT_EXPOSURE_SINK_EXISTS",
        "request_side_semantics": "REQUEST_COLLECTION_OR_COMPARISON_IS_NOT_DISCLOSURE_WITHOUT_EXPOSURE_SINK",
        "engine_mode": "STATIC_PRIVACY_PATTERN_AND_CONTEXT_ANALYSIS_V3_SINK_DRIVEN",
        "indicators": indicators[:500],
    }








