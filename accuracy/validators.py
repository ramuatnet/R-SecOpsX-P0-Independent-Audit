"""Accuracy-layer validators.

Each validator takes (finding, context) and returns None (no opinion) or
(verdict_hint, confidence_delta, reason). The orchestrator combines them.
All regexes are ReDoS-safe (no nested quantifiers). File reads are bounded
and cached (shared with the UFIB reader).
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from accuracy.sink_table import (
    FAMILY_LAYER,
    MINIFIED_HINTS,
    family_for_finding,
    other_family_sink,
    sinks_for,
    suggested_rule_for,
)
from accuracy.config import context_window, entropy_threshold_generic

# Reuse the bounded, cached reader from the UFIB package (same process,
# same cache -- no double file reads, no new dependency).
from analysis.ufib_brain import read_source  # noqa: E402

# ---------------------------------------------------------------------------
# 1f. Mitigation detectors
# ---------------------------------------------------------------------------
_MITIGATION_PATTERNS = {
    "parameterized_query": re.compile(
        r"\b(?:execute|executemany|query)\s*\(\s*['\"][^'\"]*['\"]\s*,|"
        r"prepareStatement\s*\([^)]*\)\s*[.;]?\s*\n?\s*set[A-Z]|"
        r"setParameter\s*\(|\bcreateNamedQuery\s*\(", re.I),
    "input_validation": re.compile(
        r"@(?:Valid|Validated)\b|@RequestBody\s+@\w*Valid|"
        r"Validators?\.(?:required|email)|marshmallow|pydantic|"
        r"@ IsValid|validate[A-Z]\w*\s*\(", re.I),
    "xml_hardened": re.compile(
        r"XMLConstants\.FEATURE_SECURE_PROCESSING|"
        r"disallow-doctype-decl|disallow-doctype-decl\"?\s*,\s*true|"
        r"setFeature\s*\(\s*\"http://apache\.org/xml/features/disallow", re.I),
    "path_canonicalized": re.compile(
        r"(?:getCanonicalPath\s*\(\s*\)|toRealPath\s*\(\s*\)|"
        r"(?:os\.path\.)?(?:normpath|realpath|abspath)\s*\()|"
        r"startsWith\s*\(\s*(?:base|root|upload)", re.I),
    "secure_random": re.compile(
        r"\bSecureRandom\b|\bsecrets\.|os\.urandom\s*\(|"
        r"crypto\.random|getRandomValues", re.I),
    "safe_yaml": re.compile(r"yaml\.safe_load\b|Loader\s*=\s*SafeLoader", re.I),
}


def mitigation_check(finding: dict, window_text: str):
    """Any mitigation present in the window -> downgrade with a reason."""
    for name, pat in _MITIGATION_PATTERNS.items():
        if pat.search(window_text):
            return ("NEEDS_REVIEW", -25,
                    "mitigation present in context: %s" % name)
    return None


# ---------------------------------------------------------------------------
# Evidence-sink consistency (mission a) + MISLABELED
# ---------------------------------------------------------------------------
def sink_consistency(finding: dict, window_text: str):
    family = family_for_finding(finding)
    if family is None:
        return None  # types without a sink model (secrets, config readings)
    for pat in sinks_for(family):
        if pat.search(window_text):
            return None  # claimed sink observed
    other = other_family_sink(window_text, exclude=family)
    if other:
        suggested = suggested_rule_for(other)
        return ("MISLABELED", -30,
                "flagged window has no %s sink; a %s sink is present "
                "(suggested rule: %s)" % (family, other, suggested))
    return ("LIKELY_FALSE_POSITIVE", -45,
            "flagged line/window contains no %s sink" % family)


# ---------------------------------------------------------------------------
# Minified/bundled heuristics (mission b)
# ---------------------------------------------------------------------------
_MINIFIED_LINE = re.compile(r".")
_WS_RUN = re.compile(r"\s{2,}")


def minified_check(finding: dict, file_text: str | None):
    fname = str(finding.get("file") or "")
    if any(h.search(fname) for h in MINIFIED_HINTS):
        return ("LIKELY_FALSE_POSITIVE", -40,
                "bundled/minified artifact by name")
    if file_text:
        lines = file_text.splitlines()
        if lines:
            longest = max(len(l) for l in lines)
            if longest > 2000:
                return ("LIKELY_FALSE_POSITIVE", -40,
                        "minified file (longest line %d chars)" % longest)
            sample = "\n".join(lines[:400])
            if len(sample) > 2000:
                ws = len(_WS_RUN.findall(sample))
                ratio = ws / max(1, len(sample))
                if ratio < 0.02:
                    return ("LIKELY_FALSE_POSITIVE", -40,
                            "minified file (whitespace ratio %.3f)" % ratio)
    return None


# ---------------------------------------------------------------------------
# Language/layer gate (mission d)
# ---------------------------------------------------------------------------
def layer_gate(finding: dict):
    family = family_for_finding(finding)
    if family is None:
        return None
    allowed, layer = FAMILY_LAYER.get(family, (None, None))
    if allowed is None:
        return None
    ext = Path(str(finding.get("file") or "")).suffix.lower()
    from accuracy.sink_table import _EXT_LANGUAGE
    lang = _EXT_LANGUAGE.get(ext)
    if lang is None:
        return None
    if lang not in allowed:
        return ("LIKELY_FALSE_POSITIVE", -40,
                "layer mismatch: %s rule on a %s (%s-layer) file"
                % (family, lang, layer))
    return None


# ---------------------------------------------------------------------------
# Secret validator (mission H/c): key-name AND value checks
# ---------------------------------------------------------------------------
_SECRET_FORMATS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"),
    re.compile(r"\b(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_SECRET_PLACEHOLDERS = re.compile(
    r"\[REDACTED[^\]]*\]|\$\{[^}]{1,60}\}|\{\{[^}]{1,60}\}\}|"
    r"\b(?:changeme|change-me|placeholder|example|sample|dummy|not-a-real|"
    r"your-api-key|xxxxxx)\b", re.I)
_I18N_LABEL = re.compile(
    r"(?:^|[./\\])(?:i18n|locale[s]?|messages|bundle)[./\\]|"
    r"(?:label|msg|err|error|title|text|prompt)[._]", re.I)


def _shannon_entropy(data: str) -> float:
    """Shannon entropy, bits/char (ported idea from ne0psych/codeshield,
    MIT -- see docs/rule_gap_analysis.md attribution)."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    ent = 0.0
    for c in freq.values():
        p = c / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent


_COMMON_WORDS = re.compile(
    r"\b(?:the|and|for|you|your|please|enter|invalid|required|password|"
    r"login|user|name|failed|error|success|welcome)\b", re.I)


def secret_check(finding: dict, window_text: str):
    rid = str(finding.get("rule_id") or "").upper()
    vt = str(finding.get("vuln_type") or "").lower()
    if not ("SECRET" in rid or "CREDENTIAL" in rid or "PASSWORD" in rid
            or "HARDCRED" in rid or "secret" in vt):
        return None
    # UI/i18n label keys are not secrets (mission 1c).
    file_l = str(finding.get("file") or "")
    if _I18N_LABEL.search(file_l) or _I18N_LABEL.search(window_text[:200]):
        return ("LIKELY_FALSE_POSITIVE", -50,
                "i18n/message resource or UI label, not a credential value")

    # The value candidate is the quoted string ON THE FLAGGED LINE (or the
    # nearest credential-keyword assignment) -- never "the last quoted
    # string anywhere in the window", which could be any unrelated literal.
    # Line-scoped candidates first, then keyword-adjacent in the window.
    line_text = str(finding.get("snippet") or "") or window_text.splitlines()[0]
    value = None
    lm = None
    for lm in re.finditer(r"[\"']([^\"']{4,})[\"']", line_text):
        pass
    if lm:
        value = lm.group(1)
    else:
        best = None
        for km in re.finditer(
                r"(?i)(?:secret|password|passwd|pwd|api[_-]?key|token|key)"
                r"\s*[:=]\s*[\"']([^\"']{4,})[\"']", window_text):
            best = km
        if best:
            value = best.group(1)
    if not value:
        return ("NEEDS_REVIEW", -10,
                "no literal value candidate to validate (identifier-only)")
    # The pipeline's own privacy redaction removed the value: the layer has
    # no lexical signal, so it ABSTAINS (no opinion) rather than reading
    # redaction as a placeholder -- the upstream verdict stands.
    if re.search(r"\[\s*REDACTED[^\]]*\]|\[\s*KNOWN SECRET REDACTED\s*\]|"
                 r"\*{4,}", value, re.I):
        return None
    if _SECRET_PLACEHOLDERS.search(value):
        return ("LIKELY_FALSE_POSITIVE", -50,
                "placeholder-shaped value")
    if _COMMON_WORDS.search(value) and value.count(" ") >= 2:
        return ("LIKELY_FALSE_POSITIVE", -45,
                "value is a plain sentence, not a credential")
    if any(p.search(value) for p in _SECRET_FORMATS):
        return ("TRUE_POSITIVE", +10,
                "recognized credential format with value")
    ent = _shannon_entropy(value)
    if ent >= entropy_threshold_generic() and len(value) >= 12:
        return ("TRUE_POSITIVE", +10,
                "high-entropy value (%.2f bits/char)" % ent)
    if ent < 2.5:
        return ("LIKELY_FALSE_POSITIVE", -40,
                "low-entropy value (%.2f bits/char)" % ent)
    return ("NEEDS_REVIEW", -5,
            "medium-entropy value (%.2f bits/char)" % ent)


# ---------------------------------------------------------------------------
# Lightweight intra-procedural taint confirm (mission: never TRUE_POSITIVE
# without a traced source-to-sink path)
# ---------------------------------------------------------------------------
_SOURCE_HINT = re.compile(
    r"request\.(?:args|form|json|data|GET|POST|values|body|params)|"
    r"@\w*(?:PathVariable|RequestParam|RequestBody)|"
    r"getParameter\s*\(|getOriginalFilename\s*\(|"
    r"ctx\.params|req\.(?:query|body|params)|inputs\[", re.I)


def taint_confirm(finding: dict, file_text: str | None,
                  line_no: int | None) -> str | None:
    """confirmed | unconfirmed | None (not applicable)."""
    detail = finding.get("evidence_validation_detail")
    if finding.get("taint_validated") or (
            isinstance(detail, dict) and detail.get("taint_validated")):
        return "confirmed"
    if file_text is None or not line_no:
        return "unconfirmed"
    lines = file_text.splitlines()
    if not (1 <= line_no <= len(lines)):
        return "unconfirmed"
    # Method body around the flagged line (intra-procedural, +/-40 lines).
    lo = max(0, line_no - 41)
    hi = min(len(lines), line_no + 40)
    body = "\n".join(lines[lo:hi])
    return "confirmed_filescope" if _SOURCE_HINT.search(body) else "unconfirmed"


# ---------------------------------------------------------------------------
# Upload validation (mission follow-up: CWE-434 has no dedicated rule, and
# the RBI2 corpus's real upload sinks split cleanly into two shapes:
# filename-reaching sinks (real) vs property/constant-built sinks (FP).
# Evidence-scoped, not a broad regex rule.
# ---------------------------------------------------------------------------
_UPLOAD_SINK = re.compile(
    r"\.transferTo\s*\(|new\s+(?:java\.io\.)?File\s*\(([^)]*)\)|"
    r"move_uploaded_file\s*\(|write\s*\(\s*[^)]*filename", re.I)
_UPLOAD_PARAM = re.compile(
    r"\b(?:fileName|originalFilename|getOriginalFilename|multipartFile)\b", re.I)
_UPLOAD_VALIDATION = re.compile(
    r"endsWith\s*\(\s*['\"]\.|allowedExtensions\s*|getContentType\s*\(\s*\)|"
    r"contentType\s*\.equals|assertValidUpload|extension_whitelist|"
    r"\.equals\s*\(\s*['\"]\.", re.I)


def upload_check(finding: dict, window_text: str):
    """For path/multipart findings: classify the upload sink by its ARGUMENT.
    Property/constant-built argument -> LIKELY_FALSE_POSITIVE (decisive,
    regardless of other validation in the window -- the real RBI2 methods
    contain extension checks on the REQUEST file while the sink consumes a
    property value). Filename reaches the argument -> extension/content-type
    validation in the window downgrades to NEEDS_REVIEW; otherwise no
    opinion (UFIB verdict stands)."""
    rid = str(finding.get("rule_id") or "").upper()
    vt = str(finding.get("vuln_type") or "").lower()
    if not ("MULTIPART" in rid or "TRAVERSAL" in rid or "PATH" in rid
            or "zipslip" in vt or "path_traversal" in vt):
        return None
    m = _UPLOAD_SINK.search(window_text)
    if not m:
        return None  # not an upload sink shape
    arg = m.group(1) or ""
    if arg and not _UPLOAD_PARAM.search(arg):
        return ("LIKELY_FALSE_POSITIVE", -35,
                "File() argument built from property/constant values "
                "(%r), not the uploaded filename" % arg.strip()[:60])
    if _UPLOAD_VALIDATION.search(window_text):
        return ("NEEDS_REVIEW", -20,
                "upload validation present in context "
                "(extension/content-type check)")
    return None  # filename reaches the sink: real claim, UFIB decides


# ---------------------------------------------------------------------------
# Absence-based findings (mission g)
# ---------------------------------------------------------------------------
_ABSENCE_RULES = re.compile(
    r"MISSING_RATE_LIMIT|MISSING_VALIDATION|BRUTE_FORCE|MISSING_AUTHZ|"
    r"SPRING_MISSING_VALIDATION", re.I)
_STATE_CHANGING = re.compile(
    r"@(?:Post|Put|Patch|Delete)Mapping|method\s*[:=]\s*['\"](?:POST|PUT|"
    r"PATCH|DELETE)|app\.(?:post|put|patch|delete)\s*\(|"
    r"/(?:login|auth|token|password|register|admin)", re.I)


def absence_check(finding: dict, window_text: str):
    rid = str(finding.get("rule_id") or "")
    if not _ABSENCE_RULES.search(rid):
        return None
    endpoint = _STATE_CHANGING.search(window_text)
    if endpoint:
        return ("NEEDS_REVIEW", -15,
                "design-level (control absence) on a state-changing/auth "
                "endpoint")
    return ("LIKELY_FALSE_POSITIVE", -35,
            "design-level absence finding on a non-state-changing endpoint; "
            "middleware/gateway policies are outside file scope")


# ---------------------------------------------------------------------------
# Deduplication key (mission h)
# ---------------------------------------------------------------------------
def dedup_key(finding: dict) -> tuple:
    return (str(finding.get("file") or ""),
            finding.get("line") if isinstance(finding.get("line"), int) else
            str(finding.get("line")),
            str(finding.get("rule_id") or ""))


__all__ = [
    "mitigation_check", "sink_consistency", "minified_check", "layer_gate",
    "secret_check", "taint_confirm", "absence_check", "dedup_key",
    "context_window",
]
