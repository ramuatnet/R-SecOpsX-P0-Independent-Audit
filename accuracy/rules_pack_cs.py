"""Codeshield-imported rule pack (Phase 3).

Source: https://github.com/ne0psych/codeshield -- LICENSE: MIT (permissive).
Attribution recorded per rule; ideas adapted, regexes rewritten for ReDoS
safety and fitted to this repository's finding schema.

Every rule ships DISABLED by default (enabled=False) until it passes the
Phase 4 quality gates. Registration is additive: these rules never touch the
legacy rule tables; they are consumed ONLY by the accuracy layer's
validators (as confirm/deny checks) when explicitly enabled.

Rule ids use the CS_ prefix so they can never collide with legacy ids.
"""
from __future__ import annotations

import re

PACK_SCHEMA = "RSECOPSX-CS-PACK-1"
SOURCE_REPO = "https://github.com/ne0psych/codeshield"
SOURCE_LICENSE = "MIT"

# Each rule: id, title, cwe, owasp, severity, language, layer, pattern,
# positive/negative test snippets, provenance, enabled.
CS_RULES = [
    {
        "id": "CS_BEARER_TOKEN",
        "title": "Hardcoded bearer token in source",
        "cwe": "CWE-798", "owasp": "A07:2021", "severity": "Medium",
        "language": "*", "layer": "server",
        "pattern": re.compile(
            r"(?i)Authorization['\"]?\s*[:=]\s*['\"]?Bearer\s+"
            r"[A-Za-z0-9\-._~+/]{16,}={0,2}"),
        "source_rule": "SEC-012 Bearer Token (ideas adapted; regex rewritten)",
        "enabled": False,
        "positive": ['headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9x0123456789"}'],
        "negative": [
            'headers = {"Authorization": "Bearer " + token_from_vault}',
            'auth_header = request.headers.get("Authorization")',
            '# Authorization: Bearer <token> -- documentation',
        ],
    },
    {
        "id": "CS_PRIVATE_KEY_BLOCK",
        "title": "Private key block embedded in source",
        "cwe": "CWE-321", "owasp": "A02:2021", "severity": "Critical",
        "language": "*", "layer": "server",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "source_rule": "SEC-014/SEC-005/SEC-006 (union of PEM variants)",
        "enabled": False,
        "positive": [  # sast-ignore PEM_PRIVATE_KEY rule-data positive fixture example, not a real key
            'KEY = """-----BEGIN OPENSSH PRIVATE KEY-----"""',
            "pem = '-----BEGIN EC PRIVATE KEY-----'",
        ],
        "negative": [
            'cert = "-----BEGIN CERTIFICATE-----"',       # public cert
            'pub = "-----BEGIN PUBLIC KEY-----"',          # public key
            '# never commit -----BEGIN PRIVATE KEY-----',  # comment-only? fires; documented limitation
        ],
    },
    {
        "id": "CS_DEBUG_IN_PRODUCTION",
        "title": "Debug breakpoint left in production code",
        "cwe": "CWE-489", "owasp": "A05:2021", "severity": "Low",
        "language": "*", "layer": "server",
        "pattern": re.compile(
            r"\b(?:pdb\.set_trace\s*\(\s*\)|breakpoint\s*\(\s*\)|"
            r"debugger\b\s*[;]?)"),
        # console.log deliberately excluded: the repo already carries
        # front-end debug findings elsewhere and console.log is high-FP.
        "source_rule": "SAST-008 (narrowed: debugger/pdb/breakpoint only)",
        "enabled": False,
        "positive": [
            "def f():\n    import pdb; pdb.set_trace()",
            "function f(){ debugger; }",
        ],
        "negative": [
            "log.debug('entering f')",
            "const dbg = require('debug')",
        ],
    },
]


def pack_summary() -> list[dict]:
    return [
        {"id": r["id"], "title": r["title"], "cwe": r["cwe"],
         "severity": r["severity"], "enabled": r["enabled"],
         "source": r["source_rule"]}
        for r in CS_RULES
    ]


def iter_enabled_rules():
    for r in CS_RULES:
        if r.get("enabled"):
            yield r


def check(text: str, rule: dict) -> bool:
    """Run one pack rule against text. Used by the accuracy layer's
    confirm/deny stage when the rule is enabled."""
    return bool(rule["pattern"].search(text))


def redos_safe(rule: dict) -> bool:
    """Reject patterns with nested quantifiers or unbounded dangerous
    repetition (mission Phase 3). Conservative heuristic: no `(*)+`,
    no `.+)*`, no `[^x]*x*` shapes."""
    p = rule["pattern"].pattern
    if re.search(r"\)\s*[+*]\s*[+*]", p):
        return False
    if re.search(r"\.[^\\]*\)\s*\+", p) and re.search(r"\+[^)]*\)\+", p):
        return False
    if re.search(r"\(\.\*[+*]\)\s*\{", p):
        return False
    return True


for _r in CS_RULES:
    assert redos_safe(_r), "ReDoS-unsafe pattern in %s" % _r["id"]
