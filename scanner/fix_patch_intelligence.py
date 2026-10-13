"""
Feature 12 — Fix/Patch Generation Intelligence.

Produces remediation guidance and patch blueprints.
Does NOT automatically modify source code.

Design principles:
- Read-only
- Deep-copy input protection
- Deterministic finding identity
- Rule/category normalization
- Granular remediation blueprints
- Human review required
- No automatic source modification

Phase 3.3 adds FIX_SNIPPET_MAP: recipe-style before/after transformation
templates for the top rules, in the language of the file the finding was
raised against (OpenRewrite's before/after recipe shape -- a TEMPLATE to
adapt by hand, not an executable recipe and not a generated patch).
The snippet is attached to the finding (`fix_snippet`) and mirrored on the
blueprint row; when no template exists for that rule+language the finding
simply does not carry the key and the row carries None. Absence is the
honest answer -- a fabricated "fix" for a language we have no idiom for
would be worse than no fix at all.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Dict, List


BLUEPRINT_MAP = {
    "sql_injection": (
        "Use parameterized queries or prepared statements "
        "(for example ORM query parameters or PreparedStatement) "
        "instead of raw SQL string concatenation."
    ),
    "hardcoded_secret": (
        "Extract credentials, API keys, tokens, and other secrets "
        "into an approved secrets manager or protected environment configuration."
    ),
    "command_injection": (
        "Avoid shell execution with untrusted input. "
        "Use safe process invocation APIs with explicit argument lists "
        "and validate allowed input values."
    ),
    "ssrf": (
        "Validate outbound URLs using strict allowlists and block "
        "loopback, link-local, RFC1918/private, and other internal destinations."
    ),
    "xss": (
        "Apply context-aware output encoding before rendering untrusted data. "
        "Use framework-native escaping and avoid unsafe HTML/script sinks."
    ),
    "vulnerable_dependency": (
        "Upgrade the vulnerable dependency to a safe version identified "
        "by the applicable vendor advisory or validated remediation source."
    ),
    "insecure_configuration": (
        "Replace insecure configuration with secure defaults, "
        "restrict exposed services and permissions, and enforce the applicable "
        "security baseline."
    ),
    "path_traversal": (
        "Validate and canonicalize user-controlled paths and ensure resolved "
        "paths remain within the intended application directory."
    ),
    "idor": (
        "Enforce server-side authorization checks against the authenticated "
        "user or service identity before accessing the requested object."
    ),
    "weak_cryptography": (
        "Replace deprecated or weak cryptographic algorithms with approved "
        "modern algorithms and secure key-management practices."
    ),
}


# ---------------------------------------------------------------------------
# Phase 3.3 — fix snippets: before/after transformation templates keyed by
# (normalized rule, language). Shaped like an OpenRewrite recipe (before →
# after with placeholders) but explicitly a TEMPLATE: no snippet is ever
# applied, patched or written back to source (see enrich flags below).
#
# Coverage policy: the top injection/configuration rules x the three
# languages the benchmark actually reports (python/java/javascript), plus
# language-neutral `generic` entries where the transformation is universal
# (version bumps, server-side authorization checks) and `yaml` for cluster
# hardening. A rule/language pair with no entry yields NO snippet -- see
# _get_fix_snippet. Every `after` below is a real, correct idiom; the
# placeholders are named in `placeholders` so a human can adapt fast.
# ---------------------------------------------------------------------------
FIX_SNIPPET_MAP: Dict[str, Dict[str, Dict[str, Any]]] = {
    "sql_injection": {
        "python": {
            "kind": "parameterized_query",
            "before": 'cursor.execute("SELECT * FROM users WHERE id=" + str(uid))',
            "after": 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
            "placeholders": ["cursor", "uid"],
            "note": "Placeholder style follows the driver: %s for psycopg, "
                    "? for sqlite3/qmark drivers.",
        },
        "java": {
            "kind": "parameterized_query",
            "before": 'stmt.executeQuery("SELECT * FROM users WHERE id=" + uid);',
            "after": ('PreparedStatement ps = '
                      'conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
                      "ps.setString(1, uid);\n"
                      "ResultSet rs = ps.executeQuery();"),
            "placeholders": ["conn", "uid"],
        },
        "javascript": {
            "kind": "parameterized_query",
            "before": 'db.query("SELECT * FROM users WHERE id=" + uid)',
            "after": 'db.query("SELECT * FROM users WHERE id = ?", [uid])',
            "placeholders": ["db", "uid"],
        },
    },
    "command_injection": {
        "python": {
            "kind": "argument_vector_execution",
            "before": 'subprocess.run("convert " + name, shell=True)',
            "after": 'subprocess.run(["convert", name], check=True)',
            "placeholders": ["name"],
            "note": "shell=False with an argument vector removes the shell "
                    "parse step that turns input into commands.",
        },
        "java": {
            "kind": "argument_vector_execution",
            "before": 'Runtime.getRuntime().exec("ls " + dir);',
            "after": 'new ProcessBuilder("ls", dir).start();',
            "placeholders": ["dir"],
        },
        "javascript": {
            "kind": "argument_vector_execution",
            "before": 'child_process.exec("ls " + dir, cb)',
            "after": 'child_process.execFile("ls", [dir], cb)',
            "placeholders": ["dir"],
        },
    },
    "xss": {
        "python": {
            "kind": "contextual_output_encoding",
            "before": 'return "<p>" + comment + "</p>"',
            "after": ('from markupsafe import escape\n'
                      'return "<p>%s</p>" % escape(comment)'),
            "placeholders": ["comment"],
        },
        "java": {
            "kind": "contextual_output_encoding",
            "before": 'out.println("<p>" + comment + "</p>");',
            "after": 'out.println("<p>" + Encoder.forHtml(comment) + "</p>");',
            "placeholders": ["comment"],
            "note": "OWASP Java Encoder (org.owasp.encoder:encoder).",
        },
        "javascript": {
            "kind": "safe_dom_assignment",
            "before": "el.innerHTML = comment;",
            "after": "el.textContent = comment;",
            "placeholders": ["el", "comment"],
            "note": "textContent parses nothing; if markup must be rendered, "
                    "sanitize with a vetted sanitizer instead of assigning HTML.",
        },
    },
    "path_traversal": {
        "python": {
            "kind": "resolved_path_containment",
            "before": "open(os.path.join(BASE, name))",
            "after": ("p = Path(BASE, name).resolve()\n"
                      "p.relative_to(Path(BASE).resolve())  # raises on escape\n"
                      "open(p)"),
            "placeholders": ["BASE", "name"],
        },
        "java": {
            "kind": "resolved_path_containment",
            "before": "new File(base + name)",
            "after": ("Path p = Paths.get(base, name).normalize();\n"
                      'if (!p.startsWith(Paths.get(base).normalize())) '
                      'throw new IllegalArgumentException("path escape");'),
            "placeholders": ["base", "name"],
        },
        "javascript": {
            "kind": "resolved_path_containment",
            "before": "fs.readFileSync(path.join(dir, name))",
            "after": ("const p = path.resolve(dir, name);\n"
                      'if (!p.startsWith(path.resolve(dir) + path.sep)) '
                      'throw new Error("path escape");\n'
                      "fs.readFileSync(p)"),
            "placeholders": ["dir", "name"],
        },
    },
    "ssrf": {
        "python": {
            "kind": "destination_allowlist",
            "before": "requests.get(url)",
            "after": ("host = urlparse(url).hostname\n"
                      'if host not in ALLOWED_HOSTS: '
                      'raise ValueError("blocked destination: " + str(host))\n'
                      "requests.get(url, timeout=5)"),
            "placeholders": ["ALLOWED_HOSTS", "url"],
        },
        "java": {
            "kind": "destination_allowlist",
            "before": "new URL(url).openStream()",
            "after": ("URL u = new URL(url);\n"
                      'if (!ALLOWED_HOSTS.contains(u.getHost())) '
                      'throw new IllegalArgumentException("blocked destination");\n'
                      "InputStream in = u.openStream();"),
            "placeholders": ["ALLOWED_HOSTS", "url"],
        },
        "javascript": {
            "kind": "destination_allowlist",
            "before": "fetch(url)",
            "after": ("const {hostname} = new URL(url);\n"
                      'if (!ALLOWED_HOSTS.has(hostname)) '
                      'throw new Error("blocked destination: " + hostname);\n'
                      "fetch(url)"),
            "placeholders": ["ALLOWED_HOSTS", "url"],
        },
    },
    "hardcoded_secret": {
        "python": {
            "kind": "externalize_credential",
            "before": 'API_KEY = "hard-coded credential"',
            "after": 'API_KEY = os.environ["API_KEY"]',
            "placeholders": ["API_KEY"],
            "note": "Extracting the literal is only half the fix: ROTATE the "
                    "exposed credential, it is in the repository history.",
        },
        "java": {
            "kind": "externalize_credential",
            'before': 'static final String API_KEY = "hard-coded credential";',
            "after": 'static final String API_KEY = System.getenv("API_KEY");',
            "placeholders": ["API_KEY"],
            "note": "Rotate the exposed credential after extraction.",
        },
        "javascript": {
            "kind": "externalize_credential",
            'before': 'const API_KEY = "hard-coded credential";',
            "after": "const API_KEY = process.env.API_KEY;",
            "placeholders": ["API_KEY"],
            "note": "Rotate the exposed credential after extraction.",
        },
    },
    "weak_crypto": {
        "python": {
            "kind": "kdf_upgrade",
            "before": 'hashlib.md5(password).hexdigest()',
            "after": ('hashlib.pbkdf2_hmac("sha256", password, salt, 600000)'
                      ".hex()"),
            "placeholders": ["password", "salt"],
            "note": "For PASSWORDS use a dedicated KDF (argon2/bcrypt/scrypt "
                    "preferred); pbkdf2_hmac stands in for a general digest "
                    "upgrade. Persist the salt with the stored hash.",
        },
        "java": {
            "kind": "kdf_upgrade",
            'before': 'MessageDigest.getInstance("MD5").digest(password)',
            "after": ("SecretKeyFactory skf = "
                      'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");\n'
                      "byte[] hash = skf.generateSecret(new PBEKeySpec("
                      "password.toCharArray(), salt, 600000, 256))"
                      ".getEncoded();"),
            "placeholders": ["password", "salt"],
        },
        "javascript": {
            "kind": "kdf_upgrade",
            'before': 'crypto.createHash("md5").update(password).digest("hex")',
            "after": ('crypto.pbkdf2Sync(password, salt, 600000, 32, "sha256")'
                      '.toString("hex")'),
            "placeholders": ["password", "salt"],
        },
    },
    "vulnerable_dependency": {
        "generic": {
            "kind": "version_bump",
            "before": "<package>==<vulnerable-version>",
            "after": "<package>==<fixed-version>",
            "placeholders": ["package", "vulnerable-version", "fixed-version"],
            "note": "Take the fixed version from the advisory's patched "
                    "range, not from the newest release; re-run the tests "
                    "across the major-version boundary.",
        },
    },
    "idor": {
        "generic": {
            "kind": "server_side_authorization",
            "before": ("order = db.get_order(order_id)  # id taken from the "
                       "request"),
            "after": ("order = db.get_order(order_id)\n"
                      "if order.owner_id != current_user.id: abort(403)"),
            "placeholders": ["db", "order_id", "current_user"],
            "note": "Ownership must be checked server side against the "
                    "AUTHENTICATED principal, never against a value the "
                    "client supplied.",
        },
    },
    "insecure_configuration": {
        "yaml": {
            "kind": "harden_config",
            "before": ("securityContext:\n"
                       "  privileged: true"),
            "after": ("securityContext:\n"
                      "  privileged: false\n"
                      "  runAsNonRoot: true"),
            "placeholders": [],
            "note": "Baseline shape only: pair with the CIS/NSA hardening "
                    "checklist for the workload (drop ALL capabilities, "
                    "readOnlyRootFilesystem, seccompProfile).",
        },
    },
}


RULE_ALIASES = {
    "sqli": "sql_injection",
    "sqlinjection": "sql_injection",
    "sql_injection": "sql_injection",
    "sql-injection": "sql_injection",
    "cwe89": "sql_injection",
    "cwe-89": "sql_injection",

    "hardcodedsecret": "hardcoded_secret",
    "hardcoded_secret": "hardcoded_secret",
    "hardcoded-secret": "hardcoded_secret",
    "hardcoded_credentials": "hardcoded_secret",
    "secret_detection": "hardcoded_secret",
    "secret": "hardcoded_secret",

    "commandinjection": "command_injection",
    "command_injection": "command_injection",
    "command-injection": "command_injection",
    "cwe78": "command_injection",
    "cwe-78": "command_injection",

    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "server-side-request-forgery": "ssrf",

    "xss": "xss",
    "cross_site_scripting": "xss",
    "cross-site-scripting": "xss",
    "cwe79": "xss",
    "cwe-79": "xss",

    "vulnerabledependency": "vulnerable_dependency",
    "vulnerable_dependency": "vulnerable_dependency",
    "vulnerable-dependency": "vulnerable_dependency",
    "dependency_vulnerability": "vulnerable_dependency",
    "dependency-vulnerability": "vulnerable_dependency",

    "insecureconfiguration": "insecure_configuration",
    "insecure_configuration": "insecure_configuration",
    "insecure-configuration": "insecure_configuration",

    "pathtraversal": "path_traversal",
    "path_traversal": "path_traversal",
    "path-traversal": "path_traversal",
    "cwe22": "path_traversal",
    "cwe-22": "path_traversal",

    "idor": "idor",
    "insecure_direct_object_reference": "idor",

    "weakcryptography": "weak_cryptography",
    "weak_cryptography": "weak_cryptography",
    "weak-cryptography": "weak_cryptography",
}


def _normalize_rule(rule: Any) -> str:
    """
    Normalize scanner rule/category identifiers into a stable lookup key.
    """
    if not rule:
        return ""

    value = str(rule).strip().lower()

    value = value.replace("/", "_")
    value = value.replace(" ", "_")
    value = value.replace(".", "_")

    value = re.sub(r"[^a-z0-9_-]", "_", value)
    value = re.sub(r"_+", "_", value)
    value = value.strip("_")

    return RULE_ALIASES.get(value, value)


def _get_blueprint(rule: Any) -> str:
    """
    Return the most specific remediation blueprint available.
    """
    normalized = _normalize_rule(rule)

    if normalized in BLUEPRINT_MAP:
        return BLUEPRINT_MAP[normalized]

    for key, blueprint in BLUEPRINT_MAP.items():
        if key in normalized:
            return blueprint

    return "REVIEW_FINDING_AND_APPLY_CONTEXT_APPROPRIATE_FIX"


# Findings already carry `language` when the engine knew it; the file
# extension is the fallback. Only languages with a curated snippet in
# FIX_SNIPPET_MAP resolve -- anything else returns "" and gets no snippet.
_LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".java": "java",
    ".jsp": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".yaml": "yaml",
    ".yml": "yaml",
}

_LANGUAGE_BY_NAME = {
    "python": "python",
    "py": "python",
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "javascript",
    "ts": "javascript",
    "yaml": "yaml",
    "yml": "yaml",
}


def _finding_language(finding: Dict[str, Any]) -> str:
    """
    The snippet language for a finding: declared `language` first, then the
    target file's extension. Empty string when neither resolves -- which
    means "no snippet", never "guess a language".
    """
    declared = str(finding.get("language") or "").strip().lower()
    if declared:
        mapped = _LANGUAGE_BY_NAME.get(declared)
        if mapped:
            return mapped

    target = _target_file(finding)
    basename = target.rsplit("/", 1)[-1]
    ext = ("." + basename.rsplit(".", 1)[1].lower()) if "." in basename else ""
    return _LANGUAGE_BY_EXTENSION.get(ext, "")


def _get_fix_snippet(rule: Any, language: str) -> Dict[str, Any] | None:
    """
    Before/after template for a single rule string + language, or None.
    Thin wrapper over the candidate-based lookup used by enrichment.
    """
    return _resolve_snippet(str(rule or ""), [str(rule or "")], language)


def _rule_candidates(finding: Dict[str, Any]) -> List[str]:
    """
    Every rule-bearing field of a finding, strongest first.

    `rule_id` is the engine's identifier (JAVA_JDBC_SQL_CONCAT) while the
    semantic class lives in `vuln_type` (sql_injection) -- a lookup against
    rule_id alone resolves nothing, which is why both travel here. Empty
    fields are skipped so a lookup never normalizes to "".
    """
    candidates: List[str] = []
    for field in ("rule_id", "rule", "vuln_type", "issue_type", "category",
                  "risk_category", "vulnerability_type"):
        value = finding.get(field)
        if value is not None and str(value).strip():
            candidates.append(str(value).strip())
    return candidates


def _find_snippet_entry(candidates: List[str]) -> Dict[str, Dict[str, Any]] | None:
    """
    The snippet entry for a finding's rules: every candidate tested for an
    EXACT normalized key first, then substring. Exact-across-all before
    substring-across-all, so vuln_type "sql_injection" beats a rule_id that
    merely contains an unrelated substring match.
    """
    normalized = [_normalize_rule(c) for c in candidates]

    for value in normalized:
        if value in FIX_SNIPPET_MAP:
            return FIX_SNIPPET_MAP[value]

    for value in normalized:
        for key, entry in FIX_SNIPPET_MAP.items():
            if key in value:
                return entry

    return None


def _materialize_snippet(
    entry: Dict[str, Dict[str, Any]], language: str
) -> Dict[str, Any] | None:
    """
    Resolve (entry, language) to a snippet copy, or None.

    Language resolves exactly, then falls back to a curated `generic`
    entry (version bumps and authorization checks are language-neutral);
    if neither exists the honest answer is None -- no snippet for a
    language we have no idiom for. The returned dict carries the
    applied/template flags so a caller can never mistake a template for
    something the tool executed.
    """
    snippet = entry.get(language)
    language_used = language
    if snippet is None:
        snippet = entry.get("generic")
        language_used = "generic"
    if snippet is None:
        return None

    result = dict(snippet)
    result["language"] = language_used
    result["template"] = True
    result["applied"] = False
    result["human_review_required"] = True
    return result


def _resolve_snippet(
    rule: Any, candidates: List[str], language: str
) -> Dict[str, Any] | None:
    """Shared tail of the two public entry points (see _materialize_snippet)."""
    entry = _find_snippet_entry([c for c in candidates if c] or [str(rule or "")])
    if entry is None:
        return None
    return _materialize_snippet(entry, language)


def _get_blueprint_from_finding(finding: Dict[str, Any]) -> str:
    """
    Blueprint resolved across the same rule candidates as the snippet.

    An exact semantic key (vuln_type "sql_injection") always beats a
    substring coincidence on the rule_id, and the primary-rule fallback of
    _get_blueprint applies only when no candidate resolves -- so a finding
    whose only match would have been a substring of an unrelated field
    still lands on the review placeholder rather than on wrong advice.
    """
    candidates = _rule_candidates(finding)
    if not candidates:
        return _get_blueprint("")

    normalized = [_normalize_rule(c) for c in candidates]

    for value in normalized:
        if value in BLUEPRINT_MAP:
            return BLUEPRINT_MAP[value]

    for value in normalized:
        for key, blueprint in BLUEPRINT_MAP.items():
            if key in value:
                return blueprint

    return _get_blueprint(candidates[0])


def _target_file(finding: Dict[str, Any]) -> str:
    """
    Resolve the most useful source-file identifier.
    """
    value = (
        finding.get("file")
        or finding.get("path")
        or finding.get("source_file")
        or finding.get("filename")
        or ""
    )

    return str(value).replace("\\", "/").strip()


def _finding_rule(finding: Dict[str, Any]) -> str:
    """
    Resolve the strongest available rule/category identifier.
    """
    return str(
        finding.get("rule_id")
        or finding.get("rule")
        or finding.get("category")
        or finding.get("vulnerability_type")
        or "SECURITY_FINDING"
    ).strip()


def _finding_location(finding: Dict[str, Any]) -> str:
    """
    Produce a stable location component for deterministic identity.
    """
    for key in ("line", "start_line", "line_number"):
        value = finding.get(key)

        if value is not None:
            text = str(value).strip()

            if text:
                return text

    return ""


def _deterministic_finding_id(finding: Dict[str, Any]) -> str:
    """
    Preserve an existing finding ID when available.

    Otherwise derive a stable ID from rule + target file + location +
    message/description. This avoids positional IDs that change when
    finding ordering changes.
    """
    existing = str(
        finding.get("finding_id")
        or finding.get("id")
        or ""
    ).strip()

    if existing:
        return existing

    rule = _finding_rule(finding)
    target_file = _target_file(finding)
    location = _finding_location(finding)

    message = str(
        finding.get("message")
        or finding.get("description")
        or finding.get("title")
        or ""
    ).strip()

    identity_material = "|".join(
        [
            rule,
            target_file,
            location,
            message,
        ]
    )

    if not identity_material.strip("|"):
        return "FINDING_UNKNOWN"

    digest = hashlib.sha256(
        identity_material.encode("utf-8")
    ).hexdigest()[:12].upper()

    return f"FINDING_{digest}"


def enrich_fix_patch_intelligence(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Enrich a report payload with remediation intelligence.

    The original payload is never modified.
    """
    if not isinstance(payload, dict):
        return payload

    result = deepcopy(payload)

    findings = result.get("findings", [])

    if not isinstance(findings, list):
        findings = []

    rows: List[Dict[str, Any]] = []
    snippets_available = 0

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        fid = _deterministic_finding_id(finding)
        rule = _finding_rule(finding)
        target_file = _target_file(finding)

        normalized_rule = _normalize_rule(rule)

        language = _finding_language(finding)
        snippet = _resolve_snippet(rule, _rule_candidates(finding), language)
        if snippet is not None:
            snippets_available += 1
            # Phase 3.3: the finding itself carries the template (the gap
            # plan's acceptance is "findings include fix_snippet"). The
            # input payload is a deepcopy, so this never reaches the
            # caller's original findings.
            finding["fix_snippet"] = snippet

        rows.append(
            {
                "finding_id": fid,
                "rule": rule,
                "normalized_rule": normalized_rule,
                "target_file": target_file,
                "remediation_blueprint": _get_blueprint_from_finding(finding),
                "fix_snippet": snippet,
                "patch_generated": False,
                "source_modified": False,
                "human_review_required": True,
            }
        )

    rows.sort(
        key=lambda x: (
            x["target_file"],
            x["normalized_rule"],
            x["finding_id"],
        )
    )

    result["fix_patch_intelligence"] = {
        "status": "AVAILABLE",
        "remediation_blueprints": rows,
        "summary": {
            "findings": len(rows),
            "patches_generated": 0,
            "snippets_available": snippets_available,
        },
        "read_only": True,
        "automatic_source_modification": False,
    }

    return result
