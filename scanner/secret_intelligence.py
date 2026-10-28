"""
scanner/secret_intelligence.py
Enterprise secret intelligence scanner/enricher.

Compatibility APIs preserved:
- scan_secret_intelligence(target_path)
- analyze_secret_intelligence(target_path)
- classify_secrets(findings)
- enrich_secret_intelligence(findings)
- summarize_secret_intelligence(findings)
- secret_intelligence_summary(findings)

Important fix:
- enrich_secret_intelligence() must never stamp non-secret SAST/taint/framework/API findings
  as scanner.secret_intelligence. Older patches caused every finding in clean_report.json to show
  engine=scanner.secret_intelligence. This version only enriches true secret findings.
"""
from __future__ import annotations

import re
import math
import json
import configparser
import xml.etree.ElementTree as ET
try:
    import tomllib
except ImportError:
    tomllib = None
from collections import Counter
from pathlib import Path

_F = re.IGNORECASE | re.MULTILINE

SECRET_EXT = {
    ".py", ".js", ".ts", ".java", ".cs", ".go", ".php",
    ".env", ".properties", ".yml", ".yaml", ".json", ".xml", ".config", ".ini", ".cfg", ".conf", ".toml", ".tf", ".hcl", ".tfvars", ".pem", ".key", ".p12", ".pfx",
    # S1 (2026-10-21, prodtest/llama_index vs FortiCNAPP secrets scope):
    # documentation and notebooks were outside the sweep while CNAP reported
    # 26 secret locations in .md/.ipynb.  Real credential material does land
    # there (gigachat README holds a base64 client credential), so the scope
    # widens -- paired with the doc-class value gate in scan_file so tutorial
    # stand-ins do not arrive as Critical findings.
    ".md", ".ipynb",
}
# I2 (2026-10-19, prodtest/ethernaut): "out" joins the exclusion policy
# (forge build artifacts under contracts/out/ produced 11 CONFIG rows).
# I18 (2026-10-26, aclean report): "bundle" joins too -- i18n property
# bundles under src/main/resources/bundle/ carry credential-shaped words
# ("password", "token", "secret") as TRANSLATION VALUES in 12 languages,
# and the generic key/value parser read each pair as a committed secret.
# Keep in sync with scanner.sast.EXCLUDED_DIRS.
EXCLUDED = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", "out", "bundle"}

# Machine-generated dependency manifests. Their "keys" are package names,
# integrity hashes and engine ranges, so a credential-shaped key inside one is
# an identifier, not a secret: `packages.node_modules/@aws-sdk/credential-
# provider-env.integrity` matched as a credential 41 times on a single npm
# lockfile. These files are still scanned for known signatures, PEM material
# and high-entropy values - only the generic key/value configuration parser is
# withheld, because it is the part that reads a manifest as if it were config.
LOCKFILE_NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "pnpm-lock.yml", "poetry.lock", "pipfile.lock", "pipfile", "cargo.lock",
    "composer.lock", "gemfile.lock", "packages.lock.json", "paket.lock",
    "mix.lock", "gradle.lockfile", "go.sum", "uv.lock",
})

# Directory names that identify translation catalogues (UI strings) and
# seed/fixture datasets (demo records). See _is_translated_text_or_seed_dataset.
TRANSLATION_DIR_NAMES = frozenset({
    "i18n", "locale", "locales", "translations", "l10n",
})
SEED_DATASET_DIR_NAMES = frozenset({
    "static", "seed", "seeds", "fixture", "fixtures",
})
SEED_DATASET_PARENTS = frozenset({"data", "datasets", "fixtures", "seeds"})

SECRET_RULES = [
    # ``[\t ]*`` around ``[:=]`` is deliberate: ``\s*`` also matched newlines,
    # so a line-final colon (a python conditional ``if not self.jwt_secret:``)
    # swallowed the NEXT line's first token as the "value" and reported the
    # guard code as a hardcoded credential (autogen wsauth.py:47).
    ("SPRING_DATASOURCE_PASSWORD", "Spring datasource credential", "spring_config_secret", r"spring\.datasource\.(?:password|username|url)[\t ]*[:=][\t ]*[^\s#]+", "High", "CWE-798"),
    ("SPRING_SECURITY_OAUTH_SECRET", "Spring OAuth client secret", "oauth_client_secret", r"spring\.security\.oauth2\.client\.registration\.[\w.-]+\.client-secret[\t ]*[:=][\t ]*[^\s#]+", "Critical", "CWE-798"),
    ("JWT_SIGNING_SECRET", "JWT signing secret", "jwt_secret", r"(?:jwt|token|signing)[_-]?(?:secret|key)[\t ]*[:=][\t ]*[\"']?[^\"'\s#]{8,}", "Critical", "CWE-798"),
    ("OAUTH_CLIENT_SECRET", "OAuth client secret", "oauth_client_secret", r"(?:client[_-]?secret|oauth[_-]?secret)[\t ]*[:=][\t ]*[\"']?[^\"'\s#]{8,}", "Critical", "CWE-798"),
    ("AWS_SECRET_KEY", "AWS secret access key", "cloud_secret", r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[\t ]*[:=][\t ]*[\"']?[A-Za-z0-9/+=]{20,}", "Critical", "CWE-798"),
    ("KAFKA_CREDENTIALS", "Kafka credential in config", "messaging_secret", r"(?:sasl\.jaas\.config|sasl\.password|KAFKA_PASSWORD|kafka\.password)[\t ]*[:=][\t ]*[^\s#]+", "High", "CWE-798"),
    ("RABBITMQ_CREDENTIALS", "RabbitMQ credential / AMQP URI", "messaging_secret", r"amqps?://[^:\s'\"]+:[^@\s'\"]+@", "High", "CWE-798"),
    ("DATABASE_URL_CREDENTIALS", "Database connection string credentials", "database_connection_secret", r"(?:postgres(?:ql)?|mysql|mongodb|redis|sqlserver)://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+", "Critical", "CWE-798"),
    ("JDBC_URL_CREDENTIALS", "JDBC connection string credentials", "database_connection_secret", r"jdbc:[^\s'\"]+(?:user|username)=([^;&\s]+).*?(?:password|pwd)=([^;&\s]+)", "Critical", "CWE-798"),
    ("CLOUD_METADATA_TOKEN_USE", "Cloud metadata credential access", "cloud_metadata_credential", r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/", "High", "CWE-918"),
]

DECOY_WORDS = re.compile(r"(?:example|sample|dummy|changeme|fake|test|placeholder|corpus|invalid)", re.I)
SECRET_WORDS = re.compile(r"secret|credential|password|passwd|pwd|token|api[_-]?key|private[_-]?key|client[_-]?secret|connection[_-]?string", re.I)
SECRET_VULN_TYPES = {
    "hardcoded_secret", "secret_exposure", "jwt_secret", "connection_string",
    "oauth_client_secret", "database_connection_string", "kafka_credential",
    "rabbitmq_credential", "spring_config_secret", "cloud_secret", "messaging_secret",
    "database_connection_secret", "cloud_metadata_credential",
}


def _priority(sev: str) -> str:
    return {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}.get(sev, "P3")


def _language(path: Path) -> str:
    return {
        ".properties": "properties", ".yml": "yaml", ".yaml": "yaml", ".json": "json",
        ".java": "java", ".cs": "csharp", ".js": "javascript", ".ts": "typescript",
        ".go": "go", ".php": "php", ".py": "python",
    }.get(path.suffix.lower(), "unknown")


def _is_scanner_result_json(path: Path) -> bool:
    """True when the file is a SECURITY-SCANNER RESULT export (JSON).

    Mirrors scanner/sast.py's detector: detection is by CONTENT -- the report
    schema's own markers (``total_findings`` + ``tool`` + a ``findings`` array
    whose members carry ``rule_id``) -- and never by filename. A bounded header
    read keeps this cheap on large exports.
    """
    if path.suffix.lower() != ".json":
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    if '"total_findings"' not in head and '"scan_date"' not in head:
        return False
    if '"tool"' not in head:
        return False
    if '"findings"' not in head and '"secret-id"' not in head:
        return False
    # Member identity: rule_id (SAST export) or secret-id (the VA combined
    # secrets export's row shape). A benign config file carries neither.
    return '"rule_id"' in head or '"secret-id"' in head


def _skip(path: Path) -> bool:
    """Return True for paths that should not be scanned by Secret Intelligence."""
    excluded = {str(item).lower() for item in EXCLUDED}
    parts = {str(part).lower() for part in path.parts}

    if parts.intersection(excluded):
        return True

    artifact_names = {
        "clean_report.json",
        "security_cyclonedx.json",
        "security_cyclonedx.xml",
        "sbom.json",
        "sbom.xml",
    }

    if path.name.lower() in artifact_names:
        return True

    # I19 (2026-10-26, aclean): a scanner-result JSON export inside the tree is
    # tool output, not source. Its evidence fields embed text from ELSEWHERE in
    # the repo, so secrets read off it duplicate or invent locations.
    if _is_scanner_result_json(path):
        return True

    artifact_dirs = {
        "reports",
        "report",
        "artifacts",
        "artifact",
        "generated",
        "output",
        "outputs",
    }

    if parts.intersection(artifact_dirs):
        return True

    return False


# Third-party SCANNER-RESULT exports (findbugs/spotbugs BugCollection, ZAP,
# pmd, sonar, visualcodegrepper). Tool output, not application source: their
# <LongMessage>/evidence fields embed HTML-escaped code excerpts from ELSEWHERE
# in the repo, so secrets found there belong to the code under test, not to the
# export. Detection is by ROOT ELEMENT only — a real <config>/<settings> XML is
# still scanned in full. Mirrors scanner/sast.py::_is_scanner_result_xml.
_SCANNER_RESULT_XML_ROOTS = frozenset({
    "BugCollection",
    "FindBugsSummary",
    "OWASPZAPReport",
    "CodeIssueCollection",
    "pmd",
})


def _is_scanner_result_xml(path: Path) -> bool:
    """True when the file is a third-party scanner-result XML export."""
    if path.suffix.lower() != ".xml":
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    stripped = re.sub(r"<\?xml[^>]*\?>", "", head, count=1).lstrip()
    m = re.match(r"<([A-Za-z_][\w:.-]*)", stripped)
    if not m:
        return False
    root = m.group(1)
    if root in _SCANNER_RESULT_XML_ROOTS:
        return True
    if root == "total" and "<issues>" in head and "<component>" in head:
        return True
    return False


def _is_secret_finding(f: dict) -> bool:
    vt = str(f.get("vuln_type", "")).lower()
    title = str(f.get("title", ""))
    snippet = str(f.get("snippet", ""))
    rule_id = str(f.get("rule_id", ""))
    if vt in SECRET_VULN_TYPES:
        return True
    return bool(SECRET_WORDS.search(title) or SECRET_WORDS.search(rule_id) or SECRET_WORDS.search(snippet))


def _build_finding(rule_id, title, vuln, sev, cwe, file, line, snippet, lang):
    confidence = "Medium" if DECOY_WORDS.search(snippet) else "High"
    severity = "Medium" if confidence == "Medium" and sev == "Critical" else sev
    return {
        "rule_id": rule_id,
        "title": title,
        "vuln_type": vuln,
        "severity": severity,
        "priority": _priority(severity),
        "confidence": confidence,
        "language": lang,
        "file": str(file),
        "line": line,
        "snippet": snippet.strip(),
        "description": f"Potential {title.lower()} detected in source/configuration.",
        "business_impact": "Exposed credentials can enable unauthorized access, lateral movement, data theft, and cloud/service account compromise.",
        "remediation": [
            "Remove the secret from source/configuration files.",
            "Move it to a managed secret store.",
            "Rotate the credential immediately.",
            "Audit VCS history for exposure.",
        ],
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": cwe,
        "pci_dss": "Req 3 / Req 8 - Protect authentication secrets",
        "nist": "IA-5 / SC-12 / SC-28",
        "nist_800_53": "IA-5 / SC-12 / SC-28",
        "iso27001": "A.5.17 / A.8.24",
        "iso_27001": "A.5.17 / A.8.24",
        "soc2": "CC6.1 / CC6.6",
        "evidence": f"{file}:{line}: {snippet.strip()}",
        "detection": "Enterprise Secret Intelligence",
        "engine": "scanner.secret_intelligence",
        "secret_type": vuln,
        "validated_live": False,
        "offline_only": True,
        "enterprise_control": True,
        "group_key": f"{rule_id}|{file}|{line}",
    }


# Production secret-detection layers
# B7a (2026-10-16, Open-Assistant): ``token`` carries a
# ``(?![A-Za-z])`` lookahead so it cannot match as the PREFIX of a longer
# word -- OA's pretokenize config
# ``tokenizer_type: SentencePieceTokenizer`` reported a Hardcoded
# configuration credential because "token" sat
# inside "tokenizer".  Separators still count (``token_indices``,
# ``access_token`` keep matching via their own alternatives/positions);
# plural containers (``tokens``) stop matching, consistent with the leaf
# scoping that already excludes container names.
_PROP_SECRET_KEY = re.compile(r"(?i)(?:password|passwd|pwd|passcode|passphrase|secret|token(?![A-Za-z])|api[_.-]?key|access[_.-]?key|secret[_.-]?key|client[_.-]?secret|credential|auth(?:entication)?[_.-]?(?:token|key|secret)|private[_.-]?key|signing[_.-]?(?:key|secret)|webhook[_.-]?(?:key|secret)|dsn)")
_ENV_ONLY = re.compile(r"^\s*(?:\$\{[^}:]+\}|\$[A-Za-z_][A-Za-z0-9_]*)\s*$")
_ENV_DEFAULT = re.compile(r"^\s*\$\{[^}:]+:[^}]*\}\s*$")
_PROP_CONTEXT = re.compile(r"(?i)(?:sms|text[_.-]?message|messaging|ldap|directory|smtp|mail|email|datasource|database|db|jdbc|oauth|oidc|okta|auth0|onelogin|ping|aws|azure|gcp|cloud|stripe|payment|twilio|sendgrid|slack|discord|telegram|github|gitlab|bitbucket|npm|pypi|nuget|rubygems|docker|registry|vault|datadog|sentry|newrelic|pagerduty|grafana|honeycomb|launchdarkly|firebase|cloudflare|fastly|akamai|algolia|kafka|rabbit|amqp|mqtt|redis|mongo|postgres|mysql|oracle|mssql|jenkins|circleci|buildkite|terraform|ansible|kubernetes|helm|django|flask|rails|express|session|jwt|totp|mfa|otp|proxy|vpn|snmp|webhook|signing|cosign|gpg|pgp|openai|anthropic|huggingface|hugging_face|gemini|deepseek|pinecone|langchain|mcp)")
KNOWN_SECRET_RULES = [
("AWS_ACCESS_KEY","AWS access key","cloud_secret",r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b","Critical","CWE-798"),
("GITHUB_TOKEN","GitHub access token","source_control_token",r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b","Critical","CWE-798"),
("GITLAB_TOKEN","GitLab access token","source_control_token",r"\bglpat-[A-Za-z0-9_-]{20,}\b","Critical","CWE-798"),
("NPM_TOKEN","npm registry token","package_registry_token",r"\bnpm_[A-Za-z0-9_-]{20,}\b","High","CWE-798"),
("PYPI_TOKEN","PyPI API token","package_registry_token",r"\bpypi-[A-Za-z0-9_-]{20,}\b","High","CWE-798"),
("STRIPE_SECRET_KEY","Stripe secret key","payment_secret",r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b","Critical","CWE-798"),
("GOOGLE_API_KEY","Google API key","cloud_secret",r"\bAIza[0-9A-Za-z_-]{30,}\b","High","CWE-798"),
("SLACK_TOKEN","Slack token","communication_token",r"\bxox[bpsar]-[A-Za-z0-9-]{10,}\b","High","CWE-798"),
("OPENAI_KEY","OpenAI API key","ai_platform_credential",r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b","Critical","CWE-798"),
("ANTHROPIC_KEY","Anthropic API key","ai_platform_credential",r"\bsk-ant-[A-Za-z0-9_-]{20,}\b","Critical","CWE-798"),
("HUGGINGFACE_TOKEN","Hugging Face token","ai_platform_credential",r"\bhf_[A-Za-z0-9]{20,}\b","High","CWE-798"),
("SLACK_WEBHOOK","Slack webhook URL","webhook_secret",r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}","High","CWE-798"),
("VAULT_TOKEN","Vault token","secrets_manager_credential",r"\bhvs\.[A-Za-z0-9._-]{20,}\b","Critical","CWE-798"),
]
DECOY_WORDS = re.compile(
    r"(?i)^(?:example|sample|dummy|changeme|fake|test|placeholder|corpus|invalid|todo|fixme"
    r"|replace[_ -]?me"
    r"|your[_ -]?(?:api[_ -]?)?key(?:[_ -]?here)?"
    r"|insert[_ -]?key[_ -]?here"
    r"|test[_ -]?(?:api[_ -]?)?key"
    r"|sk[-_](?:key|api[_ -]?key|secret|password|token|test|placeholder|fake|dummy|xxxx+)"
    r"|password123|xxx|<[^>]+>)$"
)
# ``replace[_ -]?(?:me|with)`` -- "REPLACE_WITH_YOUR_API_KEY" is the template
# sentinel autogen ships in every sample model_config*.yaml; the old
# ``replace[_ -]?me`` stem missed it.  ``your[_ -]?(?:api[_ -]?)?key`` without a
# trailing "here" covers bare "your-api-key" literals.
DECOY_CONTAINS = re.compile(
    r"(?i)(?:your[_ -]?api[_ -]?key[_ -]?here|replace[_ -]?(?:me|with)"
    r"|insert[_ -]?key[_ -]?here|changeme|your[_ -]?(?:api[_ -]?)?key)"
)
SECRET_VULN_TYPES={"hardcoded_secret","secret_exposure","jwt_secret","connection_string","oauth_client_secret","database_connection_string","kafka_credential","rabbitmq_credential","spring_config_secret","cloud_secret","messaging_secret","database_connection_secret","cloud_metadata_credential","configuration_secret","configuration_secret_fallback","sms_service_credential","ldap_credential","smtp_credential","source_control_token","package_registry_token","ai_platform_credential","observability_credential","payment_secret","communication_token","webhook_secret","secrets_manager_credential","cryptographic_private_key","framework_secret","mcp_token","cloud_session_token","proxy_credential","broker_credential","snmp_credential"}
_SECRET_NAME_HINT=re.compile(r"(?i)(?:password|passwd|pwd|passcode|passphrase|secret|token(?![A-Za-z])|api[_-]?key|access[_-]?key|client[_-]?secret|credential|private[_-]?key|signing[_-]?(?:key|secret)|webhook[_-]?(?:key|secret))")

# CamelCase stand-ins: ``string appClientSecret = "testAppClientSecret";``
# (CopilotStudioTests) -- the stem must END where an uppercase letter begins,
# so only stand-in names starting with the stem are caught.
_CAMEL_PLACEHOLDER_PREFIX = re.compile(
    r"^(?:[Tt]est|[Mm]ock|[Ff]ake|[Dd]ummy|[Ss]ample|[Dd]emo|[Yy]our|[Ee]xample|[Pp]laceholder)(?:[A-Z_])"
)
_MASKED_SECRET_BODY = re.compile(r"^(?:[Xx*]{6,}|\.{3,})$")
# A SCREAMING_SNAKE value with >=2 word breaks NAMES an environment variable
# (``ENV_VAR_API_KEY = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY"`` in SK
# utils.py:39): a name at a credential key is a reference, not material.
# Single-token caps values ("SUP3RSECRET123") do not match.
_ENV_VAR_NAME_VALUE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}$")
_MASK_SIGNATURE_PREFIXES = re.compile(
    r"^(?:gh[pousr]_|github_pat_|glpat-|npm_|pypi-|sk-(?:proj-|ant-)?"
    r"|AIza|hvs\.|hf_|xox[bpsar]-|AKIA|ASIA)"
)


def _is_masked_secret(v):
    """True for a redaction placeholder wearing a signature's prefix.

    ``GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"``
    matches the GitHub signature but the body is a redaction mask, not
    token material.
    """
    x = str(v or "").strip().strip('"\'`')
    body = _MASK_SIGNATURE_PREFIXES.sub("", x)
    return bool(body) and bool(_MASKED_SECRET_BODY.fullmatch(body))


def _is_placeholder(v):
    x=v.strip().strip('"\'`')
    return ((not x) or bool(DECOY_WORDS.fullmatch(x)) or bool(DECOY_CONTAINS.search(x))
            or bool(_CAMEL_PLACEHOLDER_PREFIX.match(x)) or _is_masked_secret(x))
def _looks_like_env(v): return bool(_ENV_ONLY.fullmatch(v.strip()))

# Terraform/HCL expressions are references to values, not literal
# secret material. Keep this intentionally narrow so ordinary
# configuration values and other languages retain existing behavior.
_TERRAFORM_REFERENCE = re.compile(
    r"^\s*(?:"
    r"var\.[A-Za-z_][A-Za-z0-9_]*"
    r"|local\.[A-Za-z_][A-Za-z0-9_]*"
    r"|module\.[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"|data\.[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
    r"|resource\.[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
    r")\s*$"
)

def _looks_like_terraform_reference(v):
    value = str(v or "").strip().strip('"\'`')
    return bool(_TERRAFORM_REFERENCE.fullmatch(value))


# ---------------------------------------------------------------------------
# S1 doc-class gate (2026-10-21, prodtest/llama_index vs FortiCNAPP).
# .md/.ipynb are now in SECRET_EXT; widening alone is NOT safe.  A 2509-file
# doc sweep on the llama corpus produced 20 findings and the sampled values
# were documentation stand-ins (``postgresql://user:password@``,
# ``{username}:{password}@host:{port}``, ``YOUR_CLIENT_SECRET``,
# ``auth_client_secret=resource_owner_config``) -- the exact placeholder
# class CNAP rated High with 0/12 probed real.  This gate withholds a
# doc-class finding only when EVERY credential value on its line is provably
# a stand-in; a line whose value cannot be judged keeps its finding, so real
# material (gigachat README base64 credential) is never dropped for noise.
# The gate runs ONLY for .md/.ipynb: every other suffix keeps the exact
# filter chain it had before S1.
# ---------------------------------------------------------------------------
_DOC_CLASS_EXTS = frozenset({".md", ".ipynb"})

# Stand-in literals used as tutorial credentials.  Deliberately an EXACT
# word list: "supersecret" is a weak-but-real password and keeps its
# finding -- only values that ARE the word "password" or equally
# self-declaring defaults are withheld.
_DOC_PLACEHOLDER_VALUES = frozenset({
    "password", "passwd", "pass", "pwd", "secret", "token", "username",
    "user", "postgres", "mysql", "changeme", "pleaseletmein", "admin",
    "guest", "root", "example", "demo", "test", "host", "localhost",
    "your_client_secret", "your_api_key", "client_secret",
})

_DOC_URI_USERINFO = re.compile(r"://([^/\s\"'@]+):([^/\s\"'@]+)@")
_DOC_ASSIGN_VALUE = re.compile(
    r"(?i)(?:credentials?|secrets?|tokens?|passwords?|passwd|passphrase"
    r"|client[_ -]?secret|api[_ -]?key|private[_ -]?key|access[_ -]?(?:key|token)"
    r"|dsn|conn(?:ection)?[_ -]?string|conn_str)\s*[:=]\s*[\"']?([^\s\"',)&\\]{3,})"
)


def _is_doc_placeholder_value(v: str) -> bool:
    raw = str(v or "").strip().strip("`").rstrip("\\").strip("\"'").strip()
    if not raw:
        return True
    if "{" in raw or "}" in raw or "${" in raw:
        return True                      # {username}:{password} / ${VAR} template
    if raw.startswith("<") and raw.endswith(">"):
        return True                      # <password> angle stand-in
    s = raw.lower().strip("{}")
    if s in _DOC_PLACEHOLDER_VALUES:
        return True
    if DECOY_CONTAINS.search(raw) or _CAMEL_PLACEHOLDER_PREFIX.match(raw):
        return True
    if _is_masked_secret(raw) or _ENV_VAR_NAME_VALUE.match(raw):
        return True                      # xxxx masks / SCREAMING_SNAKE env NAMES
    # snake_case identifiers NAME a variable holding the credential
    # (auth_client_secret=resource_owner_config).  Pure-letter words are
    # kept: they can be real weak passwords.
    if re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+", s):
        return True
    return False


def _doc_line_candidates(line: str) -> list:
    vals = [m.group(2) for m in _DOC_URI_USERINFO.finditer(line)]
    for m in _DOC_ASSIGN_VALUE.finditer(line):
        v = m.group(1)
        if "://" in v:
            # An assigned URI is judged by its userinfo password part, the
            # part that is credential material.
            u = _DOC_URI_USERINFO.search(v)
            if u:
                vals.append(u.group(2))
            continue
        vals.append(v)
    return vals


def _is_doc_placeholder_finding(f: dict, lines: list) -> bool:
    ln = f.get("line") or 0
    if not (0 < ln <= len(lines)):
        return False                     # cannot judge -> keep the finding
    vals = _doc_line_candidates(lines[ln - 1])
    if not vals:
        return False                     # cannot judge -> keep the finding
    return all(_is_doc_placeholder_value(v) for v in vals)


# Values that name a credential rather than BEING one.  Each exclusion is a
# shape that cannot be secret material, measured on real scan output:
#   * ``${{ secrets.X }}`` -- a GitHub Actions secret REFERENCE; flagging it
#     punishes the secure pattern and trains reviewers to ignore the rule
#     (AgentGPT: sponsors.yml token: ${{ secrets.SPONSOR_WORKFLOW_PAT }}).
#   * ``serverEnv.GOOGLE_CLIENT_SECRET`` / ``settings.openai_api_key`` --
#     dotted config-object references (NextAuth clientSecret wiring, SDK
#     constructors).  The namespace list is deliberate: an arbitrary dotted
#     value could be a real token, ``settings.x`` never is.
#   * ``Optional[str]`` / ``None`` -- a type declaration or empty sentinel
#     (pydantic ``sid_client_secret: Optional[str] = None``).
#   * ``^1.1.1.5`` / ``1.21.4`` -- version ranges and numbers; a manifest
#     dependency line whose NAME contains "secret" is not a credential
#     assignment (AgentGPT: aws-secretsmanager-caching = "^1.1.1.5").
_GH_EXPRESSION = re.compile(r"^\s*\$\{\{.*\}\}\s*$")
# B8 (2026-10-16, Open-Assistant): 11 of 17 CONFIG_CONTEXTUAL rows were
# reference-shaped values the gates never questioned -- Jinja2
# ``{{ postgres_password }}`` (ansible), a secrets-manager PATH carrying
# ``${...}`` interpolations (CF manifests), and a GitHub Actions
# ``${{secrets.X}}`` with a trailing line-continuation backslash that
# defeated the full-match above.  Interpolation means the deployed value
# is assembled at template time; literal material never contains
# ``${...}`` and is never itself a pure template expression.
_JINJA_EXPRESSION = re.compile(r"^\{\{[\s\S]*\}\}$")
_ENV_INTERPOLATION_ANY = re.compile(r"\$\{[^}]+\}")
_CONFIG_REFERENCE = re.compile(
    r"^(?:self|this|cls|super|env|settings|config|configuration|cfg|serverEnv|"
    r"clientEnv|server_env|client_env|process|os|sys|module|vars|locals|props|"
    r"credentials|secrets|secretsmanager|params|appConfig|runtimeConfig)"
    r"(?:\.[A-Za-z_$][\w$]*)+$"
)
_TYPE_SENTINEL = re.compile(
    r"^(?:Optional|Union|List|Dict|Set|Tuple|Sequence|Mapping|Annotated|Literal|"
    r"Callable|Type|Iterable)\[.*\]$"
    r"|^(?:str|bytes|dict|list|tuple|int|float|bool|any|Any|None|Null|null|NULL|"
    r"true|false|True|False|undefined|undefined\(\))$"
)
_URL_PATH_VALUE = re.compile(r"^/[\w./-]+$")
_CONFIG_GETTER_PREFIX = re.compile(
    r"^(?:os\.getenv|os\.environ|environ\b|getenv\b|process\.env\b|"
    r"settings\.getenv|config\.get\b|runtime_env\b)"
)
_SECRET_STR_TYPE = re.compile(
    r"^(?:SecretStr|SecretBytes|BaseSecretStr|SecretMixin)(?:\b[\s\S]*)?$"
)
_DOTTED_IDENTIFIER_CHAIN = re.compile(
    r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$"
)
_DOTTED_CHAIN_MAX_SEGMENT = 24
_CALL_EXPRESSION = re.compile(r"^[A-Za-z_$][\w$.]*\(.*\)$")
_VERSION_RANGE = re.compile(
    r"^[\s<>=~^*]"
    r"|^v?\d+(?:\.\d+){1,4}(?:[-+][\w.\-+]+)?$"
)


def _value_is_code_reference(v) -> bool:
    """True when the matched value names a credential instead of being one."""
    value = str(v or "").strip().strip('"\'`;')
    if not value:
        return False
    if _JINJA_EXPRESSION.fullmatch(value):
        # ``{{ postgres_password }}`` / ``{{ web_api_key }}`` -- a Jinja2
        # expression resolves to another value at deploy time.
        return True
    if _ENV_INTERPOLATION_ANY.search(value):
        # ``/copilot/${APP}/${ENV}/secrets/X`` (CF manifest secret path)
        # or ``${{secrets.X}} \`` (workflow continuation) -- any embedded
        # ``${...}`` makes the value an interpolation, not a literal.
        return True
    if _CONFIG_GETTER_PREFIX.match(value):
        # os.getenv("X" / process.env.X -- a call whose captured prefix ends
        # at the first quote or paren; still a reference, never a literal.
        return True
    if _SECRET_STR_TYPE.match(value):
        # pydantic ``client_secret: SecretStr`` -- a TYPE annotation, and the
        # docstring variant ``- client_secret: SecretStr - the OAuth secret``.
        return True
    if _DOTTED_IDENTIFIER_CHAIN.fullmatch(value):
        # ``TestConfiguration.VertexAI.ClientSecret`` /
        # ``booking_sample_settings.client_secret`` / OTel attribute names
        # (``gen_ai.request.max_tokens``).  Every segment is identifier-shaped
        # and short: real tokens carry long random or base64url segments, and
        # JWTs contain '-' and never match the class.
        if all(len(seg) <= _DOTTED_CHAIN_MAX_SEGMENT for seg in value.split(".")):
            return True
    if _CALL_EXPRESSION.fullmatch(value):
        # ``weaviate.auth.AuthApiKey(api_key=api_key)`` -- a constructor call
        # on the right-hand side is wiring, not secret material.
        return True
    return bool(
        _GH_EXPRESSION.fullmatch(value)
        or _CONFIG_REFERENCE.fullmatch(value)
        or _TYPE_SENTINEL.fullmatch(value)
        or _URL_PATH_VALUE.fullmatch(value)
        or _VERSION_RANGE.match(value)
    )


def _looks_like_secret_value(v):
    x=v.strip().strip('"\'`')
    if not x or _looks_like_env(x) or _looks_like_terraform_reference(x) or _is_placeholder(x) or len(x)<8: return False
    if re.fullmatch(r"\[\s*-?\d+(?:\s*,\s*-?\d+)*\s*\],?", x):
        # B4 (2026-10-16, peft): a bracketed list of bare integers is
        # structured data -- token ids, indices, tensor shapes -- never
        # credential material.  adapter_config.json's
        # ``token_indices: [128000, 128001]`` (tokenizer vocabulary
        # positions) reported as a Hardcoded configuration credential
        # because only the KEY's "token" noun and a length >= 8 were
        # consulted.  Arrays whose elements are strings/objects
        # (``api_keys: ["ghp_...", ...]``) do not match this shape and
        # keep firing; the trailing-comma form covers the properties
        # parser's ``[128000, 128001],`` capture.
        return False
    if _value_is_code_reference(x): return False
    if re.match(r"^(?:https?|ftp)://",x,re.I): return False
    if re.fullmatch(r"[0-9a-fA-F-]{32,}",x) and x.count('-')>=2: return False
    return True

def _parse_properties(text):
    out=[]
    for n,line in enumerate(text.splitlines(),1):
        s=line.strip()
        if not s or s.startswith(("#","!")): continue
        m=re.match(r"^\s*([^:=\s][^:=]*?)\s*[:=]\s*(.*?)\s*$",line)
        if m: out.append((n,m.group(1).strip(),m.group(2).strip()))
    return out

def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    n = len(value)
    return -sum((c/n) * math.log2(c/n) for c in counts.values()) if n else 0.0

def _entropy_candidate(value: str, key: str = "") -> bool:
    v=value.strip().strip('"\'`')
    if len(v) < 20 or _looks_like_env(v) or _is_placeholder(v): return False
    secret_key_context = bool(
        key and _SECRET_NAME_HINT.search(key)
    )

    if re.fullmatch(r"[0-9a-fA-F]{32,64}",v):
        # Hexadecimal values can be hashes or identifiers.
        # However, a secret-bearing key must not be silently suppressed.
        if secret_key_context:
            return True
        return False
    if re.fullmatch(r"[0-9a-fA-F-]{32,}",v) and v.count('-') >= 2: return False
    # Every charset class requires a credential-bearing key, exactly as the
    # hex branch already did. Without the gate, ANY 24+ character identifier
    # clears the entropy floor: type names, mock names, dict keys and model
    # ids (``id="simple_chatbot_kernel_function"``, ``llama-4-scout=...``)
    # are not secrets and were the whole of this family on two corpora.
    if not secret_key_context: return False
    if re.fullmatch(r"[A-Za-z0-9+/=]{30,}",v): return _shannon_entropy(v) >= 4.2
    if re.fullmatch(r"[A-Za-z0-9_-]{24,}",v): return _shannon_entropy(v) >= 4.0
    if re.fullmatch(r"[0-9A-Fa-f]{20,}",v): return _shannon_entropy(v) >= 3.0
    return False

def _scan_entropy(path,text,lang):
    out=[]; lines=text.splitlines()
    for n,line in enumerate(lines,1):
        m=re.match(r"^\s*[\"']?([A-Za-z_][A-Za-z0-9_.:/-]*)[\"']?\s*[:=]\s*[\"']?([^\"',#;]+)",line)
        if not m: continue
        key,val=m.group(1),m.group(2).strip()
        if _entropy_candidate(val, key):
            out.append(_build_finding("GENERIC_HIGH_ENTROPY_SECRET","High-entropy credential candidate","generic_high_entropy_secret","Medium","CWE-798",path,n,f"{key}=[HIGH-ENTROPY VALUE REDACTED]",lang))
            break
    return out

def _parse_generic_key_values(text):
    out=[]
    for n,line in enumerate(text.splitlines(),1):
        s=line.strip()
        if not s or s.startswith(("#",";","//")): continue
        m=re.match(r"^\s*[\"']?([A-Za-z_][A-Za-z0-9_.:/-]*)[\"']?\s*[:=]\s*(.*)$",line)
        if not m: continue
        val=m.group(2).strip()
        if val[:1] in {'"', "'"}:
            # Quoted literal: everything up to the matching quote is value
            # material (it may legitimately contain " #").
            quote=val[0]; _end=val.find(quote,1)
            val=val[1:_end] if _end!=-1 else val.strip(quote)
        else:
            # Unquoted: an inline " #comment" is prose, not value material --
            # ``tokens_per_minute: auto # set to null to disable`` must not
            # become an 8+ character "secret". A '#' without preceding
            # whitespace stays part of the value (YAML semantics).
            val=re.split(r"\s+#",val,maxsplit=1)[0].strip()
        val=val.rstrip(',').strip().strip('"\'`')
        out.append((n,m.group(1),val))
    return out

# Code languages where a string literal MUST be quoted, so an unquoted
# identifier-shaped value can only be a variable reference.
_CODE_LANGS_QUOTED_LITERALS = frozenset(
    {"python", "javascript", "typescript", "csharp", "java", "go", "php", "ruby"}
)


def _key_leaf(key):
    """Final path segment of a composite/structural key, sans array indices.

    ``[0].details.tokens[0].logprob`` -> ``logprob``; ``tokens[0]`` ->
    ``tokens``.  Command substitutions are shell text, never credential
    nouns: ``jobs.x.steps.run.docker run --rm -v $(pwd)`` -> ``run --rm -v``
    (the ``pwd`` shell builtin is not a password).
    """
    leaf = re.sub(r"\$\([^)]*\)", " ", str(key or "")).rsplit(".", 1)[-1]
    return re.sub(r"\[\d+\]", "", leaf).strip()


def _key_names_credential(key):
    """True when the key's *property* (not an ancestor container) is a credential.

    Flat keys match whole, unchanged.  Composite structural paths -- JSON
    leaves and dotted YAML paths -- must match on the leaf only, so
    ``...tokens[0].logprob`` (a tensor value),
    ``paths./secrets/{name}.get.parameters.*.description`` (OpenAPI docs) and
    ``inputs.fallback-token.description`` (action docs) are not credential
    assignments merely because an ANCESTOR says "token" or "secret".
    """
    key = str(key or "")
    if "." in key or "[" in key:
        return bool(_PROP_SECRET_KEY.search(_key_leaf(key)))
    return bool(_PROP_SECRET_KEY.search(key))


def _bare_identifier_reference(text, lineno, value):
    """True when a code file's value is an unquoted identifier = a variable.

    In code, ``this.AppClientSecret = appClientSecret`` references a variable;
    a hardcoded literal is always quoted.  The RAW line decides -- the parsed
    value alone cannot distinguish ``password = "Abcdefghijklmnop123456"``
    (quoted literal, keep) from ``password = abcd1234efgh`` (name, kill).
    """
    v = str(value or "").strip().rstrip(";,").strip()
    if len(v) < 8 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v):
        return False
    try:
        src_line = text.splitlines()[lineno - 1]
    except Exception:  # pragma: no cover - defensive
        return False
    m = re.match(r"^\s*[\"']?[^:=\s\"']*[\"']?\s*[:=]\s*(.)", src_line)
    return bool(m) and m.group(1) not in "\"'"


def _scan_key_value_context(path,text,pairs,lang):
    out=[]
    for line,key,val in pairs:
        kl=key.lower(); raw=val.strip()
        if not _key_names_credential(key): continue
        fallback=bool(_ENV_DEFAULT.fullmatch(raw))
        if not fallback and (not _looks_like_secret_value(raw)): continue
        if lang in _CODE_LANGS_QUOTED_LITERALS and _bare_identifier_reference(text, line, raw):
            continue
        if not _PROP_CONTEXT.search(key) and not re.search(r"(?i)(oauth|client[_-]?secret|api[_-]?key|private[_-]?key|webhook|signing|mcp)",key) and not _SECRET_NAME_HINT.search(key): continue
        if fallback: title,vuln="Hardcoded secret fallback in configuration","configuration_secret_fallback"
        elif re.search(r"(?i)(ldap|directory)",kl): title,vuln="Hardcoded LDAP credential","ldap_credential"
        elif re.search(r"(?i)(smtp|mail|email)",kl): title,vuln="Hardcoded SMTP/mail credential","smtp_credential"
        elif re.search(r"(?i)(sms|text[_.-]?message|messaging)",kl): title,vuln="Hardcoded messaging/SMS credential","sms_service_credential"
        elif re.search(r"(?i)(datasource|database|db|jdbc|mongo|postgres|mysql|oracle|mssql|redis)",kl): title,vuln="Hardcoded database credential","database_credential"
        elif "mcp" in kl: title,vuln="Hardcoded MCP credential/token","mcp_token"
        elif re.search(r"(?i)(django.*secret|flask.*secret|rails.*secret|session.*secret|secret[_-]?key)",kl): title,vuln="Hardcoded framework/application secret","framework_secret"
        else: title,vuln="Hardcoded configuration credential","configuration_secret"
        out.append(_build_finding("CONFIG_CONTEXTUAL_CREDENTIAL",title,vuln,"High","CWE-798",path,line,f"{key}=[REDACTED]",lang))
    return out

def _scan_structured_secrets(path,text,lang):
    out=[]; lines=text.splitlines()
    uri=re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql|sqlserver|amqps?|mqtts?)://[^\s'\"<>:]+:[^\s'\"<>@]+@[^\s'\"<>]+")
    m=uri.search(text)
    if m:
        line=text[:m.start()].count("\n")+1
        safe=re.sub(r"(?i)(://[^:/@]+:)[^@]+@",r"\1[REDACTED]@",m.group(0))
        out.append(_build_finding("STRUCTURED_CONNECTION_CREDENTIAL","Credential embedded in connection URI","connection_string","Critical","CWE-798",path,line,safe,lang))
    pem=re.search(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |ED25519 |PRIVATE )?PRIVATE KEY-----",text)
    if pem:
        line=text[:pem.start()].count("\n")+1
        out.append(_build_finding("PEM_PRIVATE_KEY","Private cryptographic key material","cryptographic_private_key","Critical","CWE-321",path,line,"[PRIVATE KEY MATERIAL REDACTED]",lang))
    jwt=re.search(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])",text)
    if jwt:
        line=text[:jwt.start()].count("\n")+1; sn=lines[line-1] if line<=len(lines) else ""
        if _SECRET_NAME_HINT.search(sn) or "authorization" in sn.lower(): out.append(_build_finding("JWT_TOKEN_SIGNATURE","JWT/token credential material","jwt_secret","High","CWE-798",path,line,"[JWT REDACTED]",lang))
    return out

def _scan_known_signatures(path,text,lang):
    out=[]; lines=text.splitlines()
    for rid,title,vuln,pat,sev,cwe in KNOWN_SECRET_RULES:
        m=re.search(pat,text,re.M)
        if not m: continue
        # A signature can match a *reference* to the secret rather than the
        # secret: ``client_secret: Optional[str]`` (a type declaration),
        # ``clientSecret: serverEnv.GOOGLE_CLIENT_SECRET`` (config wiring),
        # ``oauth_secret: ${{ secrets.X }}`` (CI expression).  The value
        # after the assignment decides, never the key name.
        _assigned = re.split(r"[:=]", m.group(0), maxsplit=1)
        if len(_assigned) == 2 and _value_is_code_reference(_assigned[1]):
            continue
        line=text[:m.start()].count("\n")+1
        if _is_placeholder(m.group(0)): continue
        out.append(_build_finding(rid,title,vuln,sev,cwe,path,line,"[KNOWN SECRET REDACTED]",lang))
    return out

def _is_nonproduction_context(path):
    parts=[p.lower() for p in path.parts]
    name=path.name.lower()
    return (name in {"readme.example","readme.md","readme.txt",".env.example",".env.sample",".env.template"}
            or any(x in parts for x in {"test","tests","fixture","fixtures","mock","mocks","spec","specs","docs","doc","examples","example"})
            or any(x in name for x in {".example.", ".sample.", ".template."}))


def _is_translated_text_or_seed_dataset(path):
    """True for translation catalogues and seed/fixture datasets.

    These hold UI strings and demo records rather than deployable
    configuration, so a generic key/value parser reading
    `"MANDATORY_PASSWORD": "Required password"` out of an i18n catalogue, or
    `password: johndoe` out of a seeded user row, reports a credential that
    exists nowhere in the running system. On the Juice Shop corpus this one
    misread produced 1188 of 1290 findings (92%) - every one of them the
    `key=[REDACTED]` shape against UI labels such as LABEL_PASSWORD and demo
    rows in data/static/users.yml - while the eight findings the ground truth
    actually cares about live in config/fbctf.yml and are untouched here.

    Scope is deliberately narrow. Only CONFIG_CONTEXTUAL_CREDENTIAL (the
    key/value interpretation) is withheld. Known-signature, PEM, URI, JWT and
    high-entropy detection still run on these files, so a credential that is
    genuinely embedded in one is still reported.
    """
    try:
        parts = [str(p).lower() for p in Path(path).parts]
    except Exception:  # pragma: no cover - defensive, never suppress on error
        return False
    if any(p in TRANSLATION_DIR_NAMES for p in parts):
        return True
    for i in range(len(parts) - 1):
        if parts[i] in SEED_DATASET_PARENTS and parts[i + 1] in SEED_DATASET_DIR_NAMES:
            return True
    return False


def _parse_yaml_pairs(text):
    out=[]; stack=[]
    for n,line in enumerate(text.splitlines(),1):
        if not line.strip() or line.lstrip().startswith('#') or line.lstrip().startswith('- '): continue
        indent=len(line)-len(line.lstrip(' ')); st=line.strip()
        if st.startswith('---'): continue
        m=re.match(r'^([^:#][^:]*):\s*(.*)$',st)
        if not m: continue
        key=m.group(1).strip().strip('"\''); val=m.group(2).strip()
        while stack and indent <= stack[-1][0]: stack.pop()
        full='.'.join([x[1] for x in stack]+[key])
        if not val or val in {'|','>','{','['}:
            stack.append((indent,key)); continue
        val=val.rstrip(',').strip()
        # YAML inline comment (``tokens_per_minute: auto # set to null to
        # disable``): the note is prose, not value material. Only for unquoted
        # values -- a quoted literal may legitimately contain " #".
        if val[:1] not in {'"', "'"}:
            val = re.split(r"\s+#", val, maxsplit=1)[0].strip()
        val=val.strip('"\'')
        out.append((n,full,val))
    return out

def _structured_pairs(path, text):
    """Extract key/value leaves with source-ish line numbers using stdlib parsers where available."""
    suf=path.suffix.lower(); out=[]
    if suf in {".yml",".yaml"}:
        return _parse_yaml_pairs(text)
    if suf==".json":
        try:
            obj = json.loads(text)

            def walk_json(value, prefix=""):
                if isinstance(value, dict):
                    for key, child in value.items():
                        child_key = (
                            f"{prefix}.{key}"
                            if prefix
                            else str(key)
                        )
                        yield from walk_json(child, child_key)

                elif isinstance(value, list):
                    for index, child in enumerate(value):
                        yield from walk_json(
                            child,
                            f"{prefix}[{index}]"
                        )

                else:
                    yield prefix, str(value)

            leaves = list(walk_json(obj))

            # Source-order JSON key recovery.
            # This deliberately maps parsed leaves to matching key
            # occurrences in document order.
            key_pattern = re.compile(
                r'["\']([^"\']+)["\']\s*:'
            )

            source_key_locations = []

            for line_no, line_text in enumerate(
                text.splitlines(),
                1,
            ):
                for match in key_pattern.finditer(line_text):
                    source_key_locations.append(
                        (match.group(1), line_no)
                    )

            # Index source occurrences by key while preserving order.
            key_locations = {}

            for key_name, line_no in source_key_locations:
                key_locations.setdefault(
                    key_name,
                    [],
                ).append(line_no)

            key_offsets = {}

            for key, value in leaves:
                leaf_key = key.rsplit(".", 1)[-1]
                leaf_key = re.sub(
                    r"\[\d+\]$",
                    "",
                    leaf_key,
                )

                locations = key_locations.get(
                    leaf_key,
                    [],
                )

                position = key_offsets.get(
                    leaf_key,
                    0,
                )

                if position < len(locations):
                    line_no = locations[position]
                    key_offsets[leaf_key] = position + 1
                elif locations:
                    line_no = locations[-1]
                else:
                    line_no = 1

                out.append(
                    (
                        line_no,
                        key,
                        value,
                    )
                )

        except Exception:
            pass
    elif suf in {".ini",".cfg",".conf"}:
        try:
            cp=configparser.ConfigParser(); cp.read_string(text)
            for sec in cp.sections():
                for k,v in cp.items(sec):
                    pat=re.compile(r'(?m)^\s*'+re.escape(k)+r'\s*[=:]')
                    m=pat.search(text); out.append((text[:m.start()].count("\n")+1 if m else 1,f"{sec}.{k}",v))
        except Exception: out.extend(_parse_generic_key_values(text))
    elif suf==".toml" and tomllib:
        try:
            obj=tomllib.loads(text)
            def walkt(x,prefix=""):
                if isinstance(x,dict):
                    for k,v in x.items(): walkt(v,f"{prefix}.{k}" if prefix else str(k))
                elif isinstance(x,list):
                    for i,v in enumerate(x): walkt(v,f"{prefix}[{i}]")
                else: out.append((0,prefix,str(x)))
            walkt(obj)
            for i,(n,k,v) in enumerate(out):
                m=re.search(r'(?m)^\s*'+re.escape(k.split('.')[-1])+r'\s*=\s*',text)
                out[i]=(text[:m.start()].count("\n")+1 if m else 1,k,v)
        except Exception: pass
    elif suf==".xml":
        try:
            root=ET.fromstring(text)
            def walkx(el, pathx=""):
                name=el.tag.rsplit('}',1)[-1]
                cur=f"{pathx}.{name}" if pathx else name
                for k,v in el.attrib.items(): out.append((0,f"{cur}.{k}",v))
                if el.text and el.text.strip() and len(el)==0: out.append((0,cur,el.text.strip()))
                for c in el: walkx(c,cur)
            walkx(root)
            # Recover XML source lines with a single pass over source lines.
            # Avoid repeatedly scanning the entire document for every parsed leaf.
            source_lines = text.splitlines()
            tag_lines = {}
            for line_no, line_text in enumerate(source_lines, 1):
                for tag_match in re.finditer(
                    r"<([A-Za-z_][\\w:.-]*)\\b[^>]*>([^<]+)</\\1\\s*>",
                    line_text
                ):
                    tag_name = tag_match.group(1).rsplit(":", 1)[-1]
                    tag_lines.setdefault(tag_name, []).append(line_no)

            tag_offsets = {}
            for i,(n,k,v) in enumerate(out):
                tag = k.split('.')[-1]
                candidates = tag_lines.get(tag, [])
                if candidates:
                    pos = tag_offsets.get(tag, 0)
                    line_no = candidates[min(pos, len(candidates)-1)]
                    tag_offsets[tag] = pos + 1
                else:
                    line_no = 1
                out[i]=(line_no,k,v)
        except Exception: pass
    elif suf in {".tf",".hcl",".tfvars"}:
        # HCL-lite: capture assignments and nested block-qualified keys by context.
        stack=[]
        for n,line in enumerate(text.splitlines(),1):
            st=line.strip()
            if not st or st.startswith('#'): continue
            opens=re.match(r'^(?:resource|data|module|variable|locals|provider)\s+"?([^"\s]+)"?(?:\s+"?([^"\s]+)"?)?\s*\{',st)
            if opens: stack.append('.'.join(x for x in opens.groups() if x)); continue
            if st.startswith('}'): 
                if stack: stack.pop()
                continue
            m=re.match(r'^\s*([A-Za-z_][\w.-]*)\s*=\s*(.+?)\s*$',line)
            if m:
                val=m.group(2).strip().strip(','); key='.'.join(stack+[m.group(1)]) if stack else m.group(1); out.append((n,key,val))
    return out

def _source_identifier_names_credential(ident: str) -> bool:
    """A4: the matched noun must be a whole underscore-delimited segment of
    the identifier. ``GITHUB_TOKEN``/``OPENAI_API_KEY`` keep their finding;
    ``target_tokenizer``/``special_tokens_pattern``/``TMP_TOKENIZER_DIR``
    only *contain* the substring and never name a credential. Trailing digits
    (``PASSWORD1``) still count as a boundary so a real name cannot be lost.
    """
    return bool(
        re.search(
            r"(?i)(?:^|_)(?:password|passwd|pwd|secret|token"
            r"|api_key|private_key|access_key)(?:$|_|[0-9])",
            ident,
        )
    )


def _source_value_carries_token_material(val: str) -> bool:
    """A4: reference values are made of short words -- ``token_type_ids``,
    ``torch.Tensor | None``, ``TILE_GLOBAL``, ``]<]image[>[``,
    ``[IMG_BREAK]``, ``__start__``, ``__null__`` (longest unbroken
    alnum run < 8). Every real token format carries an 8+ character
    segment (hex/base64/JWT/ghp_/sk_), so corpus and e2e secrets keep.
    """
    runs = re.findall(r"[A-Za-z0-9]+", str(val or ""))
    return bool(runs) and max(len(r) for r in runs) >= 8


def _scan_source_assignments(path,text,lang):
    out=[]
    if path.suffix.lower() not in {'.py','.js','.ts','.java','.cs','.go','.php'}: return out
    pat=re.compile(r"(?im)^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+|String\s+|string\s+|private\s+String\s+|public\s+String\s+|\$[A-Za-z_][\w]*\s*=\s*)?([A-Za-z_][\w]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY)[A-Za-z0-9_]*)\s*(?:=|:)\s*[\"']([^\"']{8,})[\"']")
    for m in pat.finditer(text):
        val=m.group(2)
        if _is_placeholder(val) or _looks_like_env(val) or _value_is_code_reference(val): continue
        if not _source_identifier_names_credential(m.group(1)):
            # A4 identifier gate: substring noun only (tokenizer/tokens/...).
            continue
        if not _looks_like_secret_value(val):
            # A4 value gate: URLs, uuid-hex references and code references
            # are not secret material (shared with the GENERIC scanners).
            continue
        if not _source_value_carries_token_material(val):
            # A4 reference gate: no 8+ character run of secret material.
            continue
        if _ENV_VAR_NAME_VALUE.fullmatch(val.strip()):
            # ENV_VAR_API_KEY = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY" -- the
            # value is an env-var NAME. Shared with the sast GENERIC gate;
            # both engines must agree or one copy hides the other.
            continue
        # Anchor on the IDENTIFIER, not the match start: the leading
        # ``\\s*`` may swallow a blank line above the assignment, which
        # reported JWT_SIGNING_SECRET at L2 instead of L3 (bucket C).
        line=text[:m.start(1)].count('\n')+1
        out.append(_build_finding('SOURCE_HARDCODED_CREDENTIAL','Hardcoded credential in source code','hardcoded_secret','High','CWE-798',path,line,f'{m.group(1)}=[REDACTED]',lang))
    return out

def _scan_docker_k8s(path,text,lang):
    out=[]

    if path.name.lower()=='dockerfile' or path.suffix.lower() in {'.dockerfile'}:
        for n,line in enumerate(text.splitlines(),1):
            m=re.match(
                r'(?i)^\s*ENV\s+'
                r'([A-Za-z_][\w.-]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)'
                r'[A-Za-z0-9_.-]*)\s*=\s*(.+)$',
                line
            )
            if m and not _is_placeholder(m.group(2)) and not _looks_like_env(m.group(2)):
                out.append(
                    _build_finding(
                        'DOCKER_HARDCODED_CREDENTIAL',
                        'Hardcoded credential in Dockerfile ENV',
                        'hardcoded_secret',
                        'High',
                        'CWE-798',
                        path,
                        n,
                        f'{m.group(1)}=[REDACTED]',
                        'dockerfile'
                    )
                )

    if path.suffix.lower() in {'.yml','.yaml'}:
        lines=text.splitlines()

        # Kubernetes Secret semantics are resource-context dependent.
        # For kind: Secret, every scalar entry under data/stringData is
        # secret material regardless of the key name.
        is_k8s_secret = bool(
            re.search(r'(?m)^\s*kind:\s*Secret\s*$', text)
        )

        if is_k8s_secret:
            section=None
            emitted=set()

            for n,line in enumerate(lines,1):
                # Enter data/stringData sections.
                section_match = re.match(
                    r'^(\s*)(data|stringData)\s*:\s*(?:#.*)?$',
                    line
                )

                if section_match:
                    section=section_match.group(2)
                    continue

                if section is None:
                    continue

                stripped=line.strip()

                # Blank/comment lines do not terminate the section.
                if not stripped or stripped.startswith('#'):
                    continue

                # A non-indented top-level YAML key terminates data/stringData.
                if re.match(r'^\S[^:]*\s*:', line):
                    section=None
                    continue

                # Capture scalar key/value entries beneath data/stringData.
                entry=re.match(
                    r'^\s{2,}([A-Za-z_][\w.-]*)\s*:\s*(.*?)\s*$',
                    line
                )

                if not entry:
                    continue

                key=entry.group(1)
                raw_value=entry.group(2).strip()

                if not raw_value:
                    continue
                if raw_value.startswith('#'):
                    continue
                if _is_placeholder(raw_value):
                    continue
                if _looks_like_env(raw_value):
                    continue

                marker=(str(path),n)

                if marker in emitted:
                    continue

                emitted.add(marker)

                out.append(
                    _build_finding(
                        'K8S_SECRET_MATERIAL',
                        'Hardcoded Kubernetes Secret material',
                        'hardcoded_secret',
                        'High',
                        'CWE-798',
                        path,
                        n,
                        f'{key}=[REDACTED]',
                        'yaml'
                    )
                )

    return out

def scan_file(filepath: str) -> list[dict]:
    path=Path(filepath)
    if _skip(path): return []
    if _is_scanner_result_xml(path): return []
    suffix=path.suffix.lower()
    if suffix not in SECRET_EXT and path.name not in {".env","application.properties","application.yml","application.yaml","Dockerfile"}: return []
    try: text=path.read_text(encoding="utf-8",errors="replace")
    except OSError: return []
    findings=[]; lang=_language(path)
    known_findings=[]
    if not _is_nonproduction_context(path):
        known_findings=_scan_known_signatures(path,text,lang)
    # G-036a: withhold only the generic key/value configuration parser from
    # dependency manifests. Known-signature, PEM and entropy detection further
    # down still run on these files, so a real credential embedded in one is
    # not excused - only package metadata misread as configuration is.
    is_lockfile = path.name.lower() in LOCKFILE_NAMES
    if not is_lockfile:
        if suffix==".properties" or path.name=="application.properties": findings.extend(_scan_key_value_context(path,text,_parse_properties(text),"properties"))
        elif suffix in {".env",".ini",".cfg",".conf",".toml",".tfvars"}: findings.extend(_scan_key_value_context(path,text,_parse_generic_key_values(text),lang))
        elif suffix in {".yml",".yaml",".json",".xml",".config",".tf",".hcl",".dockerfile"} or path.name=="Dockerfile": findings.extend(_scan_key_value_context(path,text,_parse_generic_key_values(text),lang))
        structured_pairs=_structured_pairs(path,text)
        if structured_pairs:
            findings.extend(_scan_key_value_context(path,text,structured_pairs,lang))
    findings.extend(_scan_source_assignments(path,text,lang))
    findings.extend(_scan_docker_k8s(path,text,lang))
    known_lines={(f.get("file"),f.get("line")) for f in known_findings}
    legacy_lines=set()
    for rid,title,vuln,pat,sev,cwe in SECRET_RULES:
        m=re.search(pat,text,_F)
        if m and rid != "SPRING_DATASOURCE_PASSWORD":
            legacy_line = text[:m.start()].count("\n") + 1

            if suffix in {".tf", ".hcl", ".tfvars"}:
                source_lines = text.splitlines()
                source_line = (
                    source_lines[legacy_line - 1]
                    if 0 < legacy_line <= len(source_lines)
                    else ""
                )

                assignment = re.search(
                    r"^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*(.+?)\s*$",
                    source_line,
                )

                if assignment and _looks_like_terraform_reference(
                    assignment.group(1)
                ):
                    continue

            legacy_lines.add((str(path), legacy_line))
    suppress_context_lines=known_lines | legacy_lines
    findings=[f for f in findings if not (f.get("rule_id")=="CONFIG_CONTEXTUAL_CREDENTIAL" and (f.get("file"),f.get("line")) in suppress_context_lines)]
    if _is_nonproduction_context(path):
        findings=[f for f in findings if f.get("rule_id") not in {"CONFIG_CONTEXTUAL_CREDENTIAL","SOURCE_HARDCODED_CREDENTIAL","DOCKER_HARDCODED_CREDENTIAL","K8S_SECRET_MATERIAL"}]
    findings.extend(known_findings)
    structured=_scan_structured_secrets(path,text,lang)
    structured_lines={(f.get("file"),f.get("line")) for f in structured}
    # URI-specific legacy rules are redundant when the structured URI detector already produced the finding.
    findings=[f for f in findings if not (f.get("rule_id") in {"DATABASE_URL_CREDENTIALS","JDBC_URL_CREDENTIALS","RABBITMQ_CREDENTIALS"} and (f.get("file"),f.get("line")) in structured_lines)]
    findings.extend(structured)
    findings.extend(_scan_entropy(path,text,lang))
    lines=text.splitlines()
    for rid,title,vuln,pat,sev,cwe in SECRET_RULES:
        m=re.search(pat,text,_F)
        if not m: continue
        line=text[:m.start()].count("\n")+1; snippet=lines[line-1] if line<=len(lines) else m.group(0)
        if snippet.strip().startswith(("#","//","*")): continue
        # Same value-decision as _scan_known_signatures: a signature can match
        # a reference to the credential (type declaration, config-object
        # wiring, CI expression, version range) rather than the credential.
        _assigned = re.split(r"[:=]", m.group(0), maxsplit=1)
        if len(_assigned) == 2 and _value_is_code_reference(_assigned[1]):
            continue
        if len(_assigned) == 2 and _is_placeholder(_assigned[1]):
            # Stand-in literals at credential keys: "testAppClientSecret",
            # "sk-password", "REPLACE_WITH_YOUR_API_KEY".
            continue
        if len(_assigned) == 2 and lang in _CODE_LANGS_QUOTED_LITERALS:
            # The pattern's optional ["']? is the quote evidence: a value
            # WITHOUT a leading quote in a code file cannot be a string
            # literal, so ``this.AppClientSecret = appClientSecret;`` names a
            # variable. Quoted literals are unaffected.
            _rhs = str(_assigned[1] or "").strip()
            if (_rhs[:1] not in {'"', "'", "`"}
                    and len(_rhs.rstrip(";,").strip()) >= 8
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", _rhs.rstrip(";,").strip())):
                continue
        if rid == "CLOUD_METADATA_TOKEN_USE" and _is_nonproduction_context(path):
            # The metadata IP is an endpoint constant, not reusable secret
            # material: on test/fixture paths it is SSRF-defense fixture data
            # (dns-pinning tests verifying the block). Production code reports.
            continue

        # Terraform/HCL references are expressions, not literal secret
        # material. Prevent the final legacy SECRET_RULES pass from
        # reintroducing findings such as:
        # client_secret = module.secrets.client_secret
        if suffix in {".tf", ".hcl", ".tfvars"}:
            source_lines = text.splitlines()
            source_line = (
                source_lines[line - 1]
                if 0 < line <= len(source_lines)
                else snippet
            )

            assignment = re.search(
                r"^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*(.+?)\s*$",
                source_line,
            )

            if assignment and _looks_like_terraform_reference(
                assignment.group(1)
            ):
                continue

        if suffix in {".properties", ".yml", ".yaml", ".json", ".xml", ".config"}:
            pairs = _parse_properties(text) if suffix == ".properties" else _parse_generic_key_values(text)
            if any(n == line and (_looks_like_env(v) or _ENV_DEFAULT.fullmatch(v.strip())) for n,k,v in pairs): continue
        # Structured URI detector is the canonical finding for URI-embedded credentials.
        if rid in {"DATABASE_URL_CREDENTIALS","JDBC_URL_CREDENTIALS","RABBITMQ_CREDENTIALS"} and (str(path),line) in structured_lines: continue
        findings.append(_build_finding(rid,title,vuln,sev,cwe,path,line,"[SECRET MATERIAL REDACTED]",lang))
    # Canonicalize overlapping format-aware/contextual findings at the same source location.
    k8s_lines={(f.get("file"),f.get("line")) for f in findings if f.get("rule_id")=="K8S_SECRET_MATERIAL"}
    canonical=[]; config_seen=set()
    for f in findings:
        loc=(f.get("file"),f.get("line"))
        if f.get("rule_id")=="CONFIG_CONTEXTUAL_CREDENTIAL" and loc in k8s_lines: continue
        if f.get("rule_id")=="CONFIG_CONTEXTUAL_CREDENTIAL":
            if loc in config_seen: continue
            config_seen.add(loc)
        canonical.append(f)
    findings=canonical
    if _is_translated_text_or_seed_dataset(path):
        findings=[f for f in findings if f.get("rule_id")!="CONFIG_CONTEXTUAL_CREDENTIAL"]
    # S1 doc-class gate: only .md/.ipynb pass through it (see helpers).
    if suffix in _DOC_CLASS_EXTS:
        findings=[f for f in findings if not _is_doc_placeholder_finding(f, lines)]
    seen=set(); unique=[]
    for f in findings:
        k=(f.get("rule_id"),f.get("file"),f.get("line"),f.get("vuln_type"))
        if k not in seen: seen.add(k); unique.append(f)
    return _defer_fallback_claims(unique)

#: Generic fallback claims (bucket C, 2026-10-22). One literal, one
#: claim: every fallback yields to a SPECIFIC rule on the same
#: (file, line) — a provider signature claim for the name-gated SOURCE
#: rule, any sibling claim for the entropy layer — and a fallback alone
#: on its line keeps. Same canonicalization idea as the K8S/CONFIG
#: overlap above, one layer down.
_SECRET_FALLBACKS = frozenset({"GENERIC_HIGH_ENTROPY_SECRET",
                               "SOURCE_HARDCODED_CREDENTIAL"})


def _defer_fallback_claims(findings: list[dict]) -> list[dict]:
    """Drop shadowed generic layers: signature > name-gated > entropy.

    Kill-on-proof: a claim is removed only when ANOTHER rule already
    reports the same literal at the same (file, line) — proximity
    elsewhere never defers (the jwt L2/L3 case is the anchor bug, fixed
    by anchoring ``_scan_source_assignments`` on its identifier group,
    after which both rows share line 3 and defer here).
    """
    non_generic: set = set()
    signature: set = set()
    for f in findings:
        loc = (f.get("file"), f.get("line"))
        if f.get("rule_id") != "GENERIC_HIGH_ENTROPY_SECRET":
            non_generic.add(loc)
        if f.get("rule_id") not in _SECRET_FALLBACKS:
            signature.add(loc)
    out = []
    for f in findings:
        loc = (f.get("file"), f.get("line"))
        rule = f.get("rule_id")
        if rule == "GENERIC_HIGH_ENTROPY_SECRET" and loc in non_generic:
            continue
        if rule == "SOURCE_HARDCODED_CREDENTIAL" and loc in signature:
            continue
        out.append(f)
    return out

def scan_secret_intelligence(target_path: str) -> dict:
    target = Path(target_path)
    files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
    findings = []
    for path in files:
        findings.extend(scan_file(str(path)))
    return {"secret_intelligence_findings": findings, "secret_intelligence_summary": summarize_secret_intelligence(findings)}


def analyze_secret_intelligence(target_path: str) -> dict:
    return scan_secret_intelligence(target_path)


def classify_secrets(findings: list[dict]) -> list[dict]:
    """Classify true secret findings only; never overwrite engine on non-secret findings."""
    for finding in findings or []:
        if not _is_secret_finding(finding):
            continue
        title = str(finding.get("title", "")).lower()
        snippet = str(finding.get("snippet", "")).lower()
        if "jwt" in title or "jwt" in snippet:
            finding.setdefault("secret_type", "jwt_secret")
        elif "oauth" in title or "client_secret" in snippet:
            finding.setdefault("secret_type", "oauth_client_secret")
        elif "kafka" in title or "rabbit" in title or "amqp" in snippet:
            finding.setdefault("secret_type", "messaging_secret")
        elif "jdbc" in snippet or "://" in snippet:
            finding.setdefault("secret_type", "database_connection_secret")
        else:
            finding.setdefault("secret_type", "generic_secret")
        finding.setdefault("engine", "scanner.secret_intelligence")
        finding.setdefault("detection", "Enterprise Secret Intelligence")
    return findings


def enrich_secret_intelligence(findings: list[dict]) -> list[dict]:
    return classify_secrets(findings)


def summarize_secret_intelligence(findings: list[dict]) -> dict:
    secrets = [f for f in findings or [] if _is_secret_finding(f)]
    return {
        "total_secrets_classified": len(secrets),
        "by_secret_type": dict(Counter(f.get("secret_type", "unknown") for f in secrets)),
        "by_severity": dict(Counter(f.get("severity", "Unknown") for f in secrets)),
        "offline_only_not_validated": True,
    }


def secret_intelligence_summary(findings: list[dict]) -> dict:
    secrets = [f for f in findings or [] if _is_secret_finding(f)]
    critical = sum(1 for f in secrets if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in secrets if str(f.get("severity", "")).lower() == "high")
    return {
        "total_secrets": len(secrets),
        "critical_blast_radius": critical,
        "high_blast_radius": high,
        "validation_status": "OFFLINE_ONLY_NOT_VALIDATED",
        "summary_status": "SECRET_INTELLIGENCE_SUMMARY_AVAILABLE",
        "by_secret_type": dict(Counter(f.get("secret_type", "unknown") for f in secrets)),
        "by_severity": dict(Counter(f.get("severity", "Unknown") for f in secrets)),
    }

def apply_optional_live_secret_validation(
    findings,
    enabled=False,
    timeout=6,
    max_validations=50,
):
    """
    Optional V4 live secret validation wrapper.

    V3 behavior is preserved because this function returns an offline summary
    unless enabled=True. Any validator failure is converted to a summary object
    instead of breaking the scan.
    """
    try:
        from analysis.secret_live_validation_engine import (
            enrich_findings_with_live_secret_validation,
        )

        return enrich_findings_with_live_secret_validation(
            findings=findings or [],
            enabled=enabled,
            timeout=timeout,
            max_validations=max_validations,
        )

    except Exception as exc:
        return {
            "enabled": bool(enabled),
            "mode": "LIVE_NETWORK_VALIDATION" if enabled else "OFFLINE_ONLY_NOT_VALIDATED",
            "total_secret_findings": len(findings or []),
            "validated": 0,
            "live_valid": 0,
            "not_valid_or_revoked": 0,
            "inconclusive": 0,
            "unsupported": 0,
            "errors": 1,
            "max_validations": max_validations,
            "timeout_seconds": timeout,
            "status": "SECRET_LIVE_VALIDATION_ENGINE_ERROR",
            "error_type": type(exc).__name__,
        }

if __name__ == "__main__":
    import json, sys
    print(json.dumps(scan_secret_intelligence(sys.argv[1] if len(sys.argv) > 1 else "."), indent=2))


# ============================================================
# R-SecOpsX V10 - Secret Decision State V2
# ============================================================

_previous_enrich_secret_intelligence = enrich_secret_intelligence

def enrich_secret_intelligence(findings):
    """
    Preserve every secret finding and explicitly separate:

      detection       = static evidence
      context         = repository/path classification
      validity        = whether credential is active
      decision        = what the analyst should do

    Context NEVER proves a secret is fake.
    """
    result = _previous_enrich_secret_intelligence(findings)

    for finding in result or []:
        if not _is_secret_finding(finding):
            continue

        finding.setdefault("validity_state", "UNKNOWN")
        finding.setdefault("decision_state", "REVIEW_REQUIRED")
        finding.setdefault(
            "decision_reason",
            "Potential secret detected by static analysis. "
            "Repository context may indicate test, fixture, mock, "
            "benchmark, or production usage, but context alone cannot "
            "establish credential validity. Manual review is required."
        )
        finding.setdefault("validity_validation_mode", "OFFLINE_ONLY_NOT_VALIDATED")
        finding["context_is_not_validity"] = True
        finding["reportable_finding"] = True
        finding["suppressed_from_primary_count"] = False

    return result


_previous_secret_intelligence_summary = secret_intelligence_summary

def secret_intelligence_summary(findings):
    summary = _previous_secret_intelligence_summary(findings)

    secrets = [
        f for f in (findings or [])
        if isinstance(f, dict) and _is_secret_finding(f)
    ]

    summary["total_detected"] = len(secrets)
    summary["review_required"] = sum(
        1 for f in secrets
        if str(f.get("decision_state", "")).upper() == "REVIEW_REQUIRED"
    )
    summary["confirmed_active"] = sum(
        1 for f in secrets
        if str(f.get("validity_state", "")).upper()
        in {"VALID", "ACTIVE", "CONFIRMED_ACTIVE"}
    )
    summary["confirmed_inactive"] = sum(
        1 for f in secrets
        if str(f.get("validity_state", "")).upper()
        in {"INVALID", "INACTIVE", "CONFIRMED_INACTIVE"}
    )
    summary["validity_model"] = {
        "UNKNOWN": "Review required; validity not established",
        "VALID": "Confirmed active credential",
        "INVALID": "Confirmed inactive credential",
        "CANNOT_CHECK": "Validation not possible",
        "FAILED_TO_CHECK": "Validation attempted but failed",
    }

    return summary
