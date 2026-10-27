"""Per-vulnerability-type sink table + language/layer map + MISLABELED hints.

Used by the accuracy layer's evidence-sink consistency check: if the flagged
line (with context window) contains no sink of the CLAIMED type, the finding
is LIKELY_FALSE_POSITIVE; if it contains a real sink of a DIFFERENT type, it
is MISLABELED and the suggested rule is attached.

Regexes are ReDoS-safe: no nested quantifiers, bounded repetitions only.
"""
from __future__ import annotations

import re

# sink-family -> (compiled patterns, representative rule id, layer)
_SINK_FAMILIES = {
    "sql": ([
        re.compile(r"\b(?:execute|executemany|query)\s*\(\s*['\"][^'\"]*['\"]\s*,", re.I),
        re.compile(r"\b(?:executeQuery|executeUpdate|prepareStatement|"
                   r"createSQLQuery|createNativeQuery|jooq)\s*\(", re.I),
        re.compile(r"\bsqlite3_exec\s*\(", re.I),
        re.compile(r"\.(?:query|execute)\s*\(\s*['\"`][^'\"`]*(?:SELECT|INSERT|UPDATE|DELETE)\b", re.I),
    ], "JAVA_JDBC_SQL_CONCAT", "server"),
    "command": ([
        re.compile(r"\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|"
                   r"subprocess\.(?:run|call|Popen|check_output)|os\.system|"
                   r"os\.popen|child_process\.exec)\b", re.I),
        # PHP command sinks: shell_exec/popen/proc_open carry an underscore
        # prefix, so the \b(?:eval|exec) boundary above never matched them and
        # the layer reported "no command sink" for a literal
        # system($_GET['cmd']) -- a false-negative-producing verdict, not an
        # FP-avoiding one.
        re.compile(r"\b(?:system|shell_exec|passthru|popen|proc_open|"
                   r"pcntl_exec|expect_popen)\s*\(", re.I),
        re.compile(r"(?<![`\\])`[^`\n]{1,200}`"),
    ], "TAINT_CMDI", "server"),
    "code_eval": ([
        re.compile(r"\b(?:eval|exec)\s*\(", re.I),
        re.compile(r"\bScriptEngine\.eval|\.eval\s*\(\s*script\b", re.I),
        # PHP code-execution sinks beyond eval(): assert() (pre-8 evaluated
        # strings), request-controlled callables, create_function(), and the
        # /e modifier on preg_replace().
        re.compile(r"\b(?:assert|call_user_func|call_user_func_array|"
                   r"create_function|forward_static_call)\s*\(", re.I),
        re.compile(r"\bpreg_replace\s*\(\s*['\"].{0,160}?/[a-z]{0,7}e[a-z]{0,7}['\"]",
                   re.I),
        re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,60}\]\s*\("),
    ], "TAINT_CODE_INJECTION", "server"),
    "file_path": ([
        re.compile(r"\bnew\s+(?:java\.io\.)?File\s*\(", re.I),
        re.compile(r"\b(?:Files\.(?:read|write|copy|move|newOutput)|"
                   r"FileInputStream|FileOutputStream|open|open\()\s*\(", re.I),
        re.compile(r"\bPaths\.get\s*\(|\bPath\.Combine\s*\(", re.I),
        re.compile(r"\b(?:read_to_string|fs::read|fs::write)\s*\(", re.I),
    ], "JAVA_J3_PATH_TRAVERSAL", "server"),
    "zip_entry": ([
        re.compile(r"\b(?:ZipInputStream|ZipFile|getNextEntry|"
                   r"ArchiveInputStream|extractall|unzip)\b", re.I),
    ], "GENERIC_ZIPSLIP", "server"),
    "xml_parser": ([
        re.compile(r"\b(?:DocumentBuilderFactory|SAXParserFactory|"
                   r"XMLInputFactory|XmlReaderSettings|libxml|etree\.(?:parse|fromstring)|"
                   r"XMLReader)\b", re.I),
    ], "JAVA_XXE_PARSER", "server"),
    "jndi": ([
        re.compile(r"\b(?:InitialContext|Context)\s*\.\s*(?:lookup|search)\s*\(", re.I),
        re.compile(r"\bjndi:\b", re.I),
    ], "JAVA_JNDI_LOG4SHELL_LOOKUP", "server"),
    "ldap": ([
        re.compile(r"\b(?:LdapContext|DirContext)\s*\.\s*search\s*\(|"
                   r"\b(?:ldap|ldaps)://", re.I),
    ], "JAVA_J4_LDAP", "server"),
    "weak_random": ([
        re.compile(r"\bnew\s+Random\s*\(|\bMath\.random\s*\(|"
                   r"\brandom\.(?:random|randint|choice)\b", re.I),
    ], "JAVA_J2_WEAK_RANDOM", "server"),
    "reflection": ([
        re.compile(r"\.setAccessible\s*\(\s*true\s*\)", re.I),
    ], "JAVA_REFLECTION_SETACCESSIBLE", "server"),
    "outbound_http": ([
        re.compile(r"\b(?:requests\.(?:get|post|put)|urlopen|HttpClient|"
                   r"HttpWebRequest|axios\.|fetch\(|OkHttp|RestTemplate)\b", re.I),
    ], "TAINT_SSRF_EXPANDED", "server"),
    "deserialization": ([
        re.compile(r"\b(?:pickle\.loads?|ObjectInputStream|readObject\s*\(|"
                   r"yaml\.load\s*\(|BinaryFormatter|Deserialize\s*\(|"
                   r"unserialize\s*\()", re.I),
    ], "SAST-DESER", "server"),
    "xss_sink": ([
        re.compile(r"\b(?:innerHTML\s*=|document\.write|dangerouslySetInnerHTML|"
                   r"v-html|\.html\s*\(|echo\s+\$|Response\.Write)\b", re.I),
    ], "SAST-XSS", "client"),
    "crypto_weak": ([
        re.compile(r"\b(?:MD5|SHA1|DES|RC4|Blowfish)\b", re.I),
        re.compile(r"\b(?:new\s+Random\s*\(|Math\.random\s*\()", re.I),
    ], "JAVA_J2_WEAK_RANDOM", "server"),
}

# Claimed vulnerability type -> sink family (a finding whose flagged window
# lacks its family's sinks is LIKELY_FALSE_POSITIVE).
TYPE_TO_FAMILY = {
    "sql_injection": "sql",
    "command_injection": "command",
    "code_injection": "code_eval",
    "path_traversal": "file_path",
    "zipslip": "zip_entry",
    "xxe": "xml_parser",
    "jndi": "jndi",
    "ldap_injection": "ldap",
    "weak_random": "weak_random",
    "weak_crypto": "crypto_weak",
    "reflection": "reflection",
    "ssrf": "outbound_http",
    "insecure_deserialization": "deserialization",
    "xss": "xss_sink",
    "prototype_pollution": "code_eval",
}

_FAMILY_TO_TYPE = {v: k for k, v in TYPE_TO_FAMILY.items()}

# Rule-id prefixes -> family (for findings whose vuln_type is missing).
_RULE_PREFIX_FAMILY = (
    ("TAINT_SQL", "sql"), ("SQL", "sql"), ("HQL", "sql"), ("JDBC", "sql"),
    ("TAINT_CMD", "command"), ("CMD_INJECTION", "command"),
    ("TAINT_CODE", "code_eval"), ("EVAL", "code_eval"), ("SPEL", "code_eval"),
    ("TRAVERSAL", "file_path"), ("PATH", "file_path"), ("ZIPSLIP", "zip_entry"),
    ("XXE", "xml_parser"), ("JNDI", "jndi"), ("LDAP", "ldap"),
    ("WEAK_RANDOM", "weak_random"), ("WEAK_CRYPTO", "crypto_weak"),
    ("CBOM-", "crypto_weak"), ("REFLECTION", "reflection"),
    ("SSRF", "outbound_http"), ("DESER", "deserialization"),
    ("XSS", "xss_sink"), ("PROTOTYPE", "code_eval"),
)


def family_for_finding(finding: dict) -> str | None:
    """The sink family the finding's type claims. None for types the table
    does not model (secrets, SCA, config readings) -- those validators are
    handled elsewhere."""
    vt = str(finding.get("vuln_type") or "").strip().lower()
    if vt in TYPE_TO_FAMILY:
        return TYPE_TO_FAMILY[vt]
    rid = str(finding.get("rule_id") or "").strip().upper()
    for prefix, fam in _RULE_PREFIX_FAMILY:
        if rid.startswith(prefix) or prefix in rid:
            return fam
    return None


def sinks_for(family: str) -> list[re.Pattern]:
    return _SINK_FAMILIES.get(family, ((), None, None))[0]


def suggested_rule_for(family: str) -> str | None:
    return _SINK_FAMILIES.get(family, ((), None, None))[1]


def other_family_sink(text: str, exclude: str | None = None) -> str | None:
    """A DIFFERENT family's sink present in the text -> MISLABELED hint."""
    for fam in _SINK_FAMILIES:
        if fam == exclude:
            continue
        for pat in sinks_for(fam):
            if pat.search(text):
                return fam
    return None


# ---------------------------------------------------------------------------
# Language/layer gate (mission 1d): every rule family is valid for specific
# languages and layers; cross-layer matches are demoted to the audit list.
# ---------------------------------------------------------------------------
_EXT_LANGUAGE = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".kt": "kotlin",
    ".scala": "scala", ".go": "go", ".php": "php", ".cs": "csharp",
    ".vb": "vbnet", ".rb": "ruby", ".rs": "rust", ".c": "cpp", ".h": "cpp",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".sol": "solidity",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".xml": "xml",
    ".properties": "properties", ".tf": "terraform", ".env": "dotenv",
}

# family -> allowed languages ("*" = any) and layer
FAMILY_LAYER = {
    "sql": ({"python", "java", "javascript", "typescript", "php", "go",
             "csharp", "ruby", "rust", "kotlin", "scala"}, "server"),
    "command": ({"python", "java", "javascript", "typescript", "php", "go",
                 "csharp", "ruby", "rust", "cpp"}, "server"),
    "code_eval": ({"python", "javascript", "typescript", "php", "java", "ruby"},
                  "server"),
    "file_path": ({"python", "java", "javascript", "typescript", "php", "go",
                   "csharp", "ruby", "rust", "cpp", "kotlin"}, "server"),
    "zip_entry": ({"python", "java", "javascript", "typescript", "csharp",
                   "php", "go"}, "server"),
    "xml_parser": ({"python", "java", "javascript", "typescript", "csharp",
                    "php", "cpp"}, "server"),
    "jndi": ({"java"}, "server"),
    "ldap": ({"java", "csharp", "python", "php"}, "server"),
    "weak_random": ({"python", "java", "javascript", "typescript", "go",
                     "csharp", "ruby", "rust", "php", "kotlin", "scala"},
                    "server"),
    "reflection": ({"java", "csharp"}, "server"),
    "outbound_http": ({"python", "java", "javascript", "typescript", "go",
                       "csharp", "ruby", "rust", "php", "kotlin"}, "server"),
    "deserialization": ({"python", "java", "javascript", "typescript",
                         "csharp", "php", "ruby", "go"}, "server"),
    "xss_sink": ({"javascript", "typescript", "php", "java"}, "client"),
    "crypto_weak": ({"python", "java", "javascript", "typescript", "go",
                     "csharp", "ruby", "rust", "php", "cpp", "kotlin"},
                    "server"),
}

MINIFIED_HINTS = (
    re.compile(r"[\w.\-]+\.(?:min|bundle|chunk)[.\-][\w.\-]+\.js$", re.I),
)
