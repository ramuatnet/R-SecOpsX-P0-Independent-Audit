"""Emit the normalized T-0.6 rule files from the live rule tables.

One-shot migration plus an idempotence tool: ``python
tools/emit_rule_yaml.py`` rewrites ``scanner/rules/enterprise_v1.yaml``
and ``scanner/rules/regex_v1.yaml`` in the strict subset core.mini_yaml
understands (also valid for yaml.safe_load).  Field mapping to the
v1 schema (FND-06 canonical names):

    ENTERPRISE_RULES  pat->pattern, vuln->family, sev->severity,
                      plus optional remediation/evidence_pat
    REGEX_RULES       name->title, vuln_type->family, severity->severity,
                      pattern->pattern, languages->langs,
                      note kept as optional v1 field

Derived fields (declarative now, generated lookups later):
    span        -- "evidence" (analysis.spans WINDOW_EVIDENCE window;
                   carried as data, no consumer yet)
    exts        -- LANG_BY_EXT inverse over the rule's langs
    negative    -- the rule's anti-pattern when it declares one
                   (null when none; no rule declares one today)
    contract_ref  -- the ufib family contract whose key equals the rule's
                     family value, when one exists (no fabricated links)
    sink_category -- sast's batch-10 php sink map, moved into the rule
    disabled      -- DISABLED_CONTEXT_ONLY_RULES membership

After this migration the YAML is the source of truth; sast.py loads the
tables through core.rule_loader (a shim over scanner.rules.loader).
Re-running this tool post-migration normalizes hand edits (it loads
through the loader, not through sast's inline tables -- the tables no
longer exist there).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core import mini_yaml  # noqa: E402
from core.file_index import LANG_BY_EXT  # noqa: E402

SCHEMA_ID = "rsecopsx.rules/v1"

# Canonical key order for emission (stable diffs; FND-06 field set).
_FIELD_ORDER = (
    "id", "title", "family", "severity", "langs", "exts", "cwe", "owasp",
    "pattern", "span", "negative", "flags", "evidence_pat", "sink_category",
    "contract_ref", "sanitizers", "barriers", "remediation", "note",
    "disabled",
)

# inverse: language -> sorted known extensions (declarative derivation,
# no behaviour change -- langs remains the gate)
EXTS_BY_LANG: dict[str, list[str]] = {}
for _ext, _lang in LANG_BY_EXT.items():
    EXTS_BY_LANG.setdefault(_lang, []).append(_ext)
for _lang in EXTS_BY_LANG:
    EXTS_BY_LANG[_lang] = sorted(EXTS_BY_LANG[_lang])


def _exts_of(langs) -> list[str]:
    exts: list[str] = []
    for lang in langs or []:
        for ext in EXTS_BY_LANG.get(lang, []):
            if ext not in exts:
                exts.append(ext)
    return sorted(exts)

_FLAG_LETTERS = ((re.I, "i"), (re.M, "m"), (re.S, "s"))


def _flags_of(compiled: "re.Pattern") -> str:
    """'ims' letters for a compiled pattern (UNICODE is the str default)."""
    return "".join(letter for bit, letter in _FLAG_LETTERS
                   if compiled.flags & bit)


def _ordered(rule: dict) -> dict:
    out = {k: rule[k] for k in _FIELD_ORDER if k in rule}
    for k in rule:                       # never drop data silently
        if k not in out:
            out[k] = rule[k]
    return out


def _contract_ref(vuln) -> str | None:
    from analysis.ufib_contracts import CONTRACTS
    if isinstance(vuln, str) and vuln in CONTRACTS:
        return vuln
    return None


def _enterprise_v1() -> list[dict]:
    from scanner.php_webshell_rules import as_sast_rules
    from scanner.sast import (DISABLED_CONTEXT_ONLY_RULES, ENTERPRISE_RULES,
                              _PHP_SINK_CATEGORY)
    # The webshell pack stays code-side (its RSECOPSX_PHP_WEBSHELL_RULES
    # env switch removes it at registration time); its rules and their
    # sink categories live in scanner/php_webshell_rules.py, and sast
    # merges them after loading the YAML.
    pack_ids = {r["id"] for r in as_sast_rules()}
    rows = []
    for rule in ENTERPRISE_RULES:
        if rule["id"] in pack_ids:
            continue
        row = {
            "id": rule["id"],
            "title": rule["title"],
            "family": rule["vuln"],
            "severity": rule["sev"],
            "langs": list(rule["langs"]),
            "exts": _exts_of(rule["langs"]),
            "cwe": rule["cwe"],
            "owasp": rule["owasp"],
            "pattern": rule["pat"],
            "span": "evidence",
            "negative": None,
        }
        if rule.get("evidence_pat"):
            row["evidence_pat"] = rule["evidence_pat"]
        if rule["id"] in _PHP_SINK_CATEGORY:
            row["sink_category"] = _PHP_SINK_CATEGORY[rule["id"]]
        ref = _contract_ref(rule["vuln"])
        if ref:
            row["contract_ref"] = ref
        if rule.get("remediation"):
            row["remediation"] = rule["remediation"]
        if rule["id"] in DISABLED_CONTEXT_ONLY_RULES:
            row["disabled"] = True
        rows.append(_ordered(row))
    return rows


def _regex_v1() -> list[dict]:
    from scanner.sast import REGEX_RULES
    rows = []
    for rule in REGEX_RULES:
        pat = rule["pattern"]
        if isinstance(pat, re.Pattern):
            # The legacy table stores compiled patterns with per-rule flags
            # (most are sast's _F = I|M|S; AWS_ACCESS_KEY is default).
            row_pat, flags = pat.pattern, _flags_of(pat)
        else:
            row_pat, flags = pat, "ims"
        row = {
            "id": rule["id"],
            "title": rule["name"],
            "family": rule["vuln_type"],
            "severity": rule["severity"],
            "pattern": row_pat,
            "flags": flags,
            "cwe": rule["cwe"],
            "owasp": rule["owasp"],
            "span": "evidence",
            "negative": None,
        }
        if rule.get("languages"):
            # Legacy stores this as a set; sort so emission is deterministic
            # (the loader converts back to a set, so order is not semantic).
            row["langs"] = sorted(rule["languages"])
        row["exts"] = _exts_of(row.get("langs"))
        if rule.get("note"):
            row["note"] = rule["note"]
        ref = _contract_ref(rule["vuln_type"])
        if ref:
            row["contract_ref"] = ref
        rows.append(_ordered(row))
    return rows


def main() -> int:
    rules_dir = REPO / "scanner" / "rules"
    rules_dir.mkdir(exist_ok=True)
    for name, rows in (("enterprise_v1.yaml", _enterprise_v1()),
                       ("regex_v1.yaml", _regex_v1())):
        text = mini_yaml.dump({"schema": SCHEMA_ID, "rules": rows})
        (rules_dir / name).write_text(text, encoding="utf-8")
        print(f"wrote scanner/rules/{name}: {len(rows)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
