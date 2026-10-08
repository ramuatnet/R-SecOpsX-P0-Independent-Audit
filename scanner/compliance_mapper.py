from __future__ import annotations

from copy import deepcopy

from core.owasp_mappings import (
    OWASP_LLM_ENTRY_BY_VULN_TYPE,
    owasp_llm_reference,
)


# The mapping applied when nothing more specific is known.  Kept as a named
# constant because the AI path below reuses it verbatim: adding AI controls is
# strictly additive, it never withdraws a control a finding already receives.
GENERIC_MAPPING = {
    "frameworks": {
        "NIST 800-53": ["RA-5"],
        "ISO 27001": ["A.8.8"],
        "SOC 2": ["CC7.1"],
    },
    "control_theme": "Security Review",
}


DEFAULT_MAPPINGS = {
    "hardcoded_secret": {
        "frameworks": {
            "OWASP": ["A07:2021 - Identification and Authentication Failures"],
            "CWE": ["CWE-798 - Use of Hard-coded Credentials"],
            "NIST 800-53": ["IA-5", "SC-12", "SC-28"],
            "PCI DSS": ["3.6", "8.3.2", "8.6.1"],
            "ISO 27001": ["A.5.17", "A.8.24"],
            "SOC 2": ["CC6.1", "CC6.6"],
            "MITRE ATT&CK": ["T1552 - Unsecured Credentials"],
        },
        "control_theme": "Credential Protection",
    },
    "sql_injection": {
        "frameworks": {
            "OWASP": ["A03:2021 - Injection"],
            "CWE": ["CWE-89 - SQL Injection"],
            "NIST 800-53": ["SI-10", "SA-11"],
            "PCI DSS": ["6.2.4", "6.4.2"],
            "ISO 27001": ["A.8.28", "A.8.29"],
            "SOC 2": ["CC7.1", "CC7.2"],
            "MITRE ATT&CK": ["T1190 - Exploit Public-Facing Application"],
        },
        "control_theme": "Input Validation",
    },
    "command_injection": {
        "frameworks": {
            "OWASP": ["A03:2021 - Injection"],
            "CWE": ["CWE-78 - OS Command Injection"],
            "NIST 800-53": ["SI-10", "CM-7"],
            "PCI DSS": ["6.2.4"],
            "ISO 27001": ["A.8.28"],
            "SOC 2": ["CC7.1"],
            "MITRE ATT&CK": ["T1059 - Command and Scripting Interpreter"],
        },
        "control_theme": "Command Execution Control",
    },
    "code_injection": {
        "frameworks": {
            "OWASP": ["A03:2021 - Injection"],
            "CWE": ["CWE-94 - Code Injection"],
            "NIST 800-53": ["SI-10", "SA-11"],
            "PCI DSS": ["6.2.4"],
            "ISO 27001": ["A.8.28"],
            "SOC 2": ["CC7.1"],
            "MITRE ATT&CK": ["T1059 - Command and Scripting Interpreter"],
        },
        "control_theme": "Unsafe Dynamic Execution",
    },
    "insecure_deserialization": {
        "frameworks": {
            "OWASP": ["A08:2021 - Software and Data Integrity Failures"],
            "CWE": ["CWE-502 - Deserialization of Untrusted Data"],
            "NIST 800-53": ["SI-10", "SC-18"],
            "PCI DSS": ["6.2.4"],
            "ISO 27001": ["A.8.28"],
            "SOC 2": ["CC7.1"],
            "MITRE ATT&CK": ["T1059 - Command and Scripting Interpreter"],
        },
        "control_theme": "Unsafe Data Processing",
    },
    "ssrf": {
        "frameworks": {
            "OWASP": ["A10:2021 - Server-Side Request Forgery"],
            "CWE": ["CWE-918 - Server-Side Request Forgery"],
            "NIST 800-53": ["SC-7", "SI-10"],
            "PCI DSS": ["1.2.1", "6.2.4"],
            "ISO 27001": ["A.8.20", "A.8.21"],
            "SOC 2": ["CC6.6"],
            "MITRE ATT&CK": ["T1190 - Exploit Public-Facing Application"],
        },
        "control_theme": "Outbound Request Control",
    },
    "api_idor": {
        "frameworks": {
            "OWASP": ["A01:2021 - Broken Access Control"],
            "CWE": ["CWE-639 - Authorization Bypass Through User-Controlled Key"],
            "NIST 800-53": ["AC-3", "AC-6"],
            "PCI DSS": ["7.1", "7.2"],
            "ISO 27001": ["A.5.15", "A.5.18"],
            "SOC 2": ["CC6.1", "CC6.3"],
            "MITRE ATT&CK": ["T1190 - Exploit Public-Facing Application"],
        },
        "control_theme": "Authorization Enforcement",
    },
    "debug_exposure": {
        "frameworks": {
            "OWASP": ["A05:2021 - Security Misconfiguration"],
            "CWE": ["CWE-215 - Information Exposure Through Debug Information"],
            "NIST 800-53": ["CM-6", "SI-11"],
            "PCI DSS": ["6.2.4", "6.5.5"],
            "ISO 27001": ["A.8.9", "A.8.32"],
            "SOC 2": ["CC7.2"],
            "MITRE ATT&CK": ["T1082 - System Information Discovery"],
        },
        "control_theme": "Secure Configuration",
    },
    "vulnerable_dependency": {
        "frameworks": {
            "OWASP": ["A06:2021 - Vulnerable and Outdated Components"],
            "CWE": ["CWE-937 - Use of Vulnerable Third Party Component"],
            "NIST 800-53": ["SI-2", "RA-5", "SA-12"],
            "PCI DSS": ["6.3.3", "6.4.3"],
            "ISO 27001": ["A.8.8", "A.8.9"],
            "SOC 2": ["CC7.1", "CC7.2"],
            "MITRE ATT&CK": ["T1195 - Supply Chain Compromise"],
        },
        "control_theme": "Software Supply Chain Risk",
    },
}


PREFIX_MAPPINGS = {
    "k8s_": {
        "frameworks": {
            "OWASP": ["A05:2021 - Security Misconfiguration"],
            "CWE": ["CWE-250", "CWE-732", "CWE-798"],
            "NIST 800-53": ["AC-6", "CM-6", "CM-7", "SC-7"],
            "PCI DSS": ["2.2.4", "6.2.4"],
            "ISO 27001": ["A.8.9", "A.8.20", "A.8.24"],
            "SOC 2": ["CC6.1", "CC6.6", "CC7.2"],
            "CIS": ["CIS Kubernetes Benchmark"],
        },
        "control_theme": "Kubernetes Security",
    },
    "tf_": {
        "frameworks": {
            "OWASP": ["A05:2021 - Security Misconfiguration"],
            "CWE": ["CWE-284", "CWE-311", "CWE-732", "CWE-798"],
            "NIST 800-53": ["AC-6", "CM-6", "SC-7", "SC-28"],
            "PCI DSS": ["1.2.1", "2.2.4", "3.5.1"],
            "ISO 27001": ["A.8.9", "A.8.20", "A.8.24"],
            "SOC 2": ["CC6.1", "CC6.6"],
            "CIS": ["CIS AWS Foundations Benchmark"],
        },
        "control_theme": "Cloud Infrastructure Security",
    },
    "docker_": {
        "frameworks": {
            "OWASP": ["A05:2021 - Security Misconfiguration"],
            "CWE": ["CWE-250", "CWE-494", "CWE-732", "CWE-798"],
            "NIST 800-53": ["AC-6", "CM-6", "CM-7", "SI-7"],
            "PCI DSS": ["2.2.4", "6.2.4"],
            "ISO 27001": ["A.8.9", "A.8.20", "A.8.24"],
            "SOC 2": ["CC6.1", "CC6.6", "CC7.2"],
            "CIS": ["CIS Docker Benchmark"],
        },
        "control_theme": "Container Image Security",
    },
}


def _ai_mapping(finding: dict, vuln_type: str) -> dict | None:
    """Compliance mapping for an AI / GenAI finding.

    An AI finding previously fell straight through to :data:`GENERIC_MAPPING`,
    so on the AI/LLM corpus all 27 AI findings reported
    ``NIST 800-53: RA-5 / ISO 27001: A.8.8 / SOC 2: CC7.1`` and *no* OWASP or
    CWE control at all, while every non-AI class got a specific mapping.

    The two controls added here are not invented: the OWASP label comes from
    ``core/owasp_mappings`` (the verified 2025/2023/2026 edition catalogue the
    product already emits on the finding) and the CWE is the finding's own
    ``cwe`` field.  A subject that carries no OWASP entry id at all -- a
    governance control gap or an unclassified rule -- is given no OWASP
    control, so a control family is never borrowed to fill a column.  A
    retired 2023 entry keeps its own editioned label, which states in the
    value itself that it left the Top 10 in 2025.  The generic NIST/ISO/SOC 2
    controls are preserved unchanged, so this is strictly additive.

    Returns ``None`` when the vulnerability type is outside the catalogue, so
    an unknown finding keeps today's behaviour instead of borrowing a risk ID
    it does not describe.
    """
    if vuln_type not in OWASP_LLM_ENTRY_BY_VULN_TYPE:
        return None

    frameworks = deepcopy(GENERIC_MAPPING["frameworks"])

    reference = owasp_llm_reference(vuln_type)
    if reference["owasp_id"]:
        frameworks["OWASP"] = [reference["owasp"]]

    cwe = finding.get("cwe")
    if isinstance(cwe, str) and cwe.strip():
        frameworks["CWE"] = [cwe.strip()]
    elif isinstance(cwe, (list, tuple)):
        present = [str(v).strip() for v in cwe if str(v).strip()]
        if present:
            frameworks["CWE"] = present

    return {
        "frameworks": frameworks,
        "control_theme": GENERIC_MAPPING["control_theme"],
    }


def _mapping_for(finding: dict) -> dict:
    vuln_type = str(finding.get("vuln_type", "")).lower()
    rule_id = str(finding.get("rule_id", "")).lower()

    if vuln_type in DEFAULT_MAPPINGS:
        return DEFAULT_MAPPINGS[vuln_type]

    if rule_id in DEFAULT_MAPPINGS:
        return DEFAULT_MAPPINGS[rule_id]

    for prefix, mapping in PREFIX_MAPPINGS.items():
        if vuln_type.startswith(prefix) or rule_id.startswith(prefix):
            return mapping

    ai_mapping = _ai_mapping(finding, vuln_type)
    if ai_mapping is not None:
        return ai_mapping

    return deepcopy(GENERIC_MAPPING)


def enrich_compliance(findings: list[dict]) -> list[dict]:
    enriched = []

    for finding in findings:
        item = deepcopy(finding)
        mapping = _mapping_for(item)

        item["compliance_controls"] = mapping["frameworks"]
        item["control_theme"] = mapping["control_theme"]

        item.setdefault("framework", mapping["control_theme"])
        item.setdefault("control", mapping["control_theme"])

        enriched.append(item)

    return enriched


# Unit of every number in `compliance_summary`.
#
# Measured on the Juice Shop corpus (report 06102026 1914): this is NOT
# "findings mapped to the framework" in the sense a reader assumes.  It is
# "grouped findings that carry at least one non-empty control id for the
# framework".  On that corpus it reads NIST 800-53: 102 / ISO 27001: 102 /
# SOC 2: 102, which is arithmetically true and evidentially hollow: 80 of the
# 102 findings carry the IDENTICAL default triple from GENERIC_MAPPING
# (RA-5 / A.8.8 / CC7.1), so ~98 of those 102 are the generic fallback, not a
# per-finding mapping decision.  Only 20 findings carry a NIST 800-53 control
# id other than RA-5.
#
# The distinction is stated rather than fixed here: choosing which of the three
# parallel measures (this summary, the flat per-finding string fields, and the
# executive-PDF "Observed Mappings" column) is authoritative is G-064 and is
# still blocked.  What this constant makes possible is that a consumer can
# refuse to read these as coverage.
COMPLIANCE_SUMMARY_UNIT = (
    "grouped_findings_with_at_least_one_non_empty_control_id"
)

# Frameworks whose value is the generic fallback rather than a
# finding-specific decision.  Reported separately by
# `compliance_summary_detail` so the generic and specific populations can never
# be summed into one "coverage" figure by accident.
COMPLIANCE_GENERIC_FRAMEWORKS = ("NIST 800-53", "ISO 27001", "SOC 2")

_GENERIC_CONTROL_IDS = {
    framework: tuple(ids)
    for framework, ids in GENERIC_MAPPING["frameworks"].items()
}


def _control_ids(value) -> tuple:
    """Normalise a framework's control value to a tuple of non-empty ids.

    A framework key whose value is empty carries no mapping.  The previous
    implementation counted such keys anyway (`for framework in controls`), so a
    finding with an empty control list inflated its framework's count.  That is
    a latent bug rather than one observed on the Juice Shop corpus -- no corpus
    finding currently holds an empty list -- so this is closed proactively.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set, frozenset)):
        parts = [str(part).strip() for part in value]
    else:
        parts = [str(value).strip()]

    return tuple(part for part in parts if part)


def compliance_summary(findings: list[dict]) -> dict:
    """Count, per framework, the findings carrying a non-empty control id.

    Framework presence is now gated on the value being non-empty.  The return
    shape (framework -> int) is unchanged so existing consumers keep working.
    """
    summary: dict[str, int] = {}

    for finding in findings:
        controls = finding.get("compliance_controls", {})
        if not isinstance(controls, dict):
            continue
        for framework, value in controls.items():
            if not _control_ids(value):
                continue
            summary[framework] = summary.get(framework, 0) + 1

    return dict(sorted(summary.items()))


def compliance_summary_detail(findings: list[dict]) -> dict:
    """`compliance_summary` plus the evidence needed to read it honestly.

    Splits the three always-applied generic frameworks into the findings that
    got them from GENERIC_MAPPING and the findings that got a
    finding-specific control.  `specific_findings` is the number that a
    coverage claim would actually need.
    """
    base = compliance_summary(findings)

    generic = 0
    specific = 0
    unspecified = 0

    for finding in findings:
        controls = finding.get("compliance_controls", {})
        if not isinstance(controls, dict):
            unspecified += 1
            continue

        has_generic = False
        has_specific = False

        for framework in COMPLIANCE_GENERIC_FRAMEWORKS:
            ids = _control_ids(controls.get(framework))
            if not ids:
                continue
            if ids == _GENERIC_CONTROL_IDS.get(framework):
                has_generic = True
            else:
                has_specific = True

        if has_generic:
            generic += 1
        if has_specific:
            specific += 1
        if not has_generic and not has_specific:
            unspecified += 1

    return {
        "unit": COMPLIANCE_SUMMARY_UNIT,
        "counts": base,
        "generic_fallback": {
            "frameworks": list(COMPLIANCE_GENERIC_FRAMEWORKS),
            "control_ids": {
                framework: list(ids)
                for framework, ids in sorted(_GENERIC_CONTROL_IDS.items())
            },
            "findings_receiving_generic_only": generic,
        },
        "specific_mapping": {
            "findings_with_finding_specific_controls": specific,
            "findings_with_none_of_the_generic_frameworks": unspecified,
        },
        "population": len(findings),
        "caveat": (
            "counts are framework-presence over grouped findings, not coverage. "
            "Three frameworks are applied to every finding by GENERIC_MAPPING, so "
            "a count of 102 for NIST 800-53 means 102 findings carry *a* NIST "
            "control id, not that 102 distinct control decisions were made."
        ),
    }


if __name__ == "__main__":
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description="R-SecOpsX Compliance Mapper")
    parser.add_argument("input", help="Input findings JSON file")
    parser.add_argument("--output", default=None, help="Output enriched JSON file")
    args = parser.parse_args()

    source = Path(args.input)
    data = json.loads(source.read_text(encoding="utf-8"))

    findings = data.get("findings", data if isinstance(data, list) else [])
    enriched = enrich_compliance(findings)

    result = {
        "findings": enriched,
        "compliance_summary": compliance_summary(enriched),
    }

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[COMPLIANCE] Findings enriched: {len(enriched)}")
        print(f"[COMPLIANCE] Output written: {out}")
    else:
        print(json.dumps(result, indent=2))