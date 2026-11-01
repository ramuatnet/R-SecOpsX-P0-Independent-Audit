import os
from collections import defaultdict
import hashlib
import re


def normalize(snippet: str) -> str:
    snippet = snippet.lower()
    snippet = re.sub(r'\s+', '', snippet)
    snippet = re.sub(r'["\'].*?["\']', 'STR', snippet)
    return snippet


def root_key(f: dict) -> str:
    """Return a stable semantic grouping key for one finding location.

    Findings from different semantic engines may represent the same
    underlying vulnerability. The grouping identity is therefore based on:

        vulnerability type + canonical source file + source/sink line

    The source file is canonicalized so that equivalent paths such as:



        ./dump/Java/V10/file.java

        dump/Java/V10/file.java



    resolve to the same grouping identity.
    """
    vuln_type = normalize(f.get("vuln_type", ""))

    raw_file = str(f.get("file") or "").strip()

    try:
        source_file = os.path.normcase(
            os.path.abspath(os.path.normpath(raw_file))
        )
    except (TypeError, ValueError, OSError):
        source_file = normalize(raw_file)

    source_file = normalize(source_file)

    line = f.get("line")
    try:
        line_no = int(line or 0)
    except (TypeError, ValueError):
        line_no = 0

    return hashlib.md5(  # sast-ignore MD5_USAGE non-security dedup fingerprint over vuln_type|file|line
        f"{vuln_type}|{source_file}|{line_no}".encode()
    ).hexdigest()

def calculate_risk(severity: str, instances: int) -> int:
    base = {
        "Critical": 9,
        "High": 7,
        "Medium": 5,
        "Low": 3,
        "Info": 1
    }.get(severity, 5)

    # boost if repeated across files
    multiplier = min(2, 1 + (instances / 10))
    return round(base * multiplier, 1)


def group_findings(findings: list[dict]) -> list[dict]:
    grouped = defaultdict(lambda: {
        "title": None,
        "vuln_type": None,
        "severity": None,
        "priority": None,
        "snippet": None,

        "instances": 0,
        "affected_files": [],
        "file": "",
        "line": "",

        "owasp": "",
        "mitre": "",
        "cwe": "",
        "pci_dss": "",
        "nist": "",
        "iso27001": "",
        "soc2": "",

        "taint_path": "",
        "description": "",
        "business_impact": "",
        "remediation": [],
        "risk_score": 0,

        # Preserve semantic-engine metadata through grouping.
        "engine": None,
        "rule_id": None,
        "detection": None,
        "sink_category": None,
        "group_key": None,
        "evidence_valid": None,
        "source_type": None,
        "source": None,
        "sink": None,
        "source_variable": None,
        "sink_variable": None,
        "source_line": None,
        "sink_line": None,
        "data_flow": None,
        "semantic_layer": None,
        "confidence": None,
        "sink_call": None,
        "source_expr": None,
        "source_var": None,
        "taint_chain": None,
        "function": None,
        "language": None,
        "cve": None,
        "cvss": None,
        "enterprise_control": False,

    })

    metadata_fields = (
        "engine",
        "rule_id",
        "detection",
        "sink_category",
        "group_key",
        "evidence_valid",
        "source_type",
        "source",
        "sink",
        "source_variable",
        "sink_variable",
        "source_line",
        "sink_line",
        "data_flow",
        "semantic_layer",
        "confidence",
        "sink_call",
        "source_expr",
        "source_var",
        "taint_chain",
        "function",
        "language",
        "cve",
        "cvss",

    )

    for f in findings:
        key = root_key(f)
        g = grouped[key]

        # Deterministic representative selection for cross-engine collisions.
        #
        # Findings with the same root_key() represent the same semantic
        # vulnerability location. When an enterprise semantic finding and a
        # native finding collide, the enterprise finding is the canonical
        # representative regardless of arrival order.
        current_enterprise = bool(g.get("enterprise_control"))
        candidate_enterprise = bool(f.get("enterprise_control"))

        # Deterministic representative priority for cross-engine collisions.
        # Enterprise semantic taint findings are the canonical representative
        # when they collide with native SAST findings at the same root key.
        current_engine = str(g.get("engine") or "")
        candidate_engine = str(f.get("engine") or "")

        engine_priority = {
            "scanner.taint_engine": 100,
            "scanner.sast": 50,
        }

        current_priority = engine_priority.get(current_engine, 0)
        candidate_priority = engine_priority.get(candidate_engine, 0)

        replace_representative = (
            not g.get("rule_id")
            or (candidate_enterprise and not current_enterprise)
            or (
                candidate_enterprise
                and current_enterprise
                and candidate_priority > current_priority
            )
        )

        if replace_representative:
            g["title"] = f.get("title")
            g["vuln_type"] = f.get("vuln_type")
            g["severity"] = f.get("severity")
            g["priority"] = f.get("priority")
            g["snippet"] = f.get("snippet")

            if not g["file"]:
                g["file"] = f.get("file")
                g["line"] = f.get("line")

            # Preserve the representative's complete semantic metadata.
            for field in metadata_fields:
                value = f.get(field)
                if value is not None and value != "":
                    g[field] = value

            g["enterprise_control"] = candidate_enterprise
        else:
            if not g["file"]:
                g["file"] = f.get("file")
                g["line"] = f.get("line")

        # Preserve the first meaningful semantic value.
        for field in metadata_fields:
            value = f.get(field)
            if value is not None and value != "" and g.get(field) in (None, ""):
                g[field] = value

        g["owasp"] = f.get("owasp")
        g["mitre"] = f.get("mitre")
        g["cwe"] = f.get("cwe")
        g["pci_dss"] = f.get("pci_dss")
        g["nist"] = f.get("nist")
        g["iso27001"] = f.get("iso27001")
        g["soc2"] = f.get("soc2")

        g["description"] = f.get("description")
        g["business_impact"] = f.get("business_impact")
        g["remediation"] = f.get("remediation", [])

        if f.get("taint_path") and not g["taint_path"]:
            g["taint_path"] = f.get("taint_path")

        file_entry = f.get("file")
        if file_entry not in g["affected_files"]:
            g["affected_files"].append(file_entry)

    results = []
    for g in grouped.values():
        g["instances"] = len(g["affected_files"])
        g["risk_score"] = calculate_risk(g["severity"], g["instances"])
        results.append(g)

    return results




