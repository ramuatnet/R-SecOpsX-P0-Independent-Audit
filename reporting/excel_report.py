"""
reporting/excel_report.py  v3

FIX LOG (v2 †’ v3):
  1. BUG  SBOM sheet: pkg.get("direct", True) replaced with pkg.get("type", "Direct")
             to match the string field now produced by sbom.py v3
  2. BUG  File column: str(Path(...).name) fails on Windows-style backslash paths
             on Linux/macOS; replaced with os.path.basename() (cross-platform).
             Later: the Findings sheet now shows the relative path, not the
             basename, because same-named files in different modules rendered
             as identical rows (see _display_file).
  3. WARN Findings sheet: "Confidence" and "Score Rationale" columns added,
             surfacing score_finding() breakdown and taint confidence per finding
  4. WARN  Findings sheet: "Affected Files" column added, showing all files
             from the grouped finding's affected_files[] list
  5. ENH   Summary sheet: risk score model description rows added so auditors
             can understand and challenge the portfolio score without the PDF
"""
from __future__ import annotations

BIG4_REPORT_COMPLIANCE_FALLBACKS = {
    "tls": ("Req 4.2 / Req 6.2.4", "SC-8 / SC-13 / SI-10", "A.8.24 / A.8.20", "CC6.7 / CC6.6"),
    "actuator": ("Req 6.2.4 / Req 7", "CM-7 / AC-3 / SC-7", "A.8.9 / A.8.20", "CC6.6 / CC7.2"),
    "xxe": ("Req 6.2.4", "SI-10 / SC-7", "A.14.2.5 / A.13.1.1", "CC6.6 / CC7.2"),
    "prototype": ("Req 6.2.4", "SI-10 / CM-7", "A.8.28 / A.8.29", "CC6.6 / CC7.2"),
    "redos": ("Req 6.2.4", "SC-5 / SI-10", "A.8.16 / A.8.20", "CC7.2 / CC6.6"),
    "async": ("Req 7 / Req 8", "AC-3 / AC-6", "A.5.15 / A.8.2", "CC6.1 / CC6.6"),
    "missing @valid": ("Req 6.2.4", "SI-10", "A.8.28 / A.8.29", "CC6.6"),
}

import os
import re
from pathlib import Path
from core import report_aggregates, value_state
from reporting.report_mappings import (
    BUSINESS_IMPACT_BY_RULE,
    REMEDIATION_BY_RULE,
    rule_key as _report_rule_key,
    needs_business_impact_replacement as _needs_bi_replace,
    needs_remediation_replacement as _needs_rem_replace,
    clean_mojibake,
    format_attack_path_label,
    format_cvss_assessment,
    normalize_report_insights,
    pkg_has_advisory,
    sbom_display_sort_key,
    license_sort_key,
)

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from analysis.intelligence_provenance import note_from_payload, provenance_pair


def _sanitize_excel_value(value):
    """Remove OOXML-forbidden C0 control characters at the XLSX boundary."""
    if value is None or not isinstance(value, str):
        return value
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", value)

C_NAVY = "1B3A5C"; C_BLUE = "2563A8"; C_LBLUE = "D6E8F7"
C_RED  = "C0392B"; C_ORG  = "E67E22"; C_YEL   = "F1C40F"
C_GRN  = "27AE60"; C_WHT  = "FFFFFF"; C_GRY   = "F4F6F8"
C_BDR  = "B8CCE4"; C_BLK  = "1A1A2E"; C_GOLD  = "C9A84C"
# Confidence cell colours
C_CONF_HIGH = "E8F5E9"  # light green
C_CONF_MED  = "FFF8E1"  # light amber
C_CONF_LOW  = "FFEBEE"  # light red

def _fill(h):  return PatternFill("solid", fgColor=h)
def _font(bold=False, color=C_WHT, size=10):
    return Font(name="Calibri", bold=bold, color=color, size=size)
def _bdr():
    t = Side(style="thin", color=C_BDR)
    return Border(left=t, right=t, top=t, bottom=t)
def _ctr(): return Alignment(horizontal="center", vertical="center", wrap_text=True)
def _lft(): return Alignment(horizontal="left",   vertical="center", wrap_text=True)

SEV_FILL = {
    "Critical": _fill(C_RED), "High": _fill(C_ORG), "Medium": _fill(C_YEL),
    "Low": _fill(C_GRN), "Info": _fill("808080"), "None": _fill(C_GRN),
}
SEV_FONT = {
    "Critical": _font(True), "High": _font(True),
    "Medium":   _font(True, color=C_BLK), "Low": _font(True),
    "Info":     _font(True), "None": _font(True),
}
CONF_FILL = {
    "High":   _fill(C_CONF_HIGH),
    "Medium": _fill(C_CONF_MED),
    "Low":    _fill(C_CONF_LOW),
}
CONF_FONT = {
    "High":   _font(color="1B5E20"),
    "Medium": _font(color="E65100"),
    "Low":    _font(color="B71C1C"),
}

def _pkg_cve_list(pkg):
    values = []
    if pkg.get("cve"):
        values.append(str(pkg.get("cve")))
    # cve_list / advisory_ids are the keys the SCA enrichment actually
    # writes (CVEs and GHSAs respectively). Without them the "CVE / Advisory"
    # cells missed every GHSA the PDF rendered.
    for key in ("cves", "additional_cves", "vulnerability_ids",
                "cve_list", "advisory_ids"):
        val = pkg.get(key)
        if isinstance(val, list):
            values.extend(str(x) for x in val if x)
        elif isinstance(val, str) and val.strip():
            values.extend(x.strip() for x in val.split(",") if x.strip())
    vulns = pkg.get("vulnerabilities") or []
    if isinstance(vulns, list):
        for vuln in vulns:
            if isinstance(vuln, dict):
                vid = vuln.get("cve") or vuln.get("id") or vuln.get("advisory_id")
                if vid:
                    values.append(str(vid))
    return sorted(set(values))


def _first_value(pkg, *keys, default="--"):
    for key in keys:
        val = pkg.get(key)
        if val not in (None, "", [], {}, "Unknown"):
            return val
    return default


def _cvss_cell(pkg, has_vulnerability=True):
    """Version + score of the package's preferred CVSS assessment.

    ``cvss_preferred_score`` is the primary assessment's own score. The
    legacy ``cvss`` scalar is a fallback for payloads written before that
    key existed -- those carry no version either, so the cell reads
    "version unknown" instead of inventing one. Where a record does state a
    version it always has a preferred score alongside it, the two written by
    the same enrichment pass, so they cannot disagree.
    """
    score = pkg.get("cvss_preferred_score")
    if score is None:
        score = _first_value(pkg, "cvss", "cvss_score", default=None)
    return format_cvss_assessment(
        pkg.get("cvss_version"), score, has_vulnerability
    )


def _is_reachable_vulnerable(pkg):
    # "Reachable Vulnerable" means BOTH conditions are true:
    #   1) the component has at least one vulnerability/advisory, and
    #   2) the vulnerable component is reachable.
    # A merely reachable, non-vulnerable component is not "reachable vulnerable".
    if not _pkg_cve_list(pkg):
        return False
    return bool(pkg.get("reachable")) or str(
        pkg.get("reachability_priority", "")
    ).upper() == "REACHABLE_VULNERABLE"


def _sbom_purl(pkg):
    """Return the canonical package URL when the SBOM payload provides one."""
    for key in ("purl", "package_url", "package_purl", "packageUrl", "packageURL"):
        value = pkg.get(key)
        if value not in (None, "", "--"):
            return str(value)
    return "--"


def _sbom_component(pkg):
    """Prefer an explicit component name; otherwise use the package name."""
    return str(pkg.get("component") or pkg.get("name") or "--")


def _sbom_current_version(pkg):
    """Version cell through the one formatter (taskf T-4.2 / Gate 3).

    The old ``str(pkg.get("version") or "--")`` passed the producer's bare
    "unknown" straight into the sheet; value_state now names the absence
    (``unknown (reason)``) or dashes it, on the same alias chain
    (version -> current_version) the ``or`` chain used.
    """
    return value_state.cell(pkg, "version")


def _sbom_vulnerability_records(pkg):
    records = []
    for key in ("vulnerabilities", "vulnerability_intelligence", "advisories"):
        value = pkg.get(key)
        if isinstance(value, list):
            records.extend(x for x in value if isinstance(x, dict))
        elif isinstance(value, dict):
            records.append(value)
    return records


def _sbom_description(pkg):
    """Extract a vulnerability/package description without inventing content."""
    for key in ("description", "vulnerability_description", "summary", "details"):
        value = pkg.get(key)
        if value not in (None, "", "--"):
            return str(value)
    for vuln in _sbom_vulnerability_records(pkg):
        for key in ("description", "summary", "details"):
            value = vuln.get(key)
            if value not in (None, "", "--"):
                return str(value)
    return "--"


def _sbom_fixed_versions(pkg):
    """Preserve all known fixed versions from package and vulnerability records.

    The merged list then goes through value_state (taskf Gate 3): the two
    renderers used to disagree here -- this helper printed the producer's
    bare "Unknown" seed while the PDF's fixed text said "unknown (not
    published)" for the same row.  Placeholder elements are filtered
    inside value_state, an unpublished fix names its gap, and a row with
    no advisory dashes.
    """
    values = []
    raw = pkg.get("fixed_in") or pkg.get("fixed_versions")
    if isinstance(raw, (list, tuple, set)):
        values.extend(str(x) for x in raw if x not in (None, "", "--"))
    elif raw not in (None, "", "--"):
        values.append(str(raw))

    for vuln in _sbom_vulnerability_records(pkg):
        raw = vuln.get("fixed_in") or vuln.get("fixed_versions") or vuln.get("fixed_version")
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(x) for x in raw if x not in (None, "", "--"))
        elif raw not in (None, "", "--"):
            values.append(str(raw))

    # Keep order while removing duplicates.
    out = []
    seen = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return value_state.cell({**pkg, "fixed_versions": out},
                            "fixed_versions",
                            has_advisory=pkg_has_advisory(pkg))


def _sbom_reference_links(pkg):
    """Return CVE/advisory reference URLs supplied by the SBOM/intelligence payload."""
    links = []

    def add(value):
        if isinstance(value, str):
            value = value.strip()
            if value.startswith(("http://", "https://")):
                links.append(value)
        elif isinstance(value, dict):
            for key in ("url", "uri", "href", "reference"):
                add(value.get(key))

    for key in ("reference", "references", "reference_links", "urls"):
        value = pkg.get(key)
        if isinstance(value, (list, tuple)):
            for item in value:
                add(item)
        else:
            add(value)

    for key in ("nvd", "nvd_url", "reference_url", "cve_url"):
        add(pkg.get(key))

    for vuln in _sbom_vulnerability_records(pkg):
        for key in ("reference", "references", "reference_links", "urls"):
            value = vuln.get(key)
            if isinstance(value, (list, tuple)):
                for item in value:
                    add(item)
            else:
                add(value)

    # Deterministic reference fallbacks: CVE -> NVD; GHSA -> GitHub Advisory.
    # These are display links only and never trigger live verification.
    if not links:
        for ident in _pkg_cve_list(pkg):
            ident_s = str(ident).strip()
            if ident_s.upper().startswith("CVE-"):
                links.append(f"https://nvd.nist.gov/vuln/detail/{ident_s}")
            elif ident_s.upper().startswith("GHSA-"):
                links.append(f"https://github.com/advisories/{ident_s}")
            if links:
                break
    return "\n".join(dict.fromkeys(links)) if links else "--"


def _is_exploitable_dependency(pkg):
    epss_priority = str(pkg.get("epss_priority") or "").upper()
    patch_urgency = str(pkg.get("patch_urgency") or "").upper()
    decision = str(pkg.get("exploitability_decision") or pkg.get("exploitability_action") or "").upper()
    return (
        _is_reachable_vulnerable(pkg)
        or bool(pkg.get("kev_status"))
        or epss_priority == "P0_IMMEDIATE"
        or patch_urgency == "IMMEDIATE"
        or decision in {"IMMEDIATE_REMEDIATE", "PRIORITY_PATCH"}
    )


def _fmt_float(value, digits=3):
    try:
        if value in (None, "", "--", "N/A"):
            return "--"
        return f"{float(value):.{digits}f}"
    except Exception:
        return str(value) if value not in (None, "") else "--"

def _hdr(ws, row, headers, col=1):
    for i, h in enumerate(headers):
        c = ws.cell(row=row, column=col + i, value=_sanitize_excel_value(h))
        c.fill = _fill(C_NAVY); c.font = _font(True); c.alignment = _ctr(); c.border = _bdr()

def _title_row(ws, text, cols):
    ws.merge_cells(f"A1:{get_column_letter(cols)}1")
    c = ws["A1"]; c.value = _sanitize_excel_value(text)
    c.fill = _fill(C_NAVY); c.font = _font(True, size=12)
    c.alignment = _ctr(); ws.row_dimensions[1].height = 30

def _title(ws, text):
    # Backward-compatible helper used by privacy/IOC sheets.
    # Keeps layout consistent with existing workbook title rows.
    _title_row(ws, text, 12)


def _static_intel_note(ws, cols, row, payload=None):
    """G-003/G-001/G-002 honesty label for any sheet that prints EPSS or KEV.

    Both the header and the sentence come from the single shared module, and
    are derived from ``payload``'s own provenance — so a workbook whose scores
    arrived from a live feed is captioned as such instead of being stamped
    offline.  Rendering without a payload falls back to the shared constant,
    which is the honest description of data that never consulted a feed.
    """
    epss_prov, kev_prov = provenance_pair(payload)
    _agg_warn = ""
    if isinstance(payload, dict) and (
            payload.get("metadata") or {}).get("aggregates_inconsistent"):
        # T-1.3: a broken aggregate must surface in every artifact's
        # provenance line, not only in the ERROR log.
        _agg_warn = (" | WARNING: report aggregates failed their consistency "
                     "checks (metadata.aggregates_inconsistent); treat the "
                     "totals as unreliable.")
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=cols)
    c = ws.cell(row=row, column=1, value=_sanitize_excel_value(
        f"EPSS provenance: {epss_prov} / KEV provenance: {kev_prov} - "
        + note_from_payload(payload) + _agg_warn
    ))
    c.fill = _fill(C_YEL); c.font = _font(True, size=9, color=C_BLK)
    c.alignment = _lft(); c.border = _bdr()
    ws.row_dimensions[row].height = 30


def _supplemental_counts(payload):
    ps = payload.get("privacy_data_exposure_summary", {}) or {}
    is_ = payload.get("ioc_malware_intelligence_summary", {}) or {}
    return int(ps.get("total_privacy_indicators", 0) or 0), int(is_.get("total_ioc_indicators", 0) or 0)


def _classify_data(item: dict) -> str:
    text = " ".join(str(item.get(k, "")) for k in ("title", "vuln_type", "description", "snippet", "evidence")).lower()
    pii_types = item.get("pii_types") or []
    if pii_types:
        joined = " ".join(str(x).lower() for x in pii_types)
        if any(x in joined for x in ["card", "pci", "cvv"]): return "PCI"
        if any(x in joined for x in ["health", "medical", "phi"]): return "PHI"
        return "PII"
    if any(x in text for x in ["password", "secret", "token", "api key", "credential"]): return "Secrets"  # sast-ignore LLM06_SENSITIVE_INFORMATION_DISCLOSURE data-classification keyword table, not secret material
    if any(x in text for x in ["ssn", "aadhaar", "pan", "email", "phone", "address", "dob", "pii", "personal"]): return "PII"
    if any(x in text for x in ["card", "cvv", "stripe"]): return "PCI"
    if any(x in text for x in ["system prompt", "internal", "admin", "private"]): return "Internal"
    if any(x in text for x in ["regulated", "privacy", "gdpr", "dpdp"]): return "Regulated"
    return "Internal" if item.get("severity") in {"Critical", "High"} else "Public"


def _evidence_confidence(item: dict) -> str:
    if item.get("taint_path") or str(_display_detection(item)).upper() == "TAINT-VALIDATED": return "Confirmed"
    if item.get("correlation_evidence") or item.get("blast_radius") or item.get("chains_to"): return "Correlated"
    det = str(_display_detection(item)).lower()
    if "heuristic" in det or "privacy" in det or "ioc" in det: return "Heuristic"
    return "Pattern"


def _display_detection(item: dict) -> str:
    det = str(item.get("detection") or "").strip()
    if det.lower() not in {"", "none", "null", "n/a", "na", "not applicable", "unknown"}:
        return "TAINT-VALIDATED" if det == "AST Taint Analysis" else det
    engine = str(item.get("engine") or "").lower()
    if item.get("taint_path") and "->" in str(item.get("taint_path")):
        return "TAINT-VALIDATED"
    if "framework" in engine:
        return "Framework-Aware Static Enrichment"
    if "api_abuse" in engine:
        return "API Abuse Heuristic"
    if "data_flow" in engine:
        return "Data Flow Correlation"
    return "Enterprise SAST Pattern"


def _fallback_compliance(item: dict) -> dict:
    title = str(item.get("title") or "").lower()
    vt = str(item.get("vuln_type") or item.get("rule_id") or "").lower()
    det = str(item.get("detection") or "").lower()
    rid = str(item.get("rule_id") or "").lower()
    text = " ".join([title, vt, det, rid])

    def _val(*keys):
        for key in keys:
            v = item.get(key)
            if str(v or "").strip() and str(v).strip().lower() not in {"not applicable", "n/a", "na", "none", "null", "unknown", "-"}:
                return v
        return "Not Applicable"

    m = {
        "pci_dss": _val("pci_dss"),
        "nist": _val("nist", "nist_800_53"),
        "iso27001": _val("iso27001", "iso_27001"),
        "soc2": _val("soc2"),
    }

    def set_if_empty(pci, nist, iso, soc2):
        if m["pci_dss"] == "Not Applicable": m["pci_dss"] = pci
        if m["nist"] == "Not Applicable": m["nist"] = nist
        if m["iso27001"] == "Not Applicable": m["iso27001"] = iso
        if m["soc2"] == "Not Applicable": m["soc2"] = soc2

    # Direct reporting fallbacks for findings that previously rendered as Not Applicable.
    if "tenant" in text and "isolation" in text:
        set_if_empty(
            "Req 7 / Req 8 - Access control and tenant data segregation",
            "AC-3 / AC-6 / SC-7",
            "A.5.15 / A.8.3 / A.8.20",
            "CC6.1 / CC6.6 / CC7.2",
        )
    if "graphql" in text and "introspection" in text:
        set_if_empty(
            "Req 6.2.4 - Secure API configuration",
            "CM-7 / AC-3 / SC-7",
            "A.8.9 / A.8.20",
            "CC6.6 / CC7.2",
        )
    if "graphql" in text and ("idor" in text or "bola" in text):
        set_if_empty(
            "Req 7 / Req 8 - Access control",
            "AC-3 / AC-6 / SI-10",
            "A.5.15 / A.8.3 / A.8.20",
            "CC6.1 / CC6.6",
        )
    if "setaccessible" in text or "set_accessible" in text or "dangerous reflection" in text:
        set_if_empty(
            "Req 6.2.4 - Secure coding and unsafe reflection prevention",
            "SI-10 / CM-7 / SA-11",
            "A.8.28 / A.8.29",
            "CC7.1 / CC7.2",
        )

    if any(x in text for x in ["privacy", "pii", "personal", "sensitive information", "prompt response logging"]):
        set_if_empty("Req 3.2 / Req 10", "PT-2 / SI-12", "A.8.2 / A.18.1.4", "CC6.1 / CC8.1")
    if any(x in text for x in ["ioc", "malware", "backdoor", "reverse shell", "payload", "persistence"]):
        set_if_empty("Req 5", "SI-3 / SI-4", "A.12.2.1", "CC7.2 / CC7.3")
    if any(x in text for x in ["rate limit", "ratelimit", "rate-limit", "abuse-prone", "api_rate_limit", "api_abuse", "brute force", "otp", "mfa", "password reset", "token refresh", "coupon", "replay", "resource consumption", "api4"]):
        set_if_empty("Req 6.2.4 / Req 8 - Abuse prevention and authentication controls", "AC-7 / SC-5 / SI-10", "A.8.16 / A.8.20", "CC7.2 / CC6.6")
    if any(x in text for x in ["llm", "prompt", "rag", "model", "agent", "autonomous", "tool"]):
        set_if_empty("Req 6.2.4", "SI-10 / CM-7", "A.14.2.5", "CC7.2 / CC6.6")
    if any(x in text for x in ["kubernetes", "container", "privileged", "host network", "read-only", "non-root", "image pull"]):
        set_if_empty("Req 6.2.4", "CM-7 / AC-6", "A.12.6.1", "CC6.6")
    if any(x in text for x in ["terraform", "security group", "s3", "rds", "ebs", "public", "encryption"]):
        set_if_empty("Req 1.3 / Req 3.5", "SC-7 / AC-3 / SC-13", "A.13.1.1 / A.10.1.1", "CC6.6 / CC6.1")
    if any(x in text for x in ["mass assignment", "overposting", "field binding", "model binding"]):
        set_if_empty("Req 6.2.4 / Req 7 - Access control", "AC-3 / SI-10", "A.9.4.1 / A.14.2.5", "CC6.1 / CC6.6")
    if any(x in text for x in ["secret", "credential", "api key", "password", "token"]):
        set_if_empty("Req 8.3.2", "IA-5", "A.9.4.3", "CC6.1")
    if any(x in text for x in ["injection", "exec", "eval", "subprocess", "shell", "ssrf"]):
        set_if_empty("Req 6.2.4", "SI-10", "A.14.2.5", "CC6.6")
    return m


def _mapped_business_impact(item: dict) -> str:
    raw = str(item.get("business_impact") or "").strip()
    if _needs_bi_replace(raw):
        return BUSINESS_IMPACT_BY_RULE.get(
            _report_rule_key(item),
            "Security impact requires manual triage based on reachable context and exposed asset criticality."
        )
    return raw


def _mapped_remediation(item: dict) -> str:
    rem = item.get("remediation") or []
    if _needs_rem_replace(rem):
        rem = REMEDIATION_BY_RULE.get(_report_rule_key(item), rem)
    if isinstance(rem, list):
        return "\n".join(str(x) for x in rem if str(x).strip())
    return str(rem or "Follow secure coding best practices.")

def _root_cause_id(item: dict) -> str:
    text = " ".join(str(item.get(k, "")) for k in ("title", "vuln_type", "rule_id", "cwe", "owasp", "description")).lower()
    families = [
        ("DESERIALIZATION", ["deserialization", "objectinputstream", "binaryformatter", "typenamehandling", "unserialize", "phar", "gob"]),
        ("COMMAND_CODE_INJECTION", ["command injection", "code injection", "exec", "eval", "spel", "jndi", "template injection"]),
        ("SQL_ORM_NOSQL_INJECTION", ["sql", "hql", "jpql", "nosql", "fromsqlraw", "orm"]),
        ("BROKEN_ACCESS_CONTROL", ["idor", "bola", "mass assignment", "overposting", "open redirect", "tenant", "privilege", "workflow", "csrf"]),
        ("SSRF", ["ssrf", "server-side request forgery", "outbound request"]),
        ("CRYPTOGRAPHIC_WEAKNESS", ["tls", "insecureskipverify", "trustmanager", "hostnameverifier", "md5", "sha-1", "crypto"]),
        ("RESOURCE_EXHAUSTION", ["redos", "rate limit", "resource exhaustion", "readall", "complexity"]),
        ("SECURITY_MISCONFIGURATION", ["actuator", "xxe", "dtd", "misconfiguration", "exposed", "debug"]),
        ("SECRETS_CREDENTIALS", ["secret", "credential", "password", "token", "private key", "api key"]),
    ]
    for family, words in families:
        if any(w in text for w in words):
            return "ROOT_" + family
    base = str(item.get("vuln_type") or item.get("rule_id") or item.get("title") or "unknown").upper().replace(" ", "_")
    return "ROOT_" + "".join(ch for ch in base if ch.isalnum() or ch == "_")[:40]


def _engine_name(item: dict) -> str:
    det = str(_display_detection(item) or "").lower()
    vt = str(item.get("vuln_type", "") or "").lower()
    if "privacy" in det or "privacy" in vt: return "Privacy Data Exposure"
    if "ioc" in det or "malware" in vt or "backdoor" in vt: return "IOC / Malware Intelligence"
    if "llm" in det or "llm" in vt or "ai_" in vt: return "AI / LLM Security"
    if "kubernetes" in det: return "Kubernetes IaC"
    if "terraform" in det: return "Terraform IaC"
    if "docker" in det: return "Dockerfile IaC"
    if item.get("cve"): return "SCA / Dependency Intelligence"
    return "SAST"




def _v17923_fixed_text(pkg):
    """Fixed-version cell through the one formatter (taskf T-2.1/T-4.1).

    Why: this helper used to hand-code both absence forms -- a long
    fixed-version-absence sentence when an advisory existed, a dash when it
    did not -- while ``_sbom_fixed_versions`` returned a dash for the same
    case, so two sheets in THIS workbook disagreed by design.  ``value_state``
    resolves one ladder from provenance + has_advisory and never prints the
    old sentence (ground rules 5 and 6).
    """
    return value_state.cell(pkg, "fixed_versions",
                            has_advisory=pkg_has_advisory(pkg))

def _v17923_benchmark_note(f):
    """Benchmark disposition text, identical to the PDF renderer's helper.

    Both artifacts previously had their own copy; only the PDF one fell
    back to ``benchmark_ground_truth.status``, so all Excel rows read '--'
    while the PDF said "unresolved"/"intentional" for the same findings.
    """
    note = str(f.get("benchmark_note") or "").strip()
    if note:
        return note
    bg = f.get("benchmark_ground_truth")
    if isinstance(bg, dict):
        status = str(bg.get("status") or "").upper()
        if status == "DECLARED_INTENTIONAL":
            return ("Benchmark-intentional case; not a production waiver. "
                    "Remediation remains developer-actionable unless separately "
                    "risk-accepted.")
        if status == "UNRESOLVED":
            return ("Benchmark classification unresolved; production TP/FP "
                    "status remains pending adjudication.")
    return ""


def _agg(payload):
    """The canonical counts for this payload (taskf T-4.2).

    Renderers read ``payload["aggregates"]`` -- computed once in
    ``build_report_payload`` -- and only rebuild when handed a payload that
    never went through it (unit tests, ingest).  A workbook row must never
    re-derive its number from ``metadata`` or ``len(...)``: that is the
    DEF-A divergence this helper exists to end.
    """
    agg = payload.get("aggregates") if isinstance(payload, dict) else None
    if not isinstance(agg, dict) or not agg:
        agg = report_aggregates.build(payload if isinstance(payload, dict) else {})
    return agg


# Sheet 1: Summary
def _summary(ws, payload):
    ws.title = "Summary"
    for col, w in zip("ABCDE", [28, 20, 16, 30, 30]):
        ws.column_dimensions[col].width = w

    meta   = payload.get("metadata", {})
    agg    = _agg(payload)
    counts = agg["counts"]
    units  = agg.get("units") or report_aggregates.COUNT_UNITS
    # DEF-A: the severity table reads the combined (SAST + SCA) distribution
    # so it sums to the headline it sits under -- never the metadata value,
    # which describes a different population.
    dist   = agg["severity"]["combined"]
    model  = meta.get("risk_score_model", {})

    _title_row(ws, "SECURITY ASSESSMENT EXECUTIVE SUMMARY", 5)

    # FIX #5 + taskf T-4.2: every count row takes its label AND its value
    # from the canonical aggregate (labels via COUNT_UNITS), so no bare
    # "Total Findings" survives and each number names its population
    # (ground rule 4).
    rows = [
        ("Tool",                meta.get("tool", "")),
        ("Target",              meta.get("target", "")),
        ("Scan Date",           meta.get("scan_date", "")[:10]),
        (units["counts.sast_records"]["label"],
         counts["sast_records"]),
        (units["counts.sca_vulnerable_packages"]["label"],
         counts["sca_vulnerable_packages"]),
        (units["counts.total_reported"]["label"],
         counts["total_reported"]),
        ("Supplemental Privacy Indicators", _supplemental_counts(payload)[0]),
        ("Supplemental IOC / Backdoor Indicators", _supplemental_counts(payload)[1]),
        ("Portfolio Risk Score", f"{meta.get('risk_score', 0)}/100"),
        ("Scoring Model",       model.get("model", "")),
        ("Score Formula",       model.get("portfolio_method", "")),
        ("Confidence Multipliers", "High=1.0—  Medium=0.85—  Low=0.70—"),
        ("Methodology Note", "Pattern-only Critical findings are severity-critical because the sink is dangerous; exploitability/confidence may remain Medium/Low until taint or runtime validation confirms reachability."),
    ]
    # D3: the accuracy layer's report-level verdicts, so the workbook states
    # how many findings the pipeline itself doubts -- not only the per-row
    # verdict on the Findings sheet. Only present when the audit ran.
    _acc = meta.get("accuracy_summary") or payload.get("accuracy") or {}
    if isinstance(_acc, dict) and _acc:
        _verdicts = _acc.get("verdicts") if isinstance(_acc.get("verdicts"), dict) else {}
        rows.append((
            "Accuracy Layer Filtered",
            f"{_acc.get('filtered', 0)} of {_acc.get('total', counts['total_reported'])}",
        ))
        rows.append((
            "Accuracy Layer Verdicts",
            ", ".join(f"{k}={v}" for k, v in sorted(_verdicts.items())) or "--",
        ))
    for i, (lbl, val) in enumerate(rows, 2):
        ws.cell(row=i, column=1, value=_sanitize_excel_value(lbl)).font  = _font(True, color=C_BLK)
        ws.cell(row=i, column=1).fill              = _fill(C_GRY)
        ws.cell(row=i, column=1).alignment         = _lft()
        ws.cell(row=i, column=2, value=_sanitize_excel_value(val)).font   = _font(color=C_BLK)
        ws.cell(row=i, column=2).alignment         = _lft()

    # Count Basis (taskf T-4.2): every aggregate field with its unit and
    # value, so a reader can reconcile the Summary by arithmetic instead of
    # trusting a headline.  Insertion order = COUNT_UNITS order (stable,
    # deterministic).
    cb = len(rows) + 3
    ws.merge_cells(f"A{cb}:E{cb}")
    cbh = ws[f"A{cb}"]
    cbh.value = _sanitize_excel_value("COUNT BASIS (CANONICAL AGGREGATE)")
    cbh.fill = _fill(C_BLUE); cbh.font = _font(True, size=11); cbh.alignment = _ctr()
    ws.row_dimensions[cb].height = 22
    _hdr(ws, cb + 1, ["Aggregate field", "Label", "Unit", "Value"])
    for k, (path, spec) in enumerate(units.items()):
        r = cb + 2 + k
        val = report_aggregates.value_at(agg, path)
        for cidx, cellv in enumerate(
                [path, spec.get("label", ""), spec.get("unit", ""), val], 1):
            c = ws.cell(row=r, column=cidx, value=_sanitize_excel_value(cellv))
            c.border = _bdr()
            c.fill = _fill(C_LBLUE if k % 2 == 0 else C_WHT)
            c.font = Font(name="Calibri", size=9, color=C_BLK)
            c.alignment = _lft() if cidx < 4 else _ctr()

    sr = cb + 3 + len(units)
    ws.merge_cells(f"A{sr}:E{sr}")
    h = ws[f"A{sr}"]; h.value = _sanitize_excel_value("SEVERITY DISTRIBUTION")
    h.fill = _fill(C_BLUE); h.font = _font(True, size=11); h.alignment = _ctr()
    ws.row_dimensions[sr].height = 22

    _hdr(ws, sr + 1, ["Severity", "Count", "Priority", "SLA", "Risk Action"])
    slas = {"Critical": "< 24 hours", "High": "7 days", "Medium": "30 days",
            "Low": "90 days", "Info": "Next sprint"}
    pris = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Info": "P4"}
    acts = {
        "Critical": "Remediate immediately block release",
        "High":     "Fix within 7 days  escalate to security lead",
        "Medium":   "Fix within 30 days  add to sprint backlog",
        "Low":      "Fix within 90 days  track in backlog",
        "Info":     "Review at convenience",
    }
    for j, sev in enumerate(["Critical", "High", "Medium", "Low", "Info"]):
        r = sr + 2 + j
        for col, val in enumerate([sev, dist.get(sev, 0), pris[sev], slas[sev], acts[sev]], 1):
            c = ws.cell(row=r, column=col, value=_sanitize_excel_value(val))
            c.border = _bdr()
            if col == 1:
                c.fill = SEV_FILL.get(sev, _fill(C_GRY))
                c.font = SEV_FONT.get(sev, _font(color=C_BLK))
                c.alignment = _ctr()
            else:
                c.fill = _fill(C_GRY); c.font = _font(color=C_BLK)
                c.alignment = _lft() if col == 5 else _ctr()

    ir = sr + 9
    ws.merge_cells(f"A{ir}:E{ir}")
    ih = ws[f"A{ir}"]; ih.value = _sanitize_excel_value("INTELLIGENCE INSIGHTS")
    ih.fill = _fill(C_NAVY); ih.font = _font(True, size=11); ih.alignment = _ctr()
    for k, ins in enumerate(normalize_report_insights(payload.get("insights", []), dist), 1):
        r = ir + k
        ws.merge_cells(f"A{r}:E{r}")
        c = ws[f"A{r}"]; c.value = _sanitize_excel_value(f"* {ins}")
        c.font = _font(color=C_BLK, size=9)
        c.fill = _fill(C_GRY if k % 2 else C_WHT)
        c.alignment = _lft(); c.border = _bdr()
        ws.row_dimensions[r].height = 28


# ”€”€ Sheet 2: Findings ”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€
_NOT_RECORDED = "NOT_RECORDED"


def _excel_decision_state(finding: dict) -> str:
    """decision_state verbatim, or NOT_RECORDED when absent.

    Same rule as reporting/pdf_report.py::_decision_state_display. Kept as its
    own implementation rather than imported so the workbook does not depend on
    ReportLab being importable.
    """
    val = (finding or {}).get("decision_state")
    if isinstance(val, str):
        val = val.strip()
        return val or _NOT_RECORDED
    if val is None:
        return _NOT_RECORDED
    return str(val)


def _excel_reportable(finding: dict) -> str:
    """reportable_finding as YES / NO, or NOT_RECORDED.

    Only a real boolean (or its unambiguous string form) yields a verdict. An
    unparsed value must not become "NO": a CI reader would treat that as
    "reviewed and deliberately withheld".
    """
    val = (finding or {}).get("reportable_finding")
    if isinstance(val, bool):
        return "YES" if val else "NO"
    if isinstance(val, str):
        tok = val.strip().upper()
        if tok in {"TRUE", "YES"}:
            return "YES"
        if tok in {"FALSE", "NO"}:
            return "NO"
    return _NOT_RECORDED


def _excel_evidence_valid(finding: dict) -> str:
    """evidence_valid as VALID / INVALID, or NOT_RECORDED. Same rule as above."""
    val = (finding or {}).get("evidence_valid")
    if isinstance(val, bool):
        verdict = "VALID" if val else "INVALID"
    elif isinstance(val, str):
        tok = val.strip().upper()
        if tok in {"TRUE", "VALID"}:
            verdict = "VALID"
        elif tok in {"FALSE", "INVALID"}:
            verdict = "INVALID"
        else:
            return _NOT_RECORDED
    else:
        return _NOT_RECORDED
    if verdict == "INVALID":
        reason = (finding or {}).get("evidence_reason") or (finding or {}).get("evidence_state")
        if reason:
            verdict = f"INVALID -- {reason}"
    return verdict


def _excel_accuracy_verdict(finding: dict) -> str:
    """accuracy.verdict verbatim, or NOT_RECORDED when absent.

    The verdict token is the JSON token (LIKELY_FALSE_POSITIVE, ...) so a
    reader can grep clean_report.json, the PDF and this sheet for the same
    string. Absence is never rendered as a pass.
    """
    acc = (finding or {}).get("accuracy")
    if isinstance(acc, dict):
        verdict = str(acc.get("verdict") or "").strip()
        if verdict:
            return verdict
    return _NOT_RECORDED


def _display_file(raw) -> str:
    """Relative path for the Findings sheet, matching Technical Evidence.

    Findings used to print only the basename, so two different modules with
    the same file name at the same line rendered as identical rows: the STR
    report's 36 "duplicate" groups are 88 distinct files spread across
    rbi-ie, rbi-import, rbi-export and rbi-interlink. Showing the path is
    what lets a reader locate the finding; it is also what Technical
    Evidence already does with the same field.
    """
    text = str(raw or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def _findings(ws, payload):
    ws.title = "Findings"
    # FIX #3: added Confidence and Score Rationale columns
    # FIX #4: added Affected Files column
    headers = [
        "#", "Rule ID", "Vulnerability Type", "Issue", "Severity", "Priority", "Risk Score",
        "File", "Affected Files", "Line",
        "CWE", "OWASP", "MITRE",
        "PCI DSS", "NIST", "ISO 27001", "SOC2",
        "CVE", "CVSS",
        "Confidence", "Evidence Confidence", "Data Classification", "Detection Source", "Engine Name",
        "Primary Root Cause", "Secondary Chained Risk", "Instances", "Score Rationale", "Fix Summary",
        "Benchmark Disposition", "Evidence Qualification",
        "Decision State", "Reportable", "Evidence Valid",
        "Accuracy Verdict",
    ]
    widths = [
        4,   28,   30,   32,   12,   10,   10,
        58,  58,   6,
        14,  28,   12,
        30,  28,   24,   20,
        18,  8,
        12,  10,   52,   45,
    ]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    _title_row(ws, "DETAILED SECURITY FINDINGS SAST FINDINGS (GROUPED RECORDS) ALL COMPLIANCE FIELDS", len(headers))
    _hdr(ws, 2, headers)
    ws.row_dimensions[2].height = 22
    ws.freeze_panes = "A3"

    for i, f in enumerate(payload.get("grouped", []), start=3):
        sev        = f.get("severity", "Medium")
        confidence = f.get("confidence", "")
        bg         = C_LBLUE if i % 2 == 0 else C_WHT
        rem        = f.get("remediation", [])
        instances  = f.get("instances", 1)

        # FIX #2: the relative path, not the basename -- two modules can hold
        # the same file name at the same line and would look like duplicates.
        primary_file   = _display_file(f.get("file", ""))
        # FIX #4: show all affected files (relative path of each)
        affected_files = f.get("affected_files", [f.get("file", "")])
        affected_str   = "; ".join(_display_file(fp) for fp in affected_files)

        score_explanation = f.get("score_breakdown", {}).get("explanation", "")
        cm = _fallback_compliance(f)
        chains = ", ".join(f.get("chains_to") or []) if isinstance(f.get("chains_to"), list) else (f.get("chains_to") or "")

        row_vals = [
            i - 2,
            f.get("rule_id", ""),
            f.get("vuln_type", ""),
            f.get("title", ""),
            sev,
            f.get("priority", ""),
            f.get("risk_score", ""),
            primary_file,
            affected_str,             # FIX #4
            f.get("line", ""),
            f.get("cwe", ""),
            f.get("owasp", ""),
            f.get("mitre", ""),
            cm.get("pci_dss", "Not Applicable"),
            cm.get("nist", "Not Applicable"),
            cm.get("iso27001", "Not Applicable"),
            cm.get("soc2", "Not Applicable"),
            f.get("cve") or "N/A",
            f.get("cvss") or "N/A",
            confidence,               # FIX #3
            _evidence_confidence(f),
            _classify_data(f),
            _display_detection(f),
            _engine_name(f),
            _root_cause_id(f),
            chains or "--",
            instances,
            score_explanation,        # FIX #3
            rem[0] if rem else "",
            _v17923_benchmark_note(f) or "--",
            f.get("evidence_qualification") or "--",
            # Pipeline disposition. Absence renders as NOT_RECORDED, never as a
            # verdict: a blank or a "No" here would be read as "reviewed and
            # cleared", which is a claim the pipeline never made.
            _excel_decision_state(f),
            _excel_reportable(f),
            _excel_evidence_valid(f),
            # D3: the accuracy layer's verdict, same NOT_RECORDED rule as
            # the other disposition columns -- absence is never a pass.
            _excel_accuracy_verdict(f),
        ]
        for j, val in enumerate(row_vals, 1):
            cell = ws.cell(row=i, column=j, value=_sanitize_excel_value(val))
            cell.border    = _bdr()
            cell.font      = Font(name="Calibri", size=9, color=C_BLK)
            cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            if j == 5:   # Severity
                cell.fill = SEV_FILL.get(sev, _fill(bg))
                cell.font = SEV_FONT.get(sev, _font(color=C_BLK))
                cell.alignment = _ctr()
            elif j == 20:  # Confidence  colour-coded cell
                cell.fill = CONF_FILL.get(confidence, _fill(bg))
                cell.font = CONF_FONT.get(confidence, _font(color=C_BLK))
                cell.alignment = _ctr()
            elif j in {21, 22}:
                cell.fill = _fill("EAF4FB")
                cell.alignment = _ctr()
            else:
                cell.fill = _fill(bg)
        ws.row_dimensions[i].height = 30


# Sheet 3: SBOM 
def _sbom(ws, payload):
    ws.title = "SBOM"
    headers = [
        "Component", "Current Version", "PURL", "Type", "Parent",
        "CVE / Advisory", "CVSS", "EPSS", "KEV", "Reachable Vulnerable",
        "Exploitability Decision", "Patch Urgency", "Severity",
        "Published Date", "Age Days", "Age Bucket", "Fixed Version", "Description",
        "Vulnerability Reference Link", "Additional CVEs",
    ]
    # CVSS widened 8 -> 26 so "CVSS 4.0 — 6.9" and the longer
    # "score unavailable" variants are read in full rather than clipped.
    widths = [28, 16, 48, 12, 18, 30, 26, 8, 8, 18, 24, 16, 12, 18, 12, 20, 24, 70, 58, 28]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    _title_row(ws, "SOFTWARE BILL OF MATERIALS (SBOM) CVE / EPSS / REACHABILITY", len(headers))
    _hdr(ws, 2, headers)
    ws.row_dimensions[2].height = 34
    ws.freeze_panes = "A3"

    # Reader order (sbom_display_sort_key): vulnerable components first by
    # severity Critical -> High -> Medium -> Low, then the rest alphabetically
    # -- the same order the PDF SBOM table uses, so both artifacts page
    # together.  sorted() copies; the payload contract is untouched.
    for i, pkg in enumerate(sorted(payload.get("sbom", []) or [],
                                   key=sbom_display_sort_key), start=3):
        cves = _pkg_cve_list(pkg)
        # Shared predicate with the PDF table: one definition of "has a known
        # vulnerability" wherever an advisory-derived cell is printed.
        has_vulnerability = pkg_has_advisory(pkg)
        # No vulnerability means there is no severity to report, so '--' beside
        # the '--' in the CVE column rather than a placeholder word.  With a
        # vulnerability but no severity recorded, value_state says
        # 'unknown (...)' in words.  The legacy literal-'None' sentinel is
        # filtered inside value_state so already-generated payloads still
        # render correctly -- "None" is a truthy *string*, so a bare `or`
        # fallback cannot catch it.
        sev = value_state.cell(pkg, "severity", has_advisory=has_vulnerability)
        bg = C_LBLUE if i % 2 == 0 else C_WHT
        # Advisory-derived columns dash out on a component with no advisory
        # (the same rule as the PDF table): KEV, exploitability, patch
        # urgency and the age bucket are claims about a vulnerability, and
        # "NOT_APPLICABLE"/"STANDARD"/"No" beside a "--" CVE cell reads as
        # an assessment that was never made.  With an advisory, values render
        # as before, and a genuinely unpublished one still says so in words.
        epss_s = ("--" if not has_vulnerability
                  else _fmt_float(_first_value(pkg, "epss_score", "epss", default="--"), 3))
        pkg_type = pkg.get("dependency_type") or pkg.get("type", "Direct")
        parent = pkg.get("parent") or pkg.get("introduced_by") or "--"

        reachable_vulnerable = (
            "Yes" if _is_reachable_vulnerable(pkg)
            else ("No" if has_vulnerability else "--")
        )

        row_vals = [
            _sbom_component(pkg),
            _sbom_current_version(pkg),
            _sbom_purl(pkg),
            pkg_type,
            parent,
            ", ".join(cves) or (str(pkg.get("advisory_id")) if pkg.get("advisory_id") else "--"),
            _cvss_cell(pkg, has_vulnerability),
            epss_s,
            "--" if not has_vulnerability else ("Yes" if pkg.get("kev_status") else "No"),
            reachable_vulnerable,
            value_state.cell(pkg, "exploitability_decision",
                             has_advisory=has_vulnerability),
            ("--" if not has_vulnerability
             else _first_value(pkg, "patch_urgency", "epss_priority", default="--")),
            sev,
            ("--" if not has_vulnerability
             else _first_value(pkg, "published_date", "published", default="--")),
            ("--" if not has_vulnerability
             else _first_value(pkg, "vulnerability_age_days", default="--")),
            ("--" if not has_vulnerability
             else _first_value(pkg, "vulnerability_age_bucket", default="--")),
            _sbom_fixed_versions(pkg),
            _sbom_description(pkg),
            _sbom_reference_links(pkg),
            ", ".join(pkg.get("additional_cves", []))
            if isinstance(pkg.get("additional_cves"), list) else "--",
        ]

        for j, val in enumerate(row_vals, 1):
            cell = ws.cell(row=i, column=j, value=_sanitize_excel_value(val))
            cell.border = _bdr()
            cell.font = Font(name="Calibri", size=9, color=C_BLK)
            cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

            if j == 13:  # Severity (column M; the old `j == 16` targeted
                # Age Bucket, so severity colours never showed on this sheet)
                cell.fill = SEV_FILL.get(sev, _fill(bg))
                cell.font = SEV_FONT.get(sev, _font(color=C_BLK))
                cell.alignment = _ctr()
            elif j in {9, 10}:  # KEV / Reachable Vulnerable
                cell.fill = _fill("FFE5E5") if val == "Yes" else _fill(bg)
                cell.alignment = _ctr()
            else:
                cell.fill = _fill(bg)

        # Give detailed CVE rows enough room for description/reference links.
        ws.row_dimensions[i].height = 54 if has_vulnerability else 30

    # Legend directly beneath the data: a bare workbook cannot rely on the
    # reader having the PDF open beside it, and the Type/Reachable/dash
    # vocabulary is what the PDF states above its own SBOM table.  Row slot:
    # data ends at 2 + N, this lands at 3 + N, the G-003 note at 4 + N.
    _legend_at = 3 + len(payload.get("sbom", []) or [])
    ws.merge_cells(start_row=_legend_at, start_column=1,
                   end_row=_legend_at, end_column=len(headers))
    _lc = ws.cell(row=_legend_at, column=1, value=_sanitize_excel_value(
        "Legend: Type - Direct = declared in a manifest; Transitive = pulled in "
        "by another dependency. Reachable Vulnerable - Yes = advisory present AND "
        "the offline table marks the package reachable; No = advisory present, "
        "the table does not. Yes/No on a table-sourced row is a curated guess "
        "from that offline table, not observed imports, until a computed "
        "reachability engine replaces it. "
        "-- = no advisory recorded, so severity, age, reachability, KEV, "
        "exploitability and patch urgency do not apply. Rows are ordered: "
        "components with known vulnerabilities first by severity (Critical, High, "
        "Medium, Low), then the remaining components alphabetically."
    ))
    _lc.fill = _fill(C_GRY); _lc.border = _bdr()
    _lc.font = Font(name="Calibri", size=9, italic=True, color=C_BLK)
    _lc.alignment = _lft()
    ws.row_dimensions[_legend_at].height = 30

    # G-003: the SBOM sheet prints EPSS and KEV columns, so it must carry the
    # STATIC_REFERENCE label directly beneath the data.
    _static_intel_note(ws, len(headers), 3 + len(payload.get("sbom", []) or []) + 1,
                     payload=payload)


#Sheet: SCA Findings 
def _sca_findings(ws, payload):
    ws.title = "SCA Findings"
    headers = ["#", "Component", "Current Version", "PURL", "Dependency Type", "Dependency Path", "CVE / Advisory", "CVSS", "EPSS", "KEV", "Reachability", "Exploitability Decision", "Patch Urgency", "Severity", "Fixed Version", "Description", "Vulnerability Reference Link"]
    # CVSS widened 8 -> 26; see the SBOM sheet for why.
    widths = [4, 26, 16, 46, 16, 52, 32, 26, 8, 8, 16, 24, 16, 12, 24, 70, 58]
    for i, w in enumerate(widths, 1): ws.column_dimensions[get_column_letter(i)].width = w
    _title_row(ws, "SCA VULNERABILITY FINDINGS FIRST-CLASS PACKAGE RECORDS", len(headers))
    _hdr(ws, 2, headers); ws.freeze_panes = "A3"
    # Vulnerable-only sheet, same reader order as the PDF SBOM table.
    rows = sorted((p for p in (payload.get("sbom", []) or []) if _pkg_cve_list(p)),
                  key=sbom_display_sort_key)
    for idx, pkg in enumerate(rows, 1):
        cves = _pkg_cve_list(pkg)
        # Vulnerable-only sheet: every row has an advisory, so an
        # unpublished severity names its gap instead of a placeholder word.
        sev = value_state.cell(pkg, "severity", has_advisory=True)
        dep_type = pkg.get("dependency_type") or pkg.get("type", "Direct")
        dep_path = pkg.get("dependency_path") or pkg.get("path") or pkg.get("introduced_by") or "--"
        vals = [idx, _sbom_component(pkg), _sbom_current_version(pkg), _sbom_purl(pkg), dep_type, dep_path,
                ", ".join(cves) or "--", _cvss_cell(pkg, bool(cves)),
                _fmt_float(_first_value(pkg, "epss_score", "epss", default="--"), 3), "Yes" if pkg.get("kev_status") else "No",
                "Yes" if _is_reachable_vulnerable(pkg) else "No",
                value_state.cell(pkg, "exploitability_decision", has_advisory=True),
                _first_value(pkg, "patch_urgency", "epss_priority", default="--"), sev, _sbom_fixed_versions(pkg),
                _sbom_description(pkg), _sbom_reference_links(pkg)]
        bg = C_LBLUE if idx % 2 == 0 else C_WHT
        for j, val in enumerate(vals, 1):
            c = ws.cell(idx + 2, j, _sanitize_excel_value(val)); c.border = _bdr(); c.fill = _fill(bg)
            c.font = Font(name="Calibri", size=9, color=C_BLK); c.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            if j == 14: c.fill = SEV_FILL.get(sev, _fill(bg)); c.font = SEV_FONT.get(sev, _font(color=C_BLK)); c.alignment = _ctr()
            elif j in {10, 11}: c.alignment = _ctr()
        ws.row_dimensions[idx + 2].height = 58
    unique_names = {str(p.get("name") or "").strip() for p in rows if p.get("name")}
    ws.cell(len(rows)+4, 1, "Vulnerable package records"); ws.cell(len(rows)+4, 2, len(rows))
    ws.cell(len(rows)+5, 1, "Unique vulnerable package names"); ws.cell(len(rows)+5, 2, len(unique_names))
    # G-003: SCA Findings prints EPSS and KEV columns too.
    _static_intel_note(ws, len(headers), len(rows) + 7, payload=payload)


def _iac_details(ws, payload):
    ws.title = "IaC Details"
    headers = ["Type", "Rule ID", "Severity", "File", "Line", "Finding", "Evidence", "Remediation"]
    widths = [16, 20, 12, 42, 8, 42, 70, 70]
    for i,w in enumerate(widths,1): ws.column_dimensions[get_column_letter(i)].width=w
    _title_row(ws, "INFRASTRUCTURE / IaC DETAILS KUBERNETES / TERRAFORM / DOCKERFILE", len(headers))
    _hdr(ws, 2, headers); ws.freeze_panes="A3"
    findings=[]
    seen=set()
    for f in list(payload.get("grouped",[]) or []) + list(payload.get("findings",[]) or []):
        rid=str(f.get("rule_id") or "")
        vt=str(f.get("vuln_type") or "")
        if rid.startswith(("K8S_","TF_","DOCKER_")) or vt.startswith(("k8s_","tf_","docker_","iac_")):
            key=(rid,str(f.get("file") or f.get("file_path") or ""),str(f.get("line") or ""),str(f.get("title") or ""))
            if key not in seen:
                seen.add(key)
                findings.append(f)
    if not findings:
        ws.merge_cells(f"A3:{get_column_letter(len(headers))}3")
        ws["A3"]="No Infrastructure / IaC findings were present in the canonical payload."
        ws["A3"].alignment=_lft(); ws["A3"].fill=_fill(C_GRY)
        return
    for r,f in enumerate(findings,3):
        rid=str(f.get("rule_id") or "--")
        typ="Kubernetes" if rid.startswith("K8S_") else "Terraform" if rid.startswith("TF_") else "Dockerfile"
        vals=[typ,rid,f.get("severity",""),f.get("file") or f.get("file_path") or "",
              f.get("line",""),f.get("title") or f.get("description") or "",
              f.get("evidence") or f.get("snippet") or "",
              f.get("remediation") or f.get("recommended_action") or ""]
        bg=C_LBLUE if r%2==0 else C_WHT
        for cidx,val in enumerate(vals,1):
            c=ws.cell(r,cidx,_jsonish(val)); c.border=_bdr(); c.fill=_fill(bg)
            c.font=Font(name="Calibri",size=9,color=C_BLK); c.alignment=_lft()
        ws.row_dimensions[r].height=54


def _licensing_details(ws, payload):
    ws.title = "Licensing Details"
    headers=[
        "Component","Version","Declared License","Resolved License",
        "License Category","Resolution Status","Evidence Source",
        "Evidence","Review Status","Provenance",
        "Policy License","Policy Risk","Policy Issue",
        "Policy Decision","Notice Required","Policy Reason","Policy Method"
    ]
    widths=[28,16,24,24,22,30,20,60,16,42,22,14,28,24,16,60,28]
    for i,w in enumerate(widths,1):
        ws.column_dimensions[get_column_letter(i)].width=w
    _title_row(ws, "LICENSE EVIDENCE / IP POLICY DETAILS", len(headers))
    _hdr(ws,2,headers); ws.freeze_panes="A3"

    summary=payload.get("license_evidence_summary",{}) or {}
    # Ordered by resolved licence, then component (license_sort_key, the same
    # key the PDF licensing table sorts with, so both artifacts list the same
    # rows in the same order).  sorted() copies; the payload stays untouched.
    rows=sorted(payload.get("sbom",[]) or [],key=license_sort_key)
    if not rows:
        ws.merge_cells(f"A3:{get_column_letter(len(headers))}3")
        ws["A3"]="No SBOM components were available for license-evidence reporting."
        ws["A3"].alignment=_lft(); ws["A3"].fill=_fill(C_GRY)
        return

    cats=summary.get("category_counts",{}) or {}
    meta=[
        ("Evidence Resolver",summary.get("resolver","NOT_AVAILABLE")),
        ("Permissive",cats.get("Permissive",0)),
        ("Composite / Review",cats.get("Composite / Review",0)),
        ("Custom / Review",cats.get("Custom / Review",0)),
        ("Evidence Unavailable",cats.get("Evidence Unavailable",0)),
        ("Evidence Review Required",summary.get("review_required_components",0)),
        ("Policy Review Required",summary.get("policy_review_required_components",0)),
        ("Legal Review Required",summary.get("legal_review_required_components",0)),
        ("Unknown License Components",summary.get("unknown_license_components",0)),
    ]
    for idx,(k,v) in enumerate(meta,3):
        ws.cell(idx,1,k).fill=_fill(C_NAVY); ws.cell(idx,1).font=_font(True); ws.cell(idx,1).alignment=_lft()
        ws.cell(idx,2,_jsonish(v)).fill=_fill(C_LBLUE); ws.cell(idx,2).font=Font(name="Calibri",size=9,color=C_BLK); ws.cell(idx,2).alignment=_lft()

    start_row=11
    _hdr(ws,start_row,headers)
    for r,pkg in enumerate(rows,start_row+1):
        provenance=pkg.get("license_provenance") or {}
        provenance_text="; ".join(
            f"{k}={v}" for k,v in provenance.items()
            if v not in (None,"",[],{})
        ) or "--"
        vals=[
            pkg.get("name") or pkg.get("component") or "",
            pkg.get("version") or pkg.get("current_version") or "",
            value_state.cell(pkg, "license_declared", has_advisory=False),
            value_state.cell(pkg, "license_resolved", has_advisory=False),
            value_state.cell(pkg, "license_category", has_advisory=False),
            value_state.cell(pkg, "license_resolution_status", has_advisory=False),
            pkg.get("license_evidence_source") or "--",
            pkg.get("license_evidence") or pkg.get("license_evidence_raw") or "--",
            "Review required" if pkg.get("license_review_required") else "No",
            provenance_text,
            value_state.cell(pkg, "normalized_license", has_advisory=False),
            value_state.cell(pkg, "license_risk", has_advisory=False),
            value_state.cell(pkg, "license_issue", has_advisory=False),
            value_state.cell(pkg, "license_policy_decision", has_advisory=False),
            "Yes" if pkg.get("license_notice_required") else "No",
            pkg.get("license_reason") or "--",
            pkg.get("license_policy_method") or "--",
        ]
        bg=C_LBLUE if r%2==0 else C_WHT
        for cidx,val in enumerate(vals,1):
            c=ws.cell(r,cidx,_jsonish(val)); c.border=_bdr(); c.fill=_fill(bg)
            c.font=Font(name="Calibri",size=9,color=C_BLK); c.alignment=_lft()
        ws.row_dimensions[r].height=42


#Sheet 4: Attack Paths 
from reporting.attack_path_view import (
    attack_path_views as _apv,
    evidence_label as _ap_ev,
    shape_mix as _ap_mix,
)


def _attack_paths(ws, payload):
    ws.title = "Attack Paths"
    headers = [
        "#", "Attack Path", "Severity", "Risk Score",
        "Evidence Status", "Originating Rule", "Entry Point", "Chain", "Impact", "Chains To", "Record Shape",
    ]
    widths = [4, 30, 12, 10, 46, 24, 28, 30, 30, 25, 14]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    _title_row(ws, "ATTACK PATH CORRELATION EXPLOIT CHAINS", len(headers))
    _hdr(ws, 2, headers)
    ws.row_dimensions[2].height = 22
    ws.freeze_panes = "A4"   # rows 1-3: title, header, census

    paths = payload.get("attack_paths", [])
    if not paths:
        ws.merge_cells(f"A3:{get_column_letter(len(headers))}3")
        c = ws["A3"]; c.value = _sanitize_excel_value("No multi-step attack chains detected.")
        c.font = _font(color=C_BLK); c.alignment = _lft()
        return

    _views = _apv(paths)
    _mix = _ap_mix(_views)

    # Census line. Blank Entry Point / Impact cells are how this defect hid:
    # nothing distinguished 'no columns populated' from 'nothing to say'.
    _c = ws.cell(row=3, column=1, value=_sanitize_excel_value(
        f"{_mix['total']} path(s): {_mix['confirmed']} CONFIRMED, "
        f"{_mix['candidate']} CANDIDATE, {_mix['no_evidence_state']} with no "
        f"recorded state; {_mix['by_shape'].get('CURRENT', 0)} current record "
        f"shape, {_mix['by_shape'].get('LEGACY', 0)} legacy."))
    _c.font = Font(name="Calibri", size=9, italic=True, color=C_BLK)
    _c.alignment = _lft()
    ws.merge_cells(start_row=3, start_column=1,
                   end_row=3, end_column=len(headers))

    for i, _v in enumerate(_views, start=4):
        ap = _v
        sev    = _v.get("severity") or "Medium"
        bg     = C_LBLUE if i % 2 == 0 else C_WHT
        steps  = _v.get("chain") or []
        chains = ", ".join(_v.get("chains_to") or [])
        # From `attack_path_status` / `evidence_valid` via the shared view, NOT
        # from a defaulted `evidence_type`. That default read every confirmed
        # path as "PATTERN-ONLY ... Manual validation is required", which
        # understates validated evidence.
        confirmed = bool(_v.get("confirmed"))
        # Absent risk score stays EMPTY: `ap.get('risk_score', 0)` wrote a
        # fabricated 0 that reads as a measurement.
        risk = "" if _v.get("risk_score") is None else _v["risk_score"]
        row_vals = [
            i - 3,
            _v.get("title") or "",
            sev,
            risk,
            _ap_ev(_v),
            _v.get("rule_id") or "",
            _v.get("source") or (steps[0] if len(steps) > 0 else ""),
            " --> ".join(steps[1:-1]) if len(steps) > 2 else "",
            _v.get("sink") or (steps[-1] if len(steps) > 0 else ""),
            chains or "--",
            _v.get("shape") or "",
        ]
        for j, val in enumerate(row_vals, 1):
            cell = ws.cell(row=i, column=j, value=_sanitize_excel_value(val))
            cell.border    = _bdr()
            cell.font      = Font(name="Calibri", size=9, color=C_BLK)
            cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            if j == 3:
                cell.fill = SEV_FILL.get(sev, _fill(bg))
                cell.font = SEV_FONT.get(sev, _font(color=C_BLK))
                cell.alignment = _ctr()
            else:
                cell.fill = _fill(bg)
        ws.row_dimensions[i].height = 28



# ”€”€ Shared intelligence helpers ”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€
LATEST_SUMMARY_KEYS = [
    "sbom_summary", "cbom_summary", "ai_bom_summary", "ml_bom_summary",
    "api_bom_summary", "abom_summary", "iac_summary", "kubernetes_iac_summary",
    "terraform_iac_summary", "dockerfile_iac_summary", "reachability_summary",
    "kev_intelligence_summary", "epss_intelligence_summary",
    "exploitability_decision_summary", "license_policy_summary",
    "copyright_ip_compliance_summary", "supply_chain_trust_summary",
    "runtime_artifact_integrity_summary", "data_flow_sensitivity_summary",
    "data_flow_correlation_summary", "identity_access_risk_summary",
    "identity_access_correlation_summary", "auth_hardening_risk_summary",
    "auth_hardening_correlation_summary", "ai_model_risk_summary",
    "business_logic_risk_summary", "business_logic_correlation_summary",
    "api_abuse_risk_summary", "security_control_coverage_summary",
    "crypto_misuse_summary", "secret_intelligence_summary",
    "secret_blast_radius_correlation_summary", "framework_enrichment_summary",
    "governance_signal_summary", "release_readiness_summary",
    "executive_decision_summary",
]

def _jsonish(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        import json
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value)
    # Excel formula injection guard: evidence/source text must remain literal text.
    text = _sanitize_excel_value(text)
    # Excel formula injection guard: evidence/source text must remain literal text.
    if text[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text

def _latest_summary_items(payload):
    items = []
    meta = payload.get("metadata", {}) or {}
    for key in LATEST_SUMMARY_KEYS:
        value = payload.get(key)
        if value in (None, {}, [], ""):
            value = meta.get(key)
        if value not in (None, {}, [], ""):
            items.append((key, value))
    # Pick up future engines without another report patch.
    for key in sorted(k for k in payload.keys() if k.endswith("_summary") and k not in dict(items)):
        value = payload.get(key)
        if value not in (None, {}, [], ""):
            items.append((key, value))
    return items

def _latest_results(ws, payload):
    ws.title = "Latest Results"
    widths = [34, 26, 90]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    _title_row(ws, "LATEST ENGINE RESULTS SOURCE CODE REVIEW DECISION GRAPH", 3)
    _hdr(ws, 2, ["Engine", "Status / Key Signal", "Full Summary"])
    ws.freeze_panes = "A3"
    r = 3
    for key, value in _latest_summary_items(payload):
        status = ""
        if isinstance(value, dict):
            status = str(value.get("summary_status") or value.get("status") or value.get("decision") or value.get("executive_decision") or value.get("release_decision") or "")
        vals = [key.replace("_summary", "").replace("_", " ").title(), status, _jsonish(value)]
        bg = C_LBLUE if r % 2 == 0 else C_WHT
        for cidx, val in enumerate(vals, 1):
            c = ws.cell(row=r, column=cidx, value=_sanitize_excel_value(val))
            c.border = _bdr(); c.font = Font(name="Calibri", size=9, color=C_BLK)
            c.alignment = _lft(); c.fill = _fill(bg)
        ws.row_dimensions[r].height = 42
        r += 1
    if r == 3:
        ws.merge_cells("A3:C3")
        c = ws["A3"]; c.value = _sanitize_excel_value("No latest engine summary blocks were found in payload.")
        c.font = _font(color=C_BLK); c.alignment = _lft(); c.fill = _fill(C_GRY)


def _executive_kpis(ws, payload):
    ws.title = "Executive KPIs"
    for i, w in enumerate([32, 18, 70], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    _title_row(ws, "EXECUTIVE RISK KPIS BUSINESS AND REGULATORY EXPOSURE", 3)
    _hdr(ws, 2, ["KPI", "Value", "Interpretation"])
    grouped = payload.get("grouped", []) or []
    # taskf T-4.2: the denominator is the canonical SAST population
    # (aggregates.counts.sast_records), never a re-derived len(...).
    total = max(_agg(payload)["counts"]["sast_records"], 1)
    def pct(n): return f"{round((n/total)*100, 1)}%"
    exploitable = sum(1 for f in grouped if str(f.get("exploitability", "")).lower() == "high" or f.get("taint_path"))
    cred = sum(1 for f in grouped if any(x in str(f.get("title","")).lower()+str(f.get("vuln_type","")).lower() for x in ["secret", "credential", "password", "token", "api key"]))
    auth = sum(1 for f in grouped if any(x in str(f.get("title","")).lower()+str(f.get("vuln_type","")).lower() for x in ["auth", "jwt", "idor", "permission", "role"]))
    breach = sum(1 for f in grouped if any(x in str(f.get("business_impact","")).lower()+str(f.get("title","")).lower() for x in ["data breach", "exfiltration", "pii", "sensitive", "database"]))
    privacy, ioc = _supplemental_counts(payload)
    rows = [
        ("Exploitable / High-confidence Risk", pct(exploitable), "Findings with taint validation, high exploitability, or directly exploitable behavior."),
        ("Credential-related Risk", pct(cred), "Secrets, tokens, passwords, API keys, or credential exposure patterns."),
        ("Auth / Access-control Risk", pct(auth), "Authentication, authorization, JWT, IDOR, role, and permission issues."),
        ("Data Breach Capable Risk", pct(breach), "Findings that can plausibly lead to sensitive data disclosure or exfiltration."),
        ("Privacy Indicators", privacy, "Supplemental PII/privacy findings detected by privacy intelligence."),
        ("IOC / Backdoor Indicators", ioc, "Supplemental malicious-behavior or backdoor-like source-code indicators."),
        ("Financial / Operational Exposure", "High" if payload.get("metadata",{}).get("risk_score",0) >= 60 else "Medium", "Based on portfolio risk, critical findings, attack paths, privacy exposure, and IOC indicators."),
        ("Regulatory Exposure", "High" if privacy or cred or breach else "Medium", "Potential exposure to PCI, GDPR/DPDP-style privacy obligations, SOC2, ISO 27001, and NIST controls."),
    ]
    for r, row in enumerate(rows, 3):
        bg = C_LBLUE if r % 2 == 0 else C_WHT
        for cidx, val in enumerate(row, 1):
            c = ws.cell(r, cidx, _sanitize_excel_value(val)); c.border = _bdr(); c.alignment = _lft(); c.font = Font(name="Calibri", size=9, color=C_BLK); c.fill = _fill(bg)
        ws.row_dimensions[r].height = 34

def _release_readiness(ws, payload):
    ws.title = "Release Readiness"
    for i, w in enumerate([28, 30, 80], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    _title_row(ws, "RELEASE READINESS GOVERNANCE DECISION", 3)
    _hdr(ws, 2, ["Decision Area", "Value", "Evidence"])
    meta = payload.get("metadata", {}) or {}
    rel = payload.get("release_readiness_summary", {}) or payload.get("release_readiness", {}) or {}
    exe = payload.get("executive_decision_summary", {}) or payload.get("executive_decision", {}) or {}
    gov = payload.get("governance_signal_summary", {}) or {}
    rows = [
        ("Portfolio Risk Score", meta.get("risk_score", ""), meta.get("risk_score_model", "")),
        ("Release Decision", rel.get("release_decision") or rel.get("decision") or meta.get("release_decision", ""), rel),
        ("Executive Decision", exe.get("executive_decision") or exe.get("decision") or meta.get("executive_decision", ""), exe),
        ("Governance Signals", gov.get("summary_status") or gov.get("status") or "", gov),
        ("Blocking Gates", rel.get("blocking_gates") or rel.get("total_blocking_gates") or "", rel.get("blocking_gate_reasons") or rel.get("gates") or ""),
        ("Review Gates", rel.get("review_gates") or rel.get("total_review_gates") or "", rel.get("review_gate_reasons") or ""),
    ]
    for r, vals in enumerate(rows, 3):
        bg = C_LBLUE if r % 2 == 0 else C_WHT
        for cidx, val in enumerate(vals, 1):
            c = ws.cell(row=r, column=cidx, value=_jsonish(val))
            c.border = _bdr(); c.font = Font(name="Calibri", size=9, color=C_BLK)
            c.alignment = _lft(); c.fill = _fill(bg)

def _technical_evidence(ws, payload):
    ws.title = "Technical Evidence"
    headers = ["#", "Type", "Severity", "File", "Line", "Evidence", "Correlation / Blast Radius", "Detection Source", "Engine Name", "Evidence Confidence", "Data Classification", "Primary Root Cause"]
    widths = [5, 26, 12, 38, 8, 70, 70, 24, 24, 18, 18, 28]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    _title_row(ws, "TECHNICAL EVIDENCE RAW DETECTIONS (PRE-GROUPING)", len(headers))
    _hdr(ws, 2, headers)
    ws.freeze_panes = "A3"
    findings = payload.get("findings") or payload.get("grouped") or []
    for i, f in enumerate(findings, 3):
        sev = f.get("severity", "")
        row = [i-2, f.get("vuln_type") or f.get("rule_id") or f.get("title", ""), sev,
               f.get("file") or f.get("file_path") or "", f.get("line", ""),
               f.get("snippet") or f.get("evidence") or f.get("description") or "",
               f.get("taint_path") or f.get("blast_radius") or f.get("correlation_evidence") or "",
               _display_detection(f), _engine_name(f), _evidence_confidence(f), _classify_data(f), _root_cause_id(f)]
        bg = C_LBLUE if i % 2 == 0 else C_WHT
        for cidx, val in enumerate(row, 1):
            c = ws.cell(row=i, column=cidx, value=_jsonish(val))
            c.border = _bdr(); c.font = Font(name="Calibri", size=9, color=C_BLK)
            c.alignment = _lft(); c.fill = _fill(bg)
            if cidx == 3:
                c.fill = SEV_FILL.get(sev, _fill(bg)); c.font = SEV_FONT.get(sev, _font(color=C_BLK)); c.alignment = _ctr()
        ws.row_dimensions[i].height = 36

# ”€”€ Exploitable CVEs / Advisories ”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€
def _exploitable_cves(ws, payload):
    ws.title = "Exploitable CVEs"
    headers = [
        "#", "Package", "Version", "Dependency Type", "CVE / Advisory", "CVSS", "EPSS",
        "KEV", "Reachable Vulnerable", "Exploitability Decision", "Patch Urgency",
        "Published Date", "Age Days", "Age Bucket", "Fixed In", "Evidence / Reason",
    ]
    # CVSS widened 8 -> 26; see the SBOM sheet for why.
    widths = [4, 24, 14, 16, 30, 26, 8, 8, 18, 24, 16, 18, 18, 12, 20, 18, 52]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    _title_row(ws, "TOP REACHABLE / EXPLOITABLE CVES AND ADVISORIES", len(headers))
    _hdr(ws, 2, headers)
    ws.freeze_panes = "A3"

    rows = []
    for pkg in payload.get("sbom", []) or []:
        cves = _pkg_cve_list(pkg)
        if not cves or not _is_exploitable_dependency(pkg):
            continue
        reasons = []
        if _is_reachable_vulnerable(pkg):
            reasons.append("reachable vulnerable")
        if pkg.get("kev_status"):
            reasons.append("CISA KEV")
        if str(pkg.get("epss_priority") or "").upper() == "P0_IMMEDIATE":
            reasons.append("EPSS P0")
        if str(pkg.get("patch_urgency") or "").upper() == "IMMEDIATE":
            reasons.append("immediate patch")
        rows.append((pkg, reasons))

    # Same reader order as the SBOM sheets: Critical first, then High, then
    # the rest by name (every row here is vulnerable by construction).
    rows.sort(key=lambda _t: sbom_display_sort_key(_t[0]))

    if not rows:
        ws.merge_cells(f"A3:{get_column_letter(len(headers))}3")
        c = ws["A3"]
        c.value = _sanitize_excel_value("No reachable/KEV/EPSS-prioritized exploitable dependency CVEs were identified in this scan. Code-level findings may still be exploitable and are listed in Findings/Attack Paths.")
        c.font = _font(color=C_BLK); c.fill = _fill(C_GRY); c.alignment = _lft(); c.border = _bdr()
        # G-003: the "no KEV/EPSS" statement above is an offline-table miss,
        # not a live-feed miss; say so even when there is nothing to list.
        _static_intel_note(ws, len(headers), 4, payload=payload)
        return

    for r, (pkg, reasons) in enumerate(rows, start=3):
        bg = C_LBLUE if r % 2 == 0 else C_WHT
        vals = [
            r - 2,
            pkg.get("name", ""),
            pkg.get("version", ""),
            pkg.get("dependency_type") or pkg.get("type", ""),
            # No truncation: the cell is labelled "CVE / Advisory" and the
            # reader patches from this list; [:6] dropped the rest silently.
            ", ".join(_pkg_cve_list(pkg)),
            _cvss_cell(pkg),
            _fmt_float(_first_value(pkg, "epss_score", "epss", default="--"), 3),
            "Yes" if pkg.get("kev_status") else "No",
            "Yes" if _is_reachable_vulnerable(pkg) else "No",
            value_state.cell(pkg, "exploitability_decision", has_advisory=True),
            _first_value(pkg, "patch_urgency", "epss_priority", default="--"),
            _first_value(pkg, "published_date", "published", default="--"),
            _first_value(pkg, "vulnerability_age_days", default="--"),
            _first_value(pkg, "vulnerability_age_bucket", default="--"),
            _v17923_fixed_text(pkg),
            "; ".join(reasons) or "dependency vulnerability requires review",
        ]
        for cidx, val in enumerate(vals, 1):
            cell = ws.cell(row=r, column=cidx, value=_jsonish(val) if '_jsonish' in globals() else str(val))
            cell.border = _bdr(); cell.font = Font(name="Calibri", size=9, color=C_BLK)
            cell.alignment = _lft(); cell.fill = _fill(bg)
            if cidx in {8, 9} and val == "Yes":
                cell.fill = _fill("FFE5E5"); cell.alignment = _ctr()
        ws.row_dimensions[r].height = 30

    # G-003: this sheet is the one that asserts "CISA KEV" and "EPSS P0" as
    # reasons, so the STATIC_REFERENCE label is mandatory here.
    _static_intel_note(ws, len(headers), len(rows) + 4, payload=payload)



# ”€”€ Privacy / IOC Intelligence ”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€
def _privacy_findings(ws, payload):
    ws.title = "Privacy Findings"
    _title(ws, "Privacy / PII Exposure Findings")
    summary = payload.get("privacy_data_exposure_summary", {}) or {}
    rows = summary.get("indicators", []) or []
    # Older payloads carry no split; derive it from the rows they do carry.
    # (The summary keeps at most 500 rows, so a stored count wins when present.)
    _pii_rows = sum(1 for i in rows if i.get("pii_types"))
    meta = [
        ("Status", summary.get("summary_status", "NOT_AVAILABLE")),
        ("Total Privacy Indicators", summary.get("total_privacy_indicators", 0)),
        ("PII Data Indicators", summary.get("pii_data_indicators", _pii_rows)),
        ("Context-Only Indicators", summary.get("context_only_indicators", len(rows) - _pii_rows)),
        ("Critical Privacy Indicators", summary.get("critical_privacy_indicators", 0)),
        ("High Privacy Indicators", summary.get("high_privacy_indicators", 0)),
        ("Third-Party Transfer Indicators", summary.get("third_party_transfer_indicators", 0)),
        ("Engine Mode", summary.get("engine_mode", "STATIC_PRIVACY_PATTERN_AND_CONTEXT_ANALYSIS_V1")),
    ]
    r = 3
    for k, v in meta:
        ws.cell(r, 1, _sanitize_excel_value(k)).fill = _fill(C_NAVY); ws.cell(r, 1).font = _font(True); ws.cell(r, 1).alignment = _lft(); ws.cell(r, 1).border = _bdr()
        ws.cell(r, 2, _sanitize_excel_value(_jsonish(v))).fill = _fill(C_LBLUE); ws.cell(r, 2).font = Font(name="Calibri", size=10, color=C_BLK); ws.cell(r, 2).alignment = _lft(); ws.cell(r, 2).border = _bdr()
        r += 1
    r += 1
    headers = ["#", "Risk", "Indicator", "PII Types", "Data Classification", "Evidence Confidence", "File", "Line", "Third Party", "Description", "Evidence", "Recommended Actions", "Frameworks"]
    _hdr(ws, r, headers); r += 1
    if not rows:
        ws.cell(r, 1, _sanitize_excel_value("No privacy / PII exposure indicators identified.")); return
    for idx, item in enumerate(rows, 1):
        bg = C_LBLUE if idx % 2 == 0 else C_WHT
        vals = [
            idx,
            item.get("risk_level") or item.get("severity", ""),
            item.get("indicator", ""),
            ", ".join(item.get("pii_types") or []),
            _classify_data(item),
            _evidence_confidence({**item, "detection": "Privacy Heuristic"}),
            item.get("file", ""),
            item.get("line", ""),
            "Yes" if item.get("third_party_transfer_hint") else "No",
            item.get("description", ""),
            item.get("snippet", ""),
            "\n".join(item.get("recommended_actions") or []),
            _jsonish(item.get("framework_mappings", {})),
        ]
        for c, val in enumerate(vals, 1):
            cell = ws.cell(r, c, _jsonish(val)); cell.border = _bdr(); cell.alignment = _lft(); cell.font = Font(name="Calibri", size=9, color=C_BLK); cell.fill = _fill(bg)
            if c == 2 and str(val).upper() in {"CRITICAL", "HIGH"}:
                cell.fill = _fill(C_RED if str(val).upper() == "CRITICAL" else C_ORG); cell.font = _font(True)
        ws.row_dimensions[r].height = 45
        r += 1
    for col in range(1, len(headers)+1):
        ws.column_dimensions[get_column_letter(col)].width = 22
    ws.column_dimensions['K'].width = 45
    ws.column_dimensions['L'].width = 55


def _ioc_malware_findings(ws, payload):
    ws.title = "IOC Malware"
    _title(ws, "IOC / Backdoor / Malware Heuristic Indicators")
    summary = payload.get("ioc_malware_intelligence_summary", {}) or {}
    rows = summary.get("indicators", []) or []
    meta = [
        ("Status", summary.get("summary_status", "NOT_AVAILABLE")),
        ("Total IOC Indicators", summary.get("total_ioc_indicators", 0)),
        ("Critical IOC Indicators", summary.get("critical_ioc_indicators", 0)),
        ("High IOC Indicators", summary.get("high_ioc_indicators", 0)),
        ("Malware Behavior Indicators", summary.get("malware_behavior_indicators", 0)),
        ("Suspicious Domains Observed", ", ".join(summary.get("suspicious_domains", [])[:20])),
        ("Public IPs Observed", ", ".join(summary.get("public_ips", [])[:20])),
        ("Engine Mode", summary.get("engine_mode", "STATIC_IOC_BACKDOOR_HEURISTIC_ANALYSIS_V1_OFFLINE")),
    ]
    r = 3
    for k, v in meta:
        ws.cell(r, 1, _sanitize_excel_value(k)).fill = _fill(C_NAVY); ws.cell(r, 1).font = _font(True); ws.cell(r, 1).alignment = _lft(); ws.cell(r, 1).border = _bdr()
        ws.cell(r, 2, _sanitize_excel_value(_jsonish(v))).fill = _fill(C_LBLUE); ws.cell(r, 2).font = Font(name="Calibri", size=10, color=C_BLK); ws.cell(r, 2).alignment = _lft(); ws.cell(r, 2).border = _bdr()
        r += 1
    r += 1
    headers = ["#", "Risk", "Indicator", "IOC Type", "IOC Value", "MITRE", "Data Classification", "Evidence Confidence", "File", "Line", "Description", "Evidence", "Recommended Actions", "Confidence"]
    _hdr(ws, r, headers); r += 1
    if not rows:
        ws.cell(r, 1, _sanitize_excel_value("No IOC / backdoor / malware heuristic indicators identified.")); return
    for idx, item in enumerate(rows, 1):
        bg = C_LBLUE if idx % 2 == 0 else C_WHT
        vals = [
            idx,
            item.get("risk_level") or item.get("severity", ""),
            item.get("indicator", ""),
            item.get("ioc_type", ""),
            item.get("ioc_value", ""),
            item.get("mitre_attack", ""),
            _classify_data(item),
            _evidence_confidence({**item, "detection": "IOC Heuristic"}),
            item.get("file", ""),
            item.get("line", ""),
            item.get("description", ""),
            item.get("snippet", ""),
            "\n".join(item.get("recommended_actions") or []),
            item.get("confidence", ""),
        ]
        for c, val in enumerate(vals, 1):
            cell = ws.cell(r, c, _jsonish(val)); cell.border = _bdr(); cell.alignment = _lft(); cell.font = Font(name="Calibri", size=9, color=C_BLK); cell.fill = _fill(bg)
            if c == 2 and str(val).upper() in {"CRITICAL", "HIGH"}:
                cell.fill = _fill(C_RED if str(val).upper() == "CRITICAL" else C_ORG); cell.font = _font(True)
        ws.row_dimensions[r].height = 45
        r += 1
    for col in range(1, len(headers)+1):
        ws.column_dimensions[get_column_letter(col)].width = 22
    ws.column_dimensions['L'].width = 45
    ws.column_dimensions['M'].width = 55

# ”€”€ Public interface ”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€”€
def _sanitize_workbook_values(wb: Workbook) -> int:
    """Sanitize every worksheet string immediately before serialization."""
    changed = 0
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str):
                    clean = _sanitize_excel_value(cell.value)
                    if clean != cell.value:
                        cell.value = clean
                        changed += 1
    return changed


def _intelligence_metadata(ws, payload):
    ws.title = "Vulnerability Intelligence"
    _title_row(ws, "VULNERABILITY INTELLIGENCE PROVENANCE", 2); _hdr(ws, 2, ["Field", "Value"])
    meta = payload.get("metadata", {}) or {}
    fields = {
        "Mode": meta.get("vulnerability_intelligence_mode") or meta.get("intel_mode") or meta.get("cache_mode") or "Not declared",
        "Database Version": meta.get("vulnerability_db_version") or meta.get("intel_db_version") or "Not declared",
        "Database Updated": meta.get("vulnerability_db_updated") or meta.get("intel_db_updated") or "Not declared",
        "Last Verified": meta.get("vulnerability_last_verified") or meta.get("last_verified") or "Not declared",
        "Online Verification During Scan": meta.get("online_verification_during_scan", "Not declared"),
        "Sources": meta.get("vulnerability_sources") or meta.get("intel_sources") or "Not declared",
        "Vulnerability Records": meta.get("vulnerable_advisory_records", meta.get("advisory_count", "Not declared")),
    }
    for r, (k, v) in enumerate(fields.items(), 3):
        ws.cell(r,1,k); ws.cell(r,2,_sanitize_excel_value(v)); ws.cell(r,1).border = ws.cell(r,2).border = _bdr(); ws.cell(r,1).alignment = ws.cell(r,2).alignment = _lft()
    ws.column_dimensions["A"].width = 34; ws.column_dimensions["B"].width = 70


def _repair_report_mojibake(value):
    if not isinstance(value, str):
        return value
    text = value
    for _ in range(2):
        if not any(ch in text for ch in ("ƒÆ’", "ƒ€š", "ƒ¢", "ƒ°", "\ufffd")):
            break
        try:
            candidate = text.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            break
        if candidate == text:
            break
        old_bad = sum(text.count(ch) for ch in ("ƒÆ’", "ƒ€š", "ƒ¢", "ƒ°", "\ufffd"))
        new_bad = sum(candidate.count(ch) for ch in ("ƒÆ’", "ƒ€š", "ƒ¢", "ƒ°", "\ufffd"))
        if new_bad > old_bad:
            break
        text = candidate
    return text

def _normalize_excel_report_path(value, target_root):
    if not isinstance(value, str) or not value or not target_root:
        return value
    import ntpath
    text = value
    root = ntpath.normpath(str(target_root))
    root_name = ntpath.basename(root)
    lower = text.lower()
    root_lower = root.lower()
    prefix = root_lower + "\\"
    prefix2 = root_lower + "/"
    if lower.startswith(prefix) or lower.startswith(prefix2):
        rel = text[len(root)+1:]
        return rel.replace("\\", "/")
    name_prefix = root_name.lower() + "\\"
    name_prefix2 = root_name.lower() + "/"
    if lower.startswith(name_prefix) or lower.startswith(name_prefix2):
        return text[len(root_name)+1:].replace("\\", "/")
    return text

def _sanitize_workbook_values(wb: Workbook) -> int:
    changed = 0
    target_root = ""
    try:
        if "Summary" in wb.sheetnames:
            target_root = str(wb["Summary"]["B3"].value or "")
    except Exception:
        target_root = ""
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if not isinstance(cell.value, str):
                    continue
                old = cell.value
                new = _repair_report_mojibake(old)
                new = _normalize_excel_report_path(new, target_root)
                if new != old:
                    cell.value = new
                    changed += 1
    return changed

def _save_workbook(wb: Workbook, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _sanitize_workbook_values(wb)
    wb.save(str(path))
    return str(path)



def _bom_sheet(ws, payload, key, title):
    ws.title = title
    data = payload.get(key, []) or []
    keys = []
    for item in data:
        if isinstance(item, dict):
            for k in item.keys():
                if k not in keys: keys.append(k)
    if not keys:
        ws.freeze_panes = "A2"
        return
    _title_row(ws, title.upper() + " - INVENTORY", len(keys))
    _hdr(ws, 2, keys)
    ws.freeze_panes = "A3"
    for r, item in enumerate(data, 3):
        for c, k in enumerate(keys, 1):
            cell = ws.cell(row=r, column=c, value=_jsonish(item.get(k, "")))
            cell.font = Font(name="Calibri", size=9, color=C_BLK)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    for c in range(1, len(keys)+1):
        ws.column_dimensions[get_column_letter(c)].width = 24

def _add_advanced_bom_sheets(wb, payload):
    for title,key in [("CBOM","cbom"),("AI-BOM","aibom"),("ML-BOM","mlbom"),("API-BOM","apibom"),("ABOM","abom")]:
        _bom_sheet(wb.create_sheet(title), payload, key, title)


# ---------------------------------------------------------------------------
# PQ QBOM sheet -- post-quantum cryptographic exposure.
#
# Reported SEPARATELY from the CBOM, as required. The two answer different
# questions: the CBOM says which cryptographic primitives are in use, this says
# which of those a cryptographically relevant quantum computer breaks and in what
# order they should be migrated. Folding them together would erase which question
# a given row answers, and the migration queue is the part an engineering team
# actually needs.
#
# Two things this sheet must not do, because both have been defects elsewhere:
#
#   1. Report UNKNOWN as though it were safe. An unclassifiable primitive is
#      counted in its own row and the coverage line says how many there are.
#      "0 assets need migration" is only meaningful beside the number that could
#      not be assessed.
#   2. Hide the aggregation. The corpus has produced a project with 3,111 crypto
#      usage sites resolving to 4 distinct assets. Both numbers are printed, and
#      each row carries its usage count, so the reduction is visible rather than
#      looking like the whole inventory.
# ---------------------------------------------------------------------------


def _qbom_pq(ws, payload):
    ws.title = "PQ QBOM"
    pq = payload.get("qbom_pq") or {}
    summary = pq.get("exposure_summary") or {}
    assets = pq.get("assets") or []

    headers = [
        "Algorithm", "Normalized", "Algorithm Source", "Key Size", "Library",
        "Usage Sites", "Quantum Status", "Quantum Risk", "Migration Priority",
        "Confidence", "Classification Caveat", "Asset ID",
    ]
    widths = [22, 20, 26, 10, 26, 12, 26, 14, 18, 12, 78, 26]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    _title_row(ws, "POST-QUANTUM CRYPTOGRAPHIC EXPOSURE (PQ QBOM)", len(headers))
    _hdr(ws, 2, headers)
    ws.row_dimensions[2].height = 34

    row = 3
    # Coverage first, before the rows, so the reader knows how to read them.
    unclassified = summary.get("unclassified")
    needs = summary.get("needs_migration")
    coverage = [
        ("Crypto usage sites", summary.get("total_usage_sites", "--")),
        ("Distinct cryptographic assets", summary.get("total_assets", "--")),
        ("Classified", summary.get("classified", "--")),
        ("NOT classifiable", unclassified if unclassified is not None else "--"),
        ("Need migration", needs if needs is not None else "--"),
    ]
    for label, value in coverage:
        c1 = ws.cell(row=row, column=1, value=label)
        c1.font = Font(name="Calibri", size=10, bold=True, color=C_BLK)
        c2 = ws.cell(row=row, column=2, value=value)
        c2.font = Font(name="Calibri", size=10, bold=True, color=C_BLK)
        c2.alignment = _ctr()
        row += 1

    if summary.get("aggregation_note"):
        c = ws.cell(row=row, column=1, value=summary["aggregation_note"])
        c.font = Font(name="Calibri", size=9, italic=True, color=C_BLK)
        c.alignment = Alignment(vertical="top", wrap_text=True)
        ws.merge_cells(start_row=row, start_column=1,
                       end_row=row, end_column=len(headers))
        row += 1

    if unclassified:
        c = ws.cell(
            row=row, column=1,
            value=(f"{unclassified} asset(s) could not be classified and are "
                   "reported as UNKNOWN. UNKNOWN is NOT a safe result: it means the "
                   "inventory cannot tell whether the primitive is affected."),
        )
        c.font = Font(name="Calibri", size=9, bold=True, color=C_RED)
        c.alignment = Alignment(vertical="top", wrap_text=True)
        ws.merge_cells(start_row=row, start_column=1,
                       end_row=row, end_column=len(headers))
        row += 1

    row += 1

    for i, a in enumerate(assets, start=row):
        # quantum_status is a classifier OUTPUT: "UNKNOWN" is a real enum
        # answer (the prose above tells the reader so); only a missing
        # field dashes -- value_state keeps that distinction.
        status = value_state.cell(a, "quantum_status")
        bg = C_LBLUE if (i - row) % 2 == 0 else C_WHT
        row_vals = [
            a.get("algorithm"),
            a.get("normalized_algorithm"),
            a.get("algorithm_provenance"),
            a.get("key_size"),
            a.get("library"),
            a.get("occurrence_count"),
            status,
            a.get("quantum_risk"),
            a.get("migration_priority"),
            _fmt_float(a.get("confidence"), 2),
            a.get("classification_note"),
            a.get("qbom_id"),
        ]
        for j, v in enumerate(row_vals, start=1):
            cell = ws.cell(row=i, column=j, value=v)
            cell.fill = _fill(bg)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            cell.font = Font(name="Calibri", size=9, color=C_BLK)
            if j == 7 and status not in {"QUANTUM_IMPACT_ASSESSED", "PQC"}:
                cell.font = Font(name="Calibri", size=9, bold=True, color=C_RED)
        ws.row_dimensions[i].height = 30

    end_row = row + len(assets)
    # Not _static_intel_note: that is the EPSS/KEV provenance label for sheets
    # that print feed-derived scores. This sheet prints no feed data at all, so a
    # provenance caption about feeds would be misleading rather than merely
    # irrelevant.
    note_row = end_row + 1
    ws.merge_cells(start_row=note_row, start_column=1,
                   end_row=note_row, end_column=len(headers))
    c = ws.cell(row=note_row, column=1, value=_sanitize_excel_value(
        "Classified from this scan's own cryptographic inventory by "
        "scanner/crypto_quantum_analyzer. No external vulnerability or quantum "
        "database was consulted. 'Algorithm Source' distinguishes an algorithm the "
        "scanner asserted from one read off a display label; the latter carries a "
        "lower confidence. Absence of an asset here means it was not observed in "
        "source, not that the deployed system does not use it. This sheet answers a "
        "different question from the CBOM sheet: not which cryptography is used, "
        "but which of it a cryptographically relevant quantum computer breaks."
    ))
    c.font = Font(name="Calibri", size=8, italic=True, color=C_BLK)
    c.alignment = Alignment(vertical="top", wrap_text=True)

# ---------------------------------------------------------------------------
# NIST AI 100-2e2025 and NIST SSDF (SP 800-218) sheets.
#
# Both are added to all three workbooks. The executive workbook gets the same
# sheets as the technical one on purpose: an executive who is shown a ratio
# without the gap list will quote the ratio, so the denominator and the
# detection gaps travel with every number.
# ---------------------------------------------------------------------------


def _nistaml_sheet(ws, payload):
    """Per-attack-class NIST AI 100-2e2025 attribution, plus detection gaps."""
    ws.title = "NIST AML Mapping"
    headers = [
        "Attack Class", "Name", "Adversarial Objective", "Mapping Mode", "Findings",
        "Rules", "Related Classes", "Observed In This Scan", "Gap / Note",
    ]
    widths = [14, 26, 26, 16, 10, 34, 22, 22, 62]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    try:
        from core.nist_aml_mappings import (
            NISTAML_ATTACKS, NISTAML_DATASET_LABEL, NISTAML_DETECTION_GAPS,
            NISTAML_OBJECTIVES,
        )
    except Exception:
        NISTAML_ATTACKS, NISTAML_OBJECTIVES = {}, {}
        NISTAML_DETECTION_GAPS = {}
        NISTAML_DATASET_LABEL = "NIST AI 100-2e2025"

    # Aggregate the per-finding attribution the AI scanners stamp on.
    seen = {}
    contributing = 0
    unmapped = 0
    for f in (payload.get("findings") or []):
        if not isinstance(f, dict) or "nistaml_mapping_mode" not in f:
            continue
        contributing += 1
        mode = str(f.get("nistaml_mapping_mode") or "").strip()
        aid = str(f.get("nistaml_id") or "").strip()
        if mode == "UNMAPPED" or not aid:
            unmapped += 1
            continue
        rec = seen.setdefault(aid, {"findings": 0, "modes": set(), "rules": set(), "related": set()})
        rec["findings"] += 1
        rec["modes"].add(mode)
        rid = str(f.get("rule_id") or "").strip()
        if rid:
            rec["rules"].add(rid)
        for rel in (f.get("nistaml_related") or []):
            rec["related"].add(str(rel))

    catalogue = len(NISTAML_ATTACKS)
    _title_row(ws, f"NIST AI 100-2e2025 ADVERSARIAL ML ATTACK-CLASS MAPPING ({NISTAML_DATASET_LABEL})", len(headers))
    _hdr(ws, 2, headers)
    ws.freeze_panes = "A3"

    row = 3
    sast_records = _agg(payload)["counts"]["sast_records"]
    for aid in sorted(NISTAML_ATTACKS):
        spec = NISTAML_ATTACKS[aid] or {}
        rec = seen.get(aid)
        gap = NISTAML_DETECTION_GAPS.get(aid)
        note = gap if isinstance(gap, str) else ((gap or {}).get("gap") if isinstance(gap, dict) else "")
        row_vals = [
            aid, spec.get("name") or "",
            f"{spec.get('objective') or ''} {NISTAML_OBJECTIVES.get(spec.get('objective') or '', '')}".strip(),
            ", ".join(sorted(rec["modes"])) if rec else "--",
            rec["findings"] if rec else 0,
            ", ".join(sorted(rec["rules"])) if rec else "--",
            ", ".join(sorted(rec["related"])) if rec else "--",
            "YES" if rec else "NO",
            note or ("Attributed in this scan" if rec else
                    "Catalogue entry with no rule and no observed finding; not a finding."),
        ]
        bg = C_LBLUE if row % 2 == 0 else C_WHT
        for cidx, val in enumerate(row_vals, 1):
            c = ws.cell(row=row, column=cidx, value=_jsonish(val))
            c.border = _bdr()
            c.font = Font(name="Calibri", size=9, color=C_BLK)
            c.alignment = _lft()
            c.fill = _fill(bg)
            if cidx == 8:
                c.font = _font(bold=(rec is not None), color=C_BLK)
                c.alignment = _ctr()
        ws.row_dimensions[row].height = 30
        row += 1

    # Header note block, so the ratio is never quoted without its denominator.
    row += 1
    observed = len(seen)
    ratio = (observed / catalogue) if catalogue else 0.0
    notes = [
        f"Catalogue attack classes: {catalogue}",
        f"Attack classes attributed in this scan: {observed} (ratio {ratio:.3f})",
        f"Findings carrying an attribution decision: {contributing} of {sast_records} SAST findings in this report",
        f"  ...of which resolved UNMAPPED: {unmapped}",
        f"Recorded detection gaps (no rule in this release): {len(NISTAML_DETECTION_GAPS)} -- see gap_register.json (G-088), copied alongside this report",
        "Attribution is per-finding evidence metadata, not a detection claim and not an attestation.",
        "A catalogue entry marked 'NO' is an unimplemented detection, NOT a finding in this codebase.",
    ]
    if contributing == 0:
        notes.insert(0,
                     "No finding in this report carries NIST AML attribution: this corpus produced "
                     "no AI/LLM findings. Every row below is reference scope, not an observation.")
    for note in notes:
        c = ws.cell(row=row, column=1, value=_jsonish(note))
        c.font = Font(name="Calibri", size=9, bold=note.startswith("Catalogue"),
                      color=C_BLK)
        c.alignment = _lft()
        row += 1
    return ws


def _ssdf_sheet(ws, payload):
    """Per-practice NIST SSDF evidence alignment."""
    ws.title = "SSDF Alignment"
    headers = [
        "Practice", "Group", "Group Name", "Status", "Evidence Path",
        "Evidence Detail", "All Paths Resolved", "Rationale",
    ]
    widths = [42, 8, 30, 30, 46, 16, 16, 78]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    _title_row(ws, "NIST SSDF (SP 800-218 v1.1) EVIDENCE ALIGNMENT", len(headers))
    _hdr(ws, 2, headers)
    ws.freeze_panes = "A3"

    align = payload.get("ssdf_alignment") or {}
    row = 3

    if not isinstance(align, dict) or not align:
        c = ws.cell(row=row, column=1, value=(
            "No SSDF alignment was produced for this report. The alignment is evaluated "
            "immediately before the report is serialized; its absence means it was not "
            "evaluated or the evaluation failed. It must NOT be read as zero practices met."))
        c.font = Font(name="Calibri", size=9, bold=True, color=C_BLK)
        c.alignment = _lft()
        return ws

    if align.get("status") == "REVIEW_REQUIRED":
        c = ws.cell(row=row, column=1, value=(
            f"SSDF alignment could not be evaluated: {align.get('error')}. "
            "No practice status is claimed."))
        c.font = Font(name="Calibri", size=9, bold=True, color=C_BLK)
        c.alignment = _lft()
        return ws

    practices = align.get("practices") or []
    for p in practices:
        ev = [e for e in (p.get("evidence") or []) if isinstance(e, dict)]
        row_vals = [
            p.get("practice") or p.get("practice_id") or "",
            p.get("group") or "", p.get("group_name") or "",
            p.get("status") or "",
            "; ".join(str(e.get("path")) for e in ev) or "-- (no probe declared)",
            "; ".join(str(e.get("detail")) for e in ev) or "--",
            (all(bool(e.get("resolved")) for e in ev) if ev else "--"),
            p.get("rationale") or "",
        ]
        bg = C_LBLUE if row % 2 == 0 else C_WHT
        for cidx, val in enumerate(row_vals, 1):
            c = ws.cell(row=row, column=cidx, value=_jsonish(val))
            c.border = _bdr()
            c.font = Font(name="Calibri", size=9, color=C_BLK)
            c.alignment = _lft()
            c.fill = _fill(bg)
            if cidx == 4:
                c.font = _font(bold=True, color=C_BLK)
                c.alignment = _ctr()
        ws.row_dimensions[row].height = 30
        row += 1

    row += 1
    notes = [
        f"Dataset: {align.get('dataset')}",
        f"Observed: {align.get('observed', 0)} of {align.get('total_practices', 0)} practices"
        + (f" ({', '.join(align.get('observed_ids') or [])})" if align.get("observed_ids") else ""),
        f"Not observed: {align.get('not_observed', 0)}",
        f"Not attestable by a scanner: {align.get('not_attestable', 0)}",
        "Not attestable is the largest bucket by design. Those practices concern "
        "organisation, process and release governance; a source-code scan cannot attest "
        "them in either direction, so they are neither passes nor failures.",
        "No practice identifier is attached to any finding. SSDF is a process framework; "
        "asserting practice compliance from a static finding would convert absence into assurance.",
        f"Scope: {align.get('scope_note')}",
    ]
    for note in notes:
        c = ws.cell(row=row, column=1, value=_jsonish(note))
        c.font = Font(name="Calibri", size=9, bold=note.startswith("Dataset"), color=C_BLK)
        c.alignment = _lft()
        row += 1
    return ws


def _asvs_sheet(ws, payload):
    """OWASP ASVS v4.0.3 requirement-level reachability, with its limits.

    The header block states the semantics before any number, because the
    failure mode for this framework is a mapped requirement being read as an
    unmet one and a reachability ratio being read as a compliance score.
    """
    ws.title = "ASVS Mapping"
    headers = [
        "Requirement (version-qualified)", "Chapter", "Section", "Section Name",
        "Reached By This Scan", "ASVS CWE Cross-References",
        "Verification Levels (verbatim)", "Evidence Class",
    ]
    widths = [30, 10, 10, 42, 20, 26, 52, 28]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    try:
        from core.asvs_mappings import (
            ASVS_CHAPTERS, ASVS_CSV_SHA256, ASVS_DATASET_LABEL, ASVS_LICENSE,
            ASVS_REQUIREMENTS, ASVS_SECTIONS, ASVS_SOURCE_URL,
            UNMAPPED_RATIONALE, asvs_catalogue_cwe_coverage, evidence_class,
        )
    except Exception:
        ASVS_CHAPTERS, ASVS_REQUIREMENTS, ASVS_SECTIONS = {}, {}, {}
        ASVS_CSV_SHA256, ASVS_DATASET_LABEL, ASVS_LICENSE = "", "OWASP ASVS v4.0.3", ""
        ASVS_SOURCE_URL, UNMAPPED_RATIONALE = "", ""
        asvs_catalogue_cwe_coverage = lambda: {"total": 0, "with_cwe_edge": 0,
                                               "without_cwe_edge": 0}
        evidence_class = lambda rid: ""

    _title_row(ws, "OWASP ASVS v4.0.3 REQUIREMENT-LEVEL MAPPING", len(headers))
    _hdr(ws, 2, headers)
    ws.freeze_panes = "A3"

    summary = payload.get("asvs_summary") or {}
    if not isinstance(summary, dict) or not summary:
        c = ws.cell(row=3, column=1, value=(
            "No ASVS requirement-level mapping was produced for this report. "
            "ASVS requirements are verification statements established by testing an "
            "application; no requirement status is claimed."))
        c.font = Font(name="Calibri", size=9, bold=True, color=C_BLK)
        c.alignment = _lft()
        return ws

    if summary.get("status") == "REVIEW_REQUIRED":
        c = ws.cell(row=3, column=1, value=(
            f"ASVS mapping could not be produced: {summary.get('error')}. "
            "No requirement status is claimed."))
        c.font = Font(name="Calibri", size=9, bold=True, color=C_BLK)
        c.alignment = _lft()
        return ws

    reachable = set(summary.get("requirements_reachable") or [])
    bare_reachable = {r.split("ASVS-v4.0.3-")[-1] for r in reachable}

    row = 3
    for rid in sorted(ASVS_REQUIREMENTS, key=lambda x: tuple(
            int(p) for p in x.lstrip("V").split("."))):
        spec = ASVS_REQUIREMENTS[rid]
        bg = C_LBLUE if row % 2 == 0 else C_WHT
        row_vals = [
            "ASVS-v4.0.3-" + rid,
            spec.get("chapter") or "",
            spec.get("section") or "",
            ASVS_SECTIONS.get(spec.get("section") or "", ""),
            "YES" if rid in bare_reachable else "NO",
            ", ".join(spec.get("cwe") or []) or "-- (ASVS cites none)",
            ", ".join(f"L{i}={spec.get(f'level{i}')}"
                      for i in (1, 2, 3) if spec.get(f"level{i}")),
            evidence_class(rid),
        ]
        for cidx, val in enumerate(row_vals, 1):
            c = ws.cell(row=row, column=cidx, value=_jsonish(val))
            c.border = _bdr()
            c.font = Font(name="Calibri", size=9, color=C_BLK)
            c.alignment = _lft()
            c.fill = _fill(bg)
            if cidx == 5:
                c.font = _font(bold=(rid in bare_reachable), color=C_BLK)
                c.alignment = _ctr()
        ws.row_dimensions[row].height = 26
        row += 1

    row += 1
    combined = summary.get("combined") or {}
    # by_mode lives on the cwe / vuln_type families, not on `combined`.
    by_mode = dict((summary.get("cwe") or {}).get("by_mode") or {})
    for mode, count in ((summary.get("vuln_type") or {}).get("by_mode") or {}).items():
        by_mode[mode] = by_mode.get(mode, 0) + count
    cov = asvs_catalogue_cwe_coverage()
    unreferenced = summary.get("unreferenced_cwe") or {}

    notes = [
        f"Dataset: {summary.get('dataset') or ASVS_DATASET_LABEL} ({ASVS_LICENSE})",
        f"Enumeration SHA-256: {ASVS_CSV_SHA256}",
        f"Source: {ASVS_SOURCE_URL}",
        "",
        "SEMANTICS -- read before using any number on this sheet:",
        "  A requirement marked YES is REACHED BY THIS SCAN, i.e. some finding is "
        "evidence relevant to it. It is NOT an unmet requirement and NOT an ASVS "
        "compliance statement.",
        "  A requirement marked NO is NOT EVIDENCED AS MET. Most ASVS requirements "
        "are verification activities, architecture statements or process controls "
        "that no source-code scan can decide in either direction.",
        "  ASVS requirement ids change between versions, so every id here is "
        "version-qualified (ASVS-v4.0.3-Vx.y.z) per OWASP's own guidance.",
        "",
        f"Catalogue: {summary.get('catalogue_size')} live requirements, "
        f"{summary.get('tombstones_excluded')} ASVS [DELETED] tombstones excluded.",
        f"Requirements reached by this artifact: "
        f"{summary.get('requirements_reachable_count')} of {summary.get('catalogue_size')} "
        f"(ratio {(summary.get('requirements_reachable_count') or 0) / (summary.get('catalogue_size') or 1):.3f}) "
        "-- this is reachability, NOT compliance.",
        f"Findings mapped: {summary.get('findings_mapped')} | "
        f"findings resolved UNMAPPED: {summary.get('findings_unmapped')}",
        f"Resolution modes: {_jsonish(by_mode)}",
        f"ASVS publishes a CWE cross-reference for {cov['with_cwe_edge']} of "
        f"{cov['total']} requirements; {cov['without_cwe_edge']} carry none and are "
        "unreachable through the CWE path by construction.",
    ]
    if unreferenced:
        notes.append(
            f"Observed weakness classes ASVS does not cite anywhere "
            f"({len(unreferenced)}, declared limits not suppressed findings): "
            + ", ".join(sorted(unreferenced)))
    notes.append("")
    notes.append("UNMAPPED rationale: " + UNMAPPED_RATIONALE)

    for note in notes:
        c = ws.cell(row=row, column=1, value=_jsonish(note))
        bold = note.startswith(("SEMANTICS", "Dataset", "Catalogue"))
        c.font = Font(name="Calibri", size=9, bold=bold, color=C_BLK)
        c.alignment = _lft()
        row += 1
    return ws


def generate_excel_report(payload: dict, output_path: str) -> str:
    """Combined workbook: executive + technical sheets using existing theme."""
    wb = Workbook()
    wb.remove(wb.active)
    _summary(wb.create_sheet("Summary"),          payload)
    _executive_kpis(wb.create_sheet("Executive KPIs"), payload)
    _release_readiness(wb.create_sheet("Release Readiness"), payload)
    _latest_results(wb.create_sheet("Latest Results"), payload)
    _findings(wb.create_sheet("Findings"),         payload)
    _technical_evidence(wb.create_sheet("Technical Evidence"), payload)
    _asvs_sheet(wb.create_sheet("ASVS Mapping"), payload)
    _nistaml_sheet(wb.create_sheet("NIST AML Mapping"), payload)
    _ssdf_sheet(wb.create_sheet("SSDF Alignment"), payload)
    _exploitable_cves(wb.create_sheet("Exploitable CVEs"), payload)
    _privacy_findings(wb.create_sheet("Privacy Findings"), payload)
    _ioc_malware_findings(wb.create_sheet("IOC Malware"), payload)
    _sbom(wb.create_sheet("SBOM"),                 payload)
    _attack_paths(wb.create_sheet("Attack Paths"), payload)
    _iac_details(wb.create_sheet("IaC Details"), payload)
    _licensing_details(wb.create_sheet("Licensing Details"), payload)
    _add_advanced_bom_sheets(wb, payload)
    _qbom_pq(wb.create_sheet("PQ QBOM"), payload)
    return _save_workbook(wb, output_path)


def generate_executive_excel_report(payload: dict, output_path: str) -> str:
    """Executive workbook with decision, release, and latest engine summaries."""
    wb = Workbook()
    wb.remove(wb.active)
    _summary(wb.create_sheet("Summary"), payload)
    _executive_kpis(wb.create_sheet("Executive KPIs"), payload)
    _release_readiness(wb.create_sheet("Release Readiness"), payload)
    _latest_results(wb.create_sheet("Latest Results"), payload)
    _asvs_sheet(wb.create_sheet("ASVS Mapping"), payload)
    _nistaml_sheet(wb.create_sheet("NIST AML Mapping"), payload)
    _ssdf_sheet(wb.create_sheet("SSDF Alignment"), payload)
    _exploitable_cves(wb.create_sheet("Exploitable CVEs"), payload)
    _privacy_findings(wb.create_sheet("Privacy Findings"), payload)
    _ioc_malware_findings(wb.create_sheet("IOC Malware"), payload)
    _attack_paths(wb.create_sheet("Attack Paths"), payload)
    _iac_details(wb.create_sheet("IaC Details"), payload)
    _licensing_details(wb.create_sheet("Licensing Details"), payload)
    # PQ QBOM is present here even though the other BOM layers are not. The
    # executive workbook is a curated view, and post-quantum exposure is a
    # migration programme with a cost and a horizon, not a detail sheet -- an
    # executive who is not shown that a Shor-broken primitive is in use cannot
    # fund the migration. The sheet is coverage-first, so it reads as a summary
    # rather than as an inventory dump.
    _qbom_pq(wb.create_sheet("PQ QBOM"), payload)
    return _save_workbook(wb, output_path)


def generate_technical_excel_report(payload: dict, output_path: str) -> str:
    """Technical workbook for engineers and security analysts."""
    wb = Workbook()
    wb.remove(wb.active)
    _findings(wb.create_sheet("Findings"), payload)
    _technical_evidence(wb.create_sheet("Technical Evidence"), payload)
    _asvs_sheet(wb.create_sheet("ASVS Mapping"), payload)
    _nistaml_sheet(wb.create_sheet("NIST AML Mapping"), payload)
    _ssdf_sheet(wb.create_sheet("SSDF Alignment"), payload)
    _exploitable_cves(wb.create_sheet("Exploitable CVEs"), payload)
    _privacy_findings(wb.create_sheet("Privacy Findings"), payload)
    _ioc_malware_findings(wb.create_sheet("IOC Malware"), payload)
    _sbom(wb.create_sheet("SBOM"), payload)
    _latest_results(wb.create_sheet("Latest Results"), payload)
    _attack_paths(wb.create_sheet("Attack Paths"), payload)
    _iac_details(wb.create_sheet("IaC Details"), payload)
    _licensing_details(wb.create_sheet("Licensing Details"), payload)
    _add_advanced_bom_sheets(wb, payload)
    _qbom_pq(wb.create_sheet("PQ QBOM"), payload)
    return _save_workbook(wb, output_path)


# Backward-compatible aliases
write_excel_report = generate_excel_report

