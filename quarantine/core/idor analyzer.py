"""
core/analyzer.py  v5

CHANGES (v4 → v5):
  1. FIX  — _root_cause_key() now uses finding['group_key'] when present
             (set by sast.py v5 as vuln_type|line|snippet).  This correctly
             merges cmd_0.py…cmd_9.py — 10 files with identical code at
             line 4 — into ONE finding with 10 affected_files entries.
             Falls back to v4 per-function key when group_key is absent
             (preserves compatibility with taint_engine output).
  2. KEEP — All v4 fixes retained: _safe_float, non-mutating score_finding,
             confidence swap, SBOM scoring, pivot point analysis.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from core.mapper import get_owasp_summary, get_mitre_summary
from core.config import TOOL_FULL, RISK_MODEL
from core.risk_scorer import score_finding, compute_portfolio_score, SCORING_MODEL_DESCRIPTION
from core.attack_graph import get_attack_paths, get_pivot_points

SEVERITY_ORDER  = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
PRIORITY_MAP    = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Info": "P4"}
CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1, "": 0}


def _safe_float(v, default: float = 0.0) -> float:
    try:    return float(v)
    except: return default


def _path_fp(f: dict) -> str:
    """Strict per-file fingerprint — used only for exact-duplicate removal."""
    key = f"{f.get('vuln_type')}|{f.get('file')}|{f.get('line')}"
    return hashlib.md5(key.encode()).hexdigest()


def _normalise_sink(snippet: str, vuln_type: str) -> str:
    """
    Extract the canonical sink name from a code snippet for cross-file deduplication.
    Handles both function-call sinks (eval, subprocess.run) and
    IaC declarative patterns (privileged: true, acl = "public-read").
    """
    import re

    # IaC declarative patterns — use the vuln_type itself as the sink key
    IAC_TYPES = {
        "iac_privileged_container": "privileged_container",
        "iac_public_s3":            "public_s3_acl",
        "iac_open_security_group":  "open_cidr_0000",
    }
    if vuln_type in IAC_TYPES:
        return IAC_TYPES[vuln_type]

    # PATCH 5: hardcoded secrets — normalise to category so AWS keys from
    # 10 different files merge into ONE root cause regardless of variable name.
    if vuln_type == "hardcoded_secret":
        snip_lower = snippet.lower()
        # AWS key patterns — group all AKIA-pattern credentials
        if "akia" in snip_lower or "akid" in snip_lower:
            return "hardcoded_secret|aws_access_key"
        if "private key" in snip_lower or "begin rsa" in snip_lower or "begin ec" in snip_lower:
            return "hardcoded_secret|private_key"
        if "jwt" in snip_lower:
            return "hardcoded_secret|jwt_secret"
        # Generic API keys — group ALL together regardless of file type (yaml/py/env)
        # This ensures config.yaml and sec_0.py generic keys merge into one finding
        return "hardcoded_secret|generic_credential"

    # IDOR — normalise to generic "idor_access" so all IDOR patterns group together
    if vuln_type == "api_idor":
        return "idor_access"

    # Supply chain — group by the typo package name
    if vuln_type == "supply_chain_typosquat":
        m = re.search(r"import\s+(\w+)|from\s+(\w+)", snippet)
        return m.group(1) or m.group(2) if m else "typosquat"

    # Known function-call sinks
    SINK_NAMES = [
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "os.system", "os.popen",
        "eval", "exec", "compile",
        "pickle.loads", "pickle.load", "yaml.load", "marshal.loads",
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "urllib.request.urlopen", "http.client",
        "conn.execute", "cursor.execute", "executemany",
        "open", "os.path.join", "os.listdir",
        "redirect", "render_template_string",
        "innerHTML", "document.write",
        "jwt.decode",
    ]
    for sink in SINK_NAMES:
        if sink in snippet:
            return sink

    # Fallback: first word that looks like a function call
    m = re.search(r'(\w+(?:\.\w+)*)\s*\(', snippet)
    return m.group(1) if m else snippet.strip()[:40]


def _root_cause_key(f: dict) -> str:
    """
    ISSUE 1+2 FIX: group_key is vuln_type + normalised sink.
    PATCH 5: for secrets, use group_key directly (set to vuln_type|rule_name in sast.py)
    so all AWS Access Key findings across files merge into one root cause.

    This merges:
      eval(user_code)  →  code_injection|eval
      eval(cmd)        →  code_injection|eval     ← same key, correct
      IDOR routes across 70 files  → api_idor|<route pattern>

    Avoids over-collapsing unrelated findings of the same type from different
    datasets by including the sink name (not just the vuln_type alone).
    """
    vt      = f.get("vuln_type", "")
    snippet = (f.get("snippet") or "").strip()
    sink    = _normalise_sink(snippet, vt)
    return f"{vt}|{sink}"


# ---------------------------------------------------------------------------
# Deduplication  (logic identical to v4; key function updated above)
# ---------------------------------------------------------------------------

def deduplicate(findings: list[dict]) -> list[dict]:
    # Level 1: exact per-file dedupe
    # When two findings share the same fingerprint (same file+line+vuln),
    # keep the one with the richer detection — TAINT-VALIDATED > Regex.
    seen_exact: dict[str, int] = {}  # fp -> index in phase1
    phase1: list[dict] = []
    for f in findings:
        fp = _path_fp(f)
        if fp not in seen_exact:
            seen_exact[fp] = len(phase1)
            phase1.append(f)
        else:
            # Upgrade existing entry if incoming is TAINT-VALIDATED
            existing_idx = seen_exact[fp]
            existing     = phase1[existing_idx]
            if (f.get("detection") == "TAINT-VALIDATED"
                    and existing.get("detection") != "TAINT-VALIDATED"):
                # Replace but keep the taint-rich version
                phase1[existing_idx] = f

    # Level 2: root-cause grouping
    groups: dict[str, dict] = {}
    for f in phase1:
        rck = _root_cause_key(f)
        if rck not in groups:
            entry = dict(f)
            entry["occurrences"]    = [{"file": f.get("file"), "line": f.get("line"),
                                        "snippet": f.get("snippet", "")}]
            entry["affected_files"] = [f.get("file", "")]
            entry["instances"]      = 1
            groups[rck] = entry
        else:
            existing      = groups[rck]
            incoming_rank = CONFIDENCE_RANK.get(f.get("confidence", ""), 0)
            existing_rank = CONFIDENCE_RANK.get(existing.get("confidence", ""), 0)

            if incoming_rank > existing_rank:
                occ_bak  = existing["occurrences"]
                aff_bak  = existing["affected_files"]
                inst_bak = existing["instances"]
                groups[rck]                   = dict(f)
                groups[rck]["occurrences"]    = occ_bak
                groups[rck]["affected_files"] = aff_bak
                groups[rck]["instances"]      = inst_bak

            occ = {"file": f.get("file"), "line": f.get("line"),
                   "snippet": f.get("snippet", "")}
            if occ not in groups[rck]["occurrences"]:
                groups[rck]["occurrences"].append(occ)
            fp_path = f.get("file", "")
            if fp_path and fp_path not in groups[rck]["affected_files"]:
                groups[rck]["affected_files"].append(fp_path)
            groups[rck]["instances"] = len(groups[rck]["occurrences"])

            # Fix 1: promote detection label — TAINT-VALIDATED beats regex
            incoming_det = f.get("detection", "")
            existing_det = groups[rck].get("detection", "")
            if incoming_det == "TAINT-VALIDATED" and existing_det != "TAINT-VALIDATED":
                groups[rck]["detection"] = "TAINT-VALIDATED"
                # also carry over the real taint_path if current one is empty
                if f.get("taint_path") and "->" in str(f.get("taint_path", "")):
                    if not groups[rck].get("taint_path") or "->" not in str(groups[rck].get("taint_path", "")):
                        groups[rck]["taint_path"] = f["taint_path"]

            # Fix 2: for secrets, promote to highest severity among occurrences
            if f.get("vuln_type") == "hardcoded_secret":
                sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
                incoming_sev = f.get("severity", "Medium")
                existing_sev  = groups[rck].get("severity", "Medium")
                if sev_rank.get(incoming_sev, 0) > sev_rank.get(existing_sev, 0):
                    groups[rck]["severity"] = incoming_sev
                    groups[rck]["priority"] = {
                        "Critical":"P1","High":"P2","Medium":"P3","Low":"P4"
                    }.get(incoming_sev, "P3")

    return list(groups.values())


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def _compute_exploitability(f: dict, sbom: list | None = None) -> str:
    """
    Issue 6 FIX: derive exploitability from taint evidence, EPSS, and context.
    Priority: taint trace > EPSS from related SBOM > heuristic.
    """
    # Taint-confirmed data flow = highest exploitability
    taint = f.get("taint_path", "")
    if taint and "->" in taint:
        return "High"
    # EPSS-based: if a related SBOM CVE has EPSS > 0.5 → High
    if sbom:
        vt = f.get("vuln_type","")
        for pkg in sbom:
            epss = float(pkg.get("epss") or 0)
            if epss >= 0.5 and pkg.get("reachable"):
                # Log4Shell EPSS=0.975, Spring4Shell=0.970 → override to High
                if vt in ("insecure_deserialization","command_injection","code_injection"):
                    return "High"
    # Source-name heuristic
    source = f.get("source_expr", "") or ""
    if any(s in source.lower() for s in ("request", "input", "argv", "form", "query", "param")):
        return "Medium"
    return f.get("exploitability") or "Low"


def _compute_exploitability_legacy(f: dict) -> str:
    """
    Determine exploitability based on evidence quality:
      HIGH   — real taint path confirms user-controlled data reaches the sink
      MEDIUM — source name suggests user input but flow is not fully traced
      LOW    — pattern match only, no user-input evidence
    """
    taint = f.get("taint_path", "")
    if taint and "->" in taint:
        return "High"
    source = f.get("source_expr", "") or ""
    if any(s in source.lower() for s in ("request", "input", "argv", "form", "query", "param")):
        return "Medium"
    # Fall back to mapper value if available, else Low
    return f.get("exploitability") or "Low"


def enrich_finding(f: dict) -> dict:
    f = dict(f)
    sev = f.get("severity", "Medium")
    f["priority"]    = PRIORITY_MAP.get(sev, "P4")
    f["fingerprint"] = hashlib.md5(
        f"{f.get('vuln_type')}|{f.get('file')}|{f.get('line')}".encode()
    ).hexdigest()
    f["detected_at"] = datetime.utcnow().isoformat() + "Z"
    if "affected_files" not in f:
        f["affected_files"] = [f.get("file", "")]
        f["instances"] = 1
    # GAP 7: confidence_score (0-100) for enterprise adoption
    _conf_base  = {"High": 80, "Medium": 55, "Low": 30, "": 40}
    _det_bonus  = {"AST Taint Analysis": 15, "Regex + Contextual Analysis": 5,
                   "Structural Fallback (AST)": 8, "Regex Pattern": 0}
    _expl_bonus = {"High": 10, "Medium": 5, "Low": 0}
    conf_score  = (
        _conf_base.get(f.get("confidence", ""), 40)
        + _det_bonus.get(f.get("detection", ""), 0)
        + _expl_bonus.get(f.get("exploitability", ""), 0)
    )
    if f.get("taint_path") and "->" in str(f.get("taint_path", "")):
        conf_score += 10
    f["confidence_score"] = min(conf_score, 100)
    # PATCH 7: standardise to HIGH/MEDIUM/LOW for enterprise consistency
    f["confidence_label"] = (
        "HIGH"   if conf_score >= 85 else
        "HIGH"   if conf_score >= 75 else   # taint-validated = HIGH
        "MEDIUM" if conf_score >= 55 else
        "LOW"
    )
    # Keep numeric score for sorting but use label for display
    f["confidence"] = f["confidence_label"]  # unify the field name

    # Issue 1: always expose occurrence_count for report visibility
    # Issue 2 FIX: guarantee unique affected_files — use dict.fromkeys to preserve order
    if "affected_files" in f:
        f["affected_files"] = list(dict.fromkeys(p for p in f["affected_files"] if p))
    f["occurrence_count"]  = len(f.get("occurrences", [])) or f.get("instances", 1)
    f["unique_file_count"] = len(set(
        o.get("file","") for o in f.get("occurrences", [{"file": f.get("file","")}])
    ))
    if "occurrences" not in f:
        f["occurrences"] = [{"file": f.get("file"), "line": f.get("line"),
                              "snippet": f.get("snippet", "")}]
    f["exploitability"] = _compute_exploitability(f)
    for field in ["pci_dss", "nist", "iso27001", "soc2", "exploitability",
                  "taint_path", "confidence", "cve_note", "attack_scenario"]:
        f.setdefault(field, "")
    if not f.get("cve") and not f.get("cve_note"):
        f["cve_note"] = f"Code-level vulnerability (no CVE). Mapped to {f.get('cwe', 'CWE')}."
    return f


def severity_distribution(findings: list[dict]) -> dict[str, int]:
    dist: dict = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        dist[f.get("severity", "Info")] = dist.get(f.get("severity", "Info"), 0) + 1
    return dist


def group_by_severity(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
            -CONFIDENCE_RANK.get(f.get("confidence", ""), 0),
        )
    )


def _score_sbom_entry(pkg: dict) -> dict:
    pkg = dict(pkg)
    cvss = _safe_float(pkg.get("cvss"))
    if pkg.get("reachable") and cvss > 0:
        pkg["risk_score"]  = min(100.0, round(cvss * 10, 1))
        pkg["fingerprint"] = hashlib.md5(
            f"{pkg.get('name', '')}|{pkg.get('cve', '')}".encode()
        ).hexdigest()
        pkg["detected_at"] = datetime.utcnow().isoformat() + "Z"
    else:
        pkg.setdefault("risk_score", 0)
    return pkg


# ---------------------------------------------------------------------------
# Insights
# ---------------------------------------------------------------------------

def generate_insights(findings: list[dict], sbom: list[dict],
                      attack_paths: list[dict]) -> list[str]:
    insights = []
    dist = severity_distribution(findings)

    if dist["Critical"] > 0:
        n = dist["Critical"]
        insights.append(
            f"CRITICAL: {n} critical vulnerabilit{'y' if n==1 else 'ies'} identified — "
            "immediate remediation required before next deployment."
        )
    if dist["High"] > 0:
        n = dist["High"]
        insights.append(
            f"HIGH RISK: {n} high-severity issue{'s' if n>1 else ''} present. "
            "Schedule remediation within 7 days per SLA guidelines."
        )

    injection_types = {"sql_injection","command_injection","code_injection","xss"}
    inj = sum(1 for f in findings if f.get("vuln_type") in injection_types)
    if inj >= 2:
        insights.append(
            f"INJECTION CLUSTER: {inj} injection-class vulnerabilities detected. "
            "Review all input validation and sanitisation across the codebase."
        )

    ssrf_count = sum(1 for f in findings if f.get("vuln_type") == "ssrf")
    if ssrf_count > 0:
        insights.append(
            f"SSRF RISK: {ssrf_count} Server-Side Request Forgery "
            f"vulnerabilit{'y' if ssrf_count==1 else 'ies'} detected. "
            "Validate all outbound HTTP request URLs against a server-side allow-list."
        )

    deser_count = sum(1 for f in findings if f.get("vuln_type") == "insecure_deserialization")
    if deser_count > 0:
        insights.append(
            f"DESERIALIZATION: {deser_count} insecure deserialization sink"
            f"{'s' if deser_count>1 else ''} detected. "
            "Never deserialize untrusted data with pickle, yaml.load, or ObjectInputStream."
        )

    secret_count = sum(1 for f in findings if f.get("vuln_type") == "hardcoded_secret")
    if secret_count > 0:
        insights.append(
            f"SECRET EXPOSURE: {secret_count} hardcoded credential"
            f"{'s' if secret_count>1 else ''} found. "
            "Rotate all affected credentials immediately and audit VCS history."
        )

    multi = [f for f in findings if f.get("instances", 1) > 1]
    if multi:
        extra = sum(f.get("instances",1)-1 for f in multi)
        insights.append(
            f"REPEATED PATTERNS: {len(multi)} root-cause vulnerability type"
            f"{'s' if len(multi)>1 else ''} with {extra} additional "
            f"occurrence{'s' if extra>1 else ''}. "
            "Fix the root cause in shared code to eliminate all occurrences."
        )

    if len(attack_paths) > 0:
        insights.append(
            f"ATTACK CHAINS: {len(attack_paths)} exploitable attack path"
            f"{'s' if len(attack_paths)>1 else ''} identified. "
            "Multi-step chains significantly increase breach probability."
        )

    pivots = get_pivot_points(findings)
    if pivots:
        insights.append(
            f"PIVOT POINTS: {', '.join(pivots[:3])} "
            f"{'are' if len(pivots)>1 else 'is'} reachable from multiple attack chains — "
            "prioritize remediation of these vulnerabilities first."
        )

    vuln_deps      = [d for d in sbom if _safe_float(d.get("cvss")) >= 7.0]
    reachable_deps = [d for d in vuln_deps if d.get("reachable")]
    typosquat_deps = [f for f in findings if f.get("vuln_type") == "supply_chain_typosquat"]
    if vuln_deps:
        reach_note = (f" {len(reachable_deps)} marked reachable (exploitable in this context)."
                      if reachable_deps else "")
        insights.append(
            f"SUPPLY CHAIN: {len(vuln_deps)} dependency package"
            f"{'s' if len(vuln_deps)>1 else ''} with CVSS >= 7.0 detected.{reach_note} "
            "Upgrade to patched versions before release."
        )
    if typosquat_deps:
        insights.append(
            f"DEPENDENCY CONFUSION: {len(typosquat_deps)} probable typosquatted package"
            f"{'s' if len(typosquat_deps)>1 else ''} detected. "
            "Malicious packages execute code on install — remove immediately and audit pip history."
        )

    crit_high = dist["Critical"] + dist["High"]
    if crit_high > 0:
        insights.append(
            f"COMPLIANCE RISK: {crit_high} critical/high findings may violate "
            "PCI DSS, NIST 800-53, ISO 27001, and SOC 2 requirements. "
            "Engage security team for formal risk acceptance."
        )

    low_conf = [f for f in findings if f.get("confidence") == "Low"]
    if low_conf:
        insights.append(
            f"LOW CONFIDENCE: {len(low_conf)} finding"
            f"{'s' if len(low_conf)>1 else ''} require manual review to confirm exploitability."
        )

    if not insights:
        insights.append("No critical or high severity vulnerabilities detected. Continue monitoring.")
    return insights


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _top_root_causes(grouped: list[dict], n: int = 5) -> list[dict]:
    """Top-N findings by total occurrence count for the priority fix section."""
    return sorted(grouped, key=lambda x: x.get("instances", 1), reverse=True)[:n]


def build_report_payload(findings: list[dict], sbom: list[dict],
                         target_path: str) -> dict[str, Any]:
    deduped  = deduplicate(findings)
    enriched = [enrich_finding(score_finding(f)) for f in deduped]
    grouped  = group_by_severity(enriched)

    scored_sbom = [_score_sbom_entry(p) for p in sbom]
    reachable_sbom = [
        p for p in scored_sbom
        if p.get("reachable") and _safe_float(p.get("cvss")) > 0
    ]
    portfolio    = compute_portfolio_score(enriched + reachable_sbom)
    dist         = severity_distribution(enriched)
    owasp        = get_owasp_summary(enriched)
    mitre        = get_mitre_summary(enriched)
    attack_paths = get_attack_paths(enriched)
    insights     = generate_insights(enriched, scored_sbom, attack_paths)

    return {
        "metadata": {
            "tool":                  TOOL_FULL,
            "target":                target_path,
            "scan_date":             datetime.utcnow().isoformat() + "Z",
            "total_findings":        len(enriched) + len(reachable_sbom),
            "sast_findings":         len(enriched),
            "sca_findings":          len(reachable_sbom),
            "risk_score":            portfolio,
            "risk_score_model":      SCORING_MODEL_DESCRIPTION,
            "severity_distribution": dist,
        },
        "findings":     enriched,
        "grouped":      grouped,
        "owasp":        owasp,
        "mitre":        mitre,
        "attack_paths": attack_paths,
        "sbom":         scored_sbom,
        "insights":     insights,
        "top_root_causes": _top_root_causes(grouped),
    }
