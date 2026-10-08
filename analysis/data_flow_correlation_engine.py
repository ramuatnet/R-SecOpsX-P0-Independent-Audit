"""analysis/data_flow_correlation_engine.py
Enterprise correlation for IDOR/BOLA, tenant isolation, privilege escalation and workflow bypass.
Backward-compatible APIs:
- correlate_data_flows(payload_or_findings)
- analyze_data_flow_correlation(payload_or_findings)
- correlate_data_flow(findings)
"""
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
import re

OBJ_ACCESS = {"findById","findOne","getById","repository","repo.","db.","execute","query","select","Model.find","EntityManager"}
AUTH_WORDS = {"authorize","isAuthorized","hasPermission","hasRole","@PreAuthorize","RequireAuthorization","[Authorize]","auth","authmiddleware","authentication","authenticated","requires_auth","permission","tenant"}
PRIV_FIELDS = {"role","roles","isAdmin","admin","permission","permissions","privilege","is_superuser","tenantId","tenant_id"}
WORKFLOW_WORDS = {"approval","approved","skip_approval","auto_approve","payment","transfer","coupon","redeem","otp","reset"}

def _severity(kind):
    return "Critical" if kind in {"privilege_escalation","workflow_bypass"} else "High"
def _priority(sev): return {"Critical":"P1","High":"P2","Medium":"P3","Low":"P4"}.get(sev,"P3")

def _norm_file(f): return f.get("file") or f.get("file_path") or f.get("full_path") or ""
def _near(a,b,dist=25):
    try: return _norm_file(a)==_norm_file(b) and abs(int(a.get("line",0))-int(b.get("line",0)))<=dist
    except Exception: return False


def _source_window(f: dict, project_root=None, window: int = 40) -> str | None:
    """Read bounded source context when an actual project root/path is available.

    Returning None means source evidence is unavailable; callers must not interpret
    absence of source evidence as absence of a security control.
    """
    candidates = []
    for k in ("full_path", "file_path", "file"):
        value = str(f.get(k) or "").strip()
        if value:
            candidates.append(Path(value))
    for raw in candidates:
        try:
            if raw.is_file():
                path = raw
            elif project_root:
                norm = str(raw).replace("\\", "/")
                marker = Path(project_root).name
                idx = norm.lower().find(marker.lower())
                path = Path(project_root) / norm[idx + len(marker):].lstrip("/") if idx >= 0 else Path(project_root) / Path(norm).name
            else:
                continue
            if not path.is_file():
                continue
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            line = int(f.get("line") or 0)
            if not line:
                return "\n".join(lines[:window * 2])
            lo, hi = max(1, line-window), min(len(lines), line+window)
            return "\n".join(lines[lo-1:hi])
        except Exception:
            continue
    return None

def _has_server_object_access_context(f: dict, fs_sorted: list[dict], project_root=None) -> bool:
    """Require server-side route + object/data access evidence from source when available."""
    path = _norm_file(f).replace("\\", "/").lower()
    if any(marker in path for marker in (
        "/frontend/", "/client/", "/web/", "/src/components/",
        "/src/context/", "/src/pages/", "/src/hooks/",
    )):
        return False

    source_text = _source_window(f, project_root, 40)
    if source_text is not None:
        text = source_text
    else:
        local = [g for g in fs_sorted if _near(f, g, 40)]
        # Fallback is evidence-only and must never be used to infer missing auth.
        text = " ".join(str(g.get(k, "")) for g in local for k in ("snippet", "title", "description", "taint_path", "source_expr", "sink_call"))

    route = re.search(
        r'@(?:app|router|api|bp)\.(?:route|get|post|put|patch|delete|api_route)\s*\('
        r'|\b(?:app|router|api|server)\s*\.\s*(?:get|post|put|patch|delete|route)\s*\('
        r'|@(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\('
        r'|\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\b'
        r'|http\.(?:HandleFunc|Handle)\s*\(',
        text, re.I
    )
    access = any(x.lower() in text.lower() for x in OBJ_ACCESS)
    return bool(route and access)


def _mk(kind,title,findings,evidence_note):
    base=findings[0] if findings else {}
    confirmed = False
    underlying_sev = str(base.get("severity") or "Medium")
    sev=_severity(kind) if confirmed else underlying_sev
    return {"rule_id":f"CORR_{kind.upper()}","title":title,"vuln_type":kind,"severity":sev,"priority":_priority(sev),"confidence":"High" if len(findings)>1 else "Medium","language":base.get("language","unknown"),"file":_norm_file(base),"line":base.get("line",0),"snippet":base.get("snippet",""),"description":evidence_note,"remediation":["Enforce object-level authorization before repository/database access.","Validate tenant ownership in every data access path.","Use centralized authorization guards and regression tests.","Make workflow state transitions atomic and server-side enforced."],"owasp":"A01:2021 - Broken Access Control","cwe":"CWE-639","evidence":" | ".join(f"{_norm_file(f)}:{f.get('line')}:{f.get('title')}" for f in findings[:4]),"detection":"Data Flow Correlation","engine":"analysis.data_flow_correlation_engine","correlation_type":kind,"correlated_findings":findings,"group_key":f"CORR_{kind.upper()}|{_norm_file(base)}|{base.get('line',0)}","enterprise_control":True,
            "confirmed": confirmed,
            "evidence_status": "CONTEXTUAL_NOT_CONFIRMED",
            "requires_manual_verification": True}

def correlate_data_flows(payload_or_findings, project_root=None, api_bom=None, abom=None):
    if isinstance(payload_or_findings, dict):
        findings = payload_or_findings.get("findings") or payload_or_findings.get("deduped_findings") or []
    else:
        findings = payload_or_findings or []
    correlations=[]
    by_file=defaultdict(list)
    for f in findings: by_file[_norm_file(f)].append(f)
    for file, fs in by_file.items():
        fs_sorted=sorted(fs, key=lambda x:int(x.get("line",0) or 0))
        for f in fs_sorted:
            text=" ".join(str(f.get(k,"")) for k in ("title","vuln_type","snippet","description","taint_path","source_expr","sink_call"))
            id_hit = bool(re.search(r"(?<![A-Za-z0-9])(id|user[_-]?id|tenant[_-]?id|organization[_-]?id|args\.id)(?![A-Za-z0-9])|(?:^|[_$])id$", text, re.I))
            access_hit = any(re.search(r"(?<![A-Za-z0-9])" + re.escape(x) + r"(?![A-Za-z0-9])", text, re.I) for x in OBJ_ACCESS if re.search(r"[A-Za-z]", x))
            if id_hit and access_hit:
                source_text = _source_window(f, project_root, 30)
                if source_text is None:
                    # Unknown control state is not equivalent to missing authorization.
                    has_auth = None
                else:
                    has_auth = any(re.search(r"(?<![A-Za-z0-9])" + re.escape(w) + r"(?![A-Za-z0-9])", source_text, re.I) for w in AUTH_WORDS)
                if has_auth is False:
                    correlations.append(_mk("idor_bola","IDOR / BOLA: User-Controlled Object ID Reaches Data Access",[f],"User-controlled object identifier appears to reach repository/database access and no authorization guard was found in the bounded source context."))
            if (
                any(x in text for x in ("tenantId","tenant_id","org_id","organizationId"))
                and _has_server_object_access_context(f, fs_sorted, project_root)
            ):
                correlations.append(_mk(
                    "tenant_isolation_failure",
                    "Tenant Isolation Failure Correlation",
                    [f],
                    "Tenant identifier participates in a server-side object/data access flow; verify tenant ownership is enforced before access."
                ))
            if any(p in text for p in PRIV_FIELDS) and any(src in text for src in ("req.","request.","body","params","@RequestBody","FromBody","$_POST")):
                correlations.append(_mk("privilege_escalation","Privilege Escalation via User-Controlled Role/Permission",[f],"User-controlled role/permission/tenant field may influence privileged state."))
            if any(w in text for w in WORKFLOW_WORDS) and any(w in text for w in ("skip","auto","approved","redeem","payment","transfer","reset")):
                correlations.append(_mk("workflow_bypass","Workflow / Approval / Duplicate Action Bypass",[f],"Workflow-sensitive action appears without clear server-side approval/idempotency enforcement."))
        # Pair taint flows with auth weaknesses nearby
        auth_gaps=[f for f in fs_sorted if str(f.get("vuln_type","")).lower() in {"auth_misconfiguration","missing_authorization","idor","mass_assignment"}]
        data_flows=[f for f in fs_sorted if f.get("taint_path") or str(f.get("detection","")).lower().find("taint")>=0]
        for a in auth_gaps:
            for d in data_flows:
                if _near(a,d,40):
                    correlations.append(_mk("authorization_missing_before_object_access","Authorization Missing Before Object Access",[a,d],"Authorization weakness correlates with tainted data/object access in the same file region.")); break
    # de-duplicate
    seen=set(); out=[]
    for c in correlations:
        k=c.get("group_key")+"|"+c.get("correlation_type","")
        if k not in seen:
            seen.add(k); out.append(c)
    summary=summarize_data_flow_correlation(out)
    if isinstance(payload_or_findings, dict):
        payload_or_findings["data_flow_correlations"] = out
        payload_or_findings["data_flow_correlation_summary"] = summary
        return payload_or_findings
    return out

def correlate_data_flow(findings): return correlate_data_flows(findings)
def analyze_data_flow_correlation(payload_or_findings): return correlate_data_flows(payload_or_findings)

def summarize_data_flow_correlation(correlations):
    return {
        "total_correlated": len(correlations),
        "critical": sum(1 for c in correlations if c.get("severity") == "Critical"),
        "high": sum(1 for c in correlations if c.get("severity") == "High"),
        "critical_correlated_flows": sum(1 for c in correlations if c.get("severity") == "Critical"),
        "high_correlated_flows": sum(1 for c in correlations if c.get("severity") == "High"),
        "confirmed_flows": sum(1 for c in correlations if c.get("confirmed") is True),
        "by_type": dict(Counter(c.get("correlation_type","unknown") for c in correlations)),
        "summary_status": (
            "DATA_FLOW_CORRELATION_CONFIRMED" if any(c.get("confirmed") is True for c in correlations)
            else "DATA_FLOW_CORRELATION_REQUIRES_VALIDATION" if correlations
            else "NO_DATA_FLOW_CORRELATION_IDENTIFIED"
        )
    }

if __name__=="__main__":
    import json, sys
    data=json.load(open(sys.argv[1],encoding="utf-8")) if len(sys.argv)>1 else []
    print(json.dumps(correlate_data_flows(data), indent=2))


def enrich_data_flow_correlation(findings: list[dict], api_bom=None, abom=None, project_root=None) -> dict:
    """
    Backward-compatible wrapper expected by main.py.
    Always returns a dict summary, even if older correlation function returns a list.
    """
    api_bom = api_bom or []
    abom = abom or []

    result = None

    if "correlate_data_flows" in globals():
        try:
            result = correlate_data_flows(findings, api_bom=api_bom, abom=abom, project_root=project_root)
        except TypeError:
            try:
                result = correlate_data_flows(findings)
            except TypeError:
                result = None

    if result is None and "analyze_data_flow_correlation" in globals():
        try:
            result = analyze_data_flow_correlation(findings, api_bom=api_bom, abom=abom)
        except TypeError:
            try:
                result = analyze_data_flow_correlation(findings)
            except TypeError:
                result = None

    if isinstance(result, dict):
        result.setdefault("total_correlated_flows", len(result.get("correlated_flows", [])))
        result.setdefault("critical_correlated_flows", 0)
        result.setdefault("high_correlated_flows", 0)
        result.setdefault("confirmed_flows", 0)
        result.setdefault("fallback_candidate_flows", 0)
        result.setdefault("by_context", {"file_context": 0, "function_context": 0})
        result.setdefault("correlation_confidence", "MIXED_OR_CONTEXTUAL")
        result.setdefault("correlation_mode", "STATIC_CONTEXT_SOURCE_SINK_CORRELATION_V2_WITH_FILE_FALLBACK")
        result.setdefault("correlation_status", (
            "DATA_FLOW_CORRELATION_CONFIRMED"
            if result.get("confirmed_flows", 0) > 0
            else "DATA_FLOW_CORRELATION_REQUIRES_VALIDATION"
            if result.get("total_correlated_flows", 0) > 0
            else "NO_DATA_FLOW_CORRELATION_IDENTIFIED"
        ))
        return result

    if isinstance(result, list):
        correlations = result
    else:
        correlations = []

        for finding in findings or []:
            title = str(finding.get("title", "")).lower()
            vuln_type = str(finding.get("vuln_type", "")).lower()

            if any(x in title or x in vuln_type for x in [
                "idor",
                "bola",
                "tenant",
                "privilege",
                "authorization",
                "object id",
                "repository",
                "database",
                "workflow bypass",
            ]):
                correlations.append({
                    "rule_id": "DATA_FLOW_CONTEXTUAL_AUTHZ_CORRELATION",
                    "title": "Contextual Authorization/Data Flow Correlation",
                    "severity": finding.get("severity", "High"),
                    "priority": finding.get("priority", "P2"),
                    "confidence": finding.get("confidence", "Medium"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "snippet": finding.get("snippet"),
                    "description": "Potential user-controlled object or authorization-sensitive data flow reaches a sensitive access path.",
                    "remediation": "Validate object ownership and tenant boundary before repository, database, or workflow access.",
                    "owasp": "A01:2021 - Broken Access Control",
                    "cwe": "CWE-639",
                    "evidence": finding.get("evidence") or finding.get("snippet"),
                    "detection": "Static Data Flow Correlation",
                    "engine": "analysis.data_flow_correlation_engine",
                    "context": "file_context",
                    "confirmed": False,
                    "evidence_status": "CONTEXTUAL_NOT_CONFIRMED",
                    "requires_manual_verification": True,
                })

    critical = sum(
        1 for c in correlations
        if str(c.get("severity", "")).lower() == "critical"
    )
    high = sum(
        1 for c in correlations
        if str(c.get("severity", "")).lower() == "high"
    )

    return {
        "total_correlated_flows": len(correlations),
        "critical_correlated_flows": critical,
        "high_correlated_flows": high,
        "confirmed_flows": 0,
        "fallback_candidate_flows": len(correlations),
        "by_context": {
            "file_context": len(correlations),
            "function_context": 0,
        },
        "correlated_flows": correlations,
        "correlation_confidence": "MIXED_OR_CONTEXTUAL",
        "correlation_mode": "STATIC_CONTEXT_SOURCE_SINK_CORRELATION_V2_WITH_FILE_FALLBACK",
        "correlation_status": (
            "DATA_FLOW_CORRELATION_CONFIRMED"
            if any(c.get("confirmed") is True for c in correlations)
            else "DATA_FLOW_CORRELATION_REQUIRES_VALIDATION"
            if correlations
            else "NO_DATA_FLOW_CORRELATION_IDENTIFIED"
        ),
    }
