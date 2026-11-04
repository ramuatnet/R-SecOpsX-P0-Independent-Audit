"""analysis/framework_enrichment_engine.py
Framework-aware enrichment for existing R-SecOpsX findings.
Backward-compatible public APIs:
- enrich_framework_mappings(payload_or_findings)
- enrich_framework_enrichment(payload_or_findings)
- analyze_framework_enrichment(target_or_findings)
"""
from __future__ import annotations
import re
import sys
from pathlib import Path
from collections import Counter

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.walk import walk

FRAMEWORK_RULES = [
    ("SPRING_SECURITY_CSRF_DISABLED", "Spring Security CSRF Disabled", "spring_boot", "Critical", r"csrf\s*\(\s*\)\s*\.disable|csrf\s*->\s*csrf\.disable", "CWE-352", "A01:2021 - Broken Access Control"),
    ("SPRING_ACTUATOR_EXPOSE_ALL", "Spring Actuator Exposure Include All", "spring_boot", "Critical", r"management\.endpoints\.web\.exposure\.include\s*=\s*\*|include:\s*[\"']?\*[\"']?", "CWE-200", "A05:2021 - Security Misconfiguration"),
    ("SPRING_MISSING_VALIDATION", "Spring Missing @Valid/@Validated", "spring_boot", "Medium", r"@(PostMapping|PutMapping|PatchMapping)[\s\S]{0,250}@(RequestBody|ModelAttribute)(?![\s\S]{0,80}@(?:Valid|Validated))", "CWE-20", "A04:2021 - Insecure Design"),
    ("SPRING_ASYNC_SECURITY_CONTEXT", "Spring @Async Security Context Propagation Gap", "spring_boot", "High", r"@Async(?![\s\S]{0,250}(DelegatingSecurityContext|SecurityContextHolder))", "CWE-362", "A04:2021 - Insecure Design"),
    ("SPRING_WEBFLUX_AUTH_GAP", "Spring WebFlux Authorization Gap", "spring_boot", "High", r"authorizeExchange\s*\(\s*\)\s*\.anyExchange\s*\(\s*\)\s*\.permitAll|RouterFunctions\.route\s*\(", "CWE-284", "A01:2021 - Broken Access Control"),
    ("ASP_NET_OVERPOSTING", "ASP.NET Overposting Indicator", "aspnet_core", "High", r"\[FromBody\]\s*(?:User|Account|Role|Admin|.*Entity)|public\s+(?:IActionResult|Task<[^>]+>)\s+\w+\s*\([^)]*(?:User|Account|Role|Admin|.*Entity)", "CWE-915", "A01:2021 - Broken Access Control"),
    ("EXPRESS_MISSING_RATE_LIMIT", "Express Missing Rate Limit/Auth Middleware", "express", "High", r"app\.(?:post|get|put|delete)\s*\(\s*[\"']/(?:login|otp|reset|password|invite|coupon|payment|refresh)[\"'](?![\s\S]{0,160}(rateLimit|auth|authenticate|authorize|requireAuth))", "CWE-770", "API4:2023 - Unrestricted Resource Consumption"),
    ("GRAPHQL_INTROSPECTION_ENABLED", "GraphQL Introspection Enabled", "graphql", "High", r"introspection\s*:\s*true|graphiql\s*:\s*true|GraphQLPlayground|__schema|__type|ApolloServer\s*\([^)]*introspection\s*:\s*true", "CWE-200", "A05:2021 - Security Misconfiguration"),
]

CONTROL_MAP = {
    "spring_boot": {"nist":"SI-10 / AC-3 / CM-7", "nist_800_53":"SI-10 / AC-3 / CM-7", "iso27001":"A.14.2.5 / A.12.6.1", "iso_27001":"A.14.2.5 / A.12.6.1", "soc2":"CC6.6 / CC7.2", "pci_dss":"Req 6.2.4 / Req 7"},
    "aspnet_core": {"nist":"AC-3 / SI-10", "nist_800_53":"AC-3 / SI-10", "iso27001":"A.9.4.1 / A.14.2.5", "iso_27001":"A.9.4.1 / A.14.2.5", "soc2":"CC6.1 / CC6.6", "pci_dss":"Req 6.2.4 / Req 7"},
    "express": {"nist":"AC-3 / SI-10 / AC-7", "nist_800_53":"AC-3 / SI-10 / AC-7", "iso27001":"A.14.2.5 / A.8.16", "iso_27001":"A.14.2.5 / A.8.16", "soc2":"CC6.6 / CC7.2", "pci_dss":"Req 6.2.4 / Req 8"},
    "graphql": {"nist":"AC-3 / SI-10 / SC-7 / SC-5", "nist_800_53":"AC-3 / SI-10 / SC-7 / SC-5", "iso27001":"A.14.2.5 / A.13.1.1 / A.8.16", "iso_27001":"A.14.2.5 / A.13.1.1 / A.8.16", "soc2":"CC6.6 / CC7.2", "pci_dss":"Req 6.2.4 / Req 8"},
}

def _priority(sev: str) -> str:
    return {"Critical":"P1","High":"P2","Medium":"P3","Low":"P4"}.get(sev,"P3")

def _mk(rule, file, line, snippet):
    rid,title,fw,sev,_,cwe,owasp = rule
    controls = CONTROL_MAP.get(fw, {})
    return {"rule_id": rid, "title": title, "vuln_type": rid.lower(), "severity": sev, "priority": _priority(sev), "confidence":"Medium", "language":"framework", "file":str(file), "line":line, "snippet":snippet.strip(), "description":f"Framework-aware configuration or coding pattern detected for {fw}.", "remediation":["Apply secure framework defaults.", "Require authentication/authorization on sensitive routes.", "Add validation, rate limits and regression tests."], "owasp":owasp, "cwe":cwe, "evidence":f"{file}:{line}: {snippet.strip()}", "detection":"Framework-Aware Static Enrichment", "engine":"analysis.framework_enrichment_engine", **controls, "framework":fw, "enterprise_control":True, "group_key":f"{rid}|{file}|{line}"}

def scan_file(filepath: str) -> list[dict]:
    p=Path(filepath)
    try: text=p.read_text(encoding="utf-8", errors="replace")
    except OSError: return []
    lines=text.splitlines(); out=[]
    for rule in FRAMEWORK_RULES:
        rx=re.compile(rule[4], re.I|re.M|re.S)
        for m in rx.finditer(text):
            line=text[:m.start()].count("\n")+1
            snip=lines[line-1] if line<=len(lines) else m.group(0)
            if snip.strip().startswith(("#","//","*")): continue
            out.append(_mk(rule,p,line,snip)); break
    return out

def scan_directory(target_path: str) -> dict:
    target=Path(target_path); files=[x for x, _s, _m in walk(target, exts=None, ignore=frozenset(), max_bytes=None)]
    findings=[]
    for f in files: findings.extend(scan_file(str(f)))
    return {"framework_enrichment_findings": findings, "framework_enrichment_summary": summarize_framework_enrichment(findings)}

def _finding_list(payload_or_findings):
    if isinstance(payload_or_findings, list): return payload_or_findings
    if isinstance(payload_or_findings, dict): return payload_or_findings.get("findings") or payload_or_findings.get("deduped_findings") or []
    return []

def enrich_framework_mappings(payload_or_findings):
    findings=_finding_list(payload_or_findings)
    for f in findings:
        title=(f.get("title") or "").lower(); rid=(f.get("rule_id") or "").lower(); vt=(f.get("vuln_type") or "").lower()
        fw=""
        if "spring" in title or "spring" in rid: fw="spring_boot"
        elif "graphql" in title or "graphql" in rid or "graphql" in vt: fw="graphql"
        elif "asp" in title or "dotnet" in rid or "csharp" == f.get("language"): fw="aspnet_core"
        elif "express" in title or "node" in rid: fw="express"
        if fw:
            f["framework"] = fw; f["framework_mapping_method"]="rule_based_framework_enrichment_v2"
            for k,v in CONTROL_MAP.get(fw,{}).items(): f.setdefault(k,v)
    if isinstance(payload_or_findings, dict):
        payload_or_findings["framework_enrichment_summary"] = summarize_framework_enrichment(findings)
        return payload_or_findings
    return findings

def enrich_framework_enrichment(payload_or_findings):
    return enrich_framework_mappings(payload_or_findings)

def analyze_framework_enrichment(target_or_findings):
    if isinstance(target_or_findings,(list,dict)): return enrich_framework_mappings(target_or_findings)
    return scan_directory(str(target_or_findings))

def summarize_framework_enrichment(findings:list[dict])->dict:
    return {"total_framework_findings":len(findings), "by_framework":dict(Counter(f.get("framework","unknown") for f in findings)), "by_severity":dict(Counter(f.get("severity","Unknown") for f in findings)), "summary_status":"RULE_BASED_FRAMEWORK_ENRICHMENT_V2"}

if __name__ == "__main__":
    import json, sys
    print(json.dumps(scan_directory(sys.argv[1] if len(sys.argv)>1 else "."), indent=2))

def framework_mapping_summary(findings: list[dict]) -> dict:
    """
    Backward-compatible summary expected by main.py.
    """
    mapped = [
        f for f in findings
        if f.get("owasp")
        or f.get("cwe")
        or f.get("pci_dss")
        or f.get("nist")
        or f.get("nist_800_53")
        or f.get("iso_27001")
        or f.get("soc2")
        or f.get("mapped_frameworks")
    ]

    by_owasp = {}
    by_cwe = {}

    for finding in mapped:
        owasp = finding.get("owasp") or finding.get("owasp_top10_2021")
        cwe = finding.get("cwe")

        if isinstance(owasp, list):
            for item in owasp:
                by_owasp[str(item)] = by_owasp.get(str(item), 0) + 1
        elif owasp:
            by_owasp[str(owasp)] = by_owasp.get(str(owasp), 0) + 1

        if isinstance(cwe, list):
            for item in cwe:
                by_cwe[str(item)] = by_cwe.get(str(item), 0) + 1
        elif cwe:
            by_cwe[str(cwe)] = by_cwe.get(str(cwe), 0) + 1

    return {
        "mapped_findings": len(mapped),
        "total_findings": len(findings),
        "by_owasp": by_owasp,
        "by_cwe": by_cwe,
        "mapping_status": "RULE_BASED_FRAMEWORK_ENRICHMENT_V1",
    }