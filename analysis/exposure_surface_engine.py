import re
from typing import Any, Dict, List, Tuple


EXPOSURE_PATTERNS = [
    ("DEBUG_MODE", r"\bdebug\s*=\s*true\b|\bDEBUG\s*=\s*True\b|\bDEBUG\s*=\s*true\b", "HIGH"),

    ("SWAGGER_UI_EXPOSED", r"\b/swagger-ui\b|\b/swagger/index\.html\b|\b/api-docs\b|\b/v3/api-docs\b", "MEDIUM"),
    ("OPENAPI_EXPOSED", r"\b/openapi\.(json|yaml|yml)\b|\bopenapi_url\s*=", "MEDIUM"),
    ("GRAPHQL_INTROSPECTION", r"\b__schema\b|\b__type\b|\bintrospection\b|\b/graphql\b", "HIGH"),

    ("GIT_EXPOSURE", r"(^|[\\/])\.git([\\/]|$)|\.git/config|\.git/HEAD", "CRITICAL"),
    ("ENV_EXPOSURE", r"(^|[\\/])\.env(\.|$|[\\/])|\bdotenv\b|\benv_file\b", "CRITICAL"),
    ("BACKUP_FILE_EXPOSURE", r"\.(bak|old|backup)$|\bbackup\.(zip|tar|tar\.gz|tgz|7z|rar)\b|\bdb_dump\.sql\b", "HIGH"),

    ("ADMIN_PANEL", r"\b/admin\b|\b/admin/login\b|\b/wp-admin\b|\b/phpmyadmin\b", "HIGH"),
    ("JENKINS_EXPOSED", r"\b/jenkins\b|\bjenkins_url\b", "HIGH"),
    ("GRAFANA_EXPOSED", r"\b/grafana\b|\bgrafana\b", "MEDIUM"),
    ("KIBANA_EXPOSED", r"\b/kibana\b|\bkibana\b", "MEDIUM"),
    ("ELASTICSEARCH_EXPOSED", r":9200\b|\belasticsearch\b", "HIGH"),
    ("REDIS_EXPOSED", r":6379\b|\bredis://", "CRITICAL"),
    ("MONGODB_EXPOSED", r":27017\b|\bmongodb://", "CRITICAL"),
    ("JMX_EXPOSED", r"\bjmxremote\b|:1099\b", "HIGH"),
    ("DEBUG_PORT_EXPOSED", r":5005\b|:9229\b|\bdebug_port\b", "HIGH"),

    ("DOCKER_SOCKET_EXPOSED", r"/var/run/docker\.sock", "CRITICAL"),
    ("KUBE_API_EXPOSED", r":6443\b|\bkube-apiserver\b", "CRITICAL"),
    ("K8S_DASHBOARD", r"\bkubernetes-dashboard\b|\bk8s-dashboard\b", "CRITICAL"),

    ("PROMETHEUS_METRICS", r"\b/metrics\b|\bprometheus\b", "MEDIUM"),
    ("SPRING_ACTUATOR", r"\b/actuator\b|\b/actuator/env\b|\b/actuator/heapdump\b", "HIGH"),
    ("HEALTH_INFO_LEAK", r"\b/health\b|\b/healthz\b|\b/status\b|\b/version\b|\b/build\b", "LOW"),
]


# These patterns describe deployment SURFACES (URLs, ports, paths), so a
# component record is evaluated only against fields where a surface can be
# declared.  Whole-record text used to be scanned instead and matched text
# that merely describes the component: a package literally NAMED dotenv
# (``.../node_modules/dotenv``) satisfied ENV_EXPOSURE at CRITICAL, and
# advisory prose mentioning ``/admin`` or ``:9200`` matched ADMIN_PANEL /
# ELASTICSEARCH_EXPOSED.  Findings, API-BOM routes and ABOM agents below are
# still scanned as whole text -- that is where surface evidence genuinely
# lives.
COMPONENT_SURFACE_FIELDS: Tuple[str, ...] = (
    "homepage",
    "url",
    "repository",
    "resolved",
    "resolved_url",
    "source_url",
    "registry",
)


RISK_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _collect_text(obj: Any) -> str:
    if obj is None:
        return ""

    if isinstance(obj, str):
        return obj

    if isinstance(obj, dict):
        values = []
        for _, value in obj.items():
            if isinstance(value, (dict, list)):
                values.append(_collect_text(value))
            elif value is not None:
                values.append(str(value))
        return " ".join(values)

    if isinstance(obj, list):
        return " ".join(_collect_text(x) for x in obj)

    return str(obj)


def _detect_indicators(text: str) -> List[Dict[str, Any]]:
    detected = []

    for name, pattern, risk in EXPOSURE_PATTERNS:
        if re.search(pattern, text or "", flags=re.IGNORECASE):
            detected.append({
                "indicator": name,
                "risk_level": risk,
                "evidence_match": name,
                "executive_relevant": risk in {"CRITICAL", "HIGH"},
            })

    return detected


def _highest_risk(indicators: List[Dict[str, Any]]) -> str:
    if not indicators:
        return "NONE"

    return max(
        indicators,
        key=lambda x: RISK_RANK.get(x.get("risk_level", "NONE"), 0),
    ).get("risk_level", "NONE")


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Potentially exposed sensitive surface may allow direct unauthorized access, secret disclosure, or infrastructure compromise."
    if risk == "HIGH":
        return "Exposed administrative, debug, or introspection surface may materially increase exploitation likelihood."
    if risk == "MEDIUM":
        return "Externally discoverable technical surface may aid reconnaissance or targeted exploitation."
    if risk == "LOW":
        return "Low-risk service metadata exposure observed; review for unnecessary disclosure."
    return "No material exposure surface indicator identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediately restrict exposure, require authentication, and remove sensitive public artifacts."
    if risk == "HIGH":
        return "Prioritize access control, disable debug/introspection, and validate public exposure."
    if risk == "MEDIUM":
        return "Review necessity, restrict to trusted networks, and minimize exposed metadata."
    if risk == "LOW":
        return "Review response content and remove unnecessary version/build details."
    return "No action required."


def enrich_exposure_surface_intelligence(
    sbom: List[Dict[str, Any]],
    findings: List[Dict[str, Any]] = None,
    api_bom: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:

    findings = findings or []
    api_bom = api_bom or []
    abom = abom or []

    component_exposure_indicators = 0
    critical_affected_components = 0
    high_affected_components = 0

    enriched = []

    for pkg in sbom or []:
        pkg_text = " ".join(
            str(pkg.get(field))
            for field in COMPONENT_SURFACE_FIELDS
            if pkg.get(field) is not None
        )
        indicators = _detect_indicators(pkg_text)
        risk = _highest_risk(indicators)

        component_exposure_indicators += len(indicators)

        if risk == "CRITICAL":
            critical_affected_components += 1
        elif risk == "HIGH":
            high_affected_components += 1

        pkg["exposure_surface_intelligence"] = {
            "exposure_surface_detected": bool(indicators),
            "indicators": indicators,
            "highest_risk_indicator": risk,
            "risk_level": risk,
            "enterprise_impact": _impact_for(risk),
            "recommended_action": _action_for(risk),
            "evidence": [i["evidence_match"] for i in indicators],
            "scope": "SBOM_COMPONENT",
        }

        enriched.append(pkg)

    global_context = " ".join([
        _collect_text(findings),
        _collect_text(api_bom),
        _collect_text(abom),
    ])

    global_indicators = _detect_indicators(global_context)
    global_critical_indicators = sum(
        1 for i in global_indicators if i.get("risk_level") == "CRITICAL"
    )
    global_high_indicators = sum(
        1 for i in global_indicators if i.get("risk_level") == "HIGH"
    )
    executive_relevant_global_indicators = sum(
        1 for i in global_indicators if i.get("executive_relevant") is True
    )

    summary = {
        "component_exposure_indicators": component_exposure_indicators,
        "global_exposure_indicators": len(global_indicators),
        "critical_affected_components": critical_affected_components,
        "high_affected_components": high_affected_components,
        "global_critical_indicators": global_critical_indicators,
        "global_high_indicators": global_high_indicators,
        "executive_relevant_global_indicators": executive_relevant_global_indicators,
        "global_indicators": global_indicators,
        "executive_status": (
            "EXPOSURE_SURFACE_RISK_IDENTIFIED"
            if component_exposure_indicators > 0 or executive_relevant_global_indicators > 0
            else "NO_EXPOSURE_SURFACE_RISK_IDENTIFIED"
        ),
    }

    return enriched, summary