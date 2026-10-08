import re
from typing import Any, Dict, List


IDENTITY_ACCESS_PATTERNS = [
    # Admin / root / privileged identity
    ("HARDCODED_ADMIN_USER", r"\b(admin|administrator|root)\s*[:=]\s*['\"][^'\"]+['\"]", "HIGH"),
    (
        "ROOT_ACCOUNT_USAGE",
        r'(?i)'
        r'(?:(?:["\']?(?:username|user|login|account)["\']?)'
        r'\s*[:=]\s*["\']?root["\']?)'
        r'|(?:USER\s+root\b)'
        r'|(?:sudo\s+-u\s+root\b)'
        r'|(?:su\s+root\b)',
        "HIGH",
    ),
    ("DEFAULT_ADMIN_CREDENTIAL", r"\badmin\s*[:=]\s*['\"]admin['\"]|\badmin\s*[:=]\s*['\"]password['\"]", "CRITICAL"),

    # IAM / cloud permissions
    ("WILDCARD_IAM_ACTION", r"Action\s*[:=]\s*['\"]\*['\"]|\"Action\"\s*:\s*\"\*\"", "CRITICAL"),
    ("WILDCARD_IAM_RESOURCE", r"Resource\s*[:=]\s*['\"]\*['\"]|\"Resource\"\s*:\s*\"\*\"", "HIGH"),
    ("IAM_PASSROLE_PRIVILEGE", r"\biam:PassRole\b", "HIGH"),
    ("STS_ASSUME_ROLE_PUBLIC", r"\bsts:AssumeRole\b.*\*|\bPrincipal\s*[:=]\s*['\"]\*['\"]", "CRITICAL"),
    ("ADMIN_POLICY_ATTACHED", r"\bAdministratorAccess\b|\badmin_policy\b", "HIGH"),

    # MFA / authentication controls
    ("MFA_NOT_ENFORCED", r"\bmfa\s*[:=]\s*false\b|\brequire_mfa\s*[:=]\s*false\b|\bMultiFactorAuthPresent\b.*false", "HIGH"),
    ("AUTH_DISABLED", r"\bauth\s*[:=]\s*false\b|\bauthentication\s*[:=]\s*false\b|\bdisable_auth\b", "CRITICAL"),
    ("ALLOW_ANONYMOUS_ACCESS", r"\banonymous\s*[:=]\s*true\b|\ballowAnonymous\b|\ballow_anonymous\b", "HIGH"),

    # OAuth / token scope
    ("EXCESSIVE_OAUTH_SCOPE", r"\bhttps://www.googleapis.com/auth/cloud-platform\b|\bfull_access\b|\bopenid\s+profile\s+email\s+admin\b", "HIGH"),
    ("LONG_LIVED_TOKEN", r"\bexpires_in\s*[:=]\s*(31536000|999999|0)\b|\bnever_expires\b", "HIGH"),

    # Kubernetes RBAC
    ("K8S_CLUSTER_ADMIN_BINDING", r"\bcluster-admin\b|\bClusterRoleBinding\b", "CRITICAL"),
    ("K8S_WILDCARD_VERBS", r"verbs\s*:\s*\[\s*['\"]?\*['\"]?\s*\]|\"verbs\"\s*:\s*\[\s*\"\*\"\s*\]", "CRITICAL"),
    ("K8S_WILDCARD_RESOURCES", r"resources\s*:\s*\[\s*['\"]?\*['\"]?\s*\]|\"resources\"\s*:\s*\[\s*\"\*\"\s*\]", "HIGH"),
    ("SERVICE_ACCOUNT_TOKEN_AUTOMOUNT", r"\bautomountServiceAccountToken\s*:\s*true\b", "HIGH"),
    ("PRIVILEGE_ESCALATION_ALLOWED", r"\ballowPrivilegeEscalation\s*:\s*true\b", "HIGH"),

    # Cloud trust / public assumption / service principals
    ("PUBLIC_ROLE_TRUST", r"\bPrincipal\b.*\*|\bpublic_role\b|\btrusted_entities\b.*\*", "CRITICAL"),
    ("SERVICE_ACCOUNT_KEY_FILE", r"\bservice_account\b.*\.json\b|\bclient_email\b.*iam\.gserviceaccount\.com", "HIGH"),
    ("AZURE_OWNER_ROLE", r"\bOwner\b|\bContributor\b", "HIGH"),
    ("GCP_OWNER_ROLE", r"\broles/owner\b|\broles/editor\b", "HIGH"),
]


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

        for key, value in obj.items():
            key_text = str(key)

            if isinstance(value, (dict, list)):
                value_text = _collect_text(value)
            elif isinstance(value, bool):
                value_text = "true" if value else "false"
            elif value is not None:
                value_text = str(value)
            else:
                value_text = ""

            if value_text:
                values.append(f"{key_text}: {value_text}")
            else:
                values.append(key_text)

        return " ".join(values)

    if isinstance(obj, list):
        return " ".join(_collect_text(x) for x in obj)

    return str(obj)


def _detect_indicators(text: str) -> List[Dict[str, Any]]:
    detected = []

    for name, pattern, risk in IDENTITY_ACCESS_PATTERNS:
        if re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL):
            detected.append({
                "indicator": name,
                "risk_level": risk,
                "evidence_match": name,
                "executive_relevant": risk in {"CRITICAL", "HIGH"},
                "identity_access_risk": True,
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
        return "Identity or access control weakness may enable unauthorized privilege escalation, public role assumption, or administrative compromise."
    if risk == "HIGH":
        return "Identity and access indicators suggest elevated authorization, RBAC, or privileged access exposure requiring review."
    if risk == "MEDIUM":
        return "Identity/access governance indicator observed and should be validated."
    return "No material identity or access risk indicator identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediately restrict privileges, remove wildcard access, enforce MFA, and validate role trust boundaries."
    if risk == "HIGH":
        return "Review least privilege, service account usage, OAuth scopes, MFA enforcement, and RBAC bindings."
    if risk == "MEDIUM":
        return "Validate access policy context and reduce unnecessary permissions."
    return "No action required."


def enrich_identity_access_risk(
    findings: List[Dict[str, Any]],
    api_bom: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
    cbom: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    findings = findings or []
    api_bom = api_bom or []
    abom = abom or []
    cbom = cbom or []

    # V2: Memory-safe bounded context construction.
    #
    # CBOM/ABOM/API-BOM collections can become very large. Flattening
    # the complete structures into one string causes unnecessary memory
    # consumption and may make rule evaluation scan irrelevant content.
    #
    # Preserve findings completely while bounding auxiliary BOM context.
    def _bounded_collect(items, max_items=250, max_chars=100000):
        if not items:
            return ""

        if isinstance(items, list):
            selected = items[:max_items]
        else:
            selected = [items]

        text = _collect_text(selected)

        if len(text) > max_chars:
            text = text[:max_chars]

        return text

    findings_context = _bounded_collect(
        findings,
        max_items=1000,
        max_chars=200000,
    )

    api_bom_context = _bounded_collect(
        api_bom,
        max_items=250,
        max_chars=100000,
    )

    abom_context = _bounded_collect(
        abom,
        max_items=250,
        max_chars=100000,
    )

    cbom_context = _bounded_collect(
        cbom,
        max_items=250,
        max_chars=100000,
    )

    global_context = " ".join(
        part
        for part in (
            findings_context,
            api_bom_context,
            abom_context,
            cbom_context,
        )
        if part
    )

    indicators = _detect_indicators(global_context)
    highest_risk = _highest_risk(indicators)

    critical = sum(1 for i in indicators if i.get("risk_level") == "CRITICAL")
    high = sum(1 for i in indicators if i.get("risk_level") == "HIGH")
    executive_relevant = sum(1 for i in indicators if i.get("executive_relevant") is True)

    summary = {
        "total_identity_access_indicators": len(indicators),
        "critical_identity_access_indicators": critical,
        "high_identity_access_indicators": high,
        "executive_relevant_indicators": executive_relevant,
        "highest_risk_indicator": highest_risk,
        "global_indicators": indicators,
        "enterprise_impact": _impact_for(highest_risk),
        "recommended_action": _action_for(highest_risk),
        "engine_mode": "OFFLINE_RULE_BASED_IDENTITY_ACCESS_RISK_V1",
        "summary_status": (
            "IDENTITY_ACCESS_RISK_IDENTIFIED"
            if executive_relevant > 0
            else "NO_IDENTITY_ACCESS_RISK_IDENTIFIED"
        ),
    }

    return summary