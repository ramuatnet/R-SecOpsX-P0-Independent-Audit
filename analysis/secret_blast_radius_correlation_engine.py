import re
from collections import defaultdict
from typing import Any, Dict, List


SECRET_PROVIDER_PATTERNS = [
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}", "AWS", "CRITICAL"),
    ("AWS_SECRET_KEY", r"aws_secret_access_key|AWS_SECRET_ACCESS_KEY", "AWS", "CRITICAL"),
    ("GCP_SERVICE_ACCOUNT", r"client_email.*iam\.gserviceaccount\.com|private_key_id", "GCP", "CRITICAL"),
    ("GOOGLE_API_KEY", r"AIza[0-9A-Za-z\-_]{35}", "Google", "HIGH"),
    ("OPENAI_API_KEY", r"sk-[A-Za-z0-9]{20,}|OPENAI_API_KEY", "OpenAI", "HIGH"),
    ("ANTHROPIC_API_KEY", r"ANTHROPIC_API_KEY|sk-ant-[A-Za-z0-9\-_]+", "Anthropic", "HIGH"),
    ("GITHUB_TOKEN", r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]+", "GitHub", "CRITICAL"),
    ("SLACK_TOKEN", r"xox[baprs]-[A-Za-z0-9-]+", "Slack", "HIGH"),
    ("WEBHOOK_SECRET", r"discordapp\.com/api/webhooks|hooks\.slack\.com/services", "Webhook", "HIGH"),
    ("JWT_SECRET", r"jwt_secret|JWT_SECRET|secret_key", "Auth", "HIGH"),
    ("PRIVATE_KEY", r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----", "Private Key", "CRITICAL"),
    ("DATABASE_CONNECTION_STRING", r"(postgres|mysql|mongodb|redis)://[^\"'\s]+", "Database", "CRITICAL"),
    ("AZURE_CONNECTION_STRING", r"DefaultEndpointsProtocol=.*AccountKey=", "Azure", "CRITICAL"),
]


PROVIDER_ASSET_HINTS = {
    "AWS": [
        ("S3", r"(?<![A-Za-z0-9])s3(?![A-Za-z0-9])|put_object|bucket"),
        ("EC2", r"(?<![A-Za-z0-9])ec2(?![A-Za-z0-9])|instance"),
        ("Lambda", r"(?<![A-Za-z0-9])lambda(?![A-Za-z0-9])"),
        ("IAM", r"(?<![A-Za-z0-9])iam(?![A-Za-z0-9])|AssumeRole|PassRole"),
    ],
    "GCP": [
        ("GCS", r"\bbucket\.blob\b|storage\.bucket|upload_from"),
        ("Firebase", r"(?<![A-Za-z0-9])firebase(?![A-Za-z0-9])"),
        ("BigQuery", r"(?<![A-Za-z0-9])bigquery(?![A-Za-z0-9])"),
        ("IAM", r"\biam\.gserviceaccount\.com\b"),
    ],
    "Google": [
        ("Gemini/Google API", r"(?<![A-Za-z0-9])gemini(?![A-Za-z0-9])|google_api_key|AIza"),
        ("Maps", r"\bmaps\.googleapis\b"),
        ("Firebase", r"(?<![A-Za-z0-9])firebase(?![A-Za-z0-9])"),
    ],
    "OpenAI": [
        ("OpenAI API", r"(?<![A-Za-z0-9])openai(?![A-Za-z0-9])|OPENAI_API_KEY"),
        ("LLM Application", r"\bprompt\b|messages|chat_completion"),
    ],
    "Anthropic": [
        ("Anthropic API", r"(?<![A-Za-z0-9])anthropic(?![A-Za-z0-9])|ANTHROPIC_API_KEY"),
        ("LLM Application", r"\bprompt\b|messages"),
    ],
    "GitHub": [
        ("Repository Access", r"(?<![A-Za-z0-9])github(?![A-Za-z0-9])|repo|pull_request|workflow"),
        ("CI/CD", r"\bactions\b|workflow|runner"),
    ],
    "Slack": [
        ("Workspace Messaging", r"(?<![A-Za-z0-9])slack(?![A-Za-z0-9])|chat_postMessage"),
        ("Notification Exfiltration", r"(?<![A-Za-z0-9])webhook(?![A-Za-z0-9])"),
    ],
    "Webhook": [
        ("External Webhook", r"(?<![A-Za-z0-9])webhook(?![A-Za-z0-9])|discordapp|hooks\.slack"),
    ],
    "Database": [
        ("Database Access", r"(?<![A-Za-z0-9])postgres(?![A-Za-z0-9])|mysql|mongodb|redis"),
    ],
    "Azure": [
        ("Azure Storage", r"AccountKey|BlobClient|upload_blob"),
    ],
    "Auth": [
        ("Authentication Boundary", r"(?<![A-Za-z0-9])jwt(?![A-Za-z0-9])|session|token"),
    ],
    "Private Key": [
        ("Cryptographic Identity", r"PRIVATE KEY|ssh|tls|cert"),
    ],
}


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
        return " ".join(_collect_text(v) for v in obj.values() if v is not None)
    if isinstance(obj, list):
        return " ".join(_collect_text(x) for x in obj)
    return str(obj)


def _finding_text(finding: Dict[str, Any]) -> str:
    return " ".join([
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("snippet", "")),
        str(finding.get("evidence", "")),
        str(finding.get("file", "")),
        str(finding.get("file_path", "")),
        _collect_text(finding.get("occurrences", [])),
    ])


def _function_name(finding: Dict[str, Any]) -> str:
    return str(
        finding.get("function_name")
        or finding.get("function")
        or finding.get("method")
        or finding.get("method_name")
        or ""
    ).strip()


def _detect_secret_provider(text: str) -> List[Dict[str, Any]]:
    detected = []

    for secret_type, pattern, provider, risk in SECRET_PROVIDER_PATTERNS:
        if re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL):
            detected.append({
                "secret_type": secret_type,
                "provider": provider,
                "risk_level": risk,
            })

    return detected


def _detect_assets(provider: str, text: str) -> List[str]:
    assets = []

    for asset, pattern in PROVIDER_ASSET_HINTS.get(provider, []):
        if re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL):
            assets.append(asset)

    return sorted(set(assets))


def _risk_for(secret_risk: str, assets: List[str], secret_confirmed: bool = False, provider_scope_confirmed: bool = False) -> str:
    # Static pattern severity is not equivalent to confirmed provider blast radius.
    # Offline findings remain potential/high-risk until the secret is validated and
    # its provider scope is established.
    if secret_confirmed and provider_scope_confirmed:
        if secret_risk == "CRITICAL":  # sast-ignore HARDCODED_CREDENTIAL_COMPARISON risk-level label comparison, no credential material
            return "CRITICAL"
        if assets and secret_risk == "HIGH":
            return "HIGH"
    if secret_risk == "CRITICAL":  # sast-ignore HARDCODED_CREDENTIAL_COMPARISON risk-level label comparison, no credential material
        return "HIGH"
    if assets and secret_risk == "HIGH":
        return "MEDIUM"
    return secret_risk or "MEDIUM"


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Secret exposure may enable direct compromise of cloud, source-code, database, identity, or production systems."
    if risk == "HIGH":
        return "Secret exposure may enable unauthorized provider access, data exfiltration, or abuse of connected services."
    if risk == "MEDIUM":
        return "Secret exposure indicator observed and should be validated for provider and scope."
    return "No material secret blast-radius indicator identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediately revoke and rotate the secret, audit provider activity, and review downstream asset access."
    if risk == "HIGH":
        return "Rotate the secret, validate provider scope, and restrict permissions to least privilege."
    if risk == "MEDIUM":
        return "Validate whether the secret is active and reduce exposed scope if confirmed."
    return "No action required."


def _make_correlation(
    context_id: str,
    context_type: str,
    text: str,
    evidence: Dict[str, Any],
) -> List[Dict[str, Any]]:

    secret_hits = _detect_secret_provider(text)
    correlations = []

    for hit in secret_hits:
        assets = _detect_assets(hit["provider"], text)
        secret_confirmed = bool(evidence.get("secret_confirmed") is True or evidence.get("validated_live") is True)
        provider_scope_confirmed = bool(evidence.get("provider_scope_confirmed") is True or evidence.get("scope_confirmed") is True)
        risk = _risk_for(hit["risk_level"], assets, secret_confirmed, provider_scope_confirmed)

        correlations.append({
            "context_id": context_id,
            "context_type": context_type,
            "secret_type": hit["secret_type"],
            "provider": hit["provider"],
            "likely_assets": assets,
            "blast_radius_risk": risk,
            "secret_confirmed": secret_confirmed,
            "provider_scope_confirmed": provider_scope_confirmed,
            "correlation_status": "CONFIRMED_SECRET_BLAST_RADIUS" if (secret_confirmed and provider_scope_confirmed) else "POTENTIAL_SECRET_BLAST_RADIUS_IDENTIFIED",
            # Executive relevance requires confirmed secret presence AND
            # confirmed provider scope; potential/high offline patterns remain
            # review candidates and must not escalate to executive exposure.
            "executive_relevant": (
                risk in {"CRITICAL", "HIGH"}
                and secret_confirmed
                and provider_scope_confirmed
            ),
            "enterprise_impact": _impact_for(risk),
            "recommended_action": _action_for(risk),
            "evidence": evidence or {},
        })

    return correlations


def _dedupe(correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped = {}

    for item in correlations:
        key = (
            item.get("context_type"),
            item.get("context_id"),
            item.get("secret_type"),
            item.get("provider"),
        )

        existing = deduped.get(key)

        if existing is None:
            deduped[key] = item
            continue

        old_rank = RISK_RANK.get(existing.get("blast_radius_risk", "NONE"), 0)
        new_rank = RISK_RANK.get(item.get("blast_radius_risk", "NONE"), 0)

        if new_rank > old_rank:
            deduped[key] = item

    return list(deduped.values())


def enrich_secret_blast_radius_correlation(
    findings: List[Dict[str, Any]],
    api_bom: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
    aibom: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    findings = findings or []
    api_bom = api_bom or []
    abom = abom or []
    aibom = aibom or []

    correlations = []
    file_groups = defaultdict(list)
    function_groups = defaultdict(list)

    for finding in findings:
        file_key = finding.get("file") or finding.get("file_path") or ""
        fn = _function_name(finding)
        context_id = str(
            finding.get("id")
            or finding.get("rule_id")
            or finding.get("title")
            or file_key
            or "finding"
        )

        correlations.extend(
            _make_correlation(
                context_id,
                "FINDING",
                _finding_text(finding),
                {
                    "file": file_key,
                    "line": finding.get("line"),
                    "rule_id": finding.get("rule_id"),
                    "title": finding.get("title"),
                    "function": fn or None,
                },
            )
        )

        if file_key:
            file_groups[str(file_key)].append(finding)

        if file_key and fn:
            function_groups[(str(file_key), fn)].append(finding)

    for file_key, grouped in file_groups.items():
        correlations.extend(
            _make_correlation(
                file_key,
                "FILE_CONTEXT",
                " ".join(_finding_text(x) for x in grouped),
                {
                    "file": file_key,
                    "finding_count": len(grouped),
                },
            )
        )

    for (file_key, fn), grouped in function_groups.items():
        correlations.extend(
            _make_correlation(
                f"{file_key}::{fn}",
                "FUNCTION_CONTEXT",
                " ".join(_finding_text(x) for x in grouped),
                {
                    "file": file_key,
                    "function": fn,
                    "finding_count": len(grouped),
                },
            )
        )

    for route in api_bom:
        route_id = str(route.get("route") or route.get("path") or route.get("endpoint") or "api_route")
        correlations.extend(
            _make_correlation(
                route_id,
                "API_ROUTE",
                _collect_text(route),
                {
                    "route": route.get("route") or route.get("path") or route.get("endpoint"),
                    "method": route.get("method"),
                },
            )
        )

    for agent in abom:
        agent_id = str(agent.get("name") or agent.get("agent") or "ai_agent")
        correlations.extend(
            _make_correlation(
                agent_id,
                "AI_AGENT",
                _collect_text(agent),
                {
                    "agent": agent.get("name") or agent.get("agent"),
                    "type": agent.get("type"),
                },
            )
        )

    for ai_asset in aibom:
        asset_id = str(ai_asset.get("provider") or ai_asset.get("model") or ai_asset.get("name") or "ai_asset")
        correlations.extend(
            _make_correlation(
                asset_id,
                "AI_BOM_CONTEXT",
                _collect_text(ai_asset),
                {
                    "provider": ai_asset.get("provider"),
                    "model": ai_asset.get("model"),
                    "name": ai_asset.get("name"),
                },
            )
        )

    correlations = _dedupe(correlations)

    critical = sum(1 for c in correlations if c.get("blast_radius_risk") == "CRITICAL")
    high = sum(1 for c in correlations if c.get("blast_radius_risk") == "HIGH")
    executive_relevant = sum(1 for c in correlations if c.get("executive_relevant") is True)

    by_context = {
        "finding_context": sum(1 for c in correlations if c.get("context_type") == "FINDING"),
        "file_context": sum(1 for c in correlations if c.get("context_type") == "FILE_CONTEXT"),
        "function_context": sum(1 for c in correlations if c.get("context_type") == "FUNCTION_CONTEXT"),
        "api_route_context": sum(1 for c in correlations if c.get("context_type") == "API_ROUTE"),
        "ai_agent_context": sum(1 for c in correlations if c.get("context_type") == "AI_AGENT"),
        "ai_bom_context": sum(1 for c in correlations if c.get("context_type") == "AI_BOM_CONTEXT"),
    }

    unique_secret_types = sorted({
        c.get("secret_type")
        for c in correlations
        if c.get("secret_type")
    })

    critical_unique_secret_types = sorted({
        c.get("secret_type")
        for c in correlations
        if c.get("secret_type") and c.get("blast_radius_risk") == "CRITICAL"
    })

    high_unique_secret_types = sorted({
        c.get("secret_type")
        for c in correlations
        if c.get("secret_type") and c.get("blast_radius_risk") == "HIGH"
    })

    providers_affected = sorted({
        c.get("provider")
        for c in correlations
        if c.get("provider")
    })

    likely_assets_affected = sorted({
        asset
        for c in correlations
        for asset in c.get("likely_assets", [])
        if asset
    })
    
    normalized_unique_secrets = {}

    for c in correlations:
        key = (
            c.get("secret_type"),
            c.get("provider"),
        )

        existing = normalized_unique_secrets.get(key)

        if existing is None:
            normalized_unique_secrets[key] = c
            continue

        old_rank = RISK_RANK.get(existing.get("blast_radius_risk", "NONE"), 0)
        new_rank = RISK_RANK.get(c.get("blast_radius_risk", "NONE"), 0)

        if new_rank > old_rank:
            normalized_unique_secrets[key] = c

    normalized_secret_correlations = list(normalized_unique_secrets.values())

    total_unique_secret_blast_radius = len(normalized_secret_correlations)

    critical_unique_secret_blast_radius = sum(
        1 for c in normalized_secret_correlations
        if c.get("blast_radius_risk") == "CRITICAL"
    )

    high_unique_secret_blast_radius = sum(
        1 for c in normalized_secret_correlations
        if c.get("blast_radius_risk") == "HIGH"
    )

    return {
        "total_secret_blast_radius_correlations": len(correlations),
        "critical_secret_blast_radius": critical,
        "high_secret_blast_radius": high,
        "executive_relevant_correlations": executive_relevant,

        "total_unique_secret_blast_radius": total_unique_secret_blast_radius,
        "critical_unique_secret_blast_radius": critical_unique_secret_blast_radius,
        "high_unique_secret_blast_radius": high_unique_secret_blast_radius,

        "total_unique_secret_types": len(unique_secret_types),
        "critical_unique_secret_types": len(critical_unique_secret_types),
        "high_unique_secret_types": len(high_unique_secret_types),

        "providers_affected": providers_affected,
        "providers_affected_count": len(providers_affected),
        "likely_assets_affected": likely_assets_affected,
        "likely_assets_affected_count": len(likely_assets_affected),

        "by_context": by_context,
        "correlation_mode": "STATIC_SECRET_PROVIDER_BLAST_RADIUS_CORRELATION_V2",
        # Summary status is derived from the actual correlation records.
        # Potential correlations must never be reported as "no correlation"
        # merely because they are not confirmed/executive-relevant.
        "correlation_status": (
            "CONFIRMED_SECRET_BLAST_RADIUS_IDENTIFIED"
            if any(
                c.get("correlation_status") == "CONFIRMED_SECRET_BLAST_RADIUS"
                and c.get("secret_confirmed") is True
                and c.get("provider_scope_confirmed") is True
                for c in correlations
            )
            else (
                "POTENTIAL_SECRET_BLAST_RADIUS_REQUIRES_VALIDATION"
                if any(
                    c.get("correlation_status") in {
                        "POTENTIAL_SECRET_BLAST_RADIUS_IDENTIFIED",
                        "PROVIDER_ASSET_SCOPE_INDICATED",
                    }
                    for c in correlations
                )
                else "NO_SECRET_BLAST_RADIUS_CORRELATION_IDENTIFIED"
            )
        ),
        "correlations": correlations,
        "unique_secret_blast_radius_correlations": normalized_secret_correlations,
    }