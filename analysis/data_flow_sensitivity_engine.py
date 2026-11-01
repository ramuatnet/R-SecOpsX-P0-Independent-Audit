import re
from typing import Any, Dict, List


SENSITIVITY_PATTERNS = [
    # PII
    ("EMAIL_PII_FLOW", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "MEDIUM"),
    ("PHONE_PII_FLOW", r"\b(\+?\d{1,3})?[- ]?\d{10}\b", "MEDIUM"),
    ("AADHAAR_PII_FLOW", r"\b\d{4}\s?\d{4}\s?\d{4}\b", "HIGH"),
    ("PAN_PII_FLOW", r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", "HIGH"),
    ("PASSPORT_PII_FLOW", r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b", "HIGH"),
    ("SSN_PII_FLOW", r"\b\d{3}-\d{2}-\d{4}\b", "HIGH"),

    # PCI / Financial
    ("POTENTIAL_CREDIT_CARD_FLOW", r"\b(?:\d[ -]*?){13,16}\b", "CRITICAL"),
    ("CVV_FLOW", r"\bcvv\b|\bcvc\b|\bsecurity code\b", "HIGH"),
    ("IBAN_FINANCIAL_FLOW", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "HIGH"),
    ("BANK_ACCOUNT_FLOW", r"\b(account_number|routing_number|ifsc|iban|swift)\b", "HIGH"),

    # Auth Tokens / Secrets
    ("JWT_TOKEN_FLOW", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "HIGH"),
    ("API_KEY_FLOW", r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}", "CRITICAL"),
    ("PASSWORD_ASSIGNMENT_FLOW", r"\b(password|passwd|pwd|secret|token)\s*[:=]", "HIGH"),
    ("BEARER_TOKEN_FLOW", r"\bAuthorization\s*:\s*Bearer\b|\bbearer_token\b", "HIGH"),
    ("REFRESH_TOKEN_FLOW", r"\brefresh_token\b", "HIGH"),
    ("SESSION_COOKIE_FLOW", r"\bSet-Cookie\b|\bsessionid\b|\bJSESSIONID\b", "HIGH"),

    # Database / Storage / Queue Sinks
    ("DATABASE_SINK_FLOW", r"\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bexecute\s*\(", "MEDIUM"),
    ("S3_WRITE_FLOW", r"\bput_object\s*\(|\bupload_file\s*\(", "HIGH"),
    ("GCS_WRITE_FLOW", r"\bbucket\.blob\b|\bupload_from_filename\b", "HIGH"),
    ("AZURE_BLOB_WRITE_FLOW", r"\bBlobClient\b|\bupload_blob\s*\(", "HIGH"),
    ("KAFKA_PRODUCER_FLOW", r"\bKafkaProducer\b|\bproducer\.send\s*\(", "HIGH"),

    # Logging / Exfiltration
    ("SENSITIVE_LOGGING_INDICATOR", r"\bprint\(|\blogger\.(info|debug|error)\(", "MEDIUM"),
    ("THIRD_PARTY_HTTP_EXFIL", r"\brequests\.(post|get)\(|\bfetch\(", "HIGH"),
    ("WEBHOOK_EXFIL", r"\bwebhook\b|\bdiscordapp\.com/api/webhooks\b", "HIGH"),
    ("EMAIL_EXFIL_FLOW", r"\bsendmail\s*\(|\bsmtp\b|\bsend_email\s*\(", "HIGH"),
    ("SLACK_EXFIL_FLOW", r"\bslack\.com/api\b|\bchat_postMessage\b", "HIGH"),

    # AI / LLM / Model Risks
    ("PROMPT_DATA_LEAK_INDICATOR", r"\bprompt\b|\bmessages\b|\bsystem_prompt\b", "MEDIUM"),
    ("TRAINING_DATA_LEAK", r"\btrain_data\b|\btraining_set\b|\bfine_tune\b", "HIGH"),
    ("AI_MEMORY_LEAK_FLOW", r"\bmemory\.save_context\b|\bconversation_memory\b", "HIGH"),
    ("VECTOR_STORE_PII_FLOW", r"\bvector_store\.add_documents\b|\badd_documents\s*\(", "HIGH"),
    ("MODEL_TRAINING_PII_FLOW", r"\bfit\s*\(|\btrain\s*\(|\bfine_tune\b", "HIGH"),

    # Environment / Secrets
    ("ENV_SECRET_FLOW", r"os\.environ|getenv\(", "HIGH"),
    
    
    # Bearer / Authorization propagation
    ("BEARER_TOKEN_FLOW", r"\bAuthorization\s*:\s*Bearer\b|\bheaders\s*\[\s*['\"]Authorization['\"]\s*\]|\bauthorization\s*=\s*['\"]Bearer|\bbearer_token\b", "HIGH"),

    # AI memory leakage
    ("AI_MEMORY_LEAK_FLOW", r"\bmemory\.save_context\s*\(|\bConversationBufferMemory\b|\bRedisChatMessageHistory\b|\bconversation_memory\b", "HIGH"),

    # Vector DB leakage
    ("VECTOR_STORE_PII_FLOW", r"\bvector_store\.add_documents\s*\(|\bFAISS\.from_documents\s*\(|\bPinecone\.upsert\s*\(|\bWeaviate\.batch\b|\bChroma\.add_texts\s*\(|\badd_documents\s*\(", "HIGH"),

    # Cloud writes
    ("S3_WRITE_FLOW", r"\bput_object\s*\(|\bupload_file\s*\(|\bs3_client\.upload_file\s*\(", "HIGH"),
    ("GCS_WRITE_FLOW", r"\bbucket\.blob\b|\bupload_from_filename\s*\(|\bupload_from_string\s*\(", "HIGH"),
    ("AZURE_BLOB_WRITE_FLOW", r"\bBlobClient\b|\bupload_blob\s*\(|\.upload_blob\s*\(", "HIGH"),

    # API response leakage
    ("API_RESPONSE_PII_LEAK", r"\breturn\s*\{[^}]*['\"](card|credit_card|ssn|pan|aadhaar|password|token|secret)['\"]", "HIGH"),

    # Financial flows
    ("SWIFT_FINANCIAL_FLOW", r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b|\bswift_code\b|\bbic_code\b", "HIGH"),
    ("IBAN_FINANCIAL_FLOW", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b|\biban\b", "HIGH"),

]


RISK_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Machine identifiers are not PII evidence.  Every scan mints fresh
# uuid4s into the BOM payloads (CycloneDX serialNumber, VEX ids,
# bom-refs), and uuid hex accidentally satisfies several patterns above
# by chance (measured on 20k random uuids: PASSPORT 1.15%,
# PHONE/AADHAAR/SWIFT ~0.3%, CREDIT_CARD 0.17% per token) -- which made
# the indicator counts differ between two otherwise identical scans
# (found by the T-9.15 deterministic-output gate).  Strip uuid-shaped
# tokens from the scanned context; real PII text is unaffected.
_MACHINE_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


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

    for name, pattern, risk in SENSITIVITY_PATTERNS:
        if re.search(pattern, text or "", flags=re.IGNORECASE):
            detected.append({
                "indicator": name,
                "risk_level": risk,
                "evidence_match": name,
                "executive_relevant": risk in {"CRITICAL", "HIGH"},
                "flow_confirmed": False,
                "indicator_only": True,
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
        return "Sensitive regulated data indicator may create breach, compliance, or fraud exposure if confirmed in a real flow."
    if risk == "HIGH":
        return "Sensitive data handling indicator may materially increase privacy, regulatory, or exfiltration risk."
    if risk == "MEDIUM":
        return "Potentially sensitive data handling indicator observed and should be reviewed."
    return "No material sensitive data handling indicator identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Validate source-to-sink flow, masking, encryption, access control, and downstream transfer controls."
    if risk == "HIGH":
        return "Review data classification, logging, storage, and third-party transfer controls."
    if risk == "MEDIUM":
        return "Review context and confirm whether sensitive data reaches this sink."
    return "No action required."


def enrich_data_flow_sensitivity(
    findings: List[Dict[str, Any]],
    api_bom: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    findings = findings or []
    api_bom = api_bom or []
    abom = abom or []

    global_context = " ".join([
        _collect_text(findings),
        _collect_text(api_bom),
        _collect_text(abom),
    ])
    # Machine identifiers are not PII evidence (see _MACHINE_UUID).
    global_context = _MACHINE_UUID.sub(" ", global_context)

    indicators = _detect_indicators(global_context)
    highest_risk = _highest_risk(indicators)

    critical_indicators = sum(1 for i in indicators if i.get("risk_level") == "CRITICAL")
    high_indicators = sum(1 for i in indicators if i.get("risk_level") == "HIGH")
    medium_indicators = sum(1 for i in indicators if i.get("risk_level") == "MEDIUM")
    executive_relevant = sum(1 for i in indicators if i.get("executive_relevant") is True)

    summary = {
        "total_data_flow_sensitivity_indicators": len(indicators),
        "critical_indicators": critical_indicators,
        "high_indicators": high_indicators,
        "medium_indicators": medium_indicators,
        "executive_relevant_indicators": executive_relevant,
        "highest_risk_indicator": highest_risk,
        "global_indicators": indicators,
        "flow_confirmed": False,
        "indicator_only": True,
        "enterprise_impact": _impact_for(highest_risk),
        "recommended_action": _action_for(highest_risk),
        "engine_mode": "OFFLINE_RULE_BASED_INDICATOR_ONLY",
        "summary_status": (
            "DATA_FLOW_SENSITIVITY_INDICATORS_IDENTIFIED"
            if executive_relevant > 0
            else "NO_DATA_FLOW_SENSITIVITY_INDICATORS_IDENTIFIED"
        ),
    }

    return summary