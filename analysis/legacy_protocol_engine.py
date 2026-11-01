import re
from typing import Any, Dict, List, Tuple


LEGACY_PATTERNS = [
    ("SSLv2", r"\bsslv2\b", "CRITICAL"),
    ("SSLv3", r"\bsslv3\b", "CRITICAL"),
    ("TLS1.0", r"\btls\s*1\.0\b|\btlsv1\b", "HIGH"),
    ("TLS1.1", r"\btls\s*1\.1\b|\btlsv1\.1\b", "HIGH"),
    ("Telnet", r"\btelnet\b|:23\b", "CRITICAL"),
    ("FTP", r"\bftp://|\bftp\s*[:=]|\bprotocol\s*[:=]\s*['\"]?ftp['\"]?|:21\b", "CRITICAL"),
    ("MD5", r"\bmd5\b", "HIGH"),
    ("SHA1", r"\bsha-?1\b|\bSHA1Managed\b|\bSHA1CryptoServiceProvider\b", "HIGH"),
    ("RC4", r"\brc4\b", "CRITICAL"),
    ("DES", r"\bdes\b(?!cription)", "CRITICAL"),
    ("3DES", r"\b3des\b|\btriple\s*des\b", "CRITICAL"),
    ("OpenSSL 1.0.x", r"\bOpenSSL[/\s_-]*1\.0\.\d+[a-z]?\b|\bopenssl\s*1\.0\.x\b", "CRITICAL"),
]


RISK_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# Machine-generated clock text is not protocol evidence.  The Telnet
# (`:23\b`) and FTP (`:21\b`) port heuristics fire on the seconds/minutes
# fields of wall-clock timestamps embedded in the flattened
# findings/cbom/apibom context: the T-9.15 deterministic-output gate
# observed identical scans flipping global_legacy_indicators 1 <-> 0
# because run1's clock hit `:23` inside
# 2026-11-01T17:37:23.115774Z and run2's clock missed.  Strip ISO
# timestamps, bare HH:MM:SS clocks and MM:SS.ss durations before
# pattern matching; real evidence (the `telnet` keyword, host:23 ports)
# has no clock shape and is unaffected.
_MACHINE_CLOCK = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?"
    r"|(?<!\d)\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"|(?<!\d)\d{2}:\d{2}\.\d+")


def _collect_text(obj: Any) -> str:
    if obj is None:
        return ""

    if isinstance(obj, str):
        return obj

    if isinstance(obj, dict):
        values = []
        for key, value in obj.items():
            if isinstance(value, (dict, list)):
                values.append(_collect_text(value))
            elif value is not None:
                values.append(str(value))
        return " ".join(values)

    if isinstance(obj, list):
        return " ".join(_collect_text(x) for x in obj)

    return str(obj)


def _detect_indicators(text: str) -> List[Dict[str, str]]:
    detected = []

    # Machine-generated clock text is not protocol evidence (see
    # _MACHINE_CLOCK): strip timestamp/duration shapes from the scanned
    # context so the port heuristics only see genuine port-like text.
    text = text or ""
    text = _MACHINE_CLOCK.sub(" ", text)

    for name, pattern, risk in LEGACY_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            detected.append({
                "indicator": name,
                "risk_level": risk,
                "evidence_match": name,
            })

    return detected


def _highest_risk(indicators: List[Dict[str, str]]) -> str:
    if not indicators:
        return "NONE"

    return max(
        indicators,
        key=lambda x: RISK_RANK.get(x.get("risk_level", "NONE"), 0),
    ).get("risk_level", "NONE")


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Deprecated protocol or weak cryptographic primitive may expose enterprise systems to interception, downgrade, or exploitation risk."
    if risk == "HIGH":
        return "Weak or deprecated cryptographic control identified and should be reviewed for remediation."
    if risk == "MEDIUM":
        return "Legacy security indicator observed but active exposure is not fully confirmed."
    return "No material legacy protocol risk identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediate remediation or compensating control review recommended."
    if risk == "HIGH":
        return "Prioritized remediation recommended."
    if risk == "MEDIUM":
        return "Validate exposure and remove deprecated configuration where confirmed."
    return "No action required."


def _count_indicator_groups(indicators: List[Dict[str, str]]) -> Dict[str, int]:
    names = {i.get("indicator") for i in indicators}

    return {
        "openssl_1_0_x_detected": 1 if "OpenSSL 1.0.x" in names else 0,
        "tls_deprecated_detected": 1 if {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"} & names else 0,
        "weak_hash_detected": 1 if {"MD5", "SHA1"} & names else 0,
        "weak_cipher_detected": 1 if {"RC4", "DES", "3DES"} & names else 0,
    }


# V17.9.25 SAFE: bounded CBOM projection for legacy-protocol heuristics.
_LEGACY_CBOM_MAX_CHARS = 120_000
_LEGACY_CBOM_MAX_DEPTH = 6
_LEGACY_CBOM_MAX_ITEMS = 5000
_LEGACY_CBOM_MAX_SCALAR = 4000
_LEGACY_CBOM_PRIORITY_KEYS = {
    "name", "component", "algorithm", "protocol", "scheme", "technology",
    "description", "evidence", "value", "type", "bom-ref", "bom_ref",
    "identifier", "id", "version",
}

def _collect_cbom_text(cbom, *, max_chars=_LEGACY_CBOM_MAX_CHARS,
                       max_depth=_LEGACY_CBOM_MAX_DEPTH,
                       max_items=_LEGACY_CBOM_MAX_ITEMS):
    parts = []
    total = 0
    visited = 0

    def add(value):
        nonlocal total
        if value is None or total >= max_chars:
            return
        text = str(value).strip()[:_LEGACY_CBOM_MAX_SCALAR]
        remaining = max_chars - total
        if remaining <= 0:
            return
        text = text[:remaining]
        parts.append(text)
        total += len(text)

    def walk(obj, depth):
        nonlocal visited
        if total >= max_chars or depth > max_depth or visited >= max_items:
            return
        visited += 1
        if isinstance(obj, dict):
            for key in _LEGACY_CBOM_PRIORITY_KEYS:
                if key not in obj:
                    continue
                value = obj[key]
                add(key)
                if isinstance(value, (dict, list, tuple, set)):
                    walk(value, depth + 1)
                else:
                    add(value)
                if total >= max_chars:
                    return
            for key, value in obj.items():
                if key in _LEGACY_CBOM_PRIORITY_KEYS:
                    continue
                if isinstance(value, (dict, list, tuple, set)):
                    continue
                add(key)
                add(value)
                if total >= max_chars:
                    return
        elif isinstance(obj, (list, tuple, set)):
            for value in obj:
                walk(value, depth + 1)
                if total >= max_chars or visited >= max_items:
                    return
        else:
            add(obj)

    walk(cbom, 0)
    return " ".join(parts)[:max_chars]


def enrich_legacy_protocol_intelligence(
    sbom: List[Dict[str, Any]],
    findings: List[Dict[str, Any]] = None,
    cbom: List[Dict[str, Any]] = None,
    api_bom: List[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:

    findings = findings or []
    cbom = cbom or []
    api_bom = api_bom or []

    component_legacy_indicators = 0
    critical_affected_components = 0
    high_affected_components = 0

    openssl_1_0_x_detected = 0
    tls_deprecated_detected = 0
    weak_hash_detected = 0
    weak_cipher_detected = 0

    enriched = []

    for pkg in sbom or []:
        pkg_text = _collect_text(pkg)
        indicators = _detect_indicators(pkg_text)
        risk = _highest_risk(indicators)

        component_legacy_indicators += len(indicators)

        if risk == "CRITICAL":
            critical_affected_components += 1
        elif risk == "HIGH":
            high_affected_components += 1

        group_counts = _count_indicator_groups(indicators)
        openssl_1_0_x_detected += group_counts["openssl_1_0_x_detected"]
        tls_deprecated_detected += group_counts["tls_deprecated_detected"]
        weak_hash_detected += group_counts["weak_hash_detected"]
        weak_cipher_detected += group_counts["weak_cipher_detected"]

        pkg["legacy_protocol_intelligence"] = {
            "legacy_protocol_detected": bool(indicators),
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
        _collect_cbom_text(cbom),
        _collect_text(api_bom),
    ])

    global_indicators = _detect_indicators(global_context)
    global_critical_indicators = sum(1 for i in global_indicators if i.get("risk_level") == "CRITICAL")
    global_high_indicators = sum(1 for i in global_indicators if i.get("risk_level") == "HIGH")

    global_group_counts = _count_indicator_groups(global_indicators)
    openssl_1_0_x_detected += global_group_counts["openssl_1_0_x_detected"]
    tls_deprecated_detected += global_group_counts["tls_deprecated_detected"]
    weak_hash_detected += global_group_counts["weak_hash_detected"]
    weak_cipher_detected += global_group_counts["weak_cipher_detected"]

    summary = {
        "component_legacy_indicators": component_legacy_indicators,
        "global_legacy_indicators": len(global_indicators),
        "critical_affected_components": critical_affected_components,
        "high_affected_components": high_affected_components,
        "global_critical_indicators": global_critical_indicators,
        "global_high_indicators": global_high_indicators,
        "openssl_1_0_x_detected": openssl_1_0_x_detected,
        "tls_deprecated_detected": tls_deprecated_detected,
        "weak_hash_detected": weak_hash_detected,
        "weak_cipher_detected": weak_cipher_detected,
        "global_indicators": global_indicators,
        "executive_status": (
            "LEGACY_PROTOCOL_RISK_IDENTIFIED"
            if component_legacy_indicators > 0 or global_indicators
            else "NO_LEGACY_PROTOCOL_RISK_IDENTIFIED"
        ),
    }

    return enriched, summary