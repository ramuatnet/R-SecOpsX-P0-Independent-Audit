try:
    from analysis.spans import WINDOW_EVIDENCE
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_EVIDENCE
import re
from collections import defaultdict
from typing import Any, Dict, List, Tuple

# Enterprise Crypto Misuse Intelligence V2
# Static context analysis only. Not cryptographic proof.

CRYPTO_MISUSE_PATTERNS = [
    ("MD5_USAGE", r"\bmd5\b|\bhashlib\.md5\b", "HIGH", "MD5", "Weak hash algorithm", "Use SHA-256/SHA-512 or password-specific hashing such as bcrypt/Argon2."),
    ("SHA1_USAGE", r"\bsha1\b|\bhashlib\.sha1\b", "HIGH", "SHA1", "Weak hash algorithm", "Use SHA-256/SHA-512 or stronger approved hash algorithms."),

    ("DES_USAGE", r"\bDES\b|\bCrypto\.Cipher\.DES\b", "CRITICAL", "DES", "Weak cipher", "Replace DES with AES-GCM or ChaCha20-Poly1305."),
    ("TRIPLE_DES_USAGE", r"\b3DES\b|\bTripleDES\b", "CRITICAL", "3DES", "Deprecated cipher", "Replace 3DES with AES-GCM or ChaCha20-Poly1305."),
    ("RC4_USAGE", r"\bRC4\b|\bARC4\b", "CRITICAL", "RC4", "Broken stream cipher", "Remove RC4 and use modern authenticated encryption."),

    ("SSLV2_USAGE", r"\bSSLv2\b|\bPROTOCOL_SSLv2\b", "CRITICAL", "SSLv2", "Obsolete protocol", "Disable SSLv2 immediately."),
    ("SSLV3_USAGE", r"\bSSLv3\b|\bPROTOCOL_SSLv3\b", "CRITICAL", "SSLv3", "Obsolete protocol", "Disable SSLv3 immediately."),
    ("TLS10_USAGE", r"\bTLSv1\.0\b|\bPROTOCOL_TLSv1\b", "HIGH", "TLS1.0", "Deprecated TLS protocol", "Require TLS 1.2+ or TLS 1.3."),
    ("TLS11_USAGE", r"\bTLSv1\.1\b|\bPROTOCOL_TLSv1_1\b", "HIGH", "TLS1.1", "Deprecated TLS protocol", "Require TLS 1.2+ or TLS 1.3."),

    ("AES_ECB_MODE", r"\bMODE_ECB\b|\bAES\.ECB\b", "CRITICAL", "AES-ECB", "Insecure block mode", "Use AES-GCM, AES-CCM, or ChaCha20-Poly1305."),
    ("STATIC_IV", r"\biv\s*=\s*['\"][A-Za-z0-9+/=]{8,}['\"]", "HIGH", "IV", "Static IV", "Generate a unique random IV/nonce per encryption operation."),
    ("HARDCODED_SALT", r"\bsalt\s*=\s*['\"][A-Za-z0-9+/=]{4,}['\"]", "HIGH", "Salt", "Hardcoded salt", "Generate unique salts per password/secret derivation."),

    ("INSECURE_RANDOM", r"\brandom\.randint\b|\brandom\.random\b", "HIGH", "Random", "Non-cryptographic randomness", "Use secrets or os.urandom for security tokens."),
    ("PREDICTABLE_TOKEN", r"\btoken\s*=\s*random\b|\bnonce\s*=\s*random\b", "HIGH", "Token/Nonce", "Predictable token generation", "Use cryptographically secure random generation."),

    ("PBKDF2_LOW_ITERATION", r"\bPBKDF2\b.*\b(1000|500|100)\b", "HIGH", "PBKDF2", "Low KDF iteration count", "Increase iterations per current security baseline or use Argon2id/bcrypt."),
    ("NO_PASSWORD_HASHING", r"\bpassword\s*=\s*['\"][^'\"]+['\"]", "HIGH", "Password", "Plaintext/static password indicator", "Use salted password hashing and avoid hardcoded passwords."),

    ("CERT_VALIDATION_DISABLED", r"\bverify\s*=\s*False\b|\bcheck_hostname\s*=\s*False\b", "CRITICAL", "TLS Certificate Validation", "Certificate validation disabled", "Enable certificate and hostname validation."),
    ("TRUST_ALL_CERTS", r"\btrustAllCerts\b|\bInsecureSkipVerify\b", "CRITICAL", "TLS Trust", "Trust-all certificate behavior", "Remove trust-all logic and enforce trusted CA validation."),
]

RISK_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


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


def _function_name(item: Dict[str, Any]) -> str:
    return str(
        item.get("function_name")
        or item.get("function")
        or item.get("method")
        or item.get("method_name")
        or ""
    ).strip()


def _item_text(item: Dict[str, Any]) -> str:
    return " ".join([
        str(item.get("title", "")),
        str(item.get("description", "")),
        str(item.get("snippet", "")),
        str(item.get("evidence", "")),
        str(item.get("file", "")),
        str(item.get("file_path", "")),
        _collect_text(item.get("occurrences", [])),
    ])


def _highest_risk(indicators: List[Dict[str, Any]]) -> str:
    if not indicators:
        return "NONE"
    return max(indicators, key=lambda x: RISK_RANK.get(x.get("risk_level", "NONE"), 0)).get("risk_level", "NONE")


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Cryptographic misuse may enable data compromise, session interception, downgrade exposure, or trust bypass."
    if risk == "HIGH":
        return "Weak cryptographic controls may expose sensitive data to unauthorized access, offline attack, or integrity compromise."
    if risk == "MEDIUM":
        return "Cryptographic hygiene indicator observed and should be reviewed."
    return "No material cryptographic misuse identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediately replace insecure algorithms, modes, protocols, or trust-bypass behavior before release."
    if risk == "HIGH":
        return "Upgrade algorithms, randomness, salts, key derivation, and TLS configuration to approved secure baselines."
    if risk == "MEDIUM":
        return "Validate cryptographic implementation against secure engineering standards."
    return "No action required."


def _detect_context(
    context_id: str,
    context_type: str,
    text: str,
    evidence: Dict[str, Any],
) -> List[Dict[str, Any]]:
    indicators = []

    for name, pattern, risk, algorithm, reason, guidance in CRYPTO_MISUSE_PATTERNS:
        match = re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL)
        if not match:
            continue

        indicators.append({
            "context_id": context_id,
            "context_type": context_type,
            "indicator": name,
            "risk_level": risk,
            "algorithm": algorithm,
            "mode": algorithm if "MODE" in name or "ECB" in name else None,
            "risk_reason": reason,
            "migration_guidance": guidance,
            "confidence": "Medium",
            # Preserve authoritative confirmation only for an individual
            # finding. Aggregated file/function/CBOM contexts remain
            # contextual static evidence and are not auto-confirmed.
            "crypto_confirmed": bool(
                context_type == "FINDING"
                and evidence.get("finding_class") == "confirmed"
                and evidence.get("evidence_valid") is True
            ),
            "executive_relevant": False,
            "confirmed_executive_risk": False,
            "crypto_misuse": True,
            "evidence_match": match.group(0)[:WINDOW_EVIDENCE],
            "evidence": evidence or {},
        })

    return indicators


def _dedupe(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # One underlying cryptographic misuse should be one risk object even when
    # it is observed through FINDING, FILE_CONTEXT and CBOM evidence.
    deduped = {}
    for item in indicators:
        evidence = item.get("evidence") or {}
        file_key = str(
            evidence.get("file")
            or item.get("context_id")
            or ""
        )
        line_key = evidence.get("line")
        # Contexts are corroborating evidence for the same underlying usage.
        # Canonicalize by indicator + algorithm + file so FINDING, FILE_CONTEXT
        # and CBOM_CONTEXT do not inflate the risk count.
        key = (
            item.get("indicator"),
            item.get("algorithm"),
            file_key,
        )
        existing = deduped.get(key)
        if existing is None:
            item = dict(item)
            item["evidence_contexts"] = [item.get("context_type")]
            deduped[key] = item
            continue

        contexts = existing.setdefault("evidence_contexts", [])
        if item.get("context_type") not in contexts:
            contexts.append(item.get("context_type"))

        old_rank = RISK_RANK.get(existing.get("risk_level", "NONE"), 0)
        new_rank = RISK_RANK.get(item.get("risk_level", "NONE"), 0)
        if new_rank > old_rank:
            item = dict(item)
            item["evidence_contexts"] = contexts
            deduped[key] = item

    return list(deduped.values())


def enrich_crypto_misuse(
    findings: List[Dict[str, Any]],
    cbom: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    findings = findings or []
    cbom = cbom or []

    indicators = []
    file_groups = defaultdict(list)
    function_groups = defaultdict(list)

    for finding in findings:
        text = _item_text(finding)
        file_key = finding.get("file") or finding.get("file_path")
        fn = _function_name(finding)

        context_id = str(
            finding.get("id")
            or finding.get("rule_id")
            or finding.get("title")
            or file_key
            or "finding"
        )

        indicators.extend(_detect_context(
            context_id=context_id,
            context_type="FINDING",
            text=text,
            evidence={
                "file": file_key,
                "line": finding.get("line"),
                "rule_id": finding.get("rule_id"),
                "title": finding.get("title"),
                "function_name": fn or None,
                "finding_class": str(finding.get("finding_class") or "").lower(),
                "evidence_valid": finding.get("evidence_valid"),
            },
        ))

        if file_key:
            file_groups[str(file_key)].append(finding)
        if file_key and fn:
            function_groups[(str(file_key), fn)].append(finding)

    for file_key, grouped in file_groups.items():
        indicators.extend(_detect_context(
            context_id=file_key,
            context_type="FILE_CONTEXT",
            text=" ".join(_item_text(x) for x in grouped),
            evidence={
                "file": file_key,
                "finding_count": len(grouped),
            },
        ))

    for (file_key, fn), grouped in function_groups.items():
        indicators.extend(_detect_context(
            context_id=f"{file_key}::{fn}",
            context_type="FUNCTION_CONTEXT",
            text=" ".join(_item_text(x) for x in grouped),
            evidence={
                "file": file_key,
                "function_name": fn,
                "finding_count": len(grouped),
            },
        ))

    for component in cbom:
        context_id = str(
            component.get("algorithm")
            or component.get("primitive")
            or component.get("name")
            or component.get("component")
            or "cbom_component"
        )

        indicators.extend(_detect_context(
            context_id=context_id,
            context_type="CBOM_COMPONENT_CONTEXT",
            text=_collect_text(component),
            evidence={
                "algorithm": component.get("algorithm") or component.get("primitive"),
                "file": component.get("file"),
                "line": component.get("line"),
                "usage": component.get("usage"),
            },
        ))

    indicators = _dedupe(indicators)

    critical = sum(1 for i in indicators if i.get("risk_level") == "CRITICAL")
    high = sum(1 for i in indicators if i.get("risk_level") == "HIGH")
    medium = sum(1 for i in indicators if i.get("risk_level") == "MEDIUM")
    # Static cryptographic heuristics are not executive/release evidence unless
    # the finding has been independently confirmed.
    executive_relevant = sum(
        1 for i in indicators
        if i.get("crypto_confirmed") is True
        and i.get("risk_level") in {"CRITICAL", "HIGH"}
    )
    for item in indicators:
        item["confirmed_executive_risk"] = bool(
            item.get("crypto_confirmed") is True
            and item.get("risk_level") in {"CRITICAL", "HIGH"}
        )
        item["executive_relevant"] = item["confirmed_executive_risk"]

    highest_risk = _highest_risk(indicators)

    by_context = {
        "finding_context": sum(1 for i in indicators if i.get("context_type") == "FINDING"),
        "file_context": sum(1 for i in indicators if i.get("context_type") == "FILE_CONTEXT"),
        "function_context": sum(1 for i in indicators if i.get("context_type") == "FUNCTION_CONTEXT"),
        "cbom_component_context": sum(1 for i in indicators if i.get("context_type") == "CBOM_COMPONENT_CONTEXT"),
    }

    return {
        "total_crypto_misuse_indicators": len(indicators),
        "critical_crypto_misuse_indicators": critical,
        "high_crypto_misuse_indicators": high,
        "medium_crypto_misuse_indicators": medium,
        "executive_relevant_indicators": executive_relevant,
        "highest_risk_indicator": highest_risk,
        "by_context": by_context,
        "crypto_confirmed": any(
            i.get("crypto_confirmed") is True for i in indicators
        ),
        "engine_mode": "STATIC_CONTEXT_CRYPTO_MISUSE_INTELLIGENCE_V2",
        "summary_status": (
            "CRYPTO_MISUSE_IDENTIFIED"
            if indicators
            else "NO_CRYPTO_MISUSE_IDENTIFIED"
        ),
        "executive_risk_status": (
            "CONFIRMED_EXECUTIVE_CRYPTO_RISK_IDENTIFIED"
            if executive_relevant > 0
            else "NO_CONFIRMED_EXECUTIVE_CRYPTO_RISK"
        ),
        "enterprise_impact": _impact_for(highest_risk),
        "recommended_action": _action_for(highest_risk),
        "indicators": indicators,
    }