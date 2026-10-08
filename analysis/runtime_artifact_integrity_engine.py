import re
from typing import Any, Dict, List, Tuple


ARTIFACT_PATTERNS = [
    # --------------------------------------------------
    # Artifact Presence - inventory signal only
    # --------------------------------------------------
    ("JAVA_ARTIFACT_PRESENT", r"\.(jar|war|ear)\b", "LOW", True),
    ("NATIVE_BINARY_PRESENT", r"\.(dll|exe|so|dylib)\b", "LOW", True),
    ("MOBILE_ARTIFACT_PRESENT", r"\.(apk|ipa)\b", "LOW", True),

    # --------------------------------------------------
    # Signing / Integrity Gaps
    # --------------------------------------------------
    ("UNSIGNED_JAR", r"\bunsigned\b.*\.(jar|war|ear)\b|\.(jar|war|ear)\b.*\bunsigned\b", "HIGH", False),
    ("UNSIGNED_CONTAINER_IMAGE", r"\bunsigned\s+container\s+image\b|\bimage\s+signature\s+missing\b", "HIGH", False),
    ("DOCKER_IMAGE_NOT_DIGEST_PINNED", r"\bFROM\s+[^\s]+:[^\s]+(?!@sha256:)", "HIGH", False),

    # --------------------------------------------------
    # Checksum / Hash Gaps
    # --------------------------------------------------
    ("CHECKSUM_FILE_MISSING", r"\bchecksum\s+(file\s+)?missing\b|\bmissing\s+checksum\b", "MEDIUM", False),
    ("SHA256SUMS_MISSING", r"\bSHA256SUMS\s+missing\b|\bmissing\s+SHA256SUMS\b", "MEDIUM", False),

    # --------------------------------------------------
    # SBOM / Provenance / Attestation Gaps
    # --------------------------------------------------
    ("SBOM_MISSING_FOR_ARTIFACT", r"\bsbom\s+(missing|not\s+found|unavailable)\b|\bmissing\s+sbom\b", "HIGH", False),
    ("PROVENANCE_FILE_MISSING", r"\bprovenance\s+(missing|not\s+found|unavailable)\b|\bmissing\s+provenance\b|\bslsa\s+(missing|not\s+found)\b", "HIGH", False),
    ("IN_TOTO_ATTESTATION_MISSING", r"\bin-toto\s+(missing|not\s+found|unavailable)\b|\battestation\s+(missing|not\s+found|unavailable)\b", "HIGH", False),
    ("SIGSTORE_COSIGN_SIGNATURE_MISSING", r"\bcosign\s+(signature\s+)?(missing|not\s+found|unavailable)\b|\bsigstore\s+(signature\s+)?(missing|not\s+found|unavailable)\b", "HIGH", False),

    # --------------------------------------------------
    # Unsafe Artifact Acquisition
    # --------------------------------------------------
    ("ARTIFACT_DOWNLOADED_OVER_HTTP", r"http://[^\s\"']+\.(jar|war|ear|exe|dll|so|dylib|apk|ipa)\b", "HIGH", False),
    ("ARTIFACT_DOWNLOAD_NO_CHECKSUM", r"\b(curl|wget)\b(?!.*(sha256|sha512|checksum|gpg|cosign|sigstore)).*\.(jar|war|ear|exe|dll|so|dylib|apk|ipa)\b", "HIGH", False),

    # --------------------------------------------------
    # Binary Packing / Obfuscation
    # --------------------------------------------------
    ("UPX_PACKED_BINARY", r"\bUPX\b|\bupx\s+-", "HIGH", False),
    ("ASPACK_PACKED_BINARY", r"\bASPack\b", "HIGH", False),
    ("THEMIDA_PACKED_BINARY", r"\bThemida\b", "HIGH", False),

    # --------------------------------------------------
    # Embedded Secrets
    # --------------------------------------------------
    ("EMBEDDED_SECRET_ARTIFACT", r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----", "CRITICAL", False),

    # --------------------------------------------------
    # Tamper / Drift Indicators
    # --------------------------------------------------
    ("HASH_MISMATCH", r"\bhash mismatch\b|\bchecksum mismatch\b|\bdigest mismatch\b", "CRITICAL", False),
    ("BINARY_DRIFT", r"\bbinary drift\b|\bartifact drift\b|\bbuild drift\b", "HIGH", False),
    ("MODIFIED_RELEASE_ARTIFACT", r"\bmodified artifact\b|\brepacked\b|\brepackaged\b|\breplaced release asset\b", "HIGH", False),

    # --------------------------------------------------
    # Source / Publisher Trust
    # --------------------------------------------------
    ("UNKNOWN_PUBLISHER", r"\bunknown publisher\b|\buntrusted publisher\b", "HIGH", False),
    ("UNTRUSTED_ARTIFACT_SOURCE", r"\buntrusted artifact source\b|\buntrusted download source\b", "HIGH", False),
    ("MUTABLE_RELEASE_ASSET", r"\bmutable release asset\b|\blatest release asset\b", "HIGH", False),
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

    for name, pattern, risk, presence_only in ARTIFACT_PATTERNS:
        if re.search(pattern, text or "", flags=re.IGNORECASE):
            # Digest pinning is a release-control gap, not proof of a
            # compromised artifact. Keep the finding visible at HIGH risk,
            # but do not promote it to executive-confirmed risk without
            # artifact/runtime evidence.
            executive_relevant = (
                risk in {"CRITICAL", "HIGH"}
                and not presence_only
                and name != "DOCKER_IMAGE_NOT_DIGEST_PINNED"
            )
            detected.append({
                "indicator": name,
                "risk_level": risk,
                "evidence_match": name,
                "executive_relevant": executive_relevant,
                "artifact_presence_only": presence_only,
            })

    return detected


def _highest_risk(indicators: List[Dict[str, Any]]) -> str:
    risk_indicators = [
        i for i in indicators
        if not i.get("artifact_presence_only")
    ]

    if not risk_indicators:
        return "NONE"

    return max(
        risk_indicators,
        key=lambda x: RISK_RANK.get(x.get("risk_level", "NONE"), 0),
    ).get("risk_level", "NONE")


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Artifact integrity issue may indicate tampering, embedded secrets, or compromised release material."
    if risk == "HIGH":
        return "Artifact trust gap may materially weaken release assurance, provenance, or runtime integrity."
    if risk == "MEDIUM":
        return "Artifact integrity control gap observed and should be reviewed for release governance."
    if risk == "LOW":
        return "Artifact inventory signal observed; no direct integrity risk established."
    return "No material runtime artifact integrity issue identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediately validate artifact provenance, rotate exposed secrets if present, and block release until integrity is confirmed."
    if risk == "HIGH":
        return "Require signed artifacts, digest-pinned images, checksum validation, and provenance attestation before release."
    if risk == "MEDIUM":
        return "Add checksum, SBOM, provenance, and attestation controls to the artifact release process."
    if risk == "LOW":
        return "Track artifact inventory and validate integrity controls during normal release governance."
    return "No action required."


def enrich_runtime_artifact_integrity(
    sbom: List[Dict[str, Any]],
    findings: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
    api_bom: List[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:

    findings = findings or []
    abom = abom or []
    api_bom = api_bom or []

    total_artifact_integrity_indicators = 0
    total_artifact_presence_indicators = 0
    critical_affected_components = 0
    high_affected_components = 0

    unsigned_artifacts = 0
    tampered_artifacts = 0
    packed_binaries = 0
    embedded_secret_artifacts = 0
    provenance_gaps = 0
    digest_pinning_gaps = 0
    checksum_gaps = 0
    sbom_gaps = 0

    enriched = []

    for pkg in sbom or []:
        pkg_text = _collect_text(pkg)
        indicators = _detect_indicators(pkg_text)
        risk = _highest_risk(indicators)

        risk_indicators = [
            i for i in indicators
            if not i.get("artifact_presence_only")
        ]

        presence_indicators = [
            i for i in indicators
            if i.get("artifact_presence_only")
        ]

        total_artifact_integrity_indicators += len(risk_indicators)
        total_artifact_presence_indicators += len(presence_indicators)

        if risk == "CRITICAL":
            critical_affected_components += 1
        elif risk == "HIGH":
            high_affected_components += 1

        names = {i.get("indicator") for i in indicators}

        if {"UNSIGNED_JAR", "UNSIGNED_CONTAINER_IMAGE", "SIGSTORE_COSIGN_SIGNATURE_MISSING"} & names:
            unsigned_artifacts += 1

        if {"HASH_MISMATCH", "BINARY_DRIFT", "MODIFIED_RELEASE_ARTIFACT"} & names:
            tampered_artifacts += 1

        if {"UPX_PACKED_BINARY", "ASPACK_PACKED_BINARY", "THEMIDA_PACKED_BINARY"} & names:
            packed_binaries += 1

        if "EMBEDDED_SECRET_ARTIFACT" in names:
            embedded_secret_artifacts += 1

        if {"PROVENANCE_FILE_MISSING", "IN_TOTO_ATTESTATION_MISSING"} & names:
            provenance_gaps += 1

        if "DOCKER_IMAGE_NOT_DIGEST_PINNED" in names:
            digest_pinning_gaps += 1

        if {"CHECKSUM_FILE_MISSING", "SHA256SUMS_MISSING", "ARTIFACT_DOWNLOAD_NO_CHECKSUM"} & names:
            checksum_gaps += 1

        if "SBOM_MISSING_FOR_ARTIFACT" in names:
            sbom_gaps += 1

        pkg["runtime_artifact_integrity"] = {
            "artifact_integrity_issue_detected": bool(risk_indicators),
            "artifact_presence_detected": bool(presence_indicators),
            "indicators": indicators,
            "risk_level": risk,
            "enterprise_impact": _impact_for(risk),
            "recommended_action": _action_for(risk),
            "evidence": [i.get("evidence_match") for i in indicators],
            "scope": "SBOM_COMPONENT",
            "engine_mode": "OFFLINE_RULE_BASED",
        }

        enriched.append(pkg)

    # Source-code SAST findings are not runtime artifact evidence. In
    # particular, a PRIVATE_KEY SAST finding must not be promoted to
    # EMBEDDED_SECRET_ARTIFACT merely because the global context contains the
    # same text. Runtime artifact evidence comes from artifact/package/ABOM
    # inventory and explicit artifact integrity observations.
    global_context = " ".join([
        _collect_text(abom),
        _collect_text(api_bom),
    ])

    global_indicators = _detect_indicators(global_context)
    global_risk_indicators = [
        i for i in global_indicators
        if not i.get("artifact_presence_only")
    ]
    global_presence_indicators = [
        i for i in global_indicators
        if i.get("artifact_presence_only")
    ]

    global_critical_indicators = sum(
        1 for i in global_risk_indicators if i.get("risk_level") == "CRITICAL"
    )
    global_high_indicators = sum(
        1 for i in global_risk_indicators if i.get("risk_level") == "HIGH"
    )
    executive_relevant_global_indicators = sum(
        1 for i in global_risk_indicators if i.get("executive_relevant") is True
    )

    summary = {
        "total_artifact_integrity_indicators": total_artifact_integrity_indicators,
        "total_artifact_presence_indicators": total_artifact_presence_indicators,
        "critical_affected_components": critical_affected_components,
        "high_affected_components": high_affected_components,
        "unsigned_artifacts": unsigned_artifacts,
        "tampered_artifacts": tampered_artifacts,
        "packed_binaries": packed_binaries,
        "embedded_secret_artifacts": embedded_secret_artifacts,
        "provenance_gaps": provenance_gaps,
        "digest_pinning_gaps": digest_pinning_gaps,
        "checksum_gaps": checksum_gaps,
        "sbom_gaps": sbom_gaps,
        "global_artifact_integrity_indicators": len(global_risk_indicators),
        "global_artifact_presence_indicators": len(global_presence_indicators),
        "global_critical_indicators": global_critical_indicators,
        "global_high_indicators": global_high_indicators,
        "executive_relevant_global_indicators": executive_relevant_global_indicators,
        "global_indicators": global_indicators,
        "engine_mode": "OFFLINE_RULE_BASED",
        "summary_status": (
            "ARTIFACT_INTEGRITY_RISK_IDENTIFIED"
            if total_artifact_integrity_indicators > 0
            or executive_relevant_global_indicators > 0
            else "NO_ARTIFACT_INTEGRITY_RISK_IDENTIFIED"
        ),
    }

    return enriched, summary