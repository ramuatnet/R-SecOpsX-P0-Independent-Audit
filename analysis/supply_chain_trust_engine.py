import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


# A trust pattern states something about how a dependency is DECLARED or
# RESOLVED (a ``latest`` range, a ``git+ssh`` URL, a missing pin), so every
# pattern is evaluated only against the fields where a declaration can live.
# Whole-record text used to be scanned instead, and that matched text which
# merely *describes* a package: the CPE 2.3 wildcard form
# (``cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`` -- stamped onto every
# component by the CPE builder) satisfies ``\*`` and labelled all 822
# CPE-bearing components of an 823-package scan UNPINNED/HIGH, while advisory
# prose ("upgrade to the latest version", a github.com advisory link, a
# ``../`` example) satisfied the remaining patterns.  Field-scoping also
# keeps evaluation stable as the record schema grows: a field added by a
# later enrichment pass is invisible here until it is deliberately listed.

# The dependency's own specifier / version requirement.
SPEC_FIELDS: Tuple[str, ...] = (
    "version",
    "declared_version",
    "declared_range",
    "specifier",
    "range",
    "requirement",
    "specified_version",
)

# Where the dependency resolves from.
RESOLUTION_FIELDS: Tuple[str, ...] = (
    "resolved",
    "resolved_url",
    "source_url",
    "registry",
)

# Identity -- name hygiene only, never spec or URL semantics: a Go module
# path such as ``github.com/foo/bar`` appearing in ``name`` is identity, not
# a git-checkout dependency.
NAME_FIELDS: Tuple[str, ...] = ("name",)

SPEC_OR_RESOLUTION: Tuple[str, ...] = SPEC_FIELDS + RESOLUTION_FIELDS

TRUST_PATTERNS = [
    ("UNPINNED_DEPENDENCY", r"latest|\*|>=|>|~=", "HIGH", SPEC_FIELDS),
    ("MUTABLE_TAG", r":latest\b|\blatest\b", "HIGH", SPEC_OR_RESOLUTION),
    ("GIT_DEPENDENCY", r"git\+|github\.com|gitlab\.com|bitbucket\.org", "MEDIUM", SPEC_OR_RESOLUTION),
    ("HTTP_DEPENDENCY", r"http://", "HIGH", SPEC_OR_RESOLUTION),
    ("LOCAL_PATH_DEPENDENCY", r"\.\./|file:", "MEDIUM", SPEC_OR_RESOLUTION),
    ("PRIVATE_NAMESPACE_HINT", r"@internal|@private|company-|corp-|internal-", "MEDIUM", NAME_FIELDS),
    ("SUSPICIOUS_NAME_PATTERN", r"[-_](test|demo|tmp|temp|backup|old)$", "LOW", NAME_FIELDS),
]


RISK_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _field_text(pkg: Dict[str, Any], fields: Tuple[str, ...]) -> str:
    """The record's values for exactly ``fields`` -- nothing else."""
    values: List[str] = []
    for field in fields:
        value = pkg.get(field)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            values.extend(str(item) for item in value if item is not None)
        else:
            values.append(str(value))
    return " ".join(values)


def _detect_indicators(pkg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate each trust pattern only against the fields it can be true in."""
    detected = []

    for name, pattern, risk, fields in TRUST_PATTERNS:
        if re.search(pattern, _field_text(pkg, fields), flags=re.IGNORECASE):
            detected.append({
                "indicator": name,
                "risk_level": risk,
                "evidence_match": name,
                # Static trust-pattern evidence is a review signal, not proof
                # of executive compromise. Executive relevance requires a
                # separately confirmed material condition.
                "executive_relevant": False,
                "confirmed_executive_risk": False,
            })

    return detected


def _highest_risk(indicators: List[Dict[str, Any]]) -> str:
    if not indicators:
        return "NONE"

    return max(
        indicators,
        key=lambda x: RISK_RANK.get(x.get("risk_level", "NONE"), 0),
    ).get("risk_level", "NONE")


def _is_unpinned_version(version: Any) -> bool:
    if version is None:
        return True

    v = str(version).strip().lower()

    if not v or v in {"*", "latest", "unknown", "none", "null"}:
        return True

    if any(token in v for token in [">=", ">", "~=", "^", "x"]):
        return True

    return False


def _release_date(pkg: Dict[str, Any]) -> Any:
    """The package's own release date, or None when the record carries none.

    ``published_date`` is excluded: on this platform that key holds the
    *advisory's* publication date (written by ``vulnerability_age_engine``).
    """
    return (
        pkg.get("release_date")
        or pkg.get("created")
        or pkg.get("created_at")
        or pkg.get("package_published")
    )


def _looks_recent(pkg: Dict[str, Any], max_days: int = 30) -> bool:
    """True when the PACKAGE's own release date is within ``max_days``.

    Freshness is a supply-chain concept (freshly published packages are
    statistically more likely to be malicious); a newly disclosed ADVISORY is
    the opposite signal and already has its own engine and report column.
    Reading the advisory date here used to count every new CVE as
    ``RECENTLY_PUBLISHED_PACKAGE``.  With no release date observed on the
    record this returns False: freshness is reported only from real
    package-release evidence.
    """
    date_value = _release_date(pkg)

    if not date_value:
        return False

    try:
        text = str(date_value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - dt).days
        return 0 <= age_days <= max_days
    except Exception:
        return False


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Supply chain trust issue may allow dependency confusion, malicious package substitution, or untrusted code execution."
    if risk == "HIGH":
        return "Weak dependency trust control may materially increase build integrity or release assurance risk."
    if risk == "MEDIUM":
        return "Dependency trust indicator observed and should be reviewed for provenance and governance."
    if risk == "LOW":
        return "Low-confidence supply chain naming or hygiene indicator observed."
    return "No material supply chain trust issue identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediate validation of package source, namespace ownership, and dependency pinning recommended."
    if risk == "HIGH":
        return "Pin versions, remove mutable tags, and validate package provenance before release."
    if risk == "MEDIUM":
        return "Review source repository, maintainer trust, and dependency governance."
    if risk == "LOW":
        return "Review package naming and dependency hygiene during normal maintenance."
    return "No action required."


def enrich_supply_chain_trust(
    sbom: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:

    total_indicators = 0
    critical_affected_components = 0
    high_affected_components = 0
    unpinned_dependencies = 0
    git_dependencies = 0
    mutable_tags = 0
    recent_packages = 0
    private_namespace_hints = 0
    unique_component_risk_keys = set()
    unique_high_component_risk_keys = set()
    unique_critical_component_risk_keys = set()

    enriched = []

    for pkg in sbom or []:
        indicators = _detect_indicators(pkg)

        version = pkg.get("version")

        if _is_unpinned_version(version):
            indicators.append({
                "indicator": "UNPINNED_VERSION",
                "risk_level": "HIGH",
                "evidence_match": str(version),
                "executive_relevant": False,
                "confirmed_executive_risk": False,
            })

        if _looks_recent(pkg):
            indicators.append({
                "indicator": "RECENTLY_PUBLISHED_PACKAGE",
                "risk_level": "MEDIUM",
                "evidence_match": str(_release_date(pkg)),
                "executive_relevant": False,
                "confirmed_executive_risk": False,
            })

        risk = _highest_risk(indicators)
        names = {i.get("indicator") for i in indicators}

        # Count a component/risk once at portfolio level. Multiple trust
        # indicators on the same package remain available as evidence but do
        # not inflate the affected-component metric.
        component_key = str(
            pkg.get("purl")
            or pkg.get("bom_ref")
            or pkg.get("package_url")
            or f"{pkg.get('ecosystem','')}:{pkg.get('name','')}:{pkg.get('version','')}"
        ).strip().lower()
        risk_key = (component_key, risk or "NONE")
        if indicators:
            unique_component_risk_keys.add(risk_key)
        if risk == "HIGH":
            unique_high_component_risk_keys.add(risk_key)
        elif risk == "CRITICAL":
            unique_critical_component_risk_keys.add(risk_key)

        total_indicators += len(indicators)

        if risk == "CRITICAL":
            critical_affected_components += 1
        elif risk == "HIGH":
            high_affected_components += 1

        if "UNPINNED_VERSION" in names or "UNPINNED_DEPENDENCY" in names:
            unpinned_dependencies += 1

        if "GIT_DEPENDENCY" in names:
            git_dependencies += 1

        if "MUTABLE_TAG" in names:
            mutable_tags += 1

        if "RECENTLY_PUBLISHED_PACKAGE" in names:
            recent_packages += 1

        if "PRIVATE_NAMESPACE_HINT" in names:
            private_namespace_hints += 1

        pkg["supply_chain_trust_intelligence"] = {
            "supply_chain_trust_issue_detected": bool(indicators),
            "indicators": indicators,
            "highest_risk_indicator": risk,
            "risk_level": risk,
            "unique_component_risk_key": f"{component_key}|{risk or 'NONE'}",
            "enterprise_impact": _impact_for(risk),
            "recommended_action": _action_for(risk),
            "evidence": [i.get("evidence_match") for i in indicators],
            "scope": "SBOM_COMPONENT",
            "engine_mode": "OFFLINE_RULE_BASED",
            "governance_semantics": "STATIC_SUPPLY_CHAIN_EVIDENCE_REQUIRES_SEPARATE_EXECUTIVE_CONFIRMATION",
            "confirmed_executive_risk": False,
            "executive_relevant": False,
        }

        enriched.append(pkg)

    summary = {
        "total_supply_chain_trust_indicators": total_indicators,
        "critical_affected_components": critical_affected_components,
        "high_affected_components": high_affected_components,
        "unique_affected_component_risks": len(unique_component_risk_keys),
        "unique_high_component_risks": len(unique_high_component_risk_keys),
        "unique_critical_component_risks": len(unique_critical_component_risk_keys),
        "unpinned_dependencies": unpinned_dependencies,
        "git_dependencies": git_dependencies,
        "mutable_tags": mutable_tags,
        "recent_packages": recent_packages,
        "private_namespace_hints": private_namespace_hints,

        "package_risk_summary": {
            "affected_components": critical_affected_components + high_affected_components,
            "unique_affected_component_risks": len(unique_component_risk_keys),
            "unique_critical_component_risks": len(unique_critical_component_risk_keys),
            "unique_high_component_risks": len(unique_high_component_risk_keys),
            "critical_affected_components": critical_affected_components,
            "high_affected_components": high_affected_components,
            "unpinned_dependencies": unpinned_dependencies,
            "git_dependencies": git_dependencies,
            "mutable_tags": mutable_tags,
            "recent_packages": recent_packages,
            "private_namespace_hints": private_namespace_hints,
        },

        "global_risk_summary": {
            "total_global_indicators": total_indicators,
            "manifest_trust_indicators": unpinned_dependencies + git_dependencies + mutable_tags,
            "namespace_trust_indicators": private_namespace_hints,
            "freshness_trust_indicators": recent_packages,
        },

        "engine_mode": "OFFLINE_RULE_BASED",
        "summary_status": (
            "SUPPLY_CHAIN_TRUST_RISK_IDENTIFIED"
            if total_indicators > 0
            else "NO_SUPPLY_CHAIN_TRUST_RISK_IDENTIFIED"
        ),
    }

    return enriched, summary