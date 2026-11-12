from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from analysis.intelligence_provenance import NOT_AVAILABLE, STATIC_REFERENCE


CYCLONEDX_VERSION = "1.5"

# R1/W1 (GAP-04): endpoint classes the npm graph engine emits as raw ids
# (analysis/npm_lock_graph_v2.py). Every serialized ref must resolve inside
# its own document; endpoints that cannot are dropped and counted in a
# disclosed tally -- never shipped as dangling references.
NPM_ROOT_REF = "pkg:npm/__root__"
_NPM_WORKSPACE_PREFIX = "pkg:npm-workspace/"
_NPM_FILE_PREFIX = "pkg:npm-file/"

# Keys must include the strings the manifest parsers actually EMIT
# (scanner/sbom.py and scanner/manifests/*): "crates.io", "Packagist",
# "RubyGems", "Go". The legacy aliases (cargo/composer/gem/golang) stay
# for records that arrived from other paths.
_PURL_TYPE_BY_ECOSYSTEM = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "go": "golang",
    "golang": "golang",
    "cargo": "cargo",
    "crates.io": "cargo",
    "nuget": "nuget",
    "composer": "composer",
    "packagist": "composer",
    "gem": "gem",
    "rubygems": "gem",
}


def _canonical_component_version(pkg: dict) -> str | None:
    value = pkg.get("version")
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    return "UNRESOLVED" if "||" in value else value


def _bom_ref(pkg: dict) -> str:
    purl = _purl(pkg)
    if purl:
        return purl

    name = str(pkg.get("name") or "unknown")
    version = _canonical_component_version(pkg) or "unknown"
    return f"pkg:{name}@{version}".replace(" ", "_")


def _purl(pkg: dict) -> str | None:
    ecosystem = str(pkg.get("ecosystem") or "").lower()
    name = pkg.get("name")
    version = _canonical_component_version(pkg)

    if not name:
        return None

    purl_type = _PURL_TYPE_BY_ECOSYSTEM.get(ecosystem)

    if not purl_type:
        return None

    if version:
        return f"pkg:{purl_type}/{name}@{version}"

    return f"pkg:{purl_type}/{name}"


def _license(pkg: dict) -> list[dict]:
    lic = pkg.get("license")

    if not lic or str(lic).lower() in {"unknown", "none", "null"}:
        return []

    return [{"license": {"id": str(lic)}}]


def _component(pkg: dict) -> dict:
    comp = {
        "type": "library",
        "bom-ref": _bom_ref(pkg),
        "name": str(pkg.get("name") or "unknown"),
        "version": _canonical_component_version(pkg) or "unknown",
        "scope": "required",
        "properties": [
            {"name": "rsecopsx:ecosystem", "value": str(pkg.get("ecosystem") or "")},
            {"name": "rsecopsx:dependency_type", "value": str(pkg.get("dependency_type") or "")},
            {"name": "rsecopsx:reachability_status", "value": str(pkg.get("reachability_status") or "")},
            {"name": "rsecopsx:reachability_priority", "value": str(pkg.get("reachability_priority") or "")},
            {"name": "rsecopsx:vulnerability_age_bucket", "value": str(pkg.get("vulnerability_age_bucket") or "")},
            {"name": "rsecopsx:patch_urgency", "value": str(pkg.get("patch_urgency") or "")},
            {"name": "rsecopsx:vulnerability_severity", "value": str(pkg.get("severity") or "Unknown")},
            {"name": "rsecopsx:vulnerability_age_days", "value": str(pkg.get("vulnerability_age_days") if pkg.get("vulnerability_age_days") is not None else "")},
            {"name": "rsecopsx:vulnerability_age", "value": _human_age(pkg.get("vulnerability_age_days"))},
            {"name": "rsecopsx:zero_day_status", "value": _zero_day_status(pkg)},
        ],
    }

    purl = _purl(pkg)
    if purl:
        comp["purl"] = purl

    licenses = _license(pkg)
    if licenses:
        comp["licenses"] = licenses

    # Native CDX CPE field (gap plan 1.4): emitted only when the value is a
    # well-formed CPE 2.3 URI so a malformed override cannot poison the BOM.
    cpe = str(pkg.get("cpe") or "").strip()
    if cpe.startswith("cpe:2.3:"):
        comp["cpe"] = cpe

    return comp


def _vulnerability_id(pkg: dict) -> str | None:
    return pkg.get("cve") or pkg.get("advisory_id") or pkg.get("primary_vulnerability_id")


def _vulnerability_source(pkg: dict) -> dict:
    """Source block for one advisory record.

    The record's own provenance wins over the id-prefix guess. OSV MIRRORS
    several databases, so a record served by OSV may carry ``GHSA-...``
    (the GitHub Advisory DB owns it) or a CVE id the NVD owns -- deriving
    the source from the displayed id alone used to relabel every advisory
    "NVD" the moment a CVE alias existed, hiding which database the data
    actually came from. The prefix guess remains the fallback for records
    that predate the provenance fields.
    """
    vuln_id = _vulnerability_id(pkg) or ""
    origin = str(pkg.get("advisory_origin") or pkg.get("source") or "").strip()

    if origin == "GitHub":
        gid = pkg.get("advisory_id") or pkg.get("id") or vuln_id
        return {"name": "GitHub Security Advisory",
                "url": f"https://github.com/advisories/{gid}"}

    if origin == "NVD":
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"}

    if origin in {"PyPA", "RustSec", "Go"}:
        aid = pkg.get("advisory_id") or pkg.get("id") or vuln_id
        return {"name": f"{origin} Advisory Database",
                "url": f"https://osv.dev/vulnerability/{aid}"}

    if origin == "OSV":
        aid = pkg.get("advisory_id") or pkg.get("id") or vuln_id
        return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{aid}"}

    if vuln_id.startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"}

    if vuln_id.startswith("GHSA-"):
        return {"name": "GitHub Security Advisory"}

    return {"name": "R-SecOpsX"}


def _severity(pkg: dict) -> str:
    sev = str(pkg.get("severity") or pkg.get("cvss_severity") or "").lower()
    if sev in {"critical", "high", "medium", "low", "info", "none"}:
        return sev
    return "unknown"


def _display_severity(pkg: dict) -> str:
    sev = _severity(pkg)
    return sev.title() if sev not in {"unknown", "info", "none"} else sev.title()


def _human_age(days) -> str:
    if days is None:
        return "Unknown"
    days = max(int(days), 0)
    years, rem = divmod(days, 365)
    months, days2 = divmod(rem, 30)
    parts = []
    if years:
        parts.append(f"{years}y")
    if months:
        parts.append(f"{months}mo")
    if days2 or not parts:
        parts.append(f"{days2}d")
    return " ".join(parts)


def _zero_day_status(pkg: dict) -> str:
    value = str(pkg.get("zero_day_status") or "").upper()
    if value in {"ZERO_DAY_CONFIRMED", "ZERO_DAY_CANDIDATE", "NOT_ZERO_DAY", "NOT_ASSESSED"}:
        return value
    return "NOT_ASSESSED"


# CycloneDX 1.5 `definitions.scoreMethod` enum, read off the published schema
# (specification/1.5/schema/bom-1.5.schema.json):
#     CVSSv2, CVSSv3, CVSSv31, CVSSv4, OWASP, SSVC, other
# Two traps live in it.  CVSSv3 means v3.0 *specifically* -- v3.1 has its own
# member, and 1212 of our 2259 scored advisories publish v3.1 -- so the old
# hard-coded "CVSSv3" misstated most of them.  And there is no member for a
# version that was never stated, so `other` is the only honest value there:
# claiming CVSSv3 for "a number handed over without a version" is precisely
# the relabelling this work exists to stop.
_CDX_SCORE_METHOD = {
    "4.0": "CVSSv4",
    "3.1": "CVSSv31",
    "3.0": "CVSSv3",
}


def _cvss_number(value):
    """A CVSS score as a float in [0, 10], or None when there is not one.

    ``0.0`` is a score and is returned as such; ``None`` is the only absence.
    A numeric string is accepted because feeds publish scores as strings as
    often as numbers.  Measured across the cache, all 4397 CVSS values held
    are already numeric and inside the range, so this drops nothing that is
    published today.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        try:
            value = float(value)
        except ValueError:
            return None
    if not isinstance(value, (int, float)):
        return None
    return float(value) if 0.0 <= float(value) <= 10.0 else None


def _score_method(version, has_score: bool) -> str:
    """Map a *stated* CVSS version onto the CycloneDX method name.

    A version that was never stated is never guessed from the number: 7.5 is
    a legal 3.1 score and a legal 4.0 score, and they come from different
    formulas.
    """
    if not has_score:
        return "other"
    return _CDX_SCORE_METHOD.get(str(version or "").strip(), "other")


def _vulnerability_records(pkg: dict) -> list[dict]:
    records = pkg.get("vulnerability_intelligence")
    if isinstance(records, list) and records:
        return [r for r in records if isinstance(r, dict)]

    records = pkg.get("vulnerabilities")
    if isinstance(records, list) and records:
        return [r for r in records if isinstance(r, dict)]

    return [pkg] if _vulnerability_id(pkg) else []


def _vulnerability(pkg: dict, record: dict | None = None) -> dict | None:
    record = record or pkg
    vuln_id = (
        record.get("cve") or record.get("advisory_id") or record.get("id")
        or pkg.get("primary_vulnerability_id")
    )
    if not vuln_id:
        return None

    vuln_id = str(vuln_id)
    # One assessment, labelled as itself: the method, score and vector are all
    # taken from the advisory's preferred assessment so the three cannot
    # disagree about which standard produced the number.  The legacy `cvss`
    # scalar keeps being published unchanged below as rsecopsx:cvss -- it
    # simply no longer masquerades as CVSSv3.
    merged = {**pkg, **record}
    preferred = (
        record.get("cvss_preferred_score")
        if record.get("cvss_preferred_score") is not None
        else pkg.get("cvss_preferred_score")
    )
    legacy = (
        record.get("cvss")
        if record.get("cvss") is not None
        else pkg.get("cvss")
    )
    score = _cvss_number(preferred)
    if score is None:
        # A payload written before cvss_preferred_score existed carries only
        # the legacy scalar -- and no version either, so the method stays
        # `other` instead of being reported as some v3 number.
        score = _cvss_number(legacy)
    version = (
        record.get("cvss_version")
        if record.get("cvss_version") is not None
        else pkg.get("cvss_version")
    )
    vector = record.get("cvss_vector") or pkg.get("cvss_vector")

    rating = {
        "severity": _severity(merged),
        "method": _score_method(version, score is not None),
    }
    if score is not None:
        rating["score"] = score
    if vector:
        rating["vector"] = str(vector)

    vuln = {
        "id": vuln_id,
        "source": _vulnerability_source(merged),
        "ratings": [rating],
        "affects": [{"ref": _bom_ref(pkg)}],
        "properties": [
            {"name": "rsecopsx:cve", "value": str(record.get("cve") or pkg.get("cve") or "")},
            {"name": "rsecopsx:advisory_id", "value": str(record.get("advisory_id") or pkg.get("advisory_id") or "")},
            {"name": "rsecopsx:severity", "value": _display_severity({**pkg, **record})},
            {"name": "rsecopsx:cvss", "value": str(record.get("cvss") if record.get("cvss") is not None else pkg.get("cvss") or "")},
            {"name": "rsecopsx:kev_status", "value": str(record.get("kev_status", pkg.get("kev_status", False)))},
            # G-003: CycloneDX properties are the machine-readable channel, so the
            # STATIC_REFERENCE label belongs here rather than only in prose.
            {"name": "rsecopsx:kev_provenance", "value": str(record.get("kev_provenance") or pkg.get("kev_provenance") or STATIC_REFERENCE)},
            {"name": "rsecopsx:epss_provenance", "value": str(record.get("epss_provenance") or pkg.get("epss_provenance") or NOT_AVAILABLE)},
            {"name": "rsecopsx:actively_exploited", "value": str(record.get("actively_exploited", pkg.get("actively_exploited", False)))},
            {"name": "rsecopsx:zero_day_status", "value": _zero_day_status({**pkg, **record})},
            {"name": "rsecopsx:outbreak_status", "value": str(record.get("outbreak_status") or pkg.get("outbreak_status") or "")},
            {"name": "rsecopsx:patch_urgency", "value": str(record.get("patch_urgency") or pkg.get("patch_urgency") or "")},
            {"name": "rsecopsx:reachability_status", "value": str(pkg.get("reachability_status") or "")},
            {"name": "rsecopsx:reachability_priority", "value": str(pkg.get("reachability_priority") or "")},
            {"name": "rsecopsx:vulnerability_age_days", "value": str(record.get("vulnerability_age_days") if record.get("vulnerability_age_days") is not None else pkg.get("vulnerability_age_days") if pkg.get("vulnerability_age_days") is not None else "")},
            {"name": "rsecopsx:vulnerability_age", "value": _human_age(record.get("vulnerability_age_days") if record.get("vulnerability_age_days") is not None else pkg.get("vulnerability_age_days"))},
            {"name": "rsecopsx:published_date", "value": str(record.get("published_date") or pkg.get("published_date") or "")},
        ],
    }

    # Cross-link every other id the advisory carries. One advisory cluster
    # can exist under two GHSA ids and two CVE ids (a re-issued advisory
    # keeps the old ids as aliases), while the record above asserts only
    # the primary CVE -- so a consumer searching this SBOM for the sibling
    # CVE (CVE-2026-4800 beside CVE-2021-23337, for example) would find
    # nothing even though OSV says the cluster affects this component.
    # `references` is the CycloneDX-native channel for alternate ids, and
    # it is what analysis/differential.py reads to give each alias CVE an
    # identity of its own when diffing against a peer.
    alias_ids: list[str] = []
    for src in (record, pkg):
        raw_aliases = src.get("aliases")
        if isinstance(raw_aliases, (list, tuple)):
            for alias in raw_aliases:
                text = str(alias or "").strip()
                if text and text.upper() != vuln_id.upper():
                    alias_ids.append(text)
    if alias_ids:
        ref_source = str(record.get("source")
                         or pkg.get("vulnerability_source")
                         or "OSV")
        vuln["references"] = [
            {"source": {"name": ref_source}, "id": alias}
            for alias in sorted(dict.fromkeys(alias_ids))
        ]

    # No score is written back here.  ratings[0]["score"] was already set from
    # the preferred assessment above; re-assigning the legacy scalar over it
    # would put a 3.1 number beside a "CVSSv4" method -- the exact relabelling
    # this change exists to stop.  The legacy scalar still ships, unchanged,
    # as the rsecopsx:cvss property.
    published = record.get("published_date") or record.get("published") or pkg.get("published_date")
    if published:
        vuln["published"] = str(published)

    if record.get("summary") or record.get("details") or pkg.get("description"):
        vuln["description"] = str(record.get("summary") or record.get("details") or pkg.get("description"))

    return vuln



SUMMARY_KEYS = [
    "cbom_summary", "ai_bom_summary", "ml_bom_summary", "api_bom_summary",
    "abom_summary", "reachability_summary", "kev_intelligence_summary",
    "epss_intelligence_summary", "exploitability_decision_summary",
    "license_policy_summary", "copyright_ip_compliance_summary",
    "supply_chain_trust_summary", "runtime_artifact_integrity_summary",
    "data_flow_sensitivity_summary", "data_flow_correlation_summary",
    "identity_access_risk_summary", "identity_access_correlation_summary",
    "auth_hardening_risk_summary", "auth_hardening_correlation_summary",
    "ai_model_risk_summary", "business_logic_risk_summary",
    "business_logic_correlation_summary", "api_abuse_risk_summary",
    "security_control_coverage_summary", "crypto_misuse_summary",
    "secret_intelligence_summary", "secret_blast_radius_correlation_summary",
    "framework_enrichment_summary", "governance_signal_summary",
    "release_readiness_summary", "executive_decision_summary",
    "vulnerability_age_summary",
]

def _summary_properties(payload: dict) -> list[dict]:
    props = []
    for key in SUMMARY_KEYS:
        value = payload.get(key)
        if value not in (None, {}, [], ""):
            props.append({"name": f"rsecopsx:{key}", "value": json.dumps(value, default=str)})
    for key in sorted(k for k in payload.keys() if k.endswith("_summary") and k not in SUMMARY_KEYS):
        value = payload.get(key)
        if value not in (None, {}, [], ""):
            props.append({"name": f"rsecopsx:{key}", "value": json.dumps(value, default=str)})
    return props

# main.py writes the BOM collections under the compact keys below; earlier
# revisions of this exporter read them under underscore-separated names that no
# producer ever writes, so AI-BOM, ML-BOM and API-BOM components were silently
# absent from the CycloneDX document while CBOM/ABOM exported normally.  Both
# spellings are honoured so a payload written by either convention still
# exports, and the emitted ``bom_type`` always carries the canonical key.
BOM_ASSET_SOURCES = [
    ("cbom", ("cbom",), "cryptographic-asset"),
    ("aibom", ("aibom", "ai_bom"), "machine-learning-model"),
    ("mlbom", ("mlbom", "ml_bom"), "machine-learning-model"),
    ("apibom", ("apibom", "api_bom"), "service"),
    ("abom", ("abom",), "application"),
]


def _bom_items(payload: dict, aliases: tuple) -> list:
    """First populated list among the aliases, else the first list seen."""
    first_list = None
    for alias in aliases:
        value = payload.get(alias)
        if isinstance(value, list):
            if first_list is None:
                first_list = value
            if value:
                return value
    return first_list or []


def _bom_asset_components(payload: dict) -> list[dict]:
    from core.redaction import redact_pem_deep

    assets = []
    for key, aliases, ctype in BOM_ASSET_SOURCES:
        for i, item in enumerate(_bom_items(payload, aliases), 1):
            name = str(item.get("name") or item.get("id") or item.get("endpoint") or f"{key}-{i}")
            # Redact per-value BEFORE dumps, never on the serialized text:
            # an unterminated PEM header redacted after dumps would swallow
            # closing quotes and braces out of the JSON string, corrupting
            # the document. The CBOM private-key rule's evidence is the PEM
            # block itself, and rsecopsx:raw reproduces it verbatim -- so
            # the main SBOM was republishing the very key material the scan
            # found. A BOM is the artifact most likely to be handed to
            # third parties, which makes it the worst place for that leak.
            safe_item = redact_pem_deep(dict(item))
            assets.append({
                "type": "data" if ctype == "cryptographic-asset" else "application",
                "bom-ref": f"rsecopsx:{key}:{i}:{name}".replace(" ", "_"),
                "name": name,
                "version": str(item.get("version") or "unknown"),
                "properties": [
                    {"name": "rsecopsx:bom_type", "value": key},
                    {"name": "rsecopsx:asset_type", "value": ctype},
                    {"name": "rsecopsx:raw", "value": json.dumps(safe_item, default=str)},
                ],
            })
    return assets

def _component_ref_index(sbom: list, components: list) -> dict:
    """Exact-reference and purl-equivalent identity keys for every component.

    Same identity vocabulary as the verified-edge join (purl-equivalent
    triple), so exporter resolution cannot disagree with the join's stamps.
    """
    by_ref: dict = {}
    by_identity: dict = {}
    for comp in components:
        ref = comp.get("bom-ref")
        if ref:
            by_ref.setdefault(str(ref), ref)
    for pkg in sbom:
        ref = _bom_ref(pkg)
        by_ref[ref] = ref
        purl = _purl(pkg)
        if purl:
            by_ref.setdefault(purl, ref)
        ptype = _PURL_TYPE_BY_ECOSYSTEM.get(
            str(pkg.get("ecosystem") or "").lower())
        name = pkg.get("name")
        version = _canonical_component_version(pkg)
        if ptype and name and version:
            by_identity.setdefault((ptype, str(name), str(version)), ref)
    return {"by_ref": by_ref, "by_identity": by_identity}


def _resolve_edge_endpoint(endpoint, index: dict, has_root: bool):
    """Resolve one raw engine endpoint id to an in-document ref (R1/W1).

    Four endpoint classes: registry ids (match by exact ref or
    purl-equivalent identity -- never by name alone), the synthetic npm root
    (resolves to the metadata.component bom-ref), workspace/file ids
    (versionless; resolve only as exact refs), and everything unresolvable
    (dropped-and-counted, never serialized).
    """
    text = str(endpoint)
    by_ref = index["by_ref"]
    if text in by_ref:
        return by_ref[text], "resolved"
    if text == NPM_ROOT_REF:
        if has_root:
            return NPM_ROOT_REF, "root_mapped"
        return None, "dropped"
    if (text.startswith(_NPM_WORKSPACE_PREFIX)
            or text.startswith(_NPM_FILE_PREFIX)):
        if text in by_ref:
            return text, "resolved"
        return None, "workspace_file_dropped"
    tail = text[4:] if text.startswith("pkg:") else ""
    ptype, _, id_tail = tail.partition("/")
    name, sep, version = id_tail.rpartition("@")
    if sep and name and version:
        ref = index["by_identity"].get((ptype, name, version))
        if ref:
            return ref, "resolved"
    return None, "dropped"


def build_cyclonedx(payload: dict) -> dict:
    sbom = payload.get("sbom", []) or []
    metadata = payload.get("metadata", {}) or {}

    components = [_component(pkg) for pkg in sbom] + _bom_asset_components(payload)

    # R1/W1: the synthetic npm root is the SUBJECT of the BOM (the scanned
    # project), not a piece of software -- it ships as the CycloneDX
    # metadata.component and never as an ordinary component. Its bom-ref is
    # unchanged ("pkg:npm/__root__") so refs stay stable across the change.
    dependency_graph = payload.get("dependency_graph", {}) or {}
    graph_edges = dependency_graph.get("edges", []) or []

    has_synthetic_root = any(
        isinstance(edge, dict)
        and (
            str(edge.get("parent") or "") == NPM_ROOT_REF
            or str(edge.get("child") or "") == NPM_ROOT_REF
        )
        for edge in graph_edges
    )

    metadata_component = None
    if has_synthetic_root:
        target = str(metadata.get("target") or "").replace("\\", "/")
        metadata_component = {
            "type": "application",
            "bom-ref": NPM_ROOT_REF,
            "name": target.rsplit("/", 1)[-1] if target else "__root__",
            "version": "unknown",
        }

    vulnerabilities = []
    for pkg in sbom:
        for record in _vulnerability_records(pkg):
            vuln = _vulnerability(pkg, record)
            if vuln:
                vulnerabilities.append(vuln)

    # Dependency Graph V2
    #
    # Only authoritative VERIFIED edges are serialized into CycloneDX
    # dependency relationships, and only after endpoint resolution (R1/W1):
    # every shipped ref names a component bom-ref or the metadata.component;
    # anything else is dropped and counted in the disclosed tally -- never
    # serialized as a dangling reference.
    # R2.1: contract edges (poetry/uv extractors) carry purl-built identity
    # fields instead of raw ids -- resolved through the same component index.
    verified_edges = [
        edge
        for edge in graph_edges
        if (
            isinstance(edge, dict)
            and str(edge.get("confidence") or "").upper() == "VERIFIED"
            and (edge.get("parent") or edge.get("parent_purl"))
            and (edge.get("child") or edge.get("child_purl"))
        )
    ]

    ref_index = _component_ref_index(sbom, components)
    resolution = {
        "resolved": 0,
        "root_mapped": 0,
        "workspace_file_dropped": 0,
        "dropped": 0,
    }

    dependency_map = {}

    for edge in verified_edges:
        parent, parent_class = _resolve_edge_endpoint(
            edge.get("parent") or edge.get("parent_purl"),
            ref_index, has_synthetic_root)
        child, child_class = _resolve_edge_endpoint(
            edge.get("child") or edge.get("child_purl"),
            ref_index, has_synthetic_root)
        resolution[parent_class] += 1
        resolution[child_class] += 1
        if parent and child:
            dependency_map.setdefault(parent, set()).add(child)

    dependencies = [
        {
            "ref": parent,
            "dependsOn": sorted(children),
        }
        for parent, children in sorted(dependency_map.items())
    ]

    graph_status = (
        "VERIFIED_EDGES_AVAILABLE"
        if verified_edges
        else "NO_VERIFIED_EDGES"
    )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "R-SecOpsX",
                    "name": "R-SecOpsX SAST",
                    "version": "2.0.0",
                }
            ],
            **({"component": metadata_component} if metadata_component else {}),
            "properties": [
                {
                    "name": "rsecopsx:total_findings",
                    "value": str(metadata.get("total_findings", "")),
                },
                {
                    "name": "rsecopsx:risk_score",
                    "value": str(metadata.get("risk_score", "")),
                },
                {
                    "name": "rsecopsx:executive_decision",
                    "value": str(metadata.get("executive_decision", "")),
                },
                {
                    "name": "rsecopsx:framework_mapping_status",
                    "value": str(metadata.get("framework_mapping_status", "")),
                },
                {
                    "name": "rsecopsx:vulnerability_age_status",
                    "value": str(metadata.get("vulnerability_age_status", "")),
                },
                {
                    "name": "rsecopsx:scan_date",
                    "value": datetime.now(timezone.utc).date().isoformat(),
                },
                {
                    "name": "rsecopsx:edge_ref_resolution",
                    "value": json.dumps(resolution, sort_keys=True),
                },
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
        "dependencies": dependencies,
        "properties": _summary_properties(payload) + [
            {
                "name": "rsecopsx:executive_decision",
                "value": json.dumps(
                    payload.get("executive_decision", {}),
                    default=str,
                ),
            },
            {
                "name": "rsecopsx:dependency_graph_status",
                "value": graph_status,
            },
            {
                "name": "rsecopsx:verified_dependency_edge_count",
                "value": str(len(verified_edges)),
            },
            {
                "name": "rsecopsx:dependency_graph_evidence",
                "value": "AUTHORITATIVE_RELATIONSHIP_FIELDS_ONLY",
            },
        ],
    }

def write_cyclonedx_report(payload: dict, output_path: str) -> str:
    bom = build_cyclonedx(payload)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2, default=str)

    return str(out)


if __name__ == "__main__":
    sample_payload = {
        "metadata": {
            "total_findings": 10,
            "risk_score": 78.2,
            "executive_decision": "REMEDIATE_BEFORE_RELEASE",
            "framework_mapping_status": "RULE_BASED_FRAMEWORK_ENRICHMENT_V1",
            "vulnerability_age_status": "VULNERABILITY_AGE_INTELLIGENCE_V1_OFFLINE",
        },
        "sbom": [
            {
                "name": "log4j-core",
                "version": "2.14.1",
                "ecosystem": "maven",
                "dependency_type": "Direct",
                "license": "Apache-2.0",
                "cve": "CVE-2021-44228",
                "advisory_id": "GHSA-jfh8-c2jp-5v3q",
                "severity": "Critical",
                "reachability_status": "REACHABLE",
                "reachability_priority": "REACHABLE_VULNERABLE",
                "vulnerability_age_bucket": "LEGACY_HIGH_RISK",
                "kev_status": True,
                "actively_exploited": True,
                "outbreak_status": "OUTBREAK_ACTIVE_REACHABLE",
                "patch_urgency": "IMMEDIATE",
                "published_date": "2021-12-10T00:00:00Z",
            }
        ],
        "secret_intelligence_summary": {},
        "vulnerability_age_summary": {},
        "governance_signal_summary": {},
        "executive_decision": {},
    }

    write_cyclonedx_report(sample_payload, "reports/bom.cyclonedx.json")
    print("CycloneDX written to reports/bom.cyclonedx.json")

