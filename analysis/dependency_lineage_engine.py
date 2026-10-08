"""
analysis/dependency_lineage_engine.py

Dependency Lineage Trace Engine.
Stdlib-only. Builds explicit dependency chains from existing SBOM metadata.
"""
from __future__ import annotations

from typing import Any, Dict, List
import hashlib

UNKNOWN = {"", "none", "null", "unknown", "n/a", "na", "not applicable", "-"}


def _clean(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return default if text.lower() in UNKNOWN else text


def _first(pkg: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = pkg.get(key)
        if value not in (None, "", [], {}, "unknown", "Unknown", "UNKNOWN"):
            return value
    return default


def _name(pkg: Dict[str, Any]) -> str:
    return _clean(_first(pkg, "name", "package", "component", default="unknown"), "unknown")


def _version(pkg: Dict[str, Any]) -> str:
    return _clean(_first(pkg, "version", default="unknown"), "unknown")


def _node(pkg: Dict[str, Any]) -> str:
    return f"{_name(pkg)}@{_version(pkg)}"


def _identity(pkg: Dict[str, Any]) -> str:
    eco = _clean(_first(pkg, "ecosystem", "type", default="unknown"), "unknown").lower()
    return f"{eco}:{_node(pkg)}"


def _fp(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _vuln_ids(pkg: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for key in ("cve", "advisory_id", "primary_vulnerability_id"):
        if pkg.get(key):
            values.append(str(pkg.get(key)).strip())

    for key in ("cve_list", "cves", "advisory_ids", "vulnerability_ids"):
        value = pkg.get(key)
        if isinstance(value, list):
            values.extend(str(x).strip() for x in value if str(x).strip())
        elif isinstance(value, str) and value.strip():
            values.extend(x.strip() for x in value.split(",") if x.strip())

    return sorted(set(v for v in values if v and v.lower() not in UNKNOWN))


def _chain_item(value: Any) -> str:
    if isinstance(value, dict):
        return _clean(value.get("name") or value.get("package") or value.get("component") or
                      value.get("Parent") or value.get("id") or value.get("Id") or str(value), "")
    return _clean(value, "")


def _extract_chain(pkg: Dict[str, Any], root_name: str) -> List[str]:
    for key in ("dependency_path", "dependency_chain", "path", "ShortestDependencyPaths"):
        value = pkg.get(key)
        if isinstance(value, list) and value:
            if isinstance(value[0], list):
                value = value[0]
            chain = [_chain_item(x) for x in value]
            chain = [x for x in chain if x]
            if chain:
                if chain[0] != root_name:
                    chain.insert(0, root_name)
                if chain[-1] != _node(pkg):
                    chain.append(_node(pkg))
                return chain

    parent = _clean(_first(pkg, "parent", "parent_package", "introduced_by", default=""), "")
    current = _node(pkg)
    if parent:
        return [root_name, parent, current]

    dep_type = _clean(_first(pkg, "dependency_type", "type", default=""), "").lower()
    direct = pkg.get("direct")
    if direct is True or dep_type == "direct":
        return [root_name, current]

    return [root_name, "UNKNOWN_PARENT", current]


def build_dependency_lineage(sbom: List[Dict[str, Any]], root_name: str = "root_application") -> Dict[str, Any]:
    traces: List[Dict[str, Any]] = []

    for idx, pkg in enumerate(sbom or [], 1):
        if not isinstance(pkg, dict):
            continue

        chain = _extract_chain(pkg, root_name)
        vulnerabilities = _vuln_ids(pkg)
        lineage_text = " -> ".join(chain)

        traces.append({
            "index": idx,
            "package_identity": _identity(pkg),
            "fingerprint": _fp(lineage_text),
            "root": root_name,
            "package": _name(pkg),
            "version": _version(pkg),
            "ecosystem": _clean(_first(pkg, "ecosystem", "type", default="unknown"), "unknown"),
            "purl": _clean(_first(pkg, "purl", "Purl", default=""), ""),
            "chain": chain,
            "chain_text": lineage_text,
            "depth": max(0, len(chain) - 1),
            "direct": len(chain) <= 2,
            "has_unknown_parent": "UNKNOWN_PARENT" in chain,
            "vulnerable": bool(vulnerabilities),
            "vulnerability_ids": vulnerabilities,
            "reachability_status": _clean(_first(pkg, "reachability_status", default=""), ""),
            "reachability_priority": _clean(_first(pkg, "reachability_priority", default=""), ""),
            "kev_status": bool(_first(pkg, "kev_status", "actively_exploited", default=False)),
            "epss_score": _first(pkg, "epss_score", "epss", default=None),
        })

    summary = {
        "schema": "DEPENDENCY_LINEAGE_TRACE_V1",
        "total_traces": len(traces),
        "vulnerable_traces": sum(1 for t in traces if t["vulnerable"]),
        "direct_traces": sum(1 for t in traces if t["direct"]),
        "transitive_traces": sum(1 for t in traces if not t["direct"]),
        "unknown_parent_traces": sum(1 for t in traces if t["has_unknown_parent"]),
        "max_depth": max([t["depth"] for t in traces], default=0),
    }
    return {"summary": summary, "traces": traces}


build_lineage_trace = build_dependency_lineage
