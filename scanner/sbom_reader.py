"""Ingest an existing CycloneDX/SPDX SBOM into R-SecOpsX's package shape.

    from scanner.sbom_reader import read_sbom, ingest_sbom
    doc = read_sbom("vendor.cdx.json")      # parse + normalise only
    doc = ingest_sbom("vendor.cdx.json")    # parse + full enrichment

WHY THIS EXISTS
---------------
Until now the tool could only PRODUCE SBOMs. Phase 2 closes the consume
side: an SBOM produced by any other tool (syft, trivy, cyclonedx-cli,
the same tool from an earlier release) is loaded, normalised into the
exact package-dict shape generate_sbom() emits, and pushed through the
SAME enrichment tail (scanner/sbom.py::finalize_sbom_packages) the scan
path uses -- offline CVE table, OSV advisory enrichment (fail-open),
overrides, best-effort CPE, licence catalogue. From there
build_report_payload() and every emitter work unchanged.

WHAT IS NORMALISED (and what is not)
------------------------------------
Component membership is taken from the SBOM verbatim: an ingested SBOM is
authoritative for which components exist, so finalize is called with
add_transitive=False and our knowledge base never invents members.
Fields are mapped as:

    name/version/ecosystem/license/purl/cpe/direct  <- native fields
    sbom_ref    <- CycloneDX bom-ref / SPDX SPDXID
    hashes      <- [{alg, content}] (verbatim)
    supplier    <- supplier/author/manufacturer or SPDX originator
    component_type <- CycloneDX component "type" (library, container, ...)
    ingested_from  <- the source SBOM file (provenance, one hop)

Ecosystem comes from the purl type when a purl exists (pkg:pypi/ ->
PyPI, npm, maven, cargo -> crates.io, composer -> Packagist, gem ->
RubyGems, nuget, golang -> Go); an unmapped type is passed through as the
raw purl type so the record stays honest (OSV then counts it under
skipped_unresolvable rather than guessing). A component with no purl AND
no CPE gets ecosystem "unknown" and is likewise not queried.

Maven components are renamed to the "group:artifact" form the rest of
the pipeline uses, taken from the purl namespace when the SBOM's name is
bare.

SUPPORTED / UNSUPPORTED
-----------------------
    CycloneDX 1.5-1.7 JSON   supported
    SPDX 2.2/2.3 JSON        supported
    CycloneDX XML            rejected with a clear error (JSON only)
    SPDX YAML/tag-value      rejected with a clear error

Declared VEX (`vulnerabilities[]` in a CycloneDX document) is preserved
on the returned doc (`doc["vulnerabilities"]`) and counted in the ingest
metadata, but is NOT merged into package vulnerability records: our
records come from OSV/overrides with their own provenance. Merging VEX
statements would mix someone else's analysis into ours under our banner.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SbomReadError(RuntimeError):
    """The file is not a supported SBOM document."""


# purl type -> the ecosystem token used by the manifest parsers (see
# scanner/manifests/* and scanner/sbom.py). Order matters not; exact keys.
PURL_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "cargo": "crates.io",
    "composer": "Packagist",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "golang": "Go",
}


def parse_purl(purl: str) -> dict:
    """Minimal purl decomposition: type, namespace, name, version.

    Deliberately not a full purl implementation (no qualifiers/qualifier
    decoding beyond splitting): the reader only needs the four parts above,
    and an unparsable purl must degrade to empty parts, never to an error.
    """
    out = {"type": "", "namespace": "", "name": "", "version": ""}
    s = str(purl or "").strip()
    if not s.startswith("pkg:"):
        return out
    s = s[4:]
    # strip qualifiers and fragment
    s = s.split("?", 1)[0].split("#", 1)[0]
    type_part, _, rest = s.partition("/")
    out["type"] = type_part.lower()
    if "@" in rest:
        rest, _, version = rest.rpartition("@")
        out["version"] = version
    if "/" in rest:
        out["namespace"], _, out["name"] = rest.rpartition("/")
    else:
        out["name"] = rest
    return out


def _ecosystem_from_purl(purl: str) -> str:
    parsed = parse_purl(purl)
    if not parsed["type"]:
        return "unknown"
    # Unmapped types pass through verbatim: the record stays honest and the
    # advisory query accounts for them under skipped_unresolvable.
    return PURL_ECOSYSTEMS.get(parsed["type"], parsed["type"])


def _cdx_license(component: dict) -> str:
    """Flatten CycloneDX licenses ([{license:{id|name}} | {expression}])."""
    parts = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        expr = entry.get("expression")
        if expr:
            parts.append(str(expr))
            continue
        lic = entry.get("license") or {}
        if isinstance(lic, dict):
            value = lic.get("id") or lic.get("name")
            if value:
                parts.append(str(value))
    return " AND ".join(parts) if parts else "unknown"


def _spdx_license(package: dict) -> str:
    declared = str(package.get("licenseDeclared") or "").strip()
    concluded = str(package.get("licenseConcluded") or "").strip()
    for value in (declared, concluded):
        if value and value.upper() not in ("NOASSERTION", "NONE"):
            return value
    return "unknown"


def _spdx_external_ref(package: dict, wanted: str) -> str:
    for ref in package.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("referenceType") or "") == wanted:
            return str(ref.get("referenceLocator") or "")
    return ""


def _normalise_cdx_component(c: dict, source: str) -> dict | None:
    name = str(c.get("name") or "").strip()
    if not name:
        return None
    purl = str(c.get("purl") or "").strip()
    cpe = str(c.get("cpe") or "").strip()
    ecosystem = _ecosystem_from_purl(purl)

    if ecosystem == "Maven":
        parsed = parse_purl(purl)
        if parsed["namespace"] and ":" not in name:
            name = "%s:%s" % (parsed["namespace"], name)

    supplier = c.get("supplier") or c.get("author") or c.get("manufacturer")
    if isinstance(supplier, dict):
        supplier = supplier.get("name")

    hashes = c.get("hashes") if isinstance(c.get("hashes"), list) else []

    return {
        "name": name,
        "version": str(c.get("version") or "unknown"),
        "ecosystem": ecosystem,
        "license": _cdx_license(c),
        "purl": purl,
        "cpe": cpe,
        # "excluded" scope means the component is deliberately not shipped;
        # everything else (optional/required/absent) counts as present.
        "direct": str(c.get("scope") or "").lower() != "excluded",
        "manifest_file": source,
        "manifest_line": None,
        "sbom_ref": str(c.get("bom-ref") or ""),
        "component_type": str(c.get("type") or ""),
        "hashes": hashes,
        "supplier": str(supplier) if supplier else "",
        "ingested_from": source,
    }


def _normalise_spdx_package(p: dict, direct_refs: set[str], source: str) -> dict | None:
    name = str(p.get("name") or "").strip()
    if not name:
        return None
    purl = _spdx_external_ref(p, "purl")
    cpe = _spdx_external_ref(p, "cpe23Type") or _spdx_external_ref(p, "cpe22Type")
    ecosystem = _ecosystem_from_purl(purl)

    if ecosystem == "Maven":
        parsed = parse_purl(purl)
        if parsed["namespace"] and ":" not in name:
            name = "%s:%s" % (parsed["namespace"], name)

    spdxid = str(p.get("SPDXID") or "")
    originator = str(p.get("originator") or p.get("supplier") or "")
    originator = originator.removeprefix("Person: ").removeprefix("Organization: ")

    return {
        "name": name,
        "version": str(p.get("versionInfo") or "unknown"),
        "ecosystem": ecosystem,
        "license": _spdx_license(p),
        "purl": purl,
        "cpe": cpe,
        # A package the document DESCRIBES, or one nothing depends on, is
        # treated as direct; packages reached via DEPENDS_ON are transitive.
        "direct": (spdxid in direct_refs) or not spdxid,
        "manifest_file": source,
        "manifest_line": None,
        "sbom_ref": spdxid,
        "component_type": "library",
        "hashes": [],
        "supplier": originator,
        "ingested_from": source,
    }


def _read_json_document(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise SbomReadError("cannot read %s: %s" % (path, exc)) from exc

    head = text.lstrip()[:200].lower()
    if head.startswith("<?xml") or head.startswith("<!doctype") or head.startswith("<bom"):
        raise SbomReadError(
            "%s looks like XML; only CycloneDX JSON is supported "
            "(convert with `cyclonedx convert`)" % path)
    if "spdxversion:" in head and not head.startswith("{"):
        raise SbomReadError(
            "%s looks like SPDX YAML/tag-value; only SPDX JSON is supported" % path)

    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise SbomReadError("%s is not valid JSON: %s" % (path, exc)) from exc
    if not isinstance(doc, dict):
        raise SbomReadError("%s: top-level JSON must be an object" % path)
    return doc


def read_sbom(path: str) -> dict:
    """Parse an SBOM file into the normalised ingest document.

    Returns a dict:
        format            "cyclonedx" | "spdx"
        spec_version      e.g. "1.6" / "SPDX-2.3"
        serial_number     CDX serialNumber / SPDX document namespace
        created           metadata timestamp when present
        tools             generator tool names when present
        components        normalised package dicts (see module docstring)
        dependencies      [{ref, depends_on, type}]
        vulnerabilities   CDX VEX records, verbatim (declared, not ours)
        source_file       the path read
        warnings          non-fatal normalisation notes
    """
    p = Path(path)
    if not p.is_file():
        raise SbomReadError("SBOM file does not exist: %s" % path)
    doc = _read_json_document(p)
    source = str(p)

    if str(doc.get("bomFormat") or "").lower() == "cyclonedx" or (
            "specVersion" in doc and "components" in doc):
        return _read_cyclonedx(doc, source)
    if doc.get("spdxVersion") or doc.get("SPDXID"):
        return _read_spdx(doc, source)
    raise SbomReadError(
        "%s is not a recognised SBOM: expected CycloneDX (bomFormat/specVersion) "
        "or SPDX (spdxVersion); saw keys: %s"
        % (source, ", ".join(sorted(doc.keys())[:12]) or "<none>"))


def _read_cyclonedx(doc: dict, source: str) -> dict:
    meta = doc.get("metadata") or {}
    tools = []
    raw_tools = meta.get("tools")
    # CycloneDX 1.6 encodes metadata.tools as {"components": [...],
    # "services": [...]}; 1.5 and most emitters use a plain list. A dict
    # iterated as a list would yield its KEYS ("components") as tool names.
    if isinstance(raw_tools, dict):
        raw_tools = [raw_tools]
    for tool in raw_tools or []:
        if isinstance(tool, dict):
            if isinstance(tool.get("components"), list):
                for comp in tool["components"]:
                    if isinstance(comp, dict) and comp.get("name"):
                        tools.append(str(comp["name"]))
                continue
            name = tool.get("name") or (tool.get("vendor") or "")
            if name:
                tools.append(str(name))
        elif tool:
            tools.append(str(tool))

    warnings: list[str] = []
    components = []
    for c in doc.get("components") or []:
        if not isinstance(c, dict):
            continue
        normalised = _normalise_cdx_component(c, source)
        if normalised is None:
            warnings.append("component without a name skipped")
            continue
        components.append(normalised)

    dependencies = []
    for d in doc.get("dependencies") or []:
        if not isinstance(d, dict):
            continue
        dependencies.append({
            "ref": str(d.get("ref") or ""),
            "depends_on": [str(x) for x in (d.get("dependsOn") or [])],
            "type": "DEPENDENCY",
        })

    return {
        "format": "cyclonedx",
        "spec_version": str(doc.get("specVersion") or ""),
        "serial_number": str(doc.get("serialNumber") or ""),
        "created": str(meta.get("timestamp") or ""),
        "tools": tools,
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": list(doc.get("vulnerabilities") or []),
        "source_file": source,
        "warnings": warnings,
    }


def _read_spdx(doc: dict, source: str) -> dict:
    warnings: list[str] = []

    # DESCRIBES targets are the document's roots -> direct; packages named
    # in a DEPENDS_ON relation as the dependent side stay direct too.
    describes_targets: set[str] = set()
    depends_pairs: list[tuple[str, str]] = []
    relationships = []
    for r in doc.get("relationships") or []:
        if not isinstance(r, dict):
            continue
        rtype = str(r.get("relationshipType") or "")
        subj = str(r.get("spdxElementId") or "")
        obj = str(r.get("relatedSpdxElement") or "")
        relationships.append({
            "ref": subj,
            "depends_on": [obj] if obj else [],
            "type": rtype,
        })
        if rtype == "DESCRIBES":
            describes_targets.add(obj)
        elif rtype == "DEPENDS_ON":
            depends_pairs.append((subj, obj))

    dependents = {subj for subj, _ in depends_pairs}
    direct_refs = describes_targets | dependents

    components = []
    for p in doc.get("packages") or []:
        if not isinstance(p, dict):
            continue
        normalised = _normalise_spdx_package(p, direct_refs, source)
        if normalised is None:
            warnings.append("package without a name skipped")
            continue
        components.append(normalised)

    return {
        "format": "spdx",
        "spec_version": str(doc.get("spdxVersion") or ""),
        "serial_number": str(doc.get("documentNamespace") or ""),
        "created": str(doc.get("creationInfo", {}).get("created") or ""),
        "tools": [str(t) for t in (doc.get("creationInfo", {}).get("createdBy") or [])],
        "components": components,
        "dependencies": relationships,
        # SPDX has no VEX section; declared vulnerabilities do not exist here.
        "vulnerabilities": [],
        "source_file": source,
        "warnings": warnings,
    }


def ingest_sbom(path: str) -> dict:
    """read_sbom() + the shared enrichment tail used by generate_sbom().

    Membership stays verbatim (add_transitive=False); every declared
    component is enriched exactly like a scanned one: offline CVE table,
    OSV batch (fail-open), overrides, CPE stamping, licence catalogue.
    """
    from scanner.sbom import finalize_sbom_packages

    doc = read_sbom(path)
    doc["components"] = finalize_sbom_packages(doc["components"],
                                               add_transitive=False)
    return doc
