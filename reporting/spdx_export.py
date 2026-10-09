"""SPDX 2.3 exporter.

Why this exists
---------------
G-086: only CycloneDX and VEX were emitted. CERT-In accepts SPDX *or* CycloneDX
for its automation-support element, so SPDX is a redundancy rather than a
compliance necessity -- but SPDX is the format most SBOM consumers and most
third-party risk tools ingest, so its absence is a real interoperability gap.

What the schema forces
----------------------
The document is built against the pinned SPDX 2.3 JSON schema, which declares
``additionalProperties: false`` at the top level AND on every package. That has
three consequences this module is built around:

  1. There is no place for a vendor extension block. Every piece of R-SecOpsX
     specific evidence has to travel in a field SPDX actually defines --
     ``annotations``, ``externalRefs``, ``comment``, or ``relationships``. An
     exporter that quietly adds ``"rsecopsx": {...}`` produces a document that
     fails validation, and most consumers will reject it rather than ignore it.
  2. ``dataLicense`` is mandatory and must be ``CC0-1.0``; the specification
     requires SPDX metadata to be CC0. Hard-coded, not configurable.
  3. Unknown values must be the literal ``NOASSERTION`` (or the
     ``spdx.org/rdf/terms#noassertion`` URI for downloadLocation). SPX does not
     permit an empty string or a guess.

Three honesty properties this exporter will not trade away
----------------------------------------------------------
  * ``filesAnalyzed`` is **false** on every package. R-SecOpsX reads a dependency
    manifest; it does not unpack archives and inspect their contents. Setting
    this true would claim file-level analysis that never happened and would
    make any consumer's file-level inference unsound.
  * ``downloadLocation`` is ``NOASSERTION`` unless the payload carries a real
    location. A plausible-looking registry URL is a fabrication, and this
    product does not fetch packages.
  * The document annotation states the release verdict and the disposition
    counts. It does not state ASVS/NIST/PCI compliance, because SPDX has no
    field for it and this tool cannot attest it.

Relationship model
------------------
``documentDescribes`` and a matching ``DESCRIBES`` relationship per package.
Dependency edges from ``dependency_graph`` are emitted only when the graph
actually verified them; an unverified edge is omitted rather than guessed,
because a wrong DEPENDS_ON is worse than a missing one.

Not emitted, deliberately
-------------------------
SLSA provenance / in-toto attestations. V11 is not the builder of the software
it scans, so it cannot attest how that software was built. Emitting an
unattested provenance statement would be a counterfeit attestation. That stays
registered as G-089 rather than being quietly "satisfied" by this file.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from reporting.report_mappings import format_cvss_assessment

SPDX_VERSION = "SPDX-2.3"
SPDX_SCHEMA_URL = "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json"
SPDX_DATA_LICENSE = "CC0-1.0"
NOASSERTION = "NOASSERTION"
SPDX_DOCUMENT_ID = "SPDXRef-DOCUMENT"

TOOL_NAME = "R-SecOpsX"
TOOL_VERSION = "2.0"

# SPDX 2.3 relationshipType enum, restricted to what this exporter can justify.
REL_DESCRIBES = "DESCRIBES"
REL_DEPENDS_ON = "DEPENDS_ON"
REL_DEPENDENCY_OF = "DEPENDENCY_OF"
REL_CONTAINS = "CONTAINS"
REL_OTHER = "OTHER"

_SPDXID_CLEAN = re.compile(r"[^A-Za-z0-9.\-]+")


def _spdx_id(prefix: str, *parts: str) -> str:
    """Build a schema-legal SPDXID.

    SPDX 2.3 permits letters, digits, '.' and '-' in the idString. Package names
    routinely contain '@', '/', ':' and spaces, so the raw name cannot be used
    directly. A digest is appended so two components that differ only in
    characters we stripped do not collapse onto the same SPDXID -- the same
    injectivity property the PDF path fix was about.
    """
    import hashlib

    joined = ":".join(str(p or "") for p in parts)
    slug = _SPDXID_CLEAN.sub("-", joined).strip("-") or "x"
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-{prefix}-{slug[:60]}-{digest}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_PLACEHOLDER_VERSIONS = {"", "unknown", "none", "null", "n/a", "na", "*"}


def _real_version(pkg: dict) -> str:
    """The pinned version, or "" when the manifest does not pin one.

    162 of 168 components on the Juice Shop corpus carry the literal string
    'unknown' in their version slot, because the manifests are largely unpinned
    (package.json ranges, not exact versions). Emitting that as `versionInfo`
    would put a fabricated version into a package identity -- and SPDXID is
    derived from name+version, so 'unknown' would also make every unpinned
    component collide on one identifier. Unpinned means unpinned: the field is
    omitted and the fact is recorded in the comment instead.
    """
    raw = str(pkg.get("version") or pkg.get("resolved_version") or "").strip()
    if raw.lower() in _PLACEHOLDER_VERSIONS:
        return ""
    return raw


def _pkg_purl(pkg: dict) -> str | None:
    for key in ("purl", "package_url"):
        val = str(pkg.get(key) or "").strip()
        if val:
            return val
    eco = str(pkg.get("ecosystem") or "").strip()
    name = str(pkg.get("name") or pkg.get("package") or "").strip()
    ver = _real_version(pkg)
    if eco and name:
        prefix = {"npm": "pkg:npm", "pypi": "pkg:pypi", "maven": "pkg:maven",
                  "go": "pkg:golang", "cargo": "pkg:cargo", "nuget": "pkg:nuget"}.get(
            eco.lower(), f"pkg:{eco.lower()}")
        return f"{prefix}/{name}@{ver}" if ver else f"{prefix}/{name}"
    return None


def _declared_license(pkg: dict) -> str:
    """Declared licence, or NOASSERTION.

    Never infers. An empty or 'UNKNOWN' value becomes NOASSERTION rather than
    falling back to a permissive-looking guess.
    """
    for key in ("license_declared", "license_declared_spdx", "license", "license_expression"):
        val = pkg.get(key)
        if isinstance(val, (list, tuple)):
            val = ", ".join(str(v).strip() for v in val if str(v).strip())
        text = str(val or "").strip()
        if not text:
            continue
        if text.upper() in {"UNKNOWN", "N/A", "NA", "NONE", "NULL"}:
            continue
        return text
    return NOASSERTION


def _download_location(pkg: dict) -> str:
    """Real download location or NOASSERTION. Never synthesised."""
    for key in ("download_location", "download_url", "repository", "homepage", "url"):
        val = str(pkg.get(key) or "").strip()
        if val.startswith("http://") or val.startswith("https://"):
            return val
    return NOASSERTION


def _external_refs(pkg: dict, spdx_id: str) -> list[dict]:
    refs = []
    purl = _pkg_purl(pkg)
    if purl:
        refs.append({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
            "comment": "Package URL as resolved from the dependency manifest.",
        })
    cve = str(pkg.get("cve") or pkg.get("primary_vulnerability_id") or "").strip()
    if cve.upper().startswith("CVE-"):
        refs.append({
            "referenceCategory": "SECURITY",
            "referenceType": "cve",
            "referenceLocator": cve,
            "comment": "Advisory identifier resolved from the vulnerability dataset.",
        })
    return refs


def _cvss_assessment_bits(pkg: dict) -> list[str]:
    """One self-contained clause naming the standard that scored a package.

    SPDX 2.3 has no structured CVSS field, so this rides in the same
    free-text annotation as the bare ``cvss:`` scalar.  It is deliberately a
    single clause rather than separate version / score / vector fragments:
    split apart, "cvss version: 4.0" would sit beside "cvss: 5.3" and a
    reader would pair the version with the wrong number.  Kept whole, both
    numbers survive and neither can be mis-read -- the ``cvss:`` scalar is
    the payload's legacy value and is published here unchanged.

    The score used is the preferred assessment's *own* score, never the
    legacy one: pairing "CVSS 4.0" with a 3.1 number is the relabelling this
    work exists to stop.  The version is the record's stated version and is
    never inferred from the number -- 7.5 is a legal 3.1 score and a legal
    4.0 score, and they come from different formulas.

    Returns nothing when the record states neither a version nor a vector,
    because there is then no standard to name.
    """
    raw_version = pkg.get("cvss_version")
    version = None if raw_version is None else str(raw_version).strip()
    # "UNKNOWN" and "None" are truthy *strings*; a bare `if version` would
    # print "CVSS UNKNOWN" and read as though a version had been named.
    if version in {None, "", "UNKNOWN", "None"}:
        version = None
    vector = str(pkg.get("cvss_vector") or "").strip()
    if version is None and not vector:
        return []

    assessment = format_cvss_assessment(
        version, pkg.get("cvss_preferred_score"), has_vulnerability=True
    )
    if vector:
        return [f"cvss assessment: {assessment}, vector {vector}"]
    return [f"cvss assessment: {assessment}"]


def _package_annotations(pkg: dict, spdx_id: str) -> list[dict]:
    """Evidence annotations for a vulnerable component.

    Only emitted when the payload actually records vulnerability evidence for
    this package. A clean package gets no annotation rather than a reassuring
    one -- SPDX annotations are evidence, and 'nothing to say' is not evidence of
    safety.
    """
    out = []
    primary = str(pkg.get("cve") or pkg.get("primary_vulnerability_id")
                  or pkg.get("advisory_id") or "").strip()
    if not pkg.get("is_vulnerable") and not primary and not pkg.get("advisory_id"):
        return out

    bits = []
    # The primary advisory is always named when one exists. A component with a
    # known CVE and no other enrichment must still surface that CVE -- dropping
    # it because a CVSS score happened to be absent would hide the one fact
    # that matters.
    if primary:
        bits.append(f"primary advisory: {primary}")
    cves = pkg.get("cve_list") or []
    others = sorted({str(c) for c in cves if str(c) and str(c) != primary})
    if others:
        bits.append("also: " + ", ".join(others))
    cvss = pkg.get("cvss_score", pkg.get("cvss"))
    if cvss not in (None, ""):
        bits.append(f"cvss: {cvss}")
    # Emitted only when the record states a version or a vector, so a
    # package that carries no score at all still gets no "cvss" text.
    bits.extend(_cvss_assessment_bits(pkg))
    reach = str(pkg.get("reachability_status") or "").strip()
    if reach:
        bits.append(f"reachability: {reach}")
    decision = str(pkg.get("exploitability_decision") or "").strip()
    if decision:
        bits.append(f"exploitability_decision: {decision}")
    epss = pkg.get("epss_score")
    if epss not in (None, ""):
        bits.append(f"epss: {epss}")
    kev = str(pkg.get("kev_status") or "").strip()
    if kev:
        bits.append(f"kev: {kev}")

    if not bits:
        return out

    out.append({
        "annotationDate": _now_iso(),
        "annotationType": "OTHER",
        "annotator": f"Tool: {TOOL_NAME}-{TOOL_VERSION}",
        "comment": (
            "VULNERABILITY EVIDENCE (static analysis of the dependency manifest; "
            "no package was downloaded or executed). " + "; ".join(bits)
        ),
    })
    return out


def _build_packages(sbom: list[dict]) -> tuple[list[dict], dict[str, dict]]:
    packages = []
    by_key = {}
    for pkg in sbom:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or pkg.get("package") or "").strip()
        if not name:
            continue
        version = _real_version(pkg)
        spdx_id = _spdx_id("Package", name, version)
        entry = {
            "SPDXID": spdx_id,
            "name": name,
            "downloadLocation": _download_location(pkg),
            # We read a manifest. We did not unpack and inspect package files.
            "filesAnalyzed": False,
            "copyrightText": str(pkg.get("copyright") or NOASSERTION),
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": _declared_license(pkg),
            "licenseComments": (
                "licenseConcluded is NOASSERTION: R-SecOpsX did not review the "
                "package's licence text, so no conclusion is drawn."
            ),
            "sourceInfo": (
                "Resolved from the dependency manifest by static analysis. The "
                "package was not downloaded, unpacked or executed."
            ),
        }
        if version:
            entry["versionInfo"] = version
        eco = str(pkg.get("ecosystem") or "").strip()
        notes = []
        if eco:
            notes.append(f"Ecosystem: {eco}")
        dep_type = str(pkg.get("dependency_type") or pkg.get("scope") or "").strip()
        if dep_type:
            notes.append(f"dependency type: {dep_type}")
        if not version:
            # Say so rather than shipping a placeholder as an identity.
            notes.append(
                "version not pinned by the manifest; versionInfo is omitted "
                "rather than filled with a placeholder"
            )
        if notes:
            entry["comment"] = "; ".join(notes)
        anns = _package_annotations(pkg, spdx_id)
        if anns:
            entry["annotations"] = anns
        refs = _external_refs(pkg, spdx_id)
        if refs:
            entry["externalRefs"] = refs
        packages.append(entry)
        by_key[f"{name}@{version}"] = {
            "spdx_id": spdx_id,
            "pkg": pkg,
        }
    return packages, by_key


def _document_annotations(payload: dict) -> list[dict]:
    """The document-level verdict.

    Restricted to what R-SecOpsX actually decided. No framework-compliance
    claim appears here: SPDX has no field for it and this tool cannot attest it.
    """
    meta = payload.get("metadata") or {}
    rr = payload.get("release_readiness") or {}
    ed = payload.get("executive_decision") or {}

    parts = []
    for label, value in (
        ("release_decision", meta.get("canonical_release_decision")
         or rr.get("release_decision")),
        ("executive_decision", meta.get("canonical_executive_decision")
         or ed.get("executive_decision")),
        ("total_findings", meta.get("total_findings")),
        ("risk_score", meta.get("risk_score")),
    ):
        if value not in (None, ""):
            parts.append(f"{label}: {value}")

    findings = payload.get("findings") or []
    if findings:
        reportable = sum(1 for f in findings if f.get("reportable_finding") is True)
        unresolved = sum(1 for f in findings if "decision_state" not in f)
        ev_valid = sum(1 for f in findings if f.get("evidence_valid") is True)
        parts.append(
            f"sast findings: {len(findings)}; reportable: {reportable}; "
            f"decision state not recorded: {unresolved}; evidence_valid: {ev_valid}"
        )

    parts.append(
        "SCOPE: dependency manifest analysis plus static source analysis. No "
        "package was downloaded or executed and no file-level package contents "
        "were inspected, so filesAnalyzed is false on every package."
    )
    parts.append(
        "NO COMPLIANCE ATTESTATION: this document records tool output. It does "
        "not assert conformance to any framework, standard or regulation."
    )

    return [{
        "annotationDate": _now_iso(),
        "annotationType": "OTHER",
        "annotator": f"Tool: {TOOL_NAME}-{TOOL_VERSION}",
        "comment": " | ".join(parts),
    }]


def build_spdx(payload: dict, document_name: str | None = None) -> dict:
    """Build an SPDX 2.3 document for one produced artifact."""
    meta = payload.get("metadata") or {}
    sbom = payload.get("sbom") or []

    packages, by_key = _build_packages(sbom)

    name = document_name or str(
        meta.get("project_name") or meta.get("project") or meta.get("target_name")
        or "rsecopsx-scan"
    )

    relationships = [
        {
            "spdxElementId": SPDX_DOCUMENT_ID,
            "relatedSpdxElement": p["SPDXID"],
            "relationshipType": REL_DESCRIBES,
        }
        for p in packages
    ]

    # Dependency edges: only where the graph VERIFIED them. An unverified or
    # inferred edge is omitted, because a wrong DEPENDS_ON is worse than a
    # missing one.
    graph = payload.get("dependency_graph") or {}
    verified = graph.get("verified_edges") or graph.get("edges") or []
    edges_emitted = 0
    edges_skipped = 0
    for edge in verified:
        if not isinstance(edge, dict):
            continue
        a = by_key.get(f"{edge.get('from') or edge.get('source')}@{edge.get('from_version') or ''}")
        b = by_key.get(f"{edge.get('to') or edge.get('target')}@{edge.get('to_version') or ''}")
        if not a or not b:
            edges_skipped += 1
            continue
        relationships.append({
            "spdxElementId": a["spdx_id"],
            "relatedSpdxElement": b["spdx_id"],
            "relationshipType": REL_DEPENDS_ON,
        })
        edges_emitted += 1

    doc: dict = {
        "SPDXID": SPDX_DOCUMENT_ID,
        "spdxVersion": SPDX_VERSION,
        "dataLicense": SPDX_DATA_LICENSE,
        "name": name,
        # SPDX requires an unambiguous, unique namespace URI. Derived from the
        # scan identity so two scans of two targets never collide.
        "documentNamespace": (
            "https://r-secopsx.local/spdxdocs/"
            f"{_SPDXID_CLEAN.sub('-', name).strip('-') or 'scan'}"
            f"-{meta.get('scan_id') or _now_iso().replace(':', '').replace('-', '')}"
        ),
        "creationInfo": {
            "created": _now_iso(),
            "creators": [f"Tool: {TOOL_NAME}-{TOOL_VERSION}"],
            "comment": (
                "Generated by R-SecOpsX from a dependency manifest and a static "
                "source scan. No SLSA provenance or in-toto attestation is "
                "included: this tool is not the builder of the software it "
                "scans and cannot attest how it was built."
            ),
        },
        "documentDescribes": [p["SPDXID"] for p in packages],
        "packages": packages,
        "relationships": relationships,
        "annotations": _document_annotations(payload),
    }
    return doc


# ---------------------------------------------------------------------------
# Schema validation.
#
# The schema is not vendored (it is fetched, not shipped), so validation is
# structural and pinned to the rules that matter here. This catches the class
# of defect that makes consumers reject a document: an unexpected property, a
# missing required field, or a value outside a closed enum.
# ---------------------------------------------------------------------------

_PKG_ALLOWED = {
    "SPDXID", "name", "versionInfo", "downloadLocation", "filesAnalyzed",
    "copyrightText", "licenseConcluded", "licenseDeclared", "licenseComments",
    "sourceInfo", "comment", "homepage", "supplier", "originator",
    "externalRefs", "annotations", "attributionTexts", "checksums",
    "primaryPackagePurpose", "releaseDate", "builtDate", "validUntilDate",
    "description", "summary", "licenseInfoFromFiles", "packageFileName",
}
_DOC_ALLOWED = {
    "SPDXID", "spdxVersion", "dataLicense", "name", "documentNamespace",
    "creationInfo", "documentDescribes", "packages", "relationships",
    "annotations", "comment", "externalDocumentRefs", "hasExtractedLicensingInfos",
    "revieweds",
}
_REL_TYPES = {
    REL_DESCRIBES, REL_DEPENDS_ON, REL_DEPENDENCY_OF, REL_CONTAINS, REL_OTHER,
    "CONTAINED_BY", "DYNAMIC_LINK", "STATIC_LINK", "GENERATED_FROM",
    "BUILD_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "DEV_DEPENDENCY_OF",
    "TEST_DEPENDENCY_OF", "OPTIONAL_COMPONENT_OF", "OPTIONAL_DEPENDENCY_OF",
    "DESCENDANT_OF", "ANCESTOR_OF", "VARIANT_OF", "COPY_OF", "OTHER",
    "DISTRIBUTION_ARTIFACT", "PATCH_FOR", "PATCH_APPLIED", "GENERATES",
    "BUILD_TOOL_OF", "DEV_TOOL_OF", "TEST_OF", "TEST_TOOL_OF", "TEST_CASE_OF",
    "EXAMPLE_OF", "PACKAGE_OF", "AMENDS", "PREREQUISITE_FOR", "HAS_PREREQUISITE",
    "PROVIDED_DEPENDENCY_OF", "REQUIREMENT_DESCRIPTION_FOR", "SPECIFICATION_FOR",
    "DOCUMENTATION_OF", "DESCRIBED_BY", "METAFILE_OF", "DEPENDENCY_MANIFEST_OF",
    "DATA_FILE_OF", "EXPANDED_FROM_ARCHIVE", "FILE_ADDED", "FILE_MODIFIED",
    "FILE_DELETED",
}


def validate_spdx(doc: dict) -> list[str]:
    """Structural validation against the pinned SPDX 2.3 rules. Returns problems."""
    problems = []

    for key in ("SPDXID", "creationInfo", "dataLicense", "name", "spdxVersion"):
        if key not in doc:
            problems.append(f"document missing required key {key}")
    extra = set(doc) - _DOC_ALLOWED
    if extra:
        problems.append(f"document has properties SPDX 2.3 forbids: {sorted(extra)}")
    if doc.get("spdxVersion") != SPDX_VERSION:
        problems.append(f"spdxVersion must be {SPDX_VERSION}")
    if doc.get("dataLicense") != SPDX_DATA_LICENSE:
        problems.append(f"dataLicense must be {SPDX_DATA_LICENSE}")
    if not str(doc.get("name") or "").strip():
        problems.append("document name must be non-empty")

    ci = doc.get("creationInfo") or {}
    if not ci.get("created"):
        problems.append("creationInfo.created is required")
    if not ci.get("creators"):
        problems.append("creationInfo.creators must have at least one entry")
    ci_extra = set(ci) - {"created", "creators", "comment", "licenseListVersion"}
    if ci_extra:
        problems.append(f"creationInfo has forbidden properties: {sorted(ci_extra)}")

    ids = set()
    for i, pkg in enumerate(doc.get("packages") or []):
        for key in ("SPDXID", "name", "downloadLocation"):
            if key not in pkg:
                problems.append(f"packages[{i}] missing required key {key}")
        extra = set(pkg) - _PKG_ALLOWED
        if extra:
            problems.append(f"packages[{i}] has forbidden properties: {sorted(extra)}")
        if not str(pkg.get("name") or "").strip():
            problems.append(f"packages[{i}].name must be non-empty")
        if pkg.get("filesAnalyzed") is not False and "hasFiles" not in pkg:
            problems.append(
                f"packages[{i}] claims filesAnalyzed without hasFiles")
        if pkg.get("filesAnalyzed") is False and pkg.get("packageVerificationCode"):
            problems.append(
                f"packages[{i}] carries a packageVerificationCode while claiming "
                "filesAnalyzed=false")
        sid = pkg.get("SPDXID")
        if sid in ids:
            problems.append(f"duplicate SPDXID {sid}")
        ids.add(sid)

    described = set(doc.get("documentDescribes") or [])
    for did in described:
        if did not in ids:
            problems.append(f"documentDescribes references unknown id {did}")

    for i, rel in enumerate(doc.get("relationships") or []):
        for key in ("spdxElementId", "relatedSpdxElement", "relationshipType"):
            if key not in rel:
                problems.append(f"relationships[{i}] missing required key {key}")
        if rel.get("relationshipType") not in _REL_TYPES:
            problems.append(
                f"relationships[{i}].relationshipType "
                f"{rel.get('relationshipType')!r} is not in the SPDX 2.3 enum")
        for key in ("spdxElementId", "relatedSpdxElement"):
            val = rel.get(key)
            if val not in ids and val != SPDX_DOCUMENT_ID:
                problems.append(f"relationships[{i}].{key} references unknown id {val}")

    for i, ann in enumerate(doc.get("annotations") or []):
        for key in ("annotationDate", "annotationType", "annotator", "comment"):
            if key not in ann:
                problems.append(f"annotations[{i}] missing required key {key}")
        if ann.get("annotationType") not in {"OTHER", "REVIEW"}:
            problems.append(
                f"annotations[{i}].annotationType {ann.get('annotationType')!r} "
                "is not in the SPDX 2.3 enum")

    return problems


def write_spdx_report(payload: dict, output_path: str,
                      document_name: str | None = None) -> str:
    doc = build_spdx(payload, document_name=document_name)
    problems = validate_spdx(doc)
    if problems:
        raise ValueError(
            "SPDX 2.3 validation failed; refusing to write an invalid document:\n  "
            + "\n  ".join(problems))
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return str(out)


# Backward-compatible alias matching the other exporters.
write_spdx = write_spdx_report