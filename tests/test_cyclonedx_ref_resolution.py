"""Every CycloneDX ref must resolve inside its own document (R1/W1, GAP-04).

The defect this pins: ``dependencies[]`` serialized raw engine endpoint ids
verbatim, so three endpoint classes produced references with no matching
component -- dangling refs any CycloneDX dependency-graph consumer chokes on:

1. ``pkg:npm/__root__`` shipped as an *ordinary* ``application`` component
   (a synthetic node pretending to be software) instead of the BOM subject.
2. ``pkg:npm-workspace/{name}`` / ``pkg:npm-file/{name}`` ids (versionless,
   emitted by ``analysis/npm_lock_graph_v2`` for unresolved workspace and
   file-path specs) have no component counterpart at all.
3. registry ids naming identities absent from the canonical SBOM.

Root cause note (measured, 2026-11-11): the exporter has its OWN ``_purl``
(``reporting/cyclonedx_export.py``) built from raw parser names -- it does
NOT call ``scanner.purl`` -- so scoped refs are internally consistent
(``pkg:npm/@scope/pkg@1.0.0``) and the ``%40``-encoding mismatch claimed for
GAP-04 does not exist at the exporter. The real gap is endpoint resolution,
which is what these tests pin.

Contract: every ``ref``/``dependsOn`` value in the emitted document resolves
to a component bom-ref or to the ``metadata.component`` bom-ref; endpoints
that resolve to nothing are dropped and counted in disclosed
``metadata.properties`` tallies -- never serialized as dangling refs.
"""

import json

from reporting.cyclonedx_export import build_cyclonedx

ROOT_REF = "pkg:npm/__root__"


def _payload(sbom, edges, target="/proj/demo"):
    return {
        "sbom": sbom,
        "dependency_graph": {"edges": edges},
        "metadata": {"target": target},
    }


def _edge(parent, child):
    return {"parent": parent, "child": child, "confidence": "VERIFIED"}


def _doc(payload):
    return build_cyclonedx(payload)


def _refs(doc):
    comps = {c["bom-ref"] for c in doc.get("components", [])}
    meta = doc.get("metadata", {}).get("component", {})
    if meta:
        comps = comps | {meta["bom-ref"]}
    emitted = [x["ref"] for x in doc.get("dependencies", [])]
    emitted += [k for x in doc.get("dependencies", []) for k in x["dependsOn"]]
    return comps, emitted


def _meta_props(doc):
    return {
        p["name"]: p["value"]
        for p in doc.get("metadata", {}).get("properties", [])
    }


# ------------------------------------------------------- the synthetic root --
def test_root_is_metadata_component_not_an_ordinary_component():
    payload = _payload(
        sbom=[{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}],
        edges=[_edge(ROOT_REF, "pkg:npm/lodash@4.17.21")],
    )
    doc = _doc(payload)
    assert ROOT_REF not in {c["bom-ref"] for c in doc["components"]}
    meta = doc["metadata"]["component"]
    assert meta["bom-ref"] == ROOT_REF
    assert meta["type"] == "application"


def test_root_group_still_present_in_dependencies():
    payload = _payload(
        sbom=[{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}],
        edges=[_edge(ROOT_REF, "pkg:npm/lodash@4.17.21")],
    )
    doc = _doc(payload)
    groups = {x["ref"]: x["dependsOn"] for x in doc["dependencies"]}
    assert groups[ROOT_REF] == ["pkg:npm/lodash@4.17.21"]


# ----------------------------------------------------- scoped registry ids --
def test_scoped_depends_on_resolves_to_component_bom_ref():
    # The exporter's own purl form is raw ``@scope`` end to end, so a scoped
    # edge must resolve to the scoped component bom-ref as emitted.
    pkg = {"name": "@scope/pkg", "version": "1.0.0", "ecosystem": "npm"}
    payload = _payload(
        sbom=[pkg],
        edges=[_edge(ROOT_REF, "pkg:npm/@scope/pkg@1.0.0")],
    )
    doc = _doc(payload)
    comps, emitted = _refs(doc)
    assert "pkg:npm/@scope/pkg@1.0.0" in comps
    assert set(emitted) <= comps


# ------------------------------------------- workspace and file-path endpoints --
def test_workspace_endpoint_without_exact_counterpart_dropped_and_counted():
    payload = _payload(
        sbom=[
            {"name": "app", "version": "1.0.0", "ecosystem": "npm"},
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
        ],
        edges=[
            _edge("pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.21"),
            _edge("pkg:npm/app@1.0.0", "pkg:npm-workspace/ws-a"),
        ],
    )
    doc = _doc(payload)
    comps, emitted = _refs(doc)
    assert set(emitted) <= comps
    assert "pkg:npm-workspace/ws-a" not in emitted
    groups = {x["ref"]: x["dependsOn"] for x in doc["dependencies"]}
    assert groups["pkg:npm/app@1.0.0"] == ["pkg:npm/lodash@4.17.21"]
    props = _meta_props(doc)
    tally = json.loads(props["rsecopsx:edge_ref_resolution"])
    assert tally["workspace_file_dropped"] == 1


def test_file_endpoint_without_exact_counterpart_dropped_and_counted():
    payload = _payload(
        sbom=[{"name": "app", "version": "1.0.0", "ecosystem": "npm"}],
        edges=[_edge("pkg:npm/app@1.0.0", "pkg:npm-file/../shared/util")],
    )
    doc = _doc(payload)
    comps, emitted = _refs(doc)
    assert set(emitted) <= comps
    tally = json.loads(_meta_props(doc)["rsecopsx:edge_ref_resolution"])
    assert tally["workspace_file_dropped"] == 1


# ------------------------------------------------ unresolved registry ids --
def test_unresolved_registry_endpoint_dropped_and_counted():
    payload = _payload(
        sbom=[{"name": "app", "version": "1.0.0", "ecosystem": "npm"}],
        edges=[
            _edge("pkg:npm/ghost@9.9.9", "pkg:npm/app@1.0.0"),
            _edge("pkg:npm/app@1.0.0", "pkg:npm/phantom"),
        ],
    )
    doc = _doc(payload)
    comps, emitted = _refs(doc)
    assert set(emitted) <= comps
    tally = json.loads(_meta_props(doc)["rsecopsx:edge_ref_resolution"])
    assert tally["dropped"] == 2


# ----------------------------------------------------------- the invariant --
def test_no_dangling_refs_invariant_on_mixed_fixture():
    sbom = [
        {"name": "app", "version": "1.0.0", "ecosystem": "npm"},
        {"name": "@scope/pkg", "version": "1.0.0", "ecosystem": "npm"},
        {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
    ]
    edges = [
        _edge(ROOT_REF, "pkg:npm/app@1.0.0"),
        _edge(ROOT_REF, "pkg:npm/@scope/pkg@1.0.0"),
        _edge("pkg:npm/app@1.0.0", "pkg:npm/@scope/pkg@1.0.0"),
        _edge("pkg:npm/@scope/pkg@1.0.0", "pkg:npm/lodash@4.17.21"),
        _edge("pkg:npm/app@1.0.0", "pkg:npm-workspace/ws-a"),
        _edge("pkg:npm/app@1.0.0", "pkg:npm/ghost@9.9.9"),
    ]
    doc = _doc(_payload(sbom, edges))
    comps, emitted = _refs(doc)
    assert emitted, "fixture must produce dependency refs"
    assert set(emitted) <= comps


def test_resolution_tally_disclosed_in_metadata_properties():
    payload = _payload(
        sbom=[{"name": "app", "version": "1.0.0", "ecosystem": "npm"}],
        edges=[_edge("pkg:npm/app@1.0.0", "pkg:npm/app@1.0.0")],
    )
    doc = _doc(payload)
    assert "rsecopsx:edge_ref_resolution" in _meta_props(doc)


# ------------------------------------------------------- compatibility pin --
def test_unscoped_fully_resolved_refs_unchanged():
    # Compatibility pin: on a tree where every endpoint is a canonical
    # component, the emitted dependencies are exactly what the exporter
    # shipped before W1 (sorted refs, sorted dependsOn).
    sbom = [
        {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
        {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
    ]
    edges = [
        _edge("pkg:npm/express@4.18.2", "pkg:npm/lodash@4.17.21"),
        _edge("pkg:npm/lodash@4.17.21", "pkg:npm/express@4.18.2"),
    ]
    doc = _doc(_payload(sbom, edges))
    assert doc["dependencies"] == [
        {"ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/lodash@4.17.21"]},
        {"ref": "pkg:npm/lodash@4.17.21", "dependsOn": ["pkg:npm/express@4.18.2"]},
    ]


# ------------------------------------------------- R2.1 contract edges --
def test_contract_edges_resolve_without_raw_ids():
    # R2.1 contract edges (poetry/uv extractors) carry purl-built identity
    # fields and NO raw parent/child ids -- the exporter must resolve them
    # against the component index exactly like engine edges, or the
    # verified relationships silently vanish from CycloneDX (found on the
    # DVAP/flask R2.1 benchmark scans).
    payload = {
        "sbom": [
            {"name": "flask", "version": "3.1.0", "ecosystem": "pypi"},
            {"name": "click", "version": "8.1.7", "ecosystem": "pypi"},
        ],
        "dependency_graph": {
            "edges": [{
                "ecosystem": "pypi",
                "parent_name": "flask", "parent_version": "3.1.0",
                "parent_purl": "pkg:pypi/flask@3.1.0",
                "child_name": "click", "child_version": "8.1.7",
                "child_purl": "pkg:pypi/click@8.1.7",
                "confidence": "VERIFIED",
                "evidence_source": "POETRY_PACKAGE_DEPENDENCIES",
                "source": "poetry.lock",
                "fingerprint": "sha256:t",
            }],
        },
        "metadata": {"target": "/proj/demo"},
    }
    doc = build_cyclonedx(payload)
    comps, emitted = _refs(doc)
    assert "pkg:pypi/click@8.1.7" in comps
    groups = {x["ref"]: x["dependsOn"] for x in doc["dependencies"]}
    assert groups["pkg:pypi/flask@3.1.0"] == ["pkg:pypi/click@8.1.7"]
    assert set(emitted) <= comps


def test_contract_edge_parent_absent_dropped_and_counted():
    # W1 doctrine holds for contract edges: a parent identity absent from
    # the component set (e.g. the scanned project itself, which membership
    # parsers do not emit as a component) is dropped and counted -- never
    # serialized as a dangling ref.
    payload = {
        "sbom": [
            {"name": "click", "version": "8.1.7", "ecosystem": "pypi"},
        ],
        "dependency_graph": {
            "edges": [{
                "ecosystem": "pypi",
                "parent_name": "flask", "parent_version": "3.1.0",
                "parent_purl": "pkg:pypi/flask@3.1.0",
                "child_name": "click", "child_version": "8.1.7",
                "child_purl": "pkg:pypi/click@8.1.7",
                "confidence": "VERIFIED",
                "evidence_source": "POETRY_PACKAGE_DEPENDENCIES",
                "source": "poetry.lock",
                "fingerprint": "sha256:t",
            }],
        },
        "metadata": {"target": "/proj/demo"},
    }
    doc = build_cyclonedx(payload)
    comps, emitted = _refs(doc)
    assert set(emitted) <= comps
    tally = json.loads(_meta_props(doc)["rsecopsx:edge_ref_resolution"])
    assert tally["dropped"] == 1  # parent unresolved; child IS a component
