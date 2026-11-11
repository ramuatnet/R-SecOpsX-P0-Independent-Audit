from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path

from core.value_state import (
    GATE_LOCKFILE_MEMBERSHIP,
    GATE_MANIFEST_DIRECT,
    GATE_NAMED_PARENT,
    GATE_NO_EVIDENCE,
    GATE_PATH_HEAD,
    GATE_VERIFIED_TRANSITIVE,
    PARENT_AMBIGUOUS_MULTIPLE_PARENTS,
    PARENT_AMBIGUOUS_MULTIPLE_VERSIONS,
    PARENT_ROOT_DECLARED,
    VERIFIED_PARENT_EDGE,
)


DIRECT_MANIFESTS = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "packages.config",
    "directory.packages.props",
    "pyproject.toml",
    "pipfile",
}

# Every lockfile format the scanner parses authoritatively (see the
# _LOCKFILE_PARSERS registry in scanner/sbom.py). Names lowercase: the
# membership check compares against Path(...).name.lower(). Task 2: the
# retired set carried 7 of these, so cargo/uv/bun/deno/composer/gem/nuget
# lock rows either lost their membership evidence or, flag-less, fell
# through the old finalize default into a fabricated Direct.
LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "bun.lock",
    "deno.lock",
    "go.sum",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "packages.lock.json",
}


def _manifest_name(pkg: dict) -> str:
    manifest = (
        pkg.get("manifest_file")
        or pkg.get("source_manifest")
        or pkg.get("file")
        or ""
    )
    return Path(str(manifest)).name.lower()


# Placeholder the retired parent-synthesis path used to invent
# ("Unknown parent dependency"). Kept as a named constant so the evidence
# gate can REJECT it wherever an older payload or cached report still
# carries it -- it is evidence of nothing.
UNKNOWN_PARENT = "Unknown parent dependency"


def _path_head_is_package(value: str) -> bool:
    """True only when a path head names a PACKAGE, not a file or placeholder.

    The retired enrich_package path shape used the manifest FILENAME as the
    first hop (".../requirements.txt, flask"). A filename is provenance, not
    a parent package, so it must never satisfy the transitive evidence gate.
    """
    head = str(value or "").strip()
    if not head or head.casefold() == UNKNOWN_PARENT.casefold():
        return False
    if Path(head).name.lower() in DIRECT_MANIFESTS | LOCKFILES:
        return False
    return True


def _transitive_evidence_basis(pkg: dict) -> str | None:
    """Which evidence class a non-direct record carries, or ``None``.

    Single source for both the gate's decision and its provenance basis
    (R1/W2): ``_has_transitive_evidence`` stays the boolean read and
    ``dependency_type_evidence`` records the class -- the checks below are
    the ONLY place the transitive evidence vocabulary lives, in the same
    order the gate has always evaluated it.
    """
    # Stamped ONLY by join_verified_edges() from VERIFIED lockfile edges --
    # evidence by construction (Task 3 verified-edge integration).
    if pkg.get("verified_transitive") is True:
        return GATE_VERIFIED_TRANSITIVE

    if str(pkg.get("parent") or "").strip():
        return GATE_NAMED_PARENT

    introduced_by = str(pkg.get("introduced_by") or "").strip()
    if _path_head_is_package(introduced_by):
        return GATE_NAMED_PARENT

    path = pkg.get("dependency_path")
    if (
        isinstance(path, list)
        and len(path) >= 2
        and _path_head_is_package(str(path[0]))
    ):
        return GATE_PATH_HEAD

    # The record itself was parsed out of a lockfile: authoritative
    # membership in the resolved tree, parent unnamed.
    if _manifest_name(pkg) in LOCKFILES:
        return GATE_LOCKFILE_MEMBERSHIP

    return None


def _has_transitive_evidence(pkg: dict) -> bool:
    """Evidence a non-direct record may carry for a transitive relationship.

    Vocabulary follows the npm evidence policy (analysis/npm_lock_graph_v2):
    only authoritative declarations create relationships. A lockfile row
    vouches for TREE MEMBERSHIP even though it does not name the parent; a
    named parent / introduced_by / path head is a claim an upstream record
    actually made. A bare ``direct=False`` flag, an ``is_transitive`` flag
    or a ``transitive_guess`` are none of these -- they are assertions.
    """
    return _transitive_evidence_basis(pkg) is not None


def dependency_type_evidence(pkg: dict) -> tuple[str, str]:
    """(classification, evidence basis) from the Task-2 gate branches.

    ``infer_dependency_type`` is a thin wrapper over this -- same branches,
    same outcomes, unchanged public contract; the basis exists so provenance
    can record WHY (R1/W2) without growing a second classifier.
    """
    # Explicit dependency metadata always takes precedence
    # over manifest/lockfile inference.

    if pkg.get("direct") is True or pkg.get("is_direct") is True:
        return "Direct", GATE_MANIFEST_DIRECT

    if pkg.get("direct") is False or pkg.get("is_transitive") is True:
        # Task 2 (RC-2): a bare non-direct flag is NOT a verified
        # parent-child relationship. Transitive now requires evidence --
        # a named parent, a real path head, or authoritative lockfile
        # membership. Everything else is honestly Unknown instead of a
        # guess printed as fact.
        basis = _transitive_evidence_basis(pkg)
        if basis is None:
            return "Unknown", GATE_NO_EVIDENCE
        return "Transitive", basis

    manifest_name = _manifest_name(pkg)

    if manifest_name in DIRECT_MANIFESTS:
        return "Direct", GATE_MANIFEST_DIRECT

    if manifest_name in LOCKFILES:
        return "Transitive", GATE_LOCKFILE_MEMBERSHIP

    return "Unknown", GATE_NO_EVIDENCE


def infer_dependency_type(pkg: dict) -> str:
    return dependency_type_evidence(pkg)[0]


def stamp_parent_provenance(sbom) -> None:
    """``field_provenance['parent']`` from the join's own stamps (R1/W2).

    Reads ONLY fields ``join_verified_edges`` already wrote -- the parent
    edge fingerprint/source, ``parent_resolution``, ``verified_root_declared``
    -- and writes a reason-only provenance entry (a state-bearing entry could
    change how value_state resolves the record). An immediate verified edge
    is ONE hop; nothing here mints or implies a root-to-package path. Records
    the join never touched get no entry: no edge data existed for them.
    """
    for pkg in sbom or []:
        if not isinstance(pkg, dict):
            continue

        if pkg.get("parent_edge_fingerprint"):
            entry = {"reason": VERIFIED_PARENT_EDGE}
            if pkg.get("parent_edge_source"):
                entry["source"] = str(pkg["parent_edge_source"])
            entry["fingerprint"] = str(pkg["parent_edge_fingerprint"])
        elif pkg.get("parent_resolution") == "ambiguous_multiple_versions":
            entry = {"reason": PARENT_AMBIGUOUS_MULTIPLE_VERSIONS}
        elif pkg.get("parent_resolution") == "ambiguous_multiple_parents":
            entry = {"reason": PARENT_AMBIGUOUS_MULTIPLE_PARENTS}
        elif pkg.get("verified_root_declared"):
            entry = {"reason": PARENT_ROOT_DECLARED}
        else:
            continue

        prov = pkg.get("field_provenance")
        if isinstance(prov, dict) and "parent" in prov:
            continue  # an existing entry (an ingest adapter's) is authoritative
        if not isinstance(prov, dict):
            prov = {}
            pkg["field_provenance"] = prov
        prov["parent"] = entry
def infer_dependency_depth(pkg: dict) -> int:
    dep_type = infer_dependency_type(pkg)

    if dep_type == "Direct":
        return 1

    # A depth is computed only from a REAL multi-hop path. The retired
    # "Transitive -> 2" default synthesized a depth for records whose
    # parent was never observed; an unobserved depth is 0, like Unknown.
    existing_path = pkg.get("dependency_path")
    if isinstance(existing_path, list) and len(existing_path) >= 2:
        return len(existing_path)

    return 0


def infer_dependency_path(pkg: dict) -> list[str]:
    existing_path = pkg.get("dependency_path")
    dep_type = infer_dependency_type(pkg)

    if isinstance(existing_path, list) and existing_path:
        return existing_path

    name = str(pkg.get("name") or "unknown-package")
    version = str(pkg.get("version") or "unknown")
    package_node = f"{name}@{version}"

    if dep_type == "Direct":
        return [package_node]

    # Task 2 (RC-3): a parent hop is built ONLY from a parent something
    # actually recorded. A transitive record without that evidence carries
    # only its own node; the retired [UNKNOWN_PARENT, node] shape invented
    # a parent nothing observed.
    if dep_type == "Transitive":
        parent = str(pkg.get("parent") or pkg.get("introduced_by") or "").strip()
        if parent and _path_head_is_package(parent):
            return [parent, package_node]

    return [package_node]


def infer_introduced_by(pkg: dict) -> str:
    existing_path = pkg.get("dependency_path")

    if (
        isinstance(existing_path, list)
        and len(existing_path) >= 2
        and _path_head_is_package(str(existing_path[0]))
    ):
        return str(existing_path[0])

    dep_type = infer_dependency_type(pkg)

    if dep_type == "Direct":
        return str(pkg.get("manifest_file") or pkg.get("source_manifest") or "Direct manifest")

    if dep_type == "Transitive":
        # Task 2 (RC-3): the parent is returned only when something
        # actually recorded it. An unnamed parent yields "" so renderers
        # dash the cell out rather than print an invented one.
        return str(pkg.get("parent") or pkg.get("introduced_by") or "").strip()

    return ""



def _has_vulnerability(pkg: dict) -> bool:
    try:
        if int(pkg.get("vulnerability_count") or 0) > 0:
            return True
    except (ValueError, TypeError):
        pass

    if (
        pkg.get("cve")
        or pkg.get("advisory_id")
        or pkg.get("primary_vulnerability_id")
    ):
        return True

    vulns = pkg.get("vulnerabilities")

    if isinstance(vulns, list):
        return len(vulns) > 0

    if isinstance(vulns, (dict, int, float)):
        return bool(vulns)

    if isinstance(vulns, str):
        return bool(vulns.strip())

    return False

def enrich_dependency(pkg: dict) -> dict:
    item = deepcopy(pkg)

    dep_type = infer_dependency_type(item)
    dep_path = infer_dependency_path(item)

    item["dependency_type"] = dep_type
    item["dependency_depth"] = infer_dependency_depth({**item, "dependency_path": dep_path})
    item["introduced_by"] = infer_introduced_by({**item, "dependency_path": dep_path})
    item["dependency_path"] = dep_path

    item["is_direct"] = dep_type == "Direct"
    item["is_transitive"] = dep_type == "Transitive"

    return item


def enrich_dependency_intelligence(sbom: list[dict]) -> list[dict]:
    return [enrich_dependency(pkg) for pkg in sbom]


# ---------------------------------------------------------------------------
# Task 3: verified-edge integration
# ---------------------------------------------------------------------------

#: relationship_source stamp carried by records a verified edge explained.
VERIFIED_EDGE_RELATIONSHIP = "VERIFIED_NPM_LOCKFILE_EDGE"

_EDGE_PREFIX = "pkg:npm/"


def _parse_edge_node(node_id) -> tuple[str, str]:
    """``pkg:npm/<name>[@<version>]`` -> ``(name, version)``.

    Compares COMPONENTS, not raw purl strings: scanner.purl percent-encodes
    npm scopes (``pkg:npm/%40babel/core@7.0.0``) while the graph engine
    emits them raw (``pkg:npm/@babel/core@7.0.0``). Returns ("", "") for
    anything that is not an npm purl node. ``__root__`` is the synthetic
    root, never a package.
    """
    text = str(node_id or "").strip()
    if not text.startswith(_EDGE_PREFIX):
        return "", ""
    rest = text[len(_EDGE_PREFIX):]
    if rest == "__root__":
        return "__root__", ""
    name, sep, version = rest.rpartition("@")
    if not sep:
        return rest, ""
    return name, version


def _is_npm_ecosystem(value) -> bool:
    # npm-normalized aliases (mirrors normalize_ecosystem's npm mapping;
    # inlined here to keep this module import-light).
    return str(value or "").strip().casefold() in {
        "npm", "node", "javascript", "js",
    }


def join_verified_edges(sbom: list[dict], edges) -> dict:
    """Populate parent/introduced_by/dependency_path from VERIFIED edges only.

    Identity matching is purl-equivalent: ecosystem (npm-normalized) +
    package name (case-insensitive) + exact version. A record qualifies
    only with a resolved version -- a manifest range cannot be matched to
    a versioned lockfile node without guessing, so it is skipped and
    counted.

    Population rules (nothing is ever guessed):
      * exactly one distinct non-root parent at ONE version -> parent,
        introduced_by and dependency_path are stamped, plus edge
        provenance (fingerprint + source lockfile) that belongs to that
        exact instance;
      * one parent name at SEVERAL verified versions ->
        ``parent_resolution: "ambiguous_multiple_versions"`` with every
        verified instance and its fingerprint retained; no definitive
        parent path is minted (F-1);
      * several distinct parents -> ``ambiguous_multiple_parents`` with
        the same per-instance fingerprint pairs;
      * root-declared only -> ``verified_root_declared`` disclosure, no
        parent fields (the synthetic root is not a package);
      * direct records keep their manifest introduction -- a package
        parent edge does not overwrite it.

    Returns ``{"sbom": <the same records, mutated in place>, "summary":
    <join tallies + disclosure>}``.
    """
    summary = {
        "engine": "VERIFIED_EDGE_JOIN_V1",
        "evidence_policy": "VERIFIED_NPM_LOCKFILE_EDGES_ONLY",
        "identity": "PURL_EQUIVALENT_ECOSYSTEM_NAME_VERSION",
        "edges_seen": 0,
        "matched": 0,
        "parented": 0,
        "ambiguous_parents": 0,
        "ambiguous_parent_versions": 0,
        "root_declared_only": 0,
        "unmatched": 0,
        "skipped_non_npm": 0,
        "skipped_incomplete_identity": 0,
        "disclosure": (
            "parent/introduced_by/dependency_path are populated only from "
            "VERIFIED package-lock edges (npm engine). Records the npm "
            "engine does not cover, or whose identity is incomplete (no "
            "resolved version), keep their prior classification and are "
            "counted in the skipped/unmatched tallies. Nothing is guessed."
        ),
    }

    index: dict[tuple[str, str], list[dict]] = {}
    for edge in edges or []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("confidence") or "").strip().upper() != "VERIFIED":
            continue
        child_name, child_version = _parse_edge_node(edge.get("child"))
        parent_name, parent_version = _parse_edge_node(edge.get("parent"))
        if (not child_name or not child_version
                or not parent_name):
            # Versionless or malformed node ids: identity too weak to join.
            summary["skipped_incomplete_identity"] += 1
            continue
        summary["edges_seen"] += 1
        index.setdefault((child_name.casefold(), child_version), []).append({
            "parent_name": parent_name,
            "parent_version": parent_version,
            "is_root": parent_name == "__root__",
            "fingerprint": str(edge.get("fingerprint") or ""),
            "source": str(edge.get("source") or ""),
        })

    for pkg in sbom or []:
        if not isinstance(pkg, dict):
            continue
        if not _is_npm_ecosystem(pkg.get("ecosystem")):
            summary["skipped_non_npm"] += 1
            continue
        name = str(pkg.get("name") or "").strip()
        version = str(pkg.get("version") or "").strip()
        if not name or not version or version.casefold() == "unknown":
            summary["skipped_incomplete_identity"] += 1
            continue
        hits = index.get((name.casefold(), version))
        if not hits:
            summary["unmatched"] += 1
            continue
        summary["matched"] += 1

        # Direct records keep their manifest as the introduction point; a
        # package-parent edge would not change what introduced them.
        if pkg.get("direct") is True or pkg.get("is_direct") is True:
            if all(h["is_root"] for h in hits):
                pkg["verified_root_declared"] = True
                summary["root_declared_only"] += 1
            continue

        parent_names = sorted({
            h["parent_name"] for h in hits if not h["is_root"]
        })
        if not parent_names:
            # Only the root declares it: disclosure, no parent fields
            # (the synthetic root is not a package), classification
            # unchanged -- direct flags govern it.
            pkg["verified_root_declared"] = True
            summary["root_declared_only"] += 1
            continue

        # The transitive relationship is VERIFIED from here on.
        pkg["verified_transitive"] = True
        pkg["relationship_source"] = VERIFIED_EDGE_RELATIONSHIP

        # F-1/F-2: every verified parent instance carries its OWN
        # fingerprint and source; nothing is selected independently of
        # the instance it belongs to. Sorted for canonical order, so
        # input edge ordering can never change provenance.
        instances = sorted({
            (h["parent_name"], h["parent_version"],
             h["fingerprint"], h["source"])
            for h in hits if not h["is_root"]
        })
        pkg["verified_parent_instances"] = [
            {
                "parent": f"{n}@{v}" if v else n,
                "fingerprint": fp,
                "source": src,
            }
            for (n, v, fp, src) in instances
        ]

        if len(parent_names) == 1:
            parent_name = parent_names[0]
            versions = sorted({
                v for (n, v, _, _) in instances
                if n == parent_name and v
            })
            if len(versions) > 1:
                # F-1: the same parent name exists at several verified
                # versions and those instances point at this child.
                # Picking one version arbitrarily would manufacture a
                # definite introduction path from ambiguous evidence.
                pkg["parent_resolution"] = "ambiguous_multiple_versions"
                pkg["verified_parents"] = [parent_name]
                summary["ambiguous_parent_versions"] += 1
            else:
                v = versions[0] if versions else ""
                chosen = next(
                    i for i in pkg["verified_parent_instances"]
                    if i["parent"] == (f"{parent_name}@{v}" if v
                                       else parent_name))
                parent = chosen["parent"]
                pkg["parent"] = parent
                pkg["introduced_by"] = parent
                pkg["dependency_path"] = [parent, f"{name}@{version}"]
                # F-2: the fingerprint IS the stamped instance's edge.
                pkg["parent_edge_fingerprint"] = chosen["fingerprint"]
                pkg["parent_edge_source"] = chosen["source"]
                summary["parented"] += 1
        else:
            # Several distinct verified parents: verified transitive, but
            # picking ONE parent would be manufacturing. Disclose; the
            # per-instance fingerprint pairs travel with the disclosure.
            pkg["parent_resolution"] = "ambiguous_multiple_parents"
            pkg["verified_parents"] = parent_names
            summary["ambiguous_parents"] += 1

    return {"sbom": sbom, "summary": summary}


def dependency_summary(sbom: list[dict]) -> dict:
    direct = sum(1 for p in sbom if p.get("dependency_type") == "Direct")
    transitive = sum(1 for p in sbom if p.get("dependency_type") == "Transitive")
    unknown = sum(1 for p in sbom if p.get("dependency_type") == "Unknown")

    vulnerable_direct = sum(
        1 for p in sbom
        if p.get("dependency_type") == "Direct"
        and _has_vulnerability(p)
    )

    vulnerable_transitive = sum(
        1 for p in sbom
        if p.get("dependency_type") == "Transitive"
        and _has_vulnerability(p)
    )

    return {
        "direct_dependencies": direct,
        "transitive_dependencies": transitive,
        "unknown_dependencies": unknown,
        "vulnerable_direct_dependencies": vulnerable_direct,
        "vulnerable_transitive_dependencies": vulnerable_transitive,
    }


def enrich_report_payload(payload: dict) -> dict:
    result = deepcopy(payload)

    sbom = result.get("sbom", [])
    enriched_sbom = enrich_dependency_intelligence(sbom)

    result["sbom"] = enriched_sbom
    result["dependency_summary"] = dependency_summary(enriched_sbom)

    metadata = result.setdefault("metadata", {})
    metadata["direct_dependencies"] = result["dependency_summary"]["direct_dependencies"]
    metadata["transitive_dependencies"] = result["dependency_summary"]["transitive_dependencies"]
    metadata["unknown_dependencies"] = result["dependency_summary"]["unknown_dependencies"]
    metadata["vulnerable_direct_dependencies"] = result["dependency_summary"]["vulnerable_direct_dependencies"]
    metadata["vulnerable_transitive_dependencies"] = result["dependency_summary"]["vulnerable_transitive_dependencies"]

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="R-SecOpsX Dependency Intelligence Enhancer")
    parser.add_argument("input", help="Input clean_report.json or SBOM JSON")
    parser.add_argument("--output", default=None, help="Output enriched JSON")
    args = parser.parse_args()

    source = Path(args.input)
    data = json.loads(source.read_text(encoding="utf-8"))

    if isinstance(data, dict) and "sbom" in data:
        result = enrich_report_payload(data)
    elif isinstance(data, list):
        enriched = enrich_dependency_intelligence(data)
        result = {
            "sbom": enriched,
            "dependency_summary": dependency_summary(enriched),
        }
    else:
        raise SystemExit("Input must be clean_report.json with sbom or a list of packages")

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[DEPENDENCY-INTEL] Packages enriched: {len(result.get('sbom', []))}")
        print(f"[DEPENDENCY-INTEL] Output written: {output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

