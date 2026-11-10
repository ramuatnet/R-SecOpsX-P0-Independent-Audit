from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path


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


def _has_transitive_evidence(pkg: dict) -> bool:
    """Evidence a non-direct record may carry for a transitive relationship.

    Vocabulary follows the npm evidence policy (analysis/npm_lock_graph_v2):
    only authoritative declarations create relationships. A lockfile row
    vouches for TREE MEMBERSHIP even though it does not name the parent; a
    named parent / introduced_by / path head is a claim an upstream record
    actually made. A bare ``direct=False`` flag, an ``is_transitive`` flag
    or a ``transitive_guess`` are none of these -- they are assertions.
    """
    if str(pkg.get("parent") or "").strip():
        return True

    introduced_by = str(pkg.get("introduced_by") or "").strip()
    if _path_head_is_package(introduced_by):
        return True

    path = pkg.get("dependency_path")
    if (
        isinstance(path, list)
        and len(path) >= 2
        and _path_head_is_package(str(path[0]))
    ):
        return True

    # The record itself was parsed out of a lockfile: authoritative
    # membership in the resolved tree, parent unnamed.
    return _manifest_name(pkg) in LOCKFILES


def infer_dependency_type(pkg: dict) -> str:
    # Explicit dependency metadata always takes precedence
    # over manifest/lockfile inference.

    if pkg.get("direct") is True or pkg.get("is_direct") is True:
        return "Direct"

    if pkg.get("direct") is False or pkg.get("is_transitive") is True:
        # Task 2 (RC-2): a bare non-direct flag is NOT a verified
        # parent-child relationship. Transitive now requires evidence --
        # a named parent, a real path head, or authoritative lockfile
        # membership. Everything else is honestly Unknown instead of a
        # guess printed as fact.
        if _has_transitive_evidence(pkg):
            return "Transitive"
        return "Unknown"

    manifest_name = _manifest_name(pkg)

    if manifest_name in DIRECT_MANIFESTS:
        return "Direct"

    if manifest_name in LOCKFILES:
        return "Transitive"

    return "Unknown"
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

