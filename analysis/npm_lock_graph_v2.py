"""
R-SecOpsX V10
NPM package-lock authoritative dependency relationship extractor V2.

Step 2C:
Workspace / file / path dependency handling.

Evidence rule:
Only explicit package-lock dependency declarations create VERIFIED
relationships.

Registry, workspace, file/path and unresolved identities remain
semantically distinct.
"""

from __future__ import annotations
try:
    from analysis.spans import WINDOW_24
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_24

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ENGINE_VERSION = "NPM_LOCK_GRAPH_V2.2"
VERIFIED = "VERIFIED"


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _canonical_purl(name: str, version: str) -> str:
    name = _clean(name)
    version = _clean(version)

    if not name:
        return ""

    return (
        f"pkg:npm/{name}@{version}"
        if version
        else f"pkg:npm/{name}"
    )


def _edge_fingerprint(parent: str, child: str) -> str:
    raw = f"{parent}|{child}".encode(
        "utf-8",
        errors="ignore",
    )
    return hashlib.sha256(raw).hexdigest()[:WINDOW_24]


def _package_name_from_path(path: str) -> str:
    parts = Path(path).parts

    indexes = [
        index
        for index, value in enumerate(parts)
        if value == "node_modules"
    ]

    if not indexes:
        return ""

    index = indexes[-1]
    remaining = list(parts[index + 1:])

    if not remaining:
        return ""

    if remaining[0].startswith("@") and len(remaining) >= 2:
        return f"{remaining[0]}/{remaining[1]}"

    return remaining[0]


def _is_package_node(path: str) -> bool:
    return "node_modules" in Path(path).parts


def _is_root_node(path: str) -> bool:
    return path in ("", ".")


def _component_id(
    name: str,
    record: Dict[str, Any],
) -> str:
    version = _clean(record.get("version"))

    if version:
        return _canonical_purl(name, version)

    return _canonical_purl(name, "")


def _dependency_kind(
    requested_spec: Any,
) -> Tuple[str, str]:
    """
    Classify the declared dependency specification.

    This classification does not determine whether the relationship
    exists. The explicit dependency declaration already establishes
    the relationship as authoritative.
    """

    spec = _clean(requested_spec)

    if spec.startswith("workspace:"):
        return "WORKSPACE", spec

    if (
        spec.startswith("file:")
        or spec.startswith("./")
        or spec.startswith("../")
    ):
        return "FILE_PATH", spec

    if spec.startswith("link:"):
        return "LINK", spec

    if spec.startswith("npm:"):
        return "NPM_ALIAS", spec

    return "REGISTRY", spec


def _load_lockfile(
    path: str,
) -> Dict[str, Any]:

    with open(
        path,
        "r",
        encoding="utf-8-sig",
    ) as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(
            "package-lock.json root must be an object"
        )

    return data


def _node_modules_parent_path(
    package_path: str,
) -> Optional[str]:

    parts = list(Path(package_path).parts)

    if "node_modules" not in parts:
        return None

    indexes = [
        index
        for index, value in enumerate(parts)
        if value == "node_modules"
    ]

    if len(indexes) <= 1:
        return ""

    parent_end = indexes[-1]

    parent_parts = parts[:parent_end]

    return str(Path(*parent_parts))


def _resolve_child_path(
    parent_path: str,
    child_name: str,
    package_nodes: Dict[str, Dict[str, Any]],
) -> Tuple[Optional[str], str]:

    child_name = _clean(child_name)

    if not child_name:
        return None, "INVALID_CHILD_NAME"

    search_base = parent_path or ""

    while True:

        candidate = (
            f"{search_base}/node_modules/{child_name}"
            if search_base
            else f"node_modules/{child_name}"
        )

        if candidate in package_nodes:
            return (
                candidate,
                "RESOLVED_BY_NODE_MODULES_TOPOLOGY",
            )

        if not search_base:
            break

        # F-3: the walk uses ONE separator representation ("/") end to
        # end. The retired str(Path(*parts)) form backslash-joined the
        # base on Windows, so every intermediate candidate missed the
        # forward-slash node table and nested dependencies fell through
        # to the hoisted root node (measured: 350/1907 NodeGoat edges).
        parts = [
            segment for segment in search_base.split("/")
            if segment
        ]

        indexes = [
            index
            for index, value in enumerate(parts)
            if value == "node_modules"
        ]

        if not indexes:
            search_base = ""
            continue

        last_nm = indexes[-1]

        if last_nm == 0:
            search_base = ""
        else:
            search_base = "/".join(parts[:last_nm])

    return None, "UNRESOLVED_FROM_TOPOLOGY"


def _resolve_workspace_target(
    requested_spec: str,
    parent_path: str,
    packages: Dict[str, Dict[str, Any]],
) -> Tuple[Optional[str], str]:

    spec = _clean(requested_spec)

    if not spec.startswith("workspace:"):
        return None, "NOT_WORKSPACE"

    workspace_value = spec[len("workspace:"):]

    # workspace:* / workspace:^ / workspace:~
    # expresses workspace intent but does not itself identify
    # the physical workspace path.
    if workspace_value in ("*", "^", "~", ""):
        return None, "WORKSPACE_VERSION_SELECTOR_ONLY"

    candidate_name = workspace_value

    for package_path, record in packages.items():

        if not isinstance(record, dict):
            continue

        package_name = _clean(
            record.get("name")
        )

        if package_name == candidate_name:
            return (
                package_path,
                "RESOLVED_WORKSPACE_PACKAGE",
            )

    return None, "WORKSPACE_TARGET_NOT_FOUND"


def _resolve_file_target(
    requested_spec: str,
    parent_path: str,
    packages: Dict[str, Dict[str, Any]],
) -> Tuple[Optional[str], str]:

    spec = _clean(requested_spec)

    if spec.startswith("file:"):
        relative = spec[len("file:"):]
    elif spec.startswith("./") or spec.startswith("../"):
        relative = spec
    else:
        return None, "NOT_FILE_PATH"

    base = Path(parent_path).parent if parent_path else Path(".")

    target = str(
        (base / relative).as_posix()
    ).rstrip("/")

    target = target.replace(
        "./",
        "",
        1,
    ) if target.startswith("./") else target

    for package_path in packages:

        normalized = str(
            Path(package_path).as_posix()
        ).rstrip("/")

        if normalized == target:
            return (
                package_path,
                "RESOLVED_FILE_PATH_PACKAGE",
            )

    return None, "FILE_PATH_TARGET_NOT_FOUND"


def extract_verified_edges(
    lockfile_path: str,
) -> Dict[str, Any]:

    data = _load_lockfile(
        lockfile_path
    )

    lockfile_version = data.get(
        "lockfileVersion"
    )

    if lockfile_version not in (2, 3):

        return {
            "engine": ENGINE_VERSION,
            "source": str(lockfile_path),
            "lockfile_version":
                lockfile_version,
            "graph_status":
                "UNSUPPORTED_LOCKFILE_VERSION",
            "verified_edge_count": 0,
            "edges": [],
        }

    packages = data.get("packages")

    if not isinstance(packages, dict):

        return {
            "engine": ENGINE_VERSION,
            "source": str(lockfile_path),
            "lockfile_version":
                lockfile_version,
            "graph_status":
                "NO_AUTHORITATIVE_PACKAGES_SECTION",
            "verified_edge_count": 0,
            "edges": [],
        }

    package_nodes = {
        path: record
        for path, record in packages.items()
        if _is_package_node(path)
        and isinstance(record, dict)
    }

    edges: List[Dict[str, Any]] = []
    seen = set()

    workspace_edges = 0
    file_path_edges = 0
    registry_edges = 0
    unresolved_edges = 0

    for parent_path, parent_record in packages.items():

        if not isinstance(parent_record, dict):
            continue

        dependencies = parent_record.get(
            "dependencies"
        )

        if not isinstance(dependencies, dict):
            continue

        if _is_root_node(parent_path):

            parent_id = "pkg:npm/__root__"

        elif _is_package_node(parent_path):

            parent_name = _package_name_from_path(
                parent_path
            )

            if not parent_name:
                continue

            parent_id = _component_id(
                parent_name,
                parent_record,
            )

        else:
            continue

        for child_name, requested_spec in dependencies.items():

            child_name = _clean(child_name)
            spec = _clean(requested_spec)

            if not child_name:
                continue

            dependency_kind, normalized_spec = (
                _dependency_kind(spec)
            )

            child_path = None
            resolution_status = ""

            if dependency_kind == "WORKSPACE":

                child_path, resolution_status = (
                    _resolve_workspace_target(
                        spec,
                        parent_path,
                        packages,
                    )
                )

                workspace_edges += 1

            elif dependency_kind == "FILE_PATH":

                child_path, resolution_status = (
                    _resolve_file_target(
                        spec,
                        parent_path,
                        packages,
                    )
                )

                file_path_edges += 1

            else:

                child_path, resolution_status = (
                    _resolve_child_path(
                        parent_path,
                        child_name,
                        package_nodes,
                    )
                )

                if dependency_kind == "REGISTRY":
                    registry_edges += 1

            if child_path is not None:

                child_record = packages.get(
                    child_path,
                    {},
                )

                child_record = (
                    child_record
                    if isinstance(
                        child_record,
                        dict,
                    )
                    else {}
                )

                resolved_name = _clean(
                    child_record.get("name")
                )

                if not resolved_name:
                    resolved_name = (
                        _package_name_from_path(
                            child_path
                        )
                    )

                if resolved_name:

                    child_id = _component_id(
                        resolved_name,
                        child_record,
                    )

                else:

                    child_id = (
                        f"pkg:npm/{child_name}"
                    )

            else:

                unresolved_edges += 1

                if dependency_kind == "WORKSPACE":

                    child_id = (
                        f"pkg:npm-workspace/"
                        f"{child_name}"
                    )

                elif dependency_kind == "FILE_PATH":

                    child_id = (
                        f"pkg:npm-file/"
                        f"{child_name}"
                    )

                else:

                    child_id = (
                        f"pkg:npm/{child_name}"
                    )

                if not resolution_status:
                    resolution_status = (
                        "UNRESOLVED"
                    )

            fingerprint = _edge_fingerprint(
                parent_id,
                child_id,
            )

            if fingerprint in seen:
                continue

            seen.add(fingerprint)

            edges.append(
                {
                    "parent": parent_id,
                    "child": child_id,
                    "parent_lockfile_path":
                        parent_path,
                    "child_lockfile_path":
                        child_path or "",
                    "source":
                        str(lockfile_path),
                    "relationship":
                        "AUTHORITATIVE_NPM_LOCKFILE_DEPENDENCY",
                    "dependency_kind":
                        dependency_kind,
                    "requested_spec":
                        normalized_spec,
                    "resolution_status":
                        resolution_status,
                    "confidence":
                        VERIFIED,
                    "fingerprint":
                        fingerprint,
                }
            )

    return {
        "engine": ENGINE_VERSION,
        "source": str(lockfile_path),
        "lockfile_version":
            lockfile_version,
        "graph_status": (
            "VERIFIED_EDGES_AVAILABLE"
            if edges
            else "NO_VERIFIED_EDGES"
        ),
        "verified_edge_count":
            len(edges),
        "workspace_edge_count":
            workspace_edges,
        "file_path_edge_count":
            file_path_edges,
        "registry_edge_count":
            registry_edges,
        "unresolved_edge_count":
            unresolved_edges,
        "edges": edges,
        "evidence_policy":
            "AUTHORITATIVE_PACKAGE_LOCK_ONLY",
    }


def validate_graph(
    graph: Dict[str, Any],
) -> Dict[str, Any]:

    errors: List[str] = []

    edges = graph.get(
        "edges",
        [],
    )

    if not isinstance(edges, list):

        errors.append(
            "edges must be a list"
        )

        edges = []

    seen = set()

    for index, edge in enumerate(edges):

        if not isinstance(edge, dict):

            errors.append(
                f"edge[{index}] is not an object"
            )

            continue

        parent = _clean(
            edge.get("parent")
        )

        child = _clean(
            edge.get("child")
        )

        if not parent:
            errors.append(
                f"edge[{index}] missing parent"
            )

        if not child:
            errors.append(
                f"edge[{index}] missing child"
            )

        if edge.get("confidence") != VERIFIED:

            errors.append(
                f"edge[{index}] is not VERIFIED"
            )

        key = (
            parent,
            child,
        )

        if key in seen:

            errors.append(
                f"duplicate edge "
                f"{parent} -> {child}"
            )

        seen.add(key)

    if graph.get(
        "verified_edge_count"
    ) != len(edges):

        errors.append(
            "verified_edge_count mismatch"
        )

    return {
        "valid": not errors,
        "error_count": len(errors),
        "errors": errors,
    }


def smoke_test() -> Dict[str, Any]:

    import tempfile

    lockfile = {

        "name": "workspace-demo",

        "lockfileVersion": 3,

        "packages": {

            "": {
                "dependencies": {
                    "express": "^5.1.0",
                    "@demo/core":
                        "workspace:*",
                    "local-lib":
                        "file:packages/local-lib",
                }
            },

            "node_modules/express": {
                "name": "express",
                "version": "5.1.0",
                "dependencies": {
                    "qs": "^6.14.0",
                },
            },

            "node_modules/qs": {
                "name": "qs",
                "version": "6.14.0",
            },

            "packages/core": {
                "name": "@demo/core",
                "version": "1.0.0",
            },

            "packages/local-lib": {
                "name": "local-lib",
                "version": "1.2.0",
            },
        },
    }

    with tempfile.TemporaryDirectory() as tmp:

        path = (
            Path(tmp)
            / "package-lock.json"
        )

        path.write_text(
            json.dumps(lockfile),
            encoding="utf-8",
        )

        result = extract_verified_edges(
            str(path)
        )

    validation = validate_graph(
        result
    )

    assert validation["valid"]

    # Four authoritative dependency declarations are present:
    #   root -> express
    #   express -> qs
    #   root -> workspace package
    #   root -> local file package
    #
    # The workspace:* declaration is authoritative as a relationship,
    # but its target cannot be resolved from the version selector alone.
    assert result[
        "verified_edge_count"
    ] == 4

    assert result[
        "workspace_edge_count"
    ] == 1

    assert result[
        "file_path_edge_count"
    ] == 1

    assert result[
        "unresolved_edge_count"
    ] == 1

    assert any(
        edge["dependency_kind"]
        == "REGISTRY"
        and edge["child"]
        == "pkg:npm/express@5.1.0"
        for edge in result["edges"]
    )

    assert any(
        edge["dependency_kind"]
        == "WORKSPACE"
        and edge["child"]
        == "pkg:npm-workspace/@demo/core"
        and edge["resolution_status"]
        == "WORKSPACE_VERSION_SELECTOR_ONLY"
        and edge["child_lockfile_path"]
        == ""
        for edge in result["edges"]
    )

    assert any(
        edge["dependency_kind"]
        == "FILE_PATH"
        and edge["child"]
        == "pkg:npm/local-lib@1.2.0"
        for edge in result["edges"]
    )

    return {
        "status":
            "NPM_LOCK_GRAPH_V2_WORKSPACE_SMOKE_PASS",
        "verified_edges":
            result["verified_edge_count"],
        "registry_edges":
            result["registry_edge_count"],
        "workspace_edges":
            result["workspace_edge_count"],
        "file_path_edges":
            result["file_path_edge_count"],
        "unresolved_edges":
            result["unresolved_edge_count"],
        "graph_status":
            result["graph_status"],
    }


if __name__ == "__main__":
    print(smoke_test())

