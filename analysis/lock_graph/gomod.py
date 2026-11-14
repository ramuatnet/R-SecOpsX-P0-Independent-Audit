"""Go verified-edge extractor (R2.4, evidence tier: resolved module graph).

Evidence basis and tiers (approved R2.4 scope):

- ``go mod graph`` output (registered filename ``go-mod-graph.txt``): one
  resolved edge per line, ``parent@version child@version``. The graph IS
  the resolved evidence: an edge whose both identities parse is VERIFIED
  (instance-to-instance, so the ambiguity machinery of constraint-range
  lockfiles structurally cannot arise). Unparseable lines are counted
  INVALID; versionless identities are UNRESOLVED. Go prints module paths
  ESCAPED (uppercase letters as ``!x``); identities are decoded to their
  canonical form so ``github.com/!burnt!sushi`` and
  ``github.com/BurntSushi`` are one identity. Versions (including
  ``+incompatible`` and pseudo-versions) travel verbatim.

- ``go.mod``: pins the main module's direct requires and the ``// indirect``
  pins, plus replace/exclude directives. The parent of every require is the
  MAIN MODULE -- not a lockfile component -- so these are tallied
  (direct_declarations / indirect_declarations / replacements) and
  disclosed, never edges, and no synthetic root is minted (R2 contract §4).
  A replace directive is dependency-SUBSTITUTION evidence, not a
  relationship: recorded verbatim (Go grammar: a two-token right side is a
  module target, a one-token right side is a local filesystem path).

- ``go.sum``: a checksum list. Membership evidence only -- it encodes NO
  parent-child relationships and is answered with a disclosed membership
  envelope (``/go.mod`` hash variants dedupe to the same module@version).

No ``go`` CLI exists in the R2.4 environment (GAP-R2-08), so real
``go mod graph`` artifacts cannot be generated here; corpus go.mod/go.sum
envelopes are validated against real files, graph fixtures are synthetic
and disclosed.

FND-03: every slice bound is a named span (analysis.spans).
"""

from __future__ import annotations

import re
from pathlib import Path

from analysis.spans import WINDOW_1, WINDOW_2, WINDOW_20, WINDOW_M1
from analysis.lock_graph import contract

GRAPH_ENGINE = "GO_MOD_GRAPH_V1"
GRAPH_EVIDENCE = "GO_MODULE_GRAPH"
DECL_ENGINE = "GO_MOD_DECLARATIONS_V1"
SUM_ENGINE = "GO_SUM_MEMBERSHIP_V1"
GRAPH_FILENAME = "go-mod-graph.txt"
FORMAT_GRAPH = "go mod graph"
FORMAT_GOMOD = "go.mod"
FORMAT_GOSUM = "go.sum"

_ESCAPED_CHAR = re.compile(r"!([a-z])")
_GRAPH_LINE = re.compile(r"^(\S+)@(\S+)\s+(\S+)@(\S+)\s*$")
_GOMOD_VERSION = re.compile(r"^v\d")
_GOSUM_LINE = re.compile(r"^(\S+)\s+(\S+)\s+h1:")
_REQUIRE_LINE = re.compile(r"(?:require\s+)?(\S+)\s+(v\S+)")


def _decode_module_path(path: str) -> str:
    """Decode Go's escaped module path (``!x`` -> uppercase ``X``)."""
    if "!" not in path:
        return path
    return _ESCAPED_CHAR.sub(lambda m: m.group(WINDOW_1).upper(), path)


def _split_identity(token: str) -> tuple:
    """``module@version`` -> (module, version); versionless -> (m, '')."""
    text = str(token or "").strip()
    at = text.rfind("@")
    if at <= 0:
        return (_decode_module_path(text), "")
    return (_decode_module_path(text[:at]), text[at + WINDOW_1:])


# ---- go mod graph -------------------------------------------------------------
def extract_graph(lockfile_path: str) -> dict:
    try:
        lines = Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return contract.extraction_result(
            engine=GRAPH_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_GRAPH,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"go mod graph read failed: {exc}"])

    edges = []
    invalid_records = 0
    duplicate_dropped = 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _GRAPH_LINE.match(line)
        if m is None:
            # a two-token line with a versionless half is still an
            # identity disclosure: UNRESOLVED with the name preserved;
            # anything else is counted invalid, never guessed
            tokens = line.split()
            if len(tokens) != 2:
                invalid_records += 1
                continue
            parent_name, parent_version = _split_identity(tokens[0])
            child_name, child_version = _split_identity(tokens[1])
            location = (f"{parent_name}"
                        f"{('@' + parent_version) if parent_version else ''}"
                        f" {child_name}"
                        f"{('@' + child_version) if child_version else ''}")

            def _edge(**kwargs):
                return contract.build_edge(
                    ecosystem="golang", source=str(lockfile_path),
                    source_location=location, evidence_source=GRAPH_EVIDENCE,
                    scope="runtime", **kwargs)

            edges.append(_edge(
                parent_name=parent_name, parent_version=parent_version,
                child_name=child_name, child_version=child_version,
                resolution_status="MALFORMED_GRAPH_LINE"))
            continue
        parent_name = _decode_module_path(m.group(WINDOW_1))
        parent_version = m.group(WINDOW_2)
        child_name = _decode_module_path(m.group(3))
        child_version = m.group(4)
        location = (f"{parent_name}@{parent_version} "
                    f"{child_name}@{child_version}")

        def _edge(**kwargs):
            return contract.build_edge(
                ecosystem="golang", source=str(lockfile_path),
                source_location=location, evidence_source=GRAPH_EVIDENCE,
                scope="runtime", **kwargs)

        if not parent_version or not child_version:
            edges.append(_edge(
                parent_name=parent_name, parent_version=parent_version,
                child_name=child_name, child_version="",
                resolution_status="MALFORMED_GRAPH_LINE"))
            continue
        edges.append(_edge(
            parent_name=parent_name, parent_version=parent_version,
            child_name=child_name, child_version=child_version))

    deduped: dict[tuple, dict] = {}
    for edge in edges:
        key = (edge["parent_name"], edge["parent_version"],
               edge["child_name"], edge.get("child_version") or "",
               edge["confidence"])
        if key in deduped:
            duplicate_dropped += 1
            continue
        deduped[key] = edge

    edges = sorted(deduped.values(), key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e["confidence"], e.get("child_version") or "",
    ))
    verified_status = (contract.VERIFIED_EDGES_AVAILABLE if any(
        e["confidence"] == contract.VERIFIED for e in edges)
        else contract.NO_VERIFIED_EDGES)
    return contract.extraction_result(
        engine=GRAPH_ENGINE, source=str(lockfile_path),
        format_version=FORMAT_GRAPH, graph_status=verified_status,
        edges=edges,
        tallies={"duplicate_records_dropped": duplicate_dropped,
                 "invalid_records": invalid_records},
        limitations=[
            "go mod graph lines are instance-to-instance resolved pairs: "
            "AMBIGUOUS structurally cannot arise; unparseable lines are "
            "counted invalid and versionless identities stay UNRESOLVED.",
            "module paths are decoded from Go's escaped form (!x -> X) so "
            "one canonical identity holds; versions (including "
            "+incompatible and pseudo-versions) travel verbatim.",
            "No `go` CLI in this environment (GAP-R2-08): real go mod "
            "graph artifacts cannot be generated here; synthetic graph "
            "fixtures carry this coverage and are disclosed as such.",
        ])


# ---- go.mod declarations --------------------------------------------------------
def _parse_replace(line: str) -> dict | None:
    """One replace directive (stripped) -> detail dict, or None.

    Go grammar: ``replace old [v] => new [v]``. A TWO-token right side is
    a module target; a ONE-token right side is a local filesystem path.
    """
    body = line[len("replace"):].strip()
    if "=>" not in body:
        return None
    left, _, right = body.partition("=>")
    left_parts = left.strip().split()
    right_parts = right.strip().split()
    if not left_parts or not right_parts:
        return None
    detail = {"from": left_parts[0],
              "from_version": (left_parts[WINDOW_1]
                               if len(left_parts) > WINDOW_1 else ""),
              "to": right_parts[0],
              "version": (right_parts[WINDOW_1]
                          if len(right_parts) > WINDOW_1 else "")}
    detail["local"] = len(right_parts) == WINDOW_1
    return detail


def extract_gomod(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace")
    except Exception as exc:
        return contract.extraction_result(
            engine=DECL_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_GOMOD,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"go.mod read failed: {exc}"])

    lines = text.splitlines()
    if not any(line.startswith(("module ", "module\t"))
               for line in lines[:WINDOW_20]):
        return contract.extraction_result(
            engine=DECL_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_GOMOD,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["File does not declare a Go module; no edges "
                         "fabricated."])

    module_name = ""
    go_directive = ""
    direct_declarations = 0
    indirect_declarations = 0
    membership = 0
    replacements = []
    excludes = 0
    in_require = False
    in_replace = False
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("replace ("):
            in_replace = True
            continue
        if in_replace and line == ")":
            in_replace = False
            continue
        if in_replace or line.startswith("replace"):
            detail = _parse_replace(line) if not in_replace else \
                _parse_replace("replace " + line)
            if detail:
                replacements.append(detail)
            continue
        if line.startswith("module"):
            module_name = line[len("module"):].strip()
            continue
        if line.startswith("go ") or line.startswith("go\t"):
            go_directive = line[len("go"):].strip()
            continue
        if line.startswith("exclude"):
            excludes += 1
            continue
        if in_require or line.startswith("require"):
            decl = _REQUIRE_LINE.match(line)
            if decl is None:
                continue
            membership += 1
            if line.endswith("// indirect"):
                indirect_declarations += 1
            else:
                direct_declarations += 1

    limitations = [
        "go.mod pins the main module's direct requires and indirect "
        "markers, but every declaration's parent is the MAIN MODULE, "
        "which is not a lockfile component: declarations are tallied "
        "(direct_declarations / indirect_declarations) and disclosed, "
        "never edges -- no synthetic root is minted.",
        "resolved parent-child relationships require `go mod graph` "
        "evidence (registered filename: go-mod-graph.txt); go.sum is a "
        "checksum list with membership evidence only.",
        f"main module: {module_name or '?'}; go directive: "
        f"{go_directive or '?'}.",
    ]
    for repl in replacements:
        target = repl["to"] + (f" {repl['version']}"
                               if repl["version"] else "")
        limitations.append(
            f"replace directive (substitution evidence, not a "
            f"relationship): {repl['from']}"
            f"{(' ' + repl['from_version']) if repl['from_version'] else ''}"
            f" => {target}"
            f"{' [local filesystem path]' if repl['local'] else ''}.")
    tallies = {
        "direct_declarations": direct_declarations,
        "indirect_declarations": indirect_declarations,
        "replacements": len(replacements),
        "excludes": excludes,
    }
    return contract.extraction_result(
        engine=DECL_ENGINE, source=str(lockfile_path),
        format_version=FORMAT_GOMOD,
        graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
        tallies=tallies, limitations=limitations,
        membership_packages=membership)


# ---- go.sum membership -----------------------------------------------------------
def extract_gosum(lockfile_path: str) -> dict:
    try:
        lines = Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return contract.extraction_result(
            engine=SUM_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_GOSUM,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"go.sum read failed: {exc}"])

    modules = set()
    checksum_lines = 0
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = _GOSUM_LINE.match(line)
        if m is None:
            continue
        checksum_lines += 1
        module = _decode_module_path(m.group(WINDOW_1))
        version = m.group(WINDOW_2).removesuffix("/go.mod")
        if module and version:
            modules.add((module, version))

    return contract.extraction_result(
        engine=SUM_ENGINE, source=str(lockfile_path),
        format_version=FORMAT_GOSUM,
        graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
        tallies={"checksum_lines": checksum_lines},
        limitations=[
            "go.sum is a checksum list: it records which module@version "
            "pairs the build consumed but encodes NO parent-child "
            "relationships -- membership evidence only, never edges "
            "(approved R2.4 constraint).",
            "resolved parent-child relationships require `go mod graph` "
            "evidence (registered filename: go-mod-graph.txt).",
        ],
        membership_packages=len(modules))
