"""Ruby/Bundler verified-edge extractor (R2.5a, evidence tier:
constraint-resolvable over the resolved specs universe).

Evidence basis (verified on the real railsgoat corpus, R2.0/R1): a
Gemfile.lock's ``specs:`` blocks under the GEM / GIT / PATH sections hold
the resolved universe WITH parent-child declarations -- a parent gem line
``name (version)`` followed by indented child lines ``name (constraint)``.
A child constraint that matches EXACTLY ONE resolved gem instance is a
VERIFIED edge; several matches are AMBIGUOUS (candidates disclosed, never
picked); none, or a constraint the matcher cannot understand, is
UNRESOLVED. Membership alone is never an edge.

Section provenance travels on the edges: GEM ``remote:`` -> registry,
GIT ``remote:``+``revision:`` -> git, PATH ``remote:`` -> path -- so
registry, git and path dependency identity is preserved.

Ruby dialect (disclosed, mapped LOCALLY -- ``versions.py`` untouched):
the pessimistic operator ``~> X`` means >= X, < next-version-bump, which
is EXACTLY the shared matcher's tilde semantics for both segment counts
(``~> 2.0`` -> ``~2.0`` -> [2.0, 3.0); ``~> 2.0.3`` -> ``~2.0.3`` ->
[2.0.3, 2.1.0)). ``=``, ``>=``, ``<=``, ``>``, ``<``, ``!=`` pass through.

The DEPENDENCIES section is the application's declared set (names, git
refs marked ``!``): tallied and disclosed, never edges -- the declaration
parent is the application, not a lockfile component (no synthetic root,
R2 contract §4). PLATFORMS is counted and disclosed. Platform-specific
gems carry the platform inside the version string; the identity stays
``name@version-verbatim``.

R1/W3 (GAP-09) relationship: the MEMBERSHIP parser's direct stamping was
fixed to read the DEPENDENCIES section; this extractor adds the VERIFIED
EDGE tier from the specs blocks without touching that classification.

Gemfile: manifest declarations are tallied (gem lines, source kinds,
group blocks) and disclosed, NEVER edges.

FND-03: every slice bound is a named span (analysis.spans).
"""

from __future__ import annotations

import re
from pathlib import Path

from analysis.spans import WINDOW_1, WINDOW_2, WINDOW_10, WINDOW_M2
from analysis.lock_graph import contract
from analysis.lock_graph.versions import satisfies

ENGINE = "BUNDLER_LOCK_GRAPH_V1"
EVIDENCE = "BUNDLER_LOCK_SPECS"
MANIFEST_ENGINE = "BUNDLER_GEMFILE_DECLARATIONS_V1"
FORMAT_LOCK = "Gemfile.lock"
FORMAT_MANIFEST = "Gemfile"

_SECTIONS = ("GEM", "GIT", "PATH", "PLUGIN")
_SPEC_LINE = re.compile(r"^(\S+)\s+\(([^)]+)\)\s*$")
_GEMFILE_LINE = re.compile(r'^\s*gem\s+["\']([^"\']+)["\']')


def _normalize_ruby_constraint(constraint: str) -> str:
    """Map the Ruby dialect onto the shared matcher (disclosed, local).

    Pessimistic ``~>`` bumps the SECOND-TO-LAST segment (RubyGems
    semantics), which no single shared operator reproduces for every
    segment count:
    - ``~> A.B``   with A > 0 -> ``^A.B``     ([A.B, (A+1).0));
    - ``~> 0.B``   (major 0)  -> ``>=0.B,<1.0`` (caret would bump the
      minor instead of the major);
    - ``~> A.B.C[.D...]``     -> ``>=CORE,<HI`` where HI bumps the
      second-to-last segment (``~> 2.0.5`` -> ``>=2.0.5,<2.1.0``;
      ``~> 3.17.0.2`` -> ``>=3.17.0.2,<3.17.1.0``);
    - 1-segment ``~> A`` is not valid RubyGems syntax: passes through and
      is reported unparseable, never guessed.
    COMMA-SEPARATED conjunctions (real corpus shape:
    ``tzinfo (~> 2.0, >= 2.0.5)``) transform clause-by-clause and stay
    comma-ANDed. Everything else (``=``, ``>=``, ``<=``, ``>``, ``<``,
    ``!=``) passes through unchanged.
    """
    text = str(constraint or "").strip()
    out = []
    for clause in text.split(","):
        clause = clause.strip()
        m = re.match(r"^~>\s*(\d+(?:\.\d+){1,})$", clause)
        if not m:
            out.append(clause)
            continue
        segments = m.group(WINDOW_1).split(".")
        if len(segments) == 2:
            major = int(segments[0])
            out.append(f"^{segments[0]}.{segments[1]}" if major > 0 else
                       f">={segments[0]}.{segments[1]},<{major + 1}.0")
        else:
            # second-to-last bump, expressed as an explicit conjunction
            hi = segments[:WINDOW_M2] + [str(int(segments[WINDOW_M2]) + 1),
                                         "0"]
            out.append(f">={m.group(WINDOW_1)},<{'.'.join(hi)}")
    return ",".join(out)


def _is_constraint_version(version: str) -> bool:
    """Gemfile.lock distinguishes parents from children by the operator:
    parent lines carry plain versions, child lines carry constraints."""
    return version.startswith((">", "<", "=", "~", "!"))


def extract(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(encoding="utf-8",
                                             errors="replace")
    except Exception as exc:
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=FORMAT_LOCK,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"Gemfile.lock read failed: {exc}"])

    lines = text.splitlines()
    if not any(line.strip() == "GEM" or line.strip().startswith("GIT")
               or line.strip().startswith("PATH") for line in lines[:WINDOW_10]):
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=FORMAT_LOCK,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["File does not carry Bundler GEM/GIT/PATH "
                         "sections; no edges fabricated."])

    # ---- walk: sections, provenance, specs universe, declarations ----------
    universe: dict[str, list] = {}
    section_records = []      # (parent_name, parent_version, qualifiers)
    invalid_records = 0
    duplicate_dropped = 0
    direct_declarations = 0
    git_declarations = 0
    platforms = 0
    section = None
    in_specs = False
    source_kind = None
    source_url = ""
    revision = ""
    parent_stack = []         # list of (indent, name, version, qualifiers)
    in_dependencies = False

    for raw in lines:
        line = raw.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[:WINDOW_1].isspace():
            # column-0 section header
            section = stripped
            in_specs = False
            in_dependencies = section == "DEPENDENCIES"
            if section in _SECTIONS:
                source_kind = {"GEM": "registry", "GIT": "git",
                               "PATH": "path"}[section]
                source_url = ""
                revision = ""
            continue
        if section in _SECTIONS and not in_specs:
            if stripped.startswith("remote:"):
                source_url = stripped[len("remote:"):].strip()
                continue
            if stripped.startswith("revision:"):
                revision = stripped[len("revision:"):].strip()
                continue
            if stripped in ("branch:", "tag:") or \
                    stripped.startswith(("branch:", "tag:")):
                continue
            if stripped == "specs:":
                in_specs = True
                parent_stack = []
                continue
            continue
        if section == "PLATFORMS":
            platforms += 1
            continue
        if in_dependencies:
            if stripped.endswith("!"):
                git_declarations += 1
            direct_declarations += 1
            continue

        m = _SPEC_LINE.match(stripped)
        if m is None:
            invalid_records += 1
            continue
        name = m.group(WINDOW_1).strip().strip('"')
        version_token = m.group(WINDOW_2).strip()
        indent = len(line) - len(line.lstrip(" "))

        if _is_constraint_version(version_token):
            if not parent_stack:
                invalid_records += 1
                continue
            # dependency declaration of the nearest enclosing parent
            _indent, pname, pversion, pquals = parent_stack[-1]
            section_records.append((pname, pversion, name,
                                    version_token, dict(pquals)))
            continue

        # a resolved gem instance
        qualifiers = {"source_kind": source_kind or "registry"}
        if source_url:
            qualifiers["source"] = source_url
        if revision:
            qualifiers["revision"] = revision
        parent_stack = [(indent, name, version_token, qualifiers)
                        for (i, _n, _v, _q) in parent_stack
                        if i < indent]
        parent_stack.append((indent, name, version_token, qualifiers))
        universe.setdefault(name, []).append(version_token)

    # ---- resolve declarations against the universe -------------------------
    edges = []
    for pname, pversion, child_name, constraint, pquals in section_records:
        location = f"specs: {pname} ({pversion}) {child_name} ({constraint})"
        candidates = universe.get(child_name, [])
        constraint_norm = _normalize_ruby_constraint(constraint)

        def _edge(**kwargs):
            requested = kwargs.pop("requested_spec", "")
            edge = contract.build_edge(
                ecosystem="rubygems", source=str(lockfile_path),
                source_location=location, evidence_source=EVIDENCE,
                scope="runtime", qualifiers=pquals, **kwargs)
            # requested_spec is a contract-schema field the shared builder
            # does not consume; attach it so the declared constraint
            # travels with the edge
            if requested:
                edge["requested_spec"] = requested
            return edge

        if not candidates:
            edges.append(_edge(
                parent_name=pname, parent_version=pversion,
                child_name=child_name, child_version="",
                resolution_status="CHILD_NOT_IN_LOCKFILE"))
            continue
        matched = sorted({v for v in candidates
                          if satisfies(v, constraint_norm)})
        parseable = satisfies("1.0.0", constraint_norm) is not None
        if len(matched) == 1:
            edges.append(_edge(
                parent_name=pname, parent_version=pversion,
                child_name=child_name, child_version=matched[0],
                requested_spec=constraint))
        elif len(matched) > 1:
            edges.append(_edge(
                parent_name=pname, parent_version=pversion,
                child_name=child_name, child_version="",
                confidence=contract.AMBIGUOUS,
                ambiguity={"constraint": constraint,
                           "candidates": matched},
                resolution_status="MULTIPLE_CANDIDATES",
                requested_spec=constraint))
        else:
            edges.append(_edge(
                parent_name=pname, parent_version=pversion,
                child_name=child_name, child_version="",
                resolution_status=("UNPARSEABLE_CONSTRAINT"
                                   if not parseable
                                   else "NO_MATCHING_VERSION"),
                requested_spec=constraint))

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
        engine=ENGINE, source=str(lockfile_path),
        format_version=FORMAT_LOCK, graph_status=verified_status,
        edges=edges,
        tallies={
            "direct_declarations": direct_declarations,
            "git_declarations": git_declarations,
            "platforms": platforms,
            "duplicate_records_dropped": duplicate_dropped,
            "invalid_records": invalid_records,
        },
        membership_packages=len(universe),
        limitations=[
            "Gemfile.lock specs blocks are the resolved universe with "
            "parent-child declarations: constraints are resolved against "
            "every resolved gem instance (GEM + GIT + PATH sections); "
            "unique match -> VERIFIED, multi-match -> AMBIGUOUS with "
            "candidates, none -> UNRESOLVED. Membership alone is never "
            "an edge.",
            "Ruby dialect mapped locally: pessimistic '~>' bumps the "
            "second-to-last segment -- 3-segment '~> A.B.C' -> '~A.B.C', "
            "2-segment with major>0 -> '^A.B', 2-segment with major 0 -> "
            "'>=0.B,<1.0'; comma conjunctions transform clause-by-clause; "
            "'=', '>=', '<=', '>', '<', '!=' pass through. Platform "
            "variants keep the platform inside the version string.",
            "The DEPENDENCIES section is the application's declared set: "
            "tallied (direct_declarations; git refs marked '!') and "
            "disclosed, never edges -- no synthetic root is minted.",
        ])


# ---- Gemfile manifest envelope -----------------------------------------------------
def extract_manifest(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(encoding="utf-8",
                                             errors="replace")
    except Exception as exc:
        return contract.extraction_result(
            engine=MANIFEST_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_MANIFEST,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"Gemfile read failed: {exc}"])

    gem_declarations = 0
    source_git = 0
    source_path = 0
    source_registry = 0
    group_blocks = 0
    in_group = False
    has_gem_lines = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("group ") and line.endswith("do") or \
                (line.startswith("group ") and line.rstrip().endswith("do")):
            group_blocks += 1
            in_group = True
            continue
        if line == "end" and in_group:
            in_group = False
            continue
        m = _GEMFILE_LINE.match(line)
        if m is None:
            continue
        has_gem_lines = True
        gem_declarations += 1
        if re.search(r"git:\s*[\"']", line):
            source_git += 1
        elif re.search(r"path:\s*[\"']", line):
            source_path += 1
        else:
            source_registry += 1

    if not has_gem_lines:
        return contract.extraction_result(
            engine=MANIFEST_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_MANIFEST,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["File declares no gems; no edges fabricated."])

    tallies = {
        "gem_declarations": gem_declarations,
        "source_git": source_git,
        "source_path": source_path,
        "source_registry": source_registry,
        "group_blocks": group_blocks,
    }
    return contract.extraction_result(
        engine=MANIFEST_ENGINE, source=str(lockfile_path),
        format_version=FORMAT_MANIFEST,
        graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
        tallies=tallies,
        limitations=[
            "Gemfile declarations are manifest statements, not resolved "
            "relationships: tallied (per source kind, group blocks) and "
            "disclosed, never edges -- no synthetic root is minted.",
            "resolved parent-child relationships require Gemfile.lock "
            "specs evidence (registered filename: Gemfile.lock).",
        ],
        membership_packages=gem_declarations)
