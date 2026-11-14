"""Lockfile -> extractor dispatch (R2.1).

The one-walk index discovers lockfiles by name; main.py hands each discovered
file here instead of importing the npm engine directly. The npm path
delegates to the adapter (`npm_adapter.extract`), which wraps the unmodified
engine; each R2 ecosystem registers its own module.

Membership-only and not-yet-implemented formats answer with a disclosed
UNSUPPORTED envelope -- the registry never raises past main.py's existing
per-file error handling, and never fabricates edges for a format whose
evidence tier does not support them.
"""

from __future__ import annotations

from pathlib import Path

from analysis.lock_graph import contract
from analysis.lock_graph import gradle as _gradle
from analysis.lock_graph import maven as _maven
from analysis.lock_graph import npm_adapter
from analysis.lock_graph import pipfile
from analysis.lock_graph import pnpm as _pnpm_extractor
from analysis.lock_graph import poetry as _poetry_extractor
from analysis.lock_graph import uv as _uv_extractor
from analysis.lock_graph import yarn as _yarn_extractor
from analysis.lock_graph import cargo as _cargo_extractor
from analysis.lock_graph import nuget as _nuget_extractor
from analysis.lock_graph import rubygems as _ruby_extractor
from analysis.lock_graph import gomod as _go_extractor

ENGINE = "LOCK_GRAPH_REGISTRY_V1"


#: filename -> extractor. Keys are exact lockfile names as they appear on
#: disk (Pipfile.lock is conventionally case-sensitive; the others lowercase).
REGISTRY = {
    "package-lock.json": npm_adapter.extract,
    "poetry.lock": _poetry_extractor.extract,
    "uv.lock": _uv_extractor.extract,
    "Pipfile.lock": pipfile.extract,
    # R2.2 (Java): resolved-evidence files carry verified edges; manifest
    # files answer with disclosed UNSUPPORTED envelopes -- a pom or build
    # script is direct declarations, never a resolved graph.
    "dependency-tree.txt": _maven.extract,
    "pom.xml": _maven.extract_manifest,
    "gradle-dependencies.txt": _gradle.extract,
    "gradle.lockfile": _gradle.extract_lockfile,
    "build.gradle": _maven.extract_manifest,
    "settings.gradle": _maven.extract_manifest,
    # R2.3 (JavaScript): yarn v1 entries carry per-instance dependencies;
    # Berry lockfiles answer with disclosed UNSUPPORTED envelopes. pnpm
    # snapshot relations are exact resolved identities (5.4/6.0/6.1/9.0).
    "yarn.lock": _yarn_extractor.extract,
    "pnpm-lock.yaml": _pnpm_extractor.extract,
    # R2.4 (Go): `go mod graph` output carries resolved module-graph edges;
    # go.mod declarations and go.sum checksums answer with disclosed
    # envelopes (declarations/membership are never relationships).
    "go-mod-graph.txt": _go_extractor.extract_graph,
    "go.mod": _go_extractor.extract_gomod,
    "go.sum": _go_extractor.extract_gosum,
    # R2.4 (Rust): Cargo.lock carries resolved parent-child dependencies;
    # Cargo.toml declarations answer with a disclosed envelope.
    "Cargo.lock": _cargo_extractor.extract,
    "Cargo.toml": _cargo_extractor.extract_manifest,
    # R2.5a (Ruby): Gemfile.lock specs blocks carry resolved parent-child
    # declarations (GEM/GIT/PATH provenance); Gemfile declarations answer
    # with a disclosed envelope.
    "Gemfile.lock": _ruby_extractor.extract,
    "Gemfile": _ruby_extractor.extract_manifest,
    # R2.5b (.NET): packages.lock.json / project.assets.json targets are
    # resolved restore evidence; packages.config and the CPM catalog
    # answer with disclosed envelopes (membership/declarations are not
    # relationships).
    "packages.lock.json": _nuget_extractor.extract_lock,
    "project.assets.json": _nuget_extractor.extract_assets,
    "packages.config": _nuget_extractor.extract_packages_config,
    "Directory.Packages.props": _nuget_extractor.extract_props,
}

LOCKFILE_NAMES = frozenset(REGISTRY)


def extract_for_file(lockfile_path: str) -> dict:
    name = Path(lockfile_path).name
    extractor = REGISTRY.get(name)
    if extractor is None:
        return contract.extraction_result(
            engine=ENGINE,
            source=str(lockfile_path),
            format_version="unknown",
            graph_status=contract.UNSUPPORTED_FORMAT,
            edges=[],
            limitations=[
                f"No graph extractor registered for '{name}'; membership "
                "parsers may still classify the format, but no verified "
                "edges are fabricated.",
            ],
        )
    return extractor(lockfile_path)
