"""T-6.4: unified asset graph (external asset -> internal resource ->
code finding attack paths).

Submodules: model (nodes), links (edges), paths (attack paths),
connect (offline ingest + CLI).  ``build_graph`` / ``collect_graph``
are re-exported for convenience; the submodules themselves are never
shadowed by re-exports.
"""
from analysis.graph import links, model, paths  # noqa: F401
from analysis.graph.connect import build_graph, collect_graph  # noqa: F401

SCHEMA = model.SCHEMA
