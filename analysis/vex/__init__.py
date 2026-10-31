"""SBOM/VEX service -- offline ingest + query of VEX statements and SBOMs.

task.md section 12 PHASE 9 "SBOM/VEX service".  Pure module + CLI; no
serve routes (disclosed in model).  See model.py for the contracts.
"""
from analysis.vex.model import (
    SCHEMA, VEX_STATUSES, VexInvalid, build, conflicts_for,
    component_key, match_statement, normalize_status, normalize_vex_doc,
    run_queries, sbom_component_row,
)

__all__ = [
    "SCHEMA", "VEX_STATUSES", "VexInvalid", "build", "conflicts_for",
    "component_key", "match_statement", "normalize_status",
    "normalize_vex_doc", "run_queries", "sbom_component_row",
]
