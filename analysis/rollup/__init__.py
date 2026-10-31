"""T-9.3 org/multi-repo rollup (D-1) -- manifest envelopes + collator.

Two submodules: ``model`` (pure schemas, validators, collator) and
``connect`` (the ``--org-rollup manifests/*.json`` CLI).  The v1
contract lives on the re-exported names below; renaming a schema
string breaks every stored manifest, so they are pinned by test.
"""
from __future__ import annotations

from . import connect, model
from .model import (MANIFEST_SCHEMA, ORG_ROLLUP_SCHEMA, RollupInvalid,
                    build_rollup, manifest_from_report, validate_manifest,
                    validate_rollup)

__all__ = [
    "MANIFEST_SCHEMA",
    "ORG_ROLLUP_SCHEMA",
    "RollupInvalid",
    "build_rollup",
    "connect",
    "manifest_from_report",
    "model",
    "validate_manifest",
    "validate_rollup",
]
