"""Policy-as-code gates (T-8.3, task.md section 11).

Submodules are imported AS submodules (``pkg.model is model`` -- the
same no-shadow contract as analysis.serve); the evaluation surface is
re-exported here for ``from analysis.policy import ...`` callers
(main.py wiring, the CLI, tests).
"""
from . import connect, model, policy_yaml
from .model import (
    DOC_SCHEMA,
    POLICY_SCHEMA,
    RESULT_SCHEMA,
    SEVERITIES,
    PolicyInvalid,
    evaluate,
    load_policy_file,
    parse_policy,
    rows_from_payload,
)

__all__ = [
    "DOC_SCHEMA",
    "POLICY_SCHEMA",
    "RESULT_SCHEMA",
    "SEVERITIES",
    "PolicyInvalid",
    "connect",
    "evaluate",
    "load_policy_file",
    "model",
    "parse_policy",
    "policy_yaml",
    "rows_from_payload",
]
