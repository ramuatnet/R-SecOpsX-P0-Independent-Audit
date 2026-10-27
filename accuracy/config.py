"""Accuracy layer configuration.

Every switch lives here. Defaults: layer ON, NEEDS_REVIEW excluded from the
filtered list (mission: filtered list contains only TRUE_POSITIVE, with
NEEDS_REVIEW optionally behind a flag).

Legacy equivalence: setting RSECOPSX_ACCURACY_LAYER=0 makes every entrypoint
a no-op and the scan output is byte-identical to the pre-layer run (asserted
by the snapshot regression test).
"""
from __future__ import annotations

import os

ACCURACY_SCHEMA = "RSECOPSX-ACCURACY-1"
POLICY_VERSION = "1.0.0"

VERDICTS = (
    "TRUE_POSITIVE",
    "NEEDS_REVIEW",
    "LIKELY_FALSE_POSITIVE",
    "MISLABELED",
    "SUPPRESSED_USER",       # inline / .sastignore / baseline
    "SUPPRESSED_KNOWN",      # baseline-known finding
    "DUPLICATE",
)

# Numeric confidence bounds per verdict (0-100).
CONFIDENCE = {
    "TRUE_POSITIVE": 90,
    "NEEDS_REVIEW": 45,
    "LIKELY_FALSE_POSITIVE": 15,
    "MISLABELED": 20,
    "SUPPRESSED_USER": 5,
    "SUPPRESSED_KNOWN": 10,
    "DUPLICATE": 0,
}

# Files whose content is provenance metadata, not source.
_AUDIT_ONLY_CONTENT = (
    "RBI7SASTSBOMSCA-result.json",   # measured aclean FP (98 rows)
)


def layer_enabled() -> bool:
    raw = os.environ.get("RSECOPSX_ACCURACY_LAYER", "1")
    return str(raw).strip().lower() not in ("0", "false", "no", "off")


def filtered_include_needs_review() -> bool:
    raw = os.environ.get("RSECOPSX_ACCURACY_INCLUDE_REVIEW", "0")
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def context_window() -> int:
    try:
        return max(0, int(os.environ.get("RSECOPSX_ACCURACY_CONTEXT", "10")))
    except ValueError:
        return 10


def entropy_threshold_generic() -> float:
    try:
        return float(os.environ.get("RSECOPSX_ACCURACY_SECRET_ENTROPY", "3.0"))
    except ValueError:
        return 3.0
