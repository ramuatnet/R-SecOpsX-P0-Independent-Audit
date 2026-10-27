"""Accuracy layer: post-detection validation & suppression (additive only).

This package sits AFTER the existing rules produce candidate findings and
BEFORE reporting. It changes NOTHING about detection: existing rules, regexes
and engine functions are untouched. With the layer disabled the output is
byte-identical to legacy (asserted by tests/test_accuracy_layer.py).

Verdict vocabulary (mission Phase 2):
  TRUE_POSITIVE         confirmed with a traced source-to-sink path
  NEEDS_REVIEW          plausible but unproven, or design-level
  LIKELY_FALSE_POSITIVE a validator found concrete counterevidence
  MISLABELED            the line has a real sink of a DIFFERENT type
Suppressed findings are never deleted: they keep verdict, reason and
confidence in the audit output.

Integration: main.py calls accuracy.layer.apply_accuracy_layer(payload,
target) after the UFIB stage. Flag: RSECOPSX_ACCURACY_LAYER (default ON).
"""
from accuracy.config import (
    ACCURACY_SCHEMA,
    VERDICTS,
    layer_enabled,
    filtered_include_needs_review,
)

__all__ = [
    "ACCURACY_SCHEMA", "VERDICTS", "layer_enabled",
    "filtered_include_needs_review",
]
