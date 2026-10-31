"""T-7.2: feedback store package.

Triage outcomes, verification results, fix state, FP confidence
decay, re-scan score deltas and regression alerts.  Pure cores in
analysis.feedback.model / analysis.feedback.delta; file ingest +
CLI in analysis.feedback.connect (offline, zero-I/O by default --
no network, no environment reads).  Score deltas flow through the
T-7.1 scoring service so --explain-score stays the single
explanation surface for scores.
"""
from analysis.feedback import delta, model  # noqa: F401
from analysis.feedback.connect import main  # noqa: F401
from analysis.feedback.delta import rescan  # noqa: F401
from analysis.feedback.model import (  # noqa: F401
    SCHEMA,
    apply_events,
    empty_store,
    finding_key,
    score_inputs_for,
)
