"""T-7.1: scoring service package.

score = f(base, modifiers, feedback); base = CVSS4 (official FIRST
calculator), eight signed modifier contributions, feedback delta;
deterministic and explainable.  Pure cores in analysis.scoring.score;
file ingest + CLI in analysis.scoring.connect (offline, zero-I/O by
default -- no network, no environment reads).
"""
from analysis.scoring import connect, score  # noqa: F401
from analysis.scoring.connect import collect_scores, main  # noqa: F401
from analysis.scoring.score import (  # noqa: F401
    MAX_FINDINGS,
    SCHEMA,
    band_of,
    score_finding,
    score_findings,
)
