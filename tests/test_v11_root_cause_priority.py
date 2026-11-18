"""The priority ranking must not starve important work behind cheap work.

WHY THIS TEST EXISTS
--------------------
A first implementation ranked purely by value density (impact / effort). It looked
principled and it was worse than the plain priority ordering it replaced. Measured on
the real register:

    #1   G-045  a P3 "hand-maintained sink list" hygiene item   (XS, 1 day)
    #49  G-098  BenchmarkJava recall 0.5512                    (L, 13 days)
    #71  G-083  CERT-In xBOM unimplemented                     (XL, 30 days)

The cheap P3 item won because it was cheap. The row carrying the credibility of the
entire accuracy claim sank to 49 and the last unverified mandatory standard sank to
71 of 75. Impact-per-effort always favours small-and-trivial over
large-and-important, which is the opposite of what was asked for.

The fix is a floor rather than a different formula: priority band is a HARD
constraint, and density orders within a band. That combines the two signals instead
of replacing one with the other -- the priority field is author judgement about
importance that no formula has access to, and density is informative about which of
two equally-important rows to take first.

These tests pin that, because the failure mode is invisible in the output: a ranking
that puts G-045 first looks perfectly reasonable unless you know it shouldn't.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from analysis.benchmark_root_cause_priority import (  # noqa: E402
    EFFORT,
    OPEN_TIERS,
    banded_order,
    batched_order,
    measured_magnitude,
    score_rows,
)

REGISTER = REPO / "reports" / "gap_register.json"


def _rows(*specs) -> list[dict]:
    """Minimal register rows with the fields the scorer reads."""
    out = []
    for i, (gid, priority, cost, tier, ess) in enumerate(specs):
        out.append({
            "id": gid, "priority": priority, "cost": cost,
            "evidence_tier": tier, "enterprise_essential": bool(ess),
            "research_relevant": False, "regression_risk": "LOW",
            "domain": f"Domain{i}", "root_cause_class": f"CLASS_{i}",
            "title": f"row {gid}",
        })
    return out


# ------------------------------------------------------- the starvation bug --

def test_a_cheap_p3_row_cannot_outrank_a_costly_p0_row():
    """The exact regression, constructed rather than remembered.

    Density for the P3 is far higher -- low priority weight, XS effort. Under a
    density-only ranking it wins. Under the banded ranking it must lose.
    """
    rows = _rows(
        ("G-P0", "P0", "L", "MEASURED_OPEN", True),
        ("G-P3", "P3", "XS", "STRUCTURAL", True),
    )
    scored, _model, banded = score_rows(rows)

    by_density = sorted(scored, key=lambda r: -r["value_density"])
    assert by_density[0]["id"] == "G-P3", (
        "test setup no longer reproduces the density inversion")

    assert banded[0]["id"] == "G-P0", (
        "the P0 row must lead regardless of cost -- a cheap P3 must never "
        "outrank it")


def test_density_only_ranking_would_be_wrong():
    """Documented, not merely asserted against.

    If this stops failing the test above has stopped proving anything, so the
    inversion is re-established inside the test.
    """
    rows = _rows(
        ("G-A", "P0", "XL", "MEASURED_OPEN", True),
        ("G-B", "P3", "XS", "STRUCTURAL", True),
    )
    scored, _m, banded = score_rows(rows)

    density_leader = max(scored, key=lambda r: r["value_density"])
    band_leader = banded[0]

    assert density_leader["id"] == "G-B"
    assert band_leader["id"] == "G-A"


# ------------------------------------------------------- banding invariants --

def test_programme_order_is_monotonic_in_priority_band():
    """No row may appear before a row of a higher band."""
    rows = _rows(
        ("G-1", "P3", "XS", "STRUCTURAL", True),
        ("G-2", "P0", "XL", "MEASURED_OPEN", True),
        ("G-3", "P1", "S", "MEASURED_OPEN", True),
        ("G-4", "P2", "M", "UNMEASURED", False),
    )
    _scored, _m, banded = score_rows(rows)

    bands = ["P0", "P1", "P2", "P3"]
    seen = [bands.index(r["priority"]) for r in banded]

    assert seen == sorted(seen), f"bands interleaved: {[r['priority'] for r in banded]}"


def test_density_orders_within_a_band():
    """The whole point of combining rather than substituting."""
    rows = _rows(
        ("G-cheap", "P1", "XS", "MEASURED_OPEN", True),
        ("G-dear", "P1", "L", "MEASURED_OPEN", True),
    )
    _scored, _m, banded = score_rows(rows)

    assert banded[0]["id"] == "G-cheap"
    assert banded[1]["id"] == "G-dear"


def test_closed_rows_are_excluded():
    rows = _rows(
        ("G-open", "P0", "S", "MEASURED_OPEN", True),
        ("G-closed", "P0", "XS", "MEASURED_CLOSED", True),
    )
    scored, _m, banded = score_rows(rows)

    assert {r["id"] for r in scored} == {"G-open"}
    assert {r["id"] for r in banded} == {"G-open"}
    assert OPEN_TIERS == {"MEASURED_OPEN", "UNMEASURED", "STRUCTURAL"}


# ------------------------------------------------------ batching invariants --

def test_a_batch_holding_a_p0_leads_a_batch_holding_only_p3():
    """The same starvation bug, one level up.

    An earlier version sorted batches by density alone, so the class containing one
    cheap XS row led the entire programme ahead of the class holding a P0. Batching
    must never promote a class above rows the banding already placed ahead of it.
    """
    rows = _rows(
        ("G-p0", "P0", "L", "MEASURED_OPEN", True),
        ("G-p3", "P3", "XS", "STRUCTURAL", True),
    )
    rows[0]["root_cause_class"] = "CLASS_WITH_P0"
    rows[1]["root_cause_class"] = "CLASS_CHEAP"

    scored, _m, _banded = score_rows(rows)
    batches = batched_order(scored)

    assert batches[0]["root_cause_class"] == "CLASS_WITH_P0"
    assert batches[0]["top_priority"] == "P0"
    assert batches[-1]["root_cause_class"] == "CLASS_CHEAP"


def test_batch_top_priority_is_the_most_important_row_not_the_best_density():
    rows = _rows(
        ("G-1", "P0", "XL", "MEASURED_OPEN", True),
        ("G-2", "P3", "XS", "STRUCTURAL", True),
    )
    for r in rows:
        r["root_cause_class"] = "SAME"

    scored, _m, _banded = score_rows(rows)
    batch = batched_order(scored)[0]

    # The best-density row is the cheap P3; the band must still be P0.
    assert batch["best_value_density"] > 0
    assert batch["top_priority"] == "P0"


# ---------------------------------------------------------- auditable inputs --

def test_every_score_component_is_traceable_to_a_field():
    rows = _rows(("G-1", "P1", "M", "MEASURED_OPEN", True))
    scored, model, _banded = score_rows(rows)

    comps = scored[0]["components"]
    assert set(comps) == {
        "priority", "enterprise_essential", "research_relevant",
        "evidence_tier", "regression_risk", "domain_concentration",
    }
    # Impact is exactly the sum of its declared components -- no hidden term.
    assert scored[0]["impact"] == sum(comps.values())
    assert model["impact_weights"]["priority"]["P0"] > model["impact_weights"]["priority"]["P3"]


def test_the_model_declares_it_is_not_a_risk_model():
    _s, model, _b = score_rows(_rows(("G-1", "P1", "S", "MEASURED_OPEN", True)))

    assert "not" in model["not_a_risk_model"].lower()
    assert "formula" in model


def test_effort_weights_are_ordered_by_size():
    days = [EFFORT[k] for k in ("XS", "S", "M", "L", "XL")]
    assert days == sorted(days)
    assert EFFORT["XS"] < EFFORT["XL"]


@pytest.mark.parametrize(
    ("evidence", "want"),
    [
        ("691 of 701 packages carry no CVE", (691, 701)),
        ("33% of components unresolved", 33),
        ("1,234 of 5,678 rows", (1234, 5678)),
        ("no magnitude stated here", None),
        ("", None),
    ],
)
def test_measured_magnitude_reads_only_forms_that_exist(evidence, want):
    """A magnitude is read from the row's own evidence or it is None.

    Nothing is inferred, because a guessed blast radius would be exactly the
    invented input this ranking exists to avoid.
    """
    assert measured_magnitude(evidence) == want


# ---------------------------------------------------- the real register ------

@pytest.mark.skipif(not REGISTER.exists(), reason="gap register absent")
@pytest.mark.requires_prod_tree(artifact="reports/gap_register.json")
def test_the_real_register_ranking_is_sane():
    """The real data, checked for the properties that matter.

    Not a golden-file snapshot: the register changes every session, so pinning
    exact row positions would make this fail constantly for no reason. What must
    hold is structural.
    """
    reg = json.loads(REGISTER.read_text(encoding="utf-8"))
    scored, _model, banded = score_rows(reg["gaps"])

    assert scored, "the register has open rows"

    # Every open row is ranked exactly once.
    assert {r["id"] for r in banded} == {r["id"] for r in scored}
    assert len(banded) == len(scored)

    # No P0 row may appear after any P1 row.
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    seq = [order[r["priority"]] for r in banded]
    assert seq == sorted(seq)

    # A P0 row, if one exists, leads the programme.
    p0 = [r for r in banded if r["priority"] == "P0"]
    if p0:
        assert banded[0]["priority"] == "P0"

    # Nothing scored negative or zero-effort.
    for r in scored:
        assert r["impact"] > 0
        assert r["effort_days"] > 0
        assert r["value_density"] > 0