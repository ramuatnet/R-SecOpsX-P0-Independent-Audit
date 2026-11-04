"""Severity-weighted ranking of open gaps, with an auditable score.

WHY THIS EXISTS
---------------
The register ordered work by root-cause class and open-row count. That answers
"where is the weakness concentrated", which is genuinely useful, and it answers
nothing about "what should I do first". A P0 row touching three packages can matter
less than a P2 row touching three thousand, and no ordering that ignores blast radius
can tell those apart.

So this keeps root-cause concentration as the batching signal and adds an explicit
impact-per-effort ranking on top. It is deliberately NOT a replacement for the
existing priority field: that field is author judgement about importance, and
overwriting it with a formula would throw away information the formula does not
have.

EVERY INPUT IS TRACEABLE
------------------------
No component of the score is invented. Each is read from a register field or
measured across the corpus, and the mapping is printed with the output so a reader
can disagree with a weight rather than having to reverse-engineer the arithmetic.

    priority          P0=40  P1=25  P2=12  P3=6      author importance
    enterprise_essential           +40            commercial/compliance blocker
    research_relevant               +8            differentiator, deliberately small
    evidence_tier    MEASURED_OPEN=15 UNMEASURED=12 STRUCTURAL=10
                                                  a measured gap outranks an
                                                  assumed one -- we know it is real
    regression_risk  HIGH=8 MED=4 LOW=0            recent work that could undo them
    domain_concentration        +0..+10           3+ open rows in a domain compounds

    effort            XS=1 S=2 M=5 L=13 XL=30       the register's own cost field

WHAT THE SCORE IS NOT
---------------------
It is not a risk model. It does not know the probability a gap causes harm, only
that the harm is documented and how much is at stake by the register's own account.
Two P1 rows with the same fields score identically and may not deserve to be worked
in that order; the ranking narrows the field, it does not decide for you.

Exits non-zero while any row is open, per the project's rule that a benchmark
reporting open gaps must not exit clean.
"""
from __future__ import annotations
try:
    from analysis.spans import (
    WINDOW_10, WINDOW_12, WINDOW_15, WINDOW_20, WINDOW_3, WINDOW_55,
    WINDOW_60, WINDOW_63, WINDOW_82, WINDOW_TOP_5)
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import (
    WINDOW_10, WINDOW_12, WINDOW_15, WINDOW_20, WINDOW_3, WINDOW_55,
    WINDOW_60, WINDOW_63, WINDOW_82, WINDOW_TOP_5)

import json
import pathlib
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parent.parent
REGISTER = REPO / "reports" / "gap_register.json"
OUT_JSON = REPO / "reports" / "benchmark_root_cause_priority.json"
OUT_MD = REPO / "reports" / "benchmark_root_cause_priority.md"

OPEN_TIERS = {"MEASURED_OPEN", "UNMEASURED", "STRUCTURAL"}

PRIORITY_WEIGHT = {"P0": 40, "P1": 25, "P2": 12, "P3": 6}
TIER_WEIGHT = {"MEASURED_OPEN": 15, "UNMEASURED": 12, "STRUCTURAL": 10}
RISK_WEIGHT = {"HIGH": 8, "MED": 4, "LOW": 0}
EFFORT = {"XS": 1.0, "S": 2.0, "M": 5.0, "L": 13.0, "XL": 30.0}

ENTERPRISE_ESSENTIAL = 40
RESEARCH_RELEVANT = 8
DOMAIN_CONCENTRATION_MAX = 10
DOMAIN_CONCENTRATION_THRESHOLD = 3

# Pull the measured magnitude out of a row's own evidence text when it states one.
# Only "N of M" and "N%" forms are recognised, and only to size the blast radius for
# the reader -- a number that is not there yields None rather than a guess.
_MAGNITUDE_PATTERNS = (
    re.compile(r"(\d[\d,]*)\s+of\s+(\d[\d,]*)"),
    re.compile(r"(\d[\d,]*)\s*%"),
)


def measured_magnitude(evidence: str) -> tuple[int, int] | int | None:
    """A magnitude stated in the row's own evidence, or None."""
    text = str(evidence or "")
    m = _MAGNITUDE_PATTERNS[0].search(text)
    if m:
        try:
            return int(m.group(1).replace(",", "")), int(m.group(2).replace(",", ""))
        except ValueError:
            pass
    m = _MAGNITUDE_PATTERNS[1].search(text)
    if m:
        try:
            return int(m.group(1).replace(",", ""))
        except ValueError:
            pass
    return None


def score_rows(gaps: list[dict]) -> tuple[list[dict], dict]:
    """Score every OPEN row. Returns (scored_by_density, model, banded)."""
    open_rows = [g for g in gaps if g.get("evidence_tier") in OPEN_TIERS]

    domains = Counter(g.get("domain", "") for g in open_rows)
    classes = Counter(g.get("root_cause_class", "") for g in open_rows)

    scored = []
    for g in open_rows:
        components = {
            "priority": PRIORITY_WEIGHT.get(g.get("priority"), 0),
            "enterprise_essential": (ENTERPRISE_ESSENTIAL
                                     if g.get("enterprise_essential") else 0),
            "research_relevant": (RESEARCH_RELEVANT
                                  if g.get("research_relevant") else 0),
            "evidence_tier": TIER_WEIGHT.get(g.get("evidence_tier"), 0),
            "regression_risk": RISK_WEIGHT.get(g.get("regression_risk"), 0),
            "domain_concentration": (
                min(DOMAIN_CONCENTRATION_MAX,
                    max(0, (domains.get(g.get("domain", ""), 0)
                            - (DOMAIN_CONCENTRATION_THRESHOLD - 1))
                        * DOMAIN_CONCENTRATION_MAX // 6))
                if domains.get(g.get("domain", ""), 0) >= DOMAIN_CONCENTRATION_THRESHOLD
                else 0
            ),
        }
        impact = sum(components.values())
        effort = EFFORT.get(g.get("cost"), 5.0)
        density = round(impact / effort, 3)

        scored.append({
            "id": g["id"],
            "title": g.get("title", ""),
            "priority": g.get("priority"),
            "evidence_tier": g.get("evidence_tier"),
            "domain": g.get("domain", ""),
            "root_cause_class": g.get("root_cause_class", ""),
            "cost": g.get("cost"),
            "regression_risk": g.get("regression_risk"),
            "components": components,
            "impact": impact,
            "effort_days": effort,
            "value_density": density,
            "measured_magnitude": measured_magnitude(g.get("evidence", "")),
            "open_rows_in_class": classes.get(g.get("root_cause_class", ""), 0),
            "open_rows_in_domain": domains.get(g.get("domain", ""), 0),
        })

    scored.sort(key=lambda r: (-r["value_density"], r["id"]))

    banded = banded_order(scored)

    model = {
        "impact_weights": {
            "priority": PRIORITY_WEIGHT,
            "enterprise_essential": ENTERPRISE_ESSENTIAL,
            "research_relevant": RESEARCH_RELEVANT,
            "evidence_tier": TIER_WEIGHT,
            "regression_risk": RISK_WEIGHT,
            "domain_concentration_max": DOMAIN_CONCENTRATION_MAX,
            "domain_concentration_threshold": DOMAIN_CONCENTRATION_THRESHOLD,
        },
        "effort_days": EFFORT,
        "formula": ("value_density = sum(impact components) / effort_days. "
                    "All inputs are register fields; none is inferred."),
        "not_a_risk_model": (
            "This ranks documented gaps by impact-per-effort using the register's "
            "own fields. It does not estimate the probability that a gap causes "
            "harm, and two rows with identical fields may still deserve a different "
            "order. It narrows the field; it does not decide."),
    }
    return scored, model, banded


def banded_order(scored: list[dict]) -> list[dict]:
    """THE actionable order: priority band first, density within the band.

    A first attempt ranked purely by value density and it was worse than the plain
    priority ordering it replaced. Measured consequence on this register:

        #1   G-045  a P3 "hand-maintained sink list" hygiene item  (XS, 1 day)
        #49  G-098  BenchmarkJava recall 0.5512                   (L)
        #71  G-083  CERT-In xBOM unimplemented                    (XL)

    G-045 wins purely by being cheap, while the row carrying the credibility of the
    entire accuracy claim sank to 49 and the last unverified P0 standard sank to 71
    of 75. Impact-per-effort systematically starves expensive-but-important work
    behind trivial-but-cheap work, which is the opposite of what was wanted.

    So priority band is a HARD CONSTRAINT, not one input among several. It is the
    author judgement about importance, and no formula has access to what only a
    human knows about a row. Density then orders WITHIN a band, which is where it
    carries real information: between two rows the register already agrees are
    equally important, the one that retires more per day is the better first move.

    This is a combination, not a substitution. The flat density view is still
    published, as a quick-wins list, because "what can I close this afternoon" is a
    legitimate question -- just not the question that sets the programme order.
    """
    bands = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    return sorted(scored, key=lambda r: (
        bands.get(r.get("priority"), 9),
        -r["value_density"],
        r["id"],
    ))


def batched_order(scored: list[dict]) -> list[dict]:
    """Group by root-cause class, best value density first.

    Concentration is the register's own lesson: fixing a class once often closes
    several rows, and 12 open MODEL_GAP rows are cheaper to attack as one piece of
    work than as twelve independent tasks. So the actionable order is by class, and
    the banded ranking above answers "which single row if I only do one".
    """
    by_class: dict[str, list[dict]] = defaultdict(list)
    for r in scored:
        by_class[r["root_cause_class"]].append(r)

    bands = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    # Position in the programme order, so a batch can never be promoted above rows
    # the banding already placed ahead of it.
    first_pos = {r["id"]: i for i, r in enumerate(banded_order(scored))}

    batches = []
    for cls, rows in by_class.items():
        rows.sort(key=lambda r: (-r["value_density"], r["id"]))
        batches.append({
            "root_cause_class": cls,
            "open_rows": len(rows),
            "total_effort_days": round(sum(r["effort_days"] for r in rows), 1),
            "best_value_density": rows[0]["value_density"],
            "row_ids": [r["id"] for r in rows],
            "lead_row": rows[0]["id"],
            # A batch belongs to the band of its MOST important row, not of the row
            # that happens to score highest on density. Sorting batches by density
            # alone reproduced the starvation bug one level up: a class holding one
            # cheap XS row led the whole programme ahead of a class holding a P0.
            "top_priority": min((r["priority"] for r in rows),
                                key=lambda p: bands.get(p, 9)),
            "first_in_programme_order": min(
                (r["id"] for r in rows), key=lambda i: first_pos.get(i, 10**6)),
            "domains": sorted({r["domain"] for r in rows}),
        })

    batches.sort(key=lambda b: (first_pos.get(b["first_in_programme_order"], 10**6),
                                b["root_cause_class"]))
    return batches


def render_md(payload: dict) -> str:
    lines = [
        "# Root-Cause Priority — severity-weighted ranking of OPEN gaps",
        "",
        f"Generated {payload['generated']} · register {payload['register_rows']} rows "
        f"· **{payload['open_rows']} open**",
        "",
        "> " + payload["model"]["not_a_risk_model"],
        "",
        "## The 20 rows that set the programme order",
        "",
        "Priority band is a hard constraint; density orders WITHIN a band. Ranking by",
        "density alone was measured and rejected: it put a P3 hygiene item first and",
        "sank the accuracy-baseline row to 49 and CERT-In to 71 of 75.",
        "",
        "| # | ID | P | impact | days | density | class | what |",
        "|---:|---|---|---:|---:|---:|---|---|",
    ]
    for i, r in enumerate(payload["ranking"][:WINDOW_20], 1):
        title = r["title"]
        if len(title) > 58:
            title = title[:WINDOW_55] + "..."
        lines.append(
            f"| {i} | `{r['id']}` | {r['priority']} | {r['impact']} | "
            f"{r['effort_days']:g} | {r['value_density']} | "
            f"`{r['root_cause_class']}` | {title} |")

    lines += [
        "",
        "## Quick wins — highest density regardless of band",
        "",
        "What can be closed cheaply, not what should lead. Useful for a spare",
        "afternoon; not a programme order, for the reason measured above.",
        "",
        "| # | ID | P | days | density | what |",
        "|---:|---|---|---:|---:|---|",
    ]
    for i, r in enumerate(payload["ranking_by_density"][:WINDOW_12], 1):
        title = r["title"]
        if len(title) > 66:
            title = title[:WINDOW_63] + "..."
        lines.append(
            f"| {i} | `{r['id']}` | {r['priority']} | {r['effort_days']:g} | "
            f"**{r['value_density']}** | {title} |")

    lines += [
        "",
        "## Attack order, batched by root-cause class",
        "",
        "Fixing a class once often closes several rows, and this is the actionable",
        "sequence. `best density` is the strongest single row standing behind the batch.",
        "",
        "| # | root-cause class | rows | days | best density | lead row | domains |",
        "|---:|---|---:|---:|---:|---|---|",
    ]
    for i, b in enumerate(payload["batches"][:WINDOW_15], 1):
        lines.append(
            f"| {i} | `{b['root_cause_class']}` | {b['open_rows']} | "
            f"{b['total_effort_days']:g} | **{b['best_value_density']}** | "
            f"`{b['lead_row']}` | {', '.join(b['domains'][:WINDOW_3])} |")

    lines += [
        "",
        "## Where the open work sits",
        "",
        "| dimension | distribution |",
        "|---|---|",
    ]
    for dim, counts in payload["distributions"].items():
        body = ", ".join(f"{k} {v}" for k, v in counts.most_common())
        lines.append(f"| {dim} | {body} |")

    lines += [
        "",
        f"Total estimated effort across all open rows: "
        f"**{payload['total_effort_days']:g} engineer-days** across "
        f"{payload['open_rows']} rows. That is the sum of the register's own coarse",
        "size labels, so treat it as an order of magnitude rather than a schedule.",
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    if not REGISTER.exists():
        print(f"missing {REGISTER}", file=sys.stderr)
        return 2

    reg = json.loads(REGISTER.read_text(encoding="utf-8"))
    gaps = reg.get("gaps") or []
    if not gaps:
        print("register has no rows", file=sys.stderr)
        return 2

    scored, model, banded = score_rows(gaps)
    batches = batched_order(scored)

    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "register_rows": len(gaps),
        "open_rows": len(scored),
        "model": model,
        "ranking": banded,
        "ranking_by_density": scored,
        "batches": batches,
        "distributions": {
            "evidence tier": Counter(r["evidence_tier"] for r in scored),
            "priority": Counter(r["priority"] for r in scored),
            "root-cause class": Counter(r["root_cause_class"] for r in scored),
            "domain": Counter(r["domain"] for r in scored),
        },
        "total_effort_days": round(sum(r["effort_days"] for r in scored), 1),
        "not_an_accuracy_claim": (
            "This ranks gaps already recorded in reports/gap_register.json. It "
            "measures no new defect and asserts no new capability; running it "
            "changes no product behaviour."
        ),
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    OUT_MD.write_text(render_md(payload), encoding="utf-8")

    print("=" * 88)
    print("SEVERITY-WEIGHTED ROOT-CAUSE PRIORITY")
    print("=" * 88)
    print(f"  register rows : {len(gaps)}      open : {len(scored)}")
    print()
    print("  programme order — priority band is a hard constraint, density")
    print("  orders within a band:")
    for r in banded[:WINDOW_10]:
        print(f"    {r['id']}  {r['priority']}  density {r['value_density']:>6}  "
              f"impact {r['impact']:>3} / {r['effort_days']:>4g}d  "
              f"{r['root_cause_class']}")
        print(f"           {r['title'][:WINDOW_82]}")
    print()
    print("  quick wins (density only, NOT programme order):")
    for r in scored[:WINDOW_TOP_5]:
        print(f"    {r['id']}  {r['priority']}  density {r['value_density']:>6}  "
              f"{r['effort_days']:>4g}d  {r['title'][:WINDOW_60]}")
    print()
    print("  attack order, batched by root-cause class:")
    for b in batches[:WINDOW_10]:
        print(f"    {b['root_cause_class']:26s} {b['open_rows']:>2} rows "
              f"{b['total_effort_days']:>5g}d  lead {b['lead_row']}")
    print()
    print(f"  total effort : {payload['total_effort_days']:g} engineer-days "
          f"across {len(scored)} open rows")
    print(f"  reports      : {OUT_JSON.name} | {OUT_MD.name}")
    print()
    if scored:
        print(f"OPEN GAP: {len(scored)} rows are still open. This benchmark exits")
        print("  non-zero while any remain; it must not be made to pass by relaxing")
        print("  a weight or dropping a row.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())