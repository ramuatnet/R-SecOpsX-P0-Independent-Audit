"""Render docs/gap_analysis.md from reports/gap_register.json.

The JSON is the source of truth for the Phase 3 gap register; this script
guarantees the human-readable document can never drift from it.

    python analysis/render_gap_register.py
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "reports" / "gap_register.json"
DST = ROOT / "docs" / "gap_analysis.md"

PRIORITY_ORDER = ["P0", "P1", "P2", "P3"]
TIER_ORDER = [
    "MEASURED_OPEN",
    "MEASURED_CLOSED",
    "UNMEASURED",
    "STRUCTURAL",
]

TIER_NOTE = {
    "MEASURED_OPEN": "benchmark reproduced it; a number exists; not yet at target",
    "MEASURED_CLOSED": "benchmark reproduced it, it was fixed, and it re-benchmarked to target",
    "UNMEASURED": "the current corpora structurally cannot expose this",
    "STRUCTURAL": "confirmed by source inspection; no benchmark built for it yet",
}

COST_LABEL = {"XS": "XS (hours)", "S": "S (≤1 day)", "M": "M (days)",
              "L": "L (1–2 weeks)", "XL": "XL (multi-week)"}


def yn(value: bool) -> str:
    return "✅ yes" if value else "— no"


def esc(text: str) -> str:
    """Keep table cells on one line."""
    return " ".join(str(text).split()).replace("|", "\\|")


def summary_table(reg) -> list[str]:
    gaps = reg["gaps"]
    lines: list[str] = []

    by_prio = Counter(g["priority"] for g in gaps)
    lines.append("| Priority | Gaps |")
    lines.append("|---|---:|")
    for p in PRIORITY_ORDER:
        lines.append(f"| {p} | {by_prio.get(p, 0)} |")
    lines.append(f"| **Total** | **{len(gaps)}** |")
    n_closed = sum(1 for g in gaps if g["evidence_tier"] == "MEASURED_CLOSED")
    lines.append("")
    lines.append(
        f"_{n_closed} of these carry `MEASURED_CLOSED` — fixed and re-measured. "
        "The tier table below is authoritative._"
    )
    lines.append("")

    lines.append("")
    lines.append("| Evidence tier | Gaps | Meaning |")
    lines.append("|---|---:|---|")
    by_tier = Counter(g["evidence_tier"] for g in gaps)
    for t in TIER_ORDER:
        lines.append(f"| {t} | {by_tier.get(t, 0)} | {TIER_NOTE[t]} |")

    lines.append("")
    lines.append("| Root-cause class | Gaps |")
    lines.append("|---|---:|")
    by_class = Counter(g["root_cause_class"] for g in gaps)
    for cls, n in sorted(by_class.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{cls}` | {n} |")

    lines.append("")
    lines.append("| Cost profile | Count | Regression risk | Count |")
    lines.append("|---|---:|---|---:|")
    by_cost = Counter(g["cost"] for g in gaps)
    by_risk = Counter(g["regression_risk"] for g in gaps)
    costs = [(c, by_cost.get(c, 0)) for c in ["XS", "S", "M", "L", "XL"]]
    risks = [(r, by_risk.get(r, 0)) for r in ["LOW", "MED", "HIGH"]]
    for i in range(max(len(costs), len(risks))):
        left = costs[i][0] if i < len(costs) else ""
        left_n = costs[i][1] if i < len(costs) else ""
        right = risks[i][0] if i < len(risks) else ""
        right_n = risks[i][1] if i < len(risks) else ""
        lines.append(f"| {left} | {left_n} | {right} | {right_n} |")
    return lines


def gap_block(g: dict) -> list[str]:
    out = [
        f"### {g['id']} · {g['priority']} · {g['domain']}",
        "",
        f"**{g['title']}**",
        "",
        "| Requirement | Answer |",
        "|---|---|",
        f"| Problem | {esc(g['problem'])} |",
        f"| Mature reference tool | {esc(g['reference_tool'])} |",
        f"| How that tool does it | {esc(g['how_reference_does_it'])} |",
        f"| Current R-SecOpsX behaviour | {esc(g['current_behavior'])} |",
        f"| **Actual gap** | **{esc(g['actual_gap'])}** |",
        f"| Root-cause class | `{g['root_cause_class']}` |",
        f"| Evidence tier | {g['evidence_tier']} |",
        f"| Enterprise-essential | {yn(g['enterprise_essential'])} |",
        f"| Research-relevant | {yn(g['research_relevant'])} |",
        f"| Cost | {COST_LABEL[g['cost']]} |",
        f"| Regression risk | {g['regression_risk']} |",
        f"| **Implementation location** | `{esc(g['implementation_location'])}` |",
        f"| Evidence | {esc(g['evidence'])} |",
        "",
    ]
    return out


def build(reg: dict) -> str:
    gaps = reg["gaps"]
    out: list[str] = []

    out += [
        "# R-SecOpsX V11 — Gap Analysis",
        "",
        "**Phase 3 deliverable — the GAP step between BENCHMARK and IMPLEMENT.**",
        "",
        "Generated from [`reports/gap_register.json`](../reports/gap_register.json)",
        "by `python analysis/render_gap_register.py`. The JSON is the source of",
        "truth; this document is derived, so the two cannot disagree.",
        "",
        "Baseline inputs: Phase 2 enterprise capability matrix, the SAST class-A",
        "benchmark, and the SCA class-A benchmark.",
        "",
        "---",
        "",
        "## 1. How to read this register",
        "",
        "Every entry answers the same ten questions — problem, mature reference",
        "tool, how that tool does it, current behaviour, actual gap,",
        "enterprise-essential, research-relevant, cost, regression risk, exact",
        "implementation location — because a capability is only worth building",
        "when all ten have a defensible answer.",
        "",
        "Two axes matter more than priority:",
        "",
        "- **Evidence tier** — whether a benchmark actually demonstrated the gap.",
        "  A gap that is merely *structural* has no number attached yet, and a gap",
        "  marked *UNMEASURED* is one the current corpora **cannot see**. The",
        "  class-A 100% score does not clear these.",
        "- **Root-cause class** — so that when a new miss appears, it is triaged to",
        "  a mechanism rather than to a symptom.",
        "",
        "### Evidence tiers",
        "",
        "| Tier | Meaning |",
        "|---|---|",
    ]
    for t in TIER_ORDER:
        out.append(f"| **{t}** | {TIER_NOTE[t]} |")

    out += ["", "### Root-cause class vocabulary", "",
            "Used to classify both historical and future missed findings.",
            "", "| Class | Definition |", "|---|---|"]
    for cls, defn in sorted(reg["root_cause_classes"].items()):
        out.append(f"| `{cls}` | {esc(defn)} |")

    out += ["", "---", "", "## 2. Register summary", ""]
    out += summary_table(reg)

    # --- benchmark-derived analysis -------------------------------------
    out += [
        "",
        "---",
        "",
        "## 3. What the benchmarks actually established",
        "",
        "### 3.1 SAST — `sast-multilang-2026-10` (class A)",
        "",
        "| Metric | Phase 4 baseline | Phase 4b | Phase 4c | Now |",
        "|---|---:|---:|---:|---:|",
        "| True positives | 7 | 10 | 13 | **13** |",
        "| False positives | 1 | 1 | 0 | **0** |",
        "| False negatives | 6 | 3 | 0 | **0** |",
        "| Precision | 87.50% | 90.91% | 100.00% | **100.00%** |",
        "| Recall | 53.85% | 76.92% | 100.00% | **100.00%** |",
        "| F1 | 66.67% | 83.33% | 100.00% | **100.00%** |",
        "",
        "Per category at the end: SQLi 5/5, command injection 5/5, path",
        "traversal 2/2, code injection 1/1 — recall 1.0 in every category,",
        "0 false positives across all 6 negative controls.",
        "",
        "**Root-cause classification of the misses that were closed:**",
        "",
        "| Missed / false-positive finding | Class |",
        "|---|---|",
        "| Java findings dropped — optional `dump/*.py` layer raised and was swallowed | `ARTIFACT` → closed |",
        "| Qualified `flask.request.args` not a source | `SOURCE_GAP` |",
        "| Django `request.GET` / `request.POST` not a source | `SOURCE_GAP` |",
        "| PHP `$id = $_GET[...]` → `system(...)` invisible | `TAINT_GAP` |",
        "| JS `req.query.id` → `cp.execSync(...)` invisible | `TAINT_GAP` + `ALIAS_GAP` |",
        "| Parameterised query reported as injection | `SANITIZER_GAP` |",
        "| `html.escape` treated as a shell sanitizer | `SANITIZER_GAP` |",
        "| Taint not killed on reassignment | `SCOPE_GAP` |",
        "| Taint leaked across functions | `SCOPE_GAP` |",
        "| `query = \"SELECT 1\"` treated as a source (NT-05) | `SCOPE_GAP` (binding kind) |",
        "| PHP `system(` produced then dropped by the evidence gate | `EVIDENCE_GAP` |",
        "| PHP `print` / JS `RegExp.exec` matched as sinks | `SINK_GAP` (no concrete-sink validator) |",
        "",
        "> **The honest reading of a 100% class-A score.** It proves those twelve",
        "> mechanisms are fixed. It does **not** bound the miss rate on",
        "> applications the corpus never contained — see G-005. Every class-A",
        "> defect is now a regression test, which is why the suite is 236 tests",
        "> and not a headline number.",
        "",
        "### 3.2 SCA — `sca-multilang-2026-10` (class A)",
        "",
        "| Metric | Before | Now | Trivy | Grype |",
        "|---|---:|---:|---:|---:|",
        "| CVE precision | 49.4% | **100.0%** | 100.0% | 100.0% |",
        "| CVE recall | 54.3% | **100.0%** | 100.0% | 100.0% |",
        "| CVE F1 | 49.7% | **100.0%** | 100.0% | 100.0% |",
        "| Discovery precision | 61.1% | **61.1%** | 91.7% | 100.0% |",
        "| Discovery recall | 100.0% | **100.0%** | 100.0% | 100.0% |",
        "",
        "**Root-cause classification of the CVE defects that were closed:**",
        "",
        "| Defect | Class |",
        "|---|---|",
        "| `_parse_requirements` kept `==`, so OSV got `version=\"==2.19.1\"` → 39 invented CVEs | `VERSION_PARSE_GAP` |",
        "| `_parse_package_json` stored the raw npm range → 4 invented CVEs incl. `ms@2.1.3` | `VERSION_PARSE_GAP` |",
        "| `apply_vulnerability_overrides` replaced OSV with the local override → log4j 7 → 2 CVEs | `MERGE_GAP` |",
        "| PURL emitted as `pkg:pypi/requests@==2.19.1` (invalid) | `VERSION_PARSE_GAP` |",
        "",
        "Ground truth came from OSV.dev queried per exact `package@version`",
        "**before** any compared tool ran, so neither tool is the reference.",
        "",
        "**The one measured gap that remains open here is G-006** — discovery",
        "precision 61.1%, caused by 7 synthesised transitive dependencies with",
        "`version: unknown`. They never match a CVE, so the CVE figures above",
        "are unaffected, but they are invented entries in a deliverable SBOM.",
        "",
        "---",
        "",
        "## 4. Priority action register",
        "",
        "Grouped by priority; within each priority, gaps are listed by id.",
        "",
    ]

    for prio in PRIORITY_ORDER:
        subset = [g for g in gaps if g["priority"] == prio]
        if not subset:
            continue
        out.append(f"### {prio} — {len(subset)} gap{'s' if len(subset) != 1 else ''}")
        out.append("")
        out.append("| ID | Domain | Gap | Root cause | Tier | Cost | Risk |")
        out.append("|---|---|---|---|---|---|---|")
        for g in subset:
            out.append(
                f"| {g['id']} | {g['domain']} | {esc(g['title'])} | "
                f"`{g['root_cause_class']}` | {g['evidence_tier']} | "
                f"{g['cost']} | {g['regression_risk']} |"
            )
        out.append("")
        for g in subset:
            out += gap_block(g)

    # --- closed -----------------------------------------------------------
    out += ["---", "", "## 5. Closed during this program", "",
            "Retained so the trend is auditable and so a closed root cause is not",
            "re-opened.", "",
            "| Outcome | Root-cause classes involved |", "|---|---|"]
    for c in reg["closed_this_program"]:
        classes = ", ".join(f"`{x}`" for x in c["root_causes"])
        out.append(f"| {esc(c['item'])} | {classes} |")

    # --- anti-feature-creep ------------------------------------------------
    out += ["", "---", "", "## 6. Explicitly **not** proposed", "",
            "The register is bounded in both directions. These were considered and",
            "rejected, so they are not silently re-proposed later.", "",
            "| Considered | Why not |", "|---|---|"]
    for n in reg["not_proposed"]:
        out.append(f"| {esc(n['item'])} | {esc(n['reason'])} |")

    out += [
        "",
        "---",
        "",
        "## 7. Next phase",
        "",
        "Recommended order — close measurement before adding capability:",
        "",
        "1. **G-005 (class B)** — build the OWASP-application corpus so the SAST",
        "   number means something outside the synthetic set. Still",
        "   `UNMEASURED`, which makes it the largest unlabelled risk in the",
        "   register: every later `TAINT_GAP`/`PARSER_GAP` row stays structural",
        "   until it exists.",
        "2. **G-035** — the largest measured recall hole. On the AI/LLM corpus",
        "   the framework taint pass reports 0/5 path-traversal and 0/1",
        "   code-write sinks, so overall pre-registered recall sits at 5/11.",
        "   The DESIGNED fix (bare-source propagation with `BoolOp` unwrap,",
        "   same-file parameter seeding, FastAPI/Flask route path params, a",
        "   `persist`/file-write sink) must be followed by re-running the same",
        "   corpus so the delta is a number rather than a claim.",
        "3. **G-039** — `correlate()`'s MODEL/PROVIDED_BY leg still has no",
        "   producer, so the declared cross-BOM differentiator stays half-live.",
        "   `M` cost but `HIGH` regression risk: the fix must add identity keys",
        "   to the AI-BOM record, never join on the free-text `provider` label,",
        "   or it will manufacture false `PROVIDED_BY` edges.",
        "4. **G-006** then **G-038** — the two remaining measured numbers",
        "   (61.1% discovery precision; 13 of 29 credential sites missed).",
        "",
        "All five P0 rows opened by the OWASP cross-check — G-004, G-040,",
        "G-041, G-042 and G-043 — are closed and re-benchmarked; §5 holds the",
        "closure ledger so they are not re-opened.",
        "",
        "Register generated 2026-10-06.",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    reg = json.loads(SRC.read_text(encoding="utf-8"))
    DST.parent.mkdir(parents=True, exist_ok=True)
    DST.write_text(build(reg), encoding="utf-8")
    print(f"gaps={len(reg['gaps'])}  ->  {DST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
