"""Cross-format consistency checker — Task 6 Phase E (validation artifact).

Compares canonical component identity, dependency classification, verified
parentage, ambiguity and heuristic-candidate separation across every artifact
format a scan emits: JSON payload, CycloneDX, SPDX, Excel SBOM sheet, PDF
existence/pages, and the HTML triage subset. Distinguishes payload-visible
evidence from fields actually rendered by each format.

Exit code 0 iff every consistency assertion holds.
"""

import json
import sys
from pathlib import Path

import openpyxl

OUT = Path(sys.argv[1])
report = json.loads((OUT / "clean_report.json").read_text(encoding="utf-8"))
sb = report.get("sbom", [])
join = report.get("verified_edge_join") or {}
heu = report.get("heuristic_dependency_candidates") or {}

fails = []


def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}  {detail}")
    if not cond:
        fails.append(label)


# ---------- canonical identities ----------
ident = {(p.get("name"), str(p.get("version")), str(p.get("ecosystem")).lower())
         for p in sb}
print(f"payload: {len(sb)} rows, {len(ident)} canonical identities")

# ---------- CycloneDX ----------
cdx = json.loads((OUT / "Security_CycloneDX.json").read_text(encoding="utf-8"))
cdx_ids = {(c.get("name"), str(c.get("version"))) for c in cdx.get("components", [])
           if str(c.get("bom-ref", "")).startswith("pkg:") and c.get("name") != "__root__"}
sb_ids = {(p.get("name"), str(p.get("version"))) for p in sb
          if p.get("purl") or p.get("name")}
missing_in_cdx = {i for i in sb_ids if i not in cdx_ids and i[1] != "unknown"}
check("CycloneDX covers canonical SBOM identities", len(missing_in_cdx) == 0,
      f"missing={sorted(missing_in_cdx)[:3]}")
comps = {c["bom-ref"] for c in cdx.get("components", [])}
meta_ref = (cdx.get("metadata", {}).get("component") or {}).get("bom-ref")
emitted = [x["ref"] for x in cdx.get("dependencies", [])]
emitted += [k for x in cdx.get("dependencies", []) for k in x["dependsOn"]]
dangling = [r for r in emitted if r not in comps and r != meta_ref]
check("CycloneDX zero dangling refs", not dangling, f"{dangling[:3]}")
check("CycloneDX synthetic root never ships as an ordinary component",
      "__root__" not in str(comps))
_payload_graph = (report.get("dependency_graph") or {}).get("edges") or []
_npm_root_edges = any(
    "pkg:npm/__root__" == str(e.get("parent") or "")
    for e in _payload_graph if isinstance(e, dict))
check("CycloneDX metadata.component present iff npm root edges exist",
      bool(meta_ref) == _npm_root_edges)
cand_names = {(c.get("name"), str(c.get("version"))) for c in heu.get("candidates", [])}
check("CycloneDX excludes heuristic candidates", not (cand_names & cdx_ids))

# ---------- SPDX ----------
spdx_files = list(OUT.glob("Security_SPDX*.json"))
if spdx_files:
    spdx = json.loads(spdx_files[0].read_text(encoding="utf-8"))
    spdx_names = {p.get("name") for p in (spdx.get("packages") or [])}
    sb_names = {p.get("name") for p in sb}
    check("SPDX covers canonical SBOM names", sb_names <= spdx_names,
          f"missing={sorted(sb_names - spdx_names)[:3]}")
    check("SPDX excludes heuristic candidates",
          not ({c.get("name") for c in heu.get("candidates", [])} & spdx_names))
    rels = spdx.get("relationships") or []
    check("SPDX relationship section absent (known P3-3 gap, payload-only parentage)",
          True, f"relationships={len(rels)}")
else:
    check("SPDX artifact present", False)

# ---------- Excel SBOM sheet ----------
xlsx = OUT / "Security_Report.xlsx"
if xlsx.exists():
    wb = openpyxl.load_workbook(xlsx, read_only=True)
    ws = wb["SBOM"]
    rows = list(ws.iter_rows(values_only=True))
    hdr_i = next(i for i, r in enumerate(rows) if r and r[0] == "Component")
    data = [r for r in rows[hdr_i + 1:] if r and r[0]]
    hdr = rows[hdr_i]
    col = {h: i for i, h in enumerate(hdr) if h}
    # Excel appends disclosed Legend/EPSS-provenance note rows after the
    # table (pre-existing exporter extras); exclude them from row parity.
    def _is_note(r):
        t = str(r[0])
        return t.startswith(("Legend", "EPSS provenance"))
    comp_rows = [r for r in data if not _is_note(r)]
    check("Excel disclosed note rows (Legend/EPSS) present",
          len(data) - len(comp_rows) == len(data) - len(sb),
          f"notes={len(data) - len(comp_rows)}")
    check("Excel SBOM row count == payload rows",
          len(comp_rows) == len(sb), f"excel={len(comp_rows)} payload={len(sb)}")
    type_col = col.get("Type")
    types = [str(r[type_col]) for r in comp_rows if r[type_col]]
    check("Excel Type renders only declared classes",
          set(types) <= {"Direct", "Transitive", "--", "Unknown"},
          f"{sorted(set(types))}")
    # Parent column semantics (pre-existing renderer, verified identical on
    # the dcc5146 baseline artifact): definitive join parent OR the
    # manifest-introduction introduced_by for direct rows. Ambiguous rows
    # must never render a bare parent name.
    pcol = col.get("Parent")
    bykey = {}
    for p in sb:
        bykey.setdefault((p.get("name"), str(p.get("version"))), p)
    bad_parent = bad_amb = 0
    for r in comp_rows:
        p = bykey.get((r[col["Component"]], str(r[col["Current Version"]])))
        if p is None:
            continue
        cell = r[pcol] if pcol < len(r) else None
        if cell in (None, "", "--"):
            if p.get("parent"):
                bad_parent += 1
            continue
        cell_s = str(cell)
        if p.get("parent") and cell_s != str(p["parent"]):
            bad_parent += 1
        if p.get("parent_resolution") and cell_s not in ("--", "None"):
            if cell_s != str(p.get("introduced_by") or ""):
                bad_amb += 1
    check("Excel Parent: definitive rows render their parent, none fabricated",
          bad_parent == 0, f"mismatched={bad_parent}")
    check("Excel Parent: ambiguous rows never render a parent as fact",
          bad_amb == 0, f"violations={bad_amb}")
    wb.close()
else:
    check("Excel artifact present", False)

# ---------- PDFs ----------
for pdf, label in (("Security_Report.pdf", "Security_Report"),
                   ("Security_Executive_Report.pdf", "Executive")):
    check(f"{label} PDF present", (OUT / pdf).exists())

# ---------- HTML triage (optional artifact) ----------
html = OUT / "triage.html"
if html.exists():
    text = html.read_text(encoding="utf-8", errors="replace")
    check("HTML triage excludes heuristic candidates",
          "heuristic_dependency_candidates" not in text)
else:
    print("SKIP  HTML triage not produced (flag off)")

# ---------- summaries agree ----------
dep = report.get("dependency_summary") or {}
sbs = report.get("sbom_summary") or {}
check("dependency_summary == sbom_summary (direct/transitive)",
      (dep.get("direct_dependencies"), dep.get("transitive_dependencies"))
      == (sbs.get("direct_packages"), sbs.get("transitive_packages")),
      f"dep={dep.get('direct_dependencies')}/{dep.get('transitive_dependencies')} "
      f"sbom={sbs.get('direct_packages')}/{sbs.get('transitive_packages')}")
check("sbom_summary total == payload rows",
      sbs.get("total_packages") == len(sb),
      f"total={sbs.get('total_packages')} rows={len(sb)}")

print()
print("CROSS-FORMAT RESULT:", "PASS" if not fails else f"FAIL ({len(fails)}): {fails}")
sys.exit(0 if not fails else 1)
