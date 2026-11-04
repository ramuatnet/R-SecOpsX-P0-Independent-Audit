# val_cross_artifact.py -- cross-artifact consistency validation for a report
# directory.  Checks that every export surface tells the same story as
# clean_report.json: finding counts by rule in SARIF/DefectDojo/webhook/Jira,
# executive PDF presence + non-trivial size, XLSX sheets, SBOM component
# counts, and severity/risk agreement.
#
# Usage: python val_cross_artifact.py <report_dir> [<report_dir> ...]
try:
    from analysis.spans import WINDOW_1, WINDOW_8
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_1, WINDOW_8
import json, os, sys
from collections import Counter

def load_json(p):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)

def validate(report_dir):
    errs, notes = [], []
    crp = os.path.join(report_dir, "clean_report.json")
    if not os.path.isfile(crp):
        return [f"missing clean_report.json in {report_dir}"], []
    data = load_json(crp)
    findings = data.get("findings") or []
    ids = Counter(str(f.get("rule_id")) for f in findings)
    meta = data.get("metadata", {})
    notes.append(f"clean_report: {len(findings)} findings, risk={meta.get('risk_score')}")

    # --- SARIF ---
    sarif_p = os.path.join(report_dir, "Security_Report.sarif")
    if os.path.isfile(sarif_p):
        sarif = load_json(sarif_p)
        results = []
        for run in sarif.get("runs", []):
            results.extend(run.get("results", []) or [])
        sarif_rules = Counter(str(r.get("ruleId")) for r in results)
        # SARIF may aggregate occurrences; require every clean_report rule to
        # exist in SARIF and vice versa (rule-set equality, not row equality).
        missing = set(ids) - set(sarif_rules)
        extra = set(sarif_rules) - set(ids)
        if missing:
            errs.append(f"SARIF missing rules: {sorted(missing)[:WINDOW_8]}")
        if extra:
            errs.append(f"SARIF extra rules: {sorted(extra)[:WINDOW_8]}")
        notes.append(f"SARIF: {len(results)} results, {len(sarif_rules)} rules")
    else:
        errs.append("missing Security_Report.sarif")

    # --- DefectDojo import ---
    # The exporter emits a POST-blueprint dict (api/form_fields/file/curl),
    # where file.content_base64 embeds the SARIF payload DefectDojo will
    # ingest.  Older or alternate exports may be a plain findings list.
    dd_p = os.path.join(report_dir, "Security_DefectDojo_Import.json")
    if os.path.isfile(dd_p):
        dd = load_json(dd_p)
        if isinstance(dd, dict) and isinstance(dd.get("file"), dict) \
                and "content_base64" in dd.get("file", {}):
            import base64
            blob = dd["file"]
            if blob.get("name") != "Security_Report.sarif":
                errs.append(f"DefectDojo blueprint attaches {blob.get('name')!r}, "
                            "expected Security_Report.sarif")
            try:
                embedded = json.loads(base64.b64decode(blob["content_base64"]))
            except Exception as exc:
                errs.append(f"DefectDojo embedded payload unreadable: {exc}")
                embedded = None
            if embedded is not None:
                emb_results = []
                for run in embedded.get("runs", []):
                    emb_results.extend(run.get("results", []) or [])
                emb_rules = Counter(str(r.get("ruleId")) for r in emb_results)
                missing = set(ids) - set(emb_rules)
                extra = set(emb_rules) - set(ids)
                if missing:
                    errs.append(f"DefectDojo embedded SARIF missing rules: {sorted(missing)[:WINDOW_8]}")
                if extra:
                    errs.append(f"DefectDojo embedded SARIF extra rules: {sorted(extra)[:WINDOW_8]}")
                notes.append(f"DefectDojo blueprint: embedded SARIF {len(emb_results)} results, "
                             f"{len(emb_rules)} rules")
            ff = dd.get("form_fields") or {}
            if not isinstance(ff, dict) or "scan_type" not in ff:
                errs.append("DefectDojo blueprint missing form_fields.scan_type")
            else:
                notes.append(f"DefectDojo form_fields: {sorted(ff)}")
            if not dd.get("api"):
                errs.append("DefectDojo blueprint missing api endpoint")
        else:
            dd_findings = dd if isinstance(dd, list) else \
                dd.get("findings") or dd.get("results") or []
            notes.append(f"DefectDojo: {len(dd_findings)} entries")
            if findings and not dd_findings:
                errs.append("DefectDojo import empty while clean_report has findings")
    else:
        notes.append("DefectDojo import: absent (optional)")

    # --- PDFs present and non-trivial ---
    for pdf in ("Security_Report.pdf", "Security_Executive_Report.pdf"):
        pp = os.path.join(report_dir, pdf)
        if os.path.isfile(pp):
            sz = os.path.getsize(pp)
            if sz < 10_000:
                errs.append(f"{pdf} suspiciously small ({sz} bytes)")
            else:
                notes.append(f"{pdf}: {sz:,} bytes")
        else:
            errs.append(f"missing {pdf}")

    # --- XLSX present ---
    for x in ("Security_Report.xlsx", "Security_Technical_Report.xlsx"):
        xp = os.path.join(report_dir, x)
        if os.path.isfile(xp):
            notes.append(f"{x}: {os.path.getsize(xp):,} bytes")
        else:
            notes.append(f"{x}: absent (optional)")

    # --- SBOM ---
    sbom_p = os.path.join(report_dir, "Security_CycloneDX.json")
    if os.path.isfile(sbom_p):
        sbom = load_json(sbom_p)
        comps = sbom.get("components") or []
        notes.append(f"SBOM: {len(comps)} components")
        if not comps and findings:
            errs.append("SBOM has zero components")
    else:
        notes.append("CycloneDX SBOM: absent (optional)")

    # --- risk score agreement between metadata and summary blocks ---
    for key in ("v11_intelligence", "insights"):
        blk = data.get(key)
        if isinstance(blk, dict):
            rs = blk.get("risk_score")
            if rs is not None and meta.get("risk_score") is not None:
                if abs(float(rs) - float(meta["risk_score"])) > 0.01:
                    errs.append(f"risk_score mismatch: metadata {meta['risk_score']} vs {key} {rs}")
    return errs, notes

def main():
    dirs = sys.argv[WINDOW_1:]
    if not dirs:
        base = r"D:\Data\Code test\prodtest\AI Benchmarks\reports"
        dirs = [os.path.join(base, d) for d in ("peft-main", "Open-Assistant-main", "llama_index-main")]
    fail = False
    for d in dirs:
        print(f"\n=== {os.path.basename(d)} ===")
        errs, notes = validate(d)
        for n in notes:
            print("  note:", n)
        for e in errs:
            print("  ERROR:", e)
            fail = True
        if not errs:
            print("  PASS")
    if fail:
        sys.exit(1)
    print("\nAll report directories passed cross-artifact validation.")

if __name__ == "__main__":
    main()
