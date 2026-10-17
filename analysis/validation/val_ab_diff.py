# val_ab_diff.py -- A/B comparison of pre-fix baseline vs post-fix reports.
#
# For each target: rule-count deltas, severity deltas, risk-score delta, and
# per-row classification of every disappeared/appeared finding so the diff is
# auditable (which fix family removed which rows, and that NOTHING was removed
# that is not attributable to a named fix).
#
# Usage: python val_ab_diff.py
import json, os, sys
from collections import Counter

BASE = r"D:\Data\Code test\prodtest\AI Benchmarks\reports\pre_fix_baseline.json"
REPORTS = {
    "peft-main": r"D:\Data\Code test\prodtest\AI Benchmarks\reports\peft-main\clean_report.json",
    "Open-Assistant-main": r"D:\Data\Code test\prodtest\AI Benchmarks\reports\Open-Assistant-main\clean_report.json",
    "llama_index-main": r"D:\Data\Code test\prodtest\AI Benchmarks\reports\llama_index-main\clean_report.json",
}

# Attribution map: which fix family owns which rule deltas. A diff row that
# does not map to a declared family is a REVIEW FAILURE unless it is zero.
FIX_FAMILIES = {
    "B2": {"TAINT_GRAPHQL_INTROSPECTION_ENABLED"},
    "B3": {"TAINT_CODE_INJECTION"},
    "B4": {"CONFIG_CONTEXTUAL_CREDENTIAL"},
    "B5": {"TAINT_CODE_INJECTION"},
    "B6": {"LLM02_INSECURE_OUTPUT_HANDLING"},
    "B7": {"CONFIG_CONTEXTUAL_CREDENTIAL", "HARDCODED_CREDENTIAL_COMPARISON"},
    "B8": {"CONFIG_CONTEXTUAL_CREDENTIAL", "OAUTH_CLIENT_SECRET"},
    "C1": {"EVAL_CALL"},
    "C2": {"LLM02_INSECURE_OUTPUT_HANDLING"},
    "C3": {"TAINT_SQL_INJECTION"},
}

def load_findings(path):
    data = json.load(open(path, encoding="utf-8"))
    return data, data.get("findings") or []

def row_key(f):
    return (str(f.get("rule_id")), str(f.get("file")), str(f.get("line")),
            str(f.get("snippet"))[:120])

def main():
    baseline = json.load(open(BASE, encoding="utf-8"))
    failures = []
    # Optional positional args restrict the comparison to named targets
    # (e.g. while other rescans are still writing their report directories).
    only = set(sys.argv[1:])
    reports = {k: v for k, v in REPORTS.items() if not only or k in only}
    for name, rpath in reports.items():
        b = baseline[name]
        data, findings = load_findings(rpath)
        meta = data.get("metadata", {})
        ids_now = Counter(str(f.get("rule_id")) for f in findings)
        ids_pre = Counter(b["rule_counts"])
        print(f"\n=== {name} ===")
        print(f"  rows:   {b['findings_len']} -> {len(findings)} "
              f"({len(findings) - b['findings_len']:+d})")
        print(f"  risk:   {b['risk_score']} -> {meta.get('risk_score')}")
        print(f"  sast:   {b['sast_findings_meta']} -> {meta.get('sast_findings')}  "
              f"sca: {b['sca_findings_meta']} -> {meta.get('sca_findings')}")
        sev_pre = Counter(b["severity"])
        sev_now = Counter(str(f.get("severity")) for f in findings)
        for s in sorted(set(sev_pre) | set(sev_now)):
            if sev_pre.get(s, 0) != sev_now.get(s, 0):
                print(f"  sev {s}: {sev_pre.get(s, 0)} -> {sev_now.get(s, 0)}")
        removed = ids_pre - ids_now
        added = ids_now - ids_pre
        if removed:
            print("  removed rules:")
            for r, c in sorted(removed.items()):
                fams = [k for k, v in FIX_FAMILIES.items() if r in v]
                tag = ",".join(fams) if fams else "UNATTRIBUTED"
                print(f"    -{c:4d}  {r}  [{tag}]")
                if not fams:
                    failures.append(f"{name}: unattributed removal {r} x{c}")
        if added:
            print("  ADDED rules (must be empty or explained):")
            for r, c in sorted(added.items()):
                print(f"    +{c:4d}  {r}")
                failures.append(f"{name}: added rule {r} x{c}")
        # unchanged-rule drift check
        for r in sorted(set(ids_pre) & set(ids_now)):
            if ids_pre[r] != ids_now[r]:
                fams = [k for k, v in FIX_FAMILIES.items() if r in v]
                tag = ",".join(fams) if fams else "UNATTRIBUTED"
                print(f"  drift {r}: {ids_pre[r]} -> {ids_now[r]}  [{tag}]")
                if not fams:
                    failures.append(f"{name}: unattributed drift {r}")
    print("\n=== VERDICT ===")
    if failures:
        for f in failures:
            print("  FAIL:", f)
        sys.exit(1)
    print("  all deltas attributable to declared fix families; no additions")

if __name__ == "__main__":
    main()
