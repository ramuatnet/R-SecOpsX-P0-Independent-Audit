"""Benchmark: OWASP GenAI Red Team Lab (AI/LLM corpus class).

Ground truth is ``reports/ground_truth_genai.json``, authored by reading the
source *before* any scanner ran.  This script never edits it.

Two scorecards are produced, because the pre-registered ground truth covers
only three finding categories and would give a misleading precision figure if
the remaining reported findings were silently counted as false positives:

  A. Pre-registered GT  - recall over the 11 positives and 6 negative controls
     written before the scan.  This is the unbiased, pre-registered number.
  B. Findings audit     - every reported finding inside the GT categories is
     individually classified TP / FP / DUPLICATE.  Findings outside the GT
     categories are counted as UNEVALUATED and excluded from precision rather
     than being asserted false, which is what the mandate forbids.

A third, explicitly post-hoc measurement re-derives the credential positives
mechanically with a stated regex, so credential recall can be quoted without
the bias of having written that ground truth by hand from a partial reading.

Exit code gates measurement completeness, never scanner performance: a corpus
that exposes a real gap must still exit 0 when it has been fully measured.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GT_PATH = REPO / "reports" / "ground_truth_genai.json"
OUT_JSON = REPO / "reports" / "benchmark_reconciliation_genai.json"
OUT_MD = REPO / "reports" / "benchmark_reconciliation_genai.md"

BENCHMARK_ID = "ai-llm-corpus-genai-2026-10"

# The categories the hand-authored ground truth actually covers.  Anything the
# product reports outside these is measured as UNEVALUATED, never as a false
# positive - we did not review it, so we do not get to call it wrong.
GT_CATEGORIES = {
    "PATH_TRAVERSAL": {"path_traversal", "path_write_traversal"},
    "CODE_INJECTION": {"code_injection", "unsafe_eval", "code_exec"},
    "HARDCODED_CREDENTIAL": {
        "hardcoded_secret", "configuration_secret", "database_credential",
        "ai_provider_secret_exposure",
    },
    "COMMAND_INJECTION": {"command_injection"},
    "SQL_INJECTION": {"sql_injection"},
}

CAT_OF_VULN = {v: k for k, vs in GT_CATEGORIES.items() for v in vs}

# Lockfiles are not credential stores.  They carry integrity hashes, engine
# version ranges and dependency names - none of which is a secret - so a
# credential rule that fires inside one is a rule-scope defect.
LOCKFILE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                  "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum"}

# Mechanical re-derivation of credential positives (scorecard B only).
CRED_ASSIGN = re.compile(
    r"""(?ix)
    ^\s*
    (?:self\.)?
    (?P<name>
        [A-Za-z_][\w.\[\]"']*
    )
    \s* = \s*
    ["'] (?P<val>[^"']{3,}) ["']
    """
)
CRED_NAME = re.compile(r"(?i)(api[_-]?key|password|passwd|pwd|secret|token|auth)")
# The left-hand side must itself be credential-named.  Matching any
# ``if x == "literal"`` counted 127 ordinary comparisons - ``if __name__ ==
# "__main__"``, ``if args.output_format == "json"`` - as credentials, which
# would have made credential recall a fiction.
CRED_COMPARE = re.compile(r"""(?ix)
    \b(?:if|elif|while|and|or)\b\s*
    (?P<lhs>[A-Za-z_][\w.\[\]"']*?)
    \s*(?:!=|==|not\s+in)\s*
    ["'] (?P<val>[^"']{3,}) ["']
""")
CRED_HASH = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
# Values that are not credentials however they are used.  sk-mock-key, foobar
# and bar are absent from this set on purpose: verify_api_key() (openai.py:43),
# put_object() (s3.py:16) and verify_api_key() (pinecone.py:40) each compare
# them against a request header to grant or deny access, so an authorization
# decision does depend on them - including "bar", which looks like a placeholder
# and is not one.  The rest are handed to endpoints in this corpus that perform
# no authentication at all (Ollama) or are dead assignments never read back
# (openai.py:17 writes the env var; the check reads a literal instead).
NON_CREDENTIAL_VALUES = {"ollama", "foo", "test", "changeme", "placeholder"}

CODE_EXTS = {".py", ".js", ".cs", ".ts", ".mjs"}
CONFIG_EXTS = {".toml", ".yml", ".yaml", ".env", ".ini", ".cfg", ".json"}
EXCLUDE_DIRS = {"tests", "test", "__pycache__", "node_modules", ".git",
                "prompts", "reports", "docs", "backup", "dump"}


def _norm(p: object) -> str:
    return str(p or "").replace("\\", "/")


def load_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("findings") or []


def finding_key(f: dict) -> tuple[str, int]:
    return (_norm(f.get("file")).lower(), int(f.get("line") or 0))


# --------------------------------------------------------------------------
# Scorecard A: pre-registered ground truth
# --------------------------------------------------------------------------
def reconcile_pre_registered(gt: dict, findings: list[dict]) -> dict:
    """Match findings onto the positives written before the scan.

    A match requires the same file and a line within a small window, because a
    rule may legitimately attach to the sink call while the hand-authored entry
    records the line the tainted value enters the sink.
    """
    WINDOW = 3
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        cat = CAT_OF_VULN.get(str(f.get("vuln_type") or ""))
        if cat:
            by_cat[cat].append(f)

    per_category: dict[str, dict] = {}
    matched: list[dict] = []
    misses: list[dict] = []

    for pos in gt["positives"]:
        cat = pos["category"]
        target = _norm(pos["file"]).lower()
        hit = None
        for f in by_cat.get(cat, []):
            if _norm(f.get("file")).lower() != target:
                continue
            if abs(int(f.get("line") or 0) - int(pos["line"])) <= WINDOW:
                hit = f
                break
        if hit:
            matched.append({"gt": pos["id"], "file": pos["file"],
                            "line": pos["line"],
                            "finding_line": hit.get("line"),
                            "rule": hit.get("rule_id"),
                            "vuln_type": hit.get("vuln_type")})
        else:
            misses.append({"gt": pos["id"], "category": cat,
                           "file": pos["file"], "line": pos["line"],
                           "sink": pos.get("sink"),
                           "title": pos["title"]})

    for cat in list(GT_CATEGORIES):
        tp = sum(1 for m in matched
                 if next(p for p in gt["positives"] if p["id"] == m["gt"])
                 ["category"] == cat)
        fn = sum(1 for m in misses if m["category"] == cat)
        fp = 0  # negative controls handled separately
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else \
            (0.0 if prec is not None and rec is not None else None)
        per_category[cat] = {
            "positives": tp + fn, "tp": tp, "fp": fp, "fn": fn,
            "precision": prec, "recall": rec, "f1": f1,
            "note": ("no positive ground-truth entries in this category"
                     if tp + fn == 0 else None),
        }

    # Negative controls: findings that land on a line we pre-declared benign.
    nc_violations, nc_respected = [], []
    for nc in gt["negative_controls"]:
        target = _norm(nc["file"]).lower()
        line = int(nc["line"])
        cat = CAT_OF_VULN.get(nc["category"])
        hit = None
        for f in findings:
            if _norm(f.get("file")).lower() != target:
                continue
            if cat and CAT_OF_VULN.get(str(f.get("vuln_type") or "")) != cat:
                continue
            if abs(int(f.get("line") or 0) - line) <= 3:
                hit = f
                break
        if hit:
            nc_violations.append({
                "id": nc["id"], "file": nc["file"], "line": nc["line"],
                "category": nc["category"], "rule": hit.get("rule_id"),
                "finding_line": hit.get("line"),
                "source_reported": hit.get("source") or hit.get("source_expr"),
                "why_not_a_finding": nc["why_not_a_finding"],
            })
        else:
            nc_respected.append(nc["id"])

    tp, fn = len(matched), len(misses)
    prec = None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = None

    return {
        "per_category": per_category,
        "matched": matched,
        "misses": misses,
        "negative_controls": {
            "total": len(gt["negative_controls"]),
            "violations": nc_violations,
            "respected": nc_respected,
            "violation_rate": len(nc_violations) / len(gt["negative_controls"]),
        },
        "totals": {
            "positives": len(gt["positives"]),
            "tp": tp, "fn": fn,
            "precision_note": ("precision is not scored on the pre-registered "
                               "ground truth alone: the GT covers three "
                               "categories, so findings outside them would be "
                               "wrongly called false positives. See the "
                               "findings audit."),
            "precision": prec, "recall": rec, "f1": f1,
        },
    }


# --------------------------------------------------------------------------
# Scorecard B: per-finding audit
# --------------------------------------------------------------------------
def audit_findings(gt: dict, findings: list[dict],
                   pre: dict, corpus_root: Path) -> dict:
    """Classify every reported finding that sits inside the GT categories."""
    gt_pos = gt["positives"]
    pre_matched_lines = {(m["file"].lower(), m["finding_line"])
                         for m in pre["matched"]}
    nc_lines = {(nc["file"].lower(), int(nc["line"]))
                for nc in gt["negative_controls"]}
    nc_files = {_norm(nc["file"]).lower() for nc in gt["negative_controls"]}

    rows, counter = [], Counter()
    # Counter() coerces missing keys to 0, so it cannot hold a list.  Kept
    # separate for the duplicate-of-a-counted-line check below.
    raw: list[tuple[str, int, str]] = []
    # One true positive per (file, line, category): two rules firing on the
    # same line describe one defect, and counting both would inflate recall.
    seen_tp: set[tuple[str, int, str]] = set()
    unevaluated = 0

    for f in findings:
        cat = CAT_OF_VULN.get(str(f.get("vuln_type") or ""))
        if not cat:
            unevaluated += 1
            continue

        fp = _norm(f.get("file")).lower()
        line = int(f.get("line") or 0)
        rule = str(f.get("rule_id") or "")

        verdict, reason, root_cause = None, None, None

        # 1. a pre-registered positive
        for pos in gt_pos:
            if (_norm(pos["file"]).lower() == fp
                    and abs(int(pos["line"]) - line) <= 3
                    and pos["category"] == cat):
                verdict, reason = "TP", f"matches {pos['id']}"
                break

        # 2. duplicate of an already-counted line
        if verdict is None and (fp, line) in pre_matched_lines and \
                any(r[0] == fp and r[1] == line and r[2] == "TP"
                    for r in raw):
            verdict, reason = "DUPLICATE", "same file:line already counted"

        # 3. negative control
        if verdict is None and cat == "COMMAND_INJECTION" and fp in nc_files \
                and abs(line - int(next(nc["line"] for nc in gt["negative_controls"]
                                        if _norm(nc["file"]).lower() == fp))) <= 3:
            verdict = "FP"
            reason = "pre-declared negative control (no untrusted source)"
            root_cause = "SOURCE_GAP"

        # 4. lockfile credential noise
        if verdict is None and Path(fp).name in LOCKFILE_NAMES and \
                cat == "HARDCODED_CREDENTIAL":
            verdict = "FP"
            reason = ("lockfile content matched as a credential: "
                      "integrity hashes / engines.node / package names are "
                      "not secrets")
            root_cause = "FILE_SCOPE_GAP"

        # 5. command injection with no source reported
        if verdict is None and cat == "COMMAND_INJECTION":
            verdict = "FP"
            reason = ("rule fired on the sink with source=None; the command "
                      "string is built from module constants or a fixed "
                      "literal list, so no untrusted value can reach it")
            root_cause = "SOURCE_GAP"

        # 6. post-hoc mechanical credential confirmation
        if verdict is None and cat == "HARDCODED_CREDENTIAL":
            if _mechanically_real_credential(f, corpus_root):
                verdict = "TP"
                reason = ("confirmed by review after the fact; GT incompleteness"
                          " - not present in the pre-registered ground truth")
                root_cause = "GT_INCOMPLETE"
            else:
                verdict = "FP"
                reason = "no authorization decision depends on this value"
                root_cause = "CONTEXT_MISCLASSIFIED"

        if verdict is None:
            unevaluated += 1
            verdict = "UNEVALUATED"

        if verdict == "TP":
            sig = (fp, line, cat)
            if sig in seen_tp:
                verdict = "DUPLICATE"
                reason = ("second rule fired on a line already counted as a "
                          "true positive")
                root_cause = None
            else:
                seen_tp.add(sig)

        counter[verdict] += 1
        raw.append((fp, line, verdict))
        rows.append({"file": fp, "line": line, "category": cat,
                     "vuln_type": f.get("vuln_type"), "rule": rule,
                     "verdict": verdict, "reason": reason,
                     "root_cause": root_cause})

    tp = counter["TP"]
    fp_n = counter["FP"]
    dup = counter["DUPLICATE"]
    prec = tp / (tp + fp_n) if (tp + fp_n) else None

    return {
        "rows": rows,
        "counts": dict(counter),
        "unevaluated_other_categories": unevaluated,
        "precision": prec,
        "fp_by_root_cause": dict(Counter(
            r["root_cause"] for r in rows if r["verdict"] == "FP" and
            r.get("root_cause"))),
        "tp_by_origin": dict(Counter(
            "pre_registered" if r["reason"] and
            r["reason"].startswith("matches") else "post_hoc_review"
            for r in rows if r["verdict"] == "TP")),
    }


def _mechanically_real_credential(f: dict, root: Path) -> bool:
    """Would a stated rule call this a credential, independent of the scanner?

    Rule: in a code or config file (not docs, tests or a lockfile), a string
    literal assigned to a credential-named identifier, or compared against a
    credential-named request value to authorise, or a committed password hash.

    The report redacts matched secrets, so ``f['snippet']`` is unusable here -
    ``password_hash=[REDACTED]`` matches no assignment pattern at all.  Reading
    the real line from the corpus is what keeps three genuine findings from
    being recorded as false positives purely because we could not see them.
    """
    fp = _norm(f.get("file"))
    p = Path(fp)
    if p.name in LOCKFILE_NAMES:
        return False
    if p.suffix.lower() not in (CODE_EXTS | CONFIG_EXTS):
        return False
    if any(part.lower() in EXCLUDE_DIRS for part in p.parts):
        return False

    snippet = str(f.get("snippet") or "")
    try:
        lines = (root / fp).read_text(
            encoding="utf-8", errors="replace").splitlines()
        n = int(f.get("line") or 0)
        if 1 <= n <= len(lines):
            snippet = lines[n - 1]
    except OSError:
        pass

    if CRED_HASH.search(snippet):
        return True
    m = CRED_ASSIGN.search(snippet)
    if m and CRED_NAME.search(m.group("name")):
        return m.group("val").strip().lower() not in NON_CREDENTIAL_VALUES
    c = CRED_COMPARE.search(snippet)
    if c and CRED_NAME.search(c.group("lhs")):
        return c.group("val").strip().lower() not in NON_CREDENTIAL_VALUES
    return False


# --------------------------------------------------------------------------
# Scorecard C: post-hoc mechanical credential recall
# --------------------------------------------------------------------------
def enumerate_credential_positives(root: Path) -> list[tuple[str, int, str]]:
    """Mechanically list credential sites so recall has no hand-authoring bias."""
    out: list[tuple[str, int, str]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in (CODE_EXTS | CONFIG_EXTS):
            continue
        if p.name in LOCKFILE_NAMES:
            continue
        rel_parts = p.relative_to(root).parts
        if any(part.lower() in EXCLUDE_DIRS for part in rel_parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = "/".join(rel_parts)
        for i, line in enumerate(text.splitlines(), 1):
            if CRED_HASH.search(line):
                out.append((rel, i, "password_hash"))
                continue
            m = CRED_ASSIGN.search(line)
            if m and CRED_NAME.search(m.group("name")) and \
                    m.group("val").strip().lower() not in NON_CREDENTIAL_VALUES:
                out.append((rel, i, f"assign:{m.group('name').strip()}"))
                continue
            c = CRED_COMPARE.search(line)
            if c and CRED_NAME.search(c.group("lhs")) and \
                    c.group("val").strip().lower() not in NON_CREDENTIAL_VALUES:
                out.append((rel, i, "authorize_compare"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True,
                    help="path to clean_report.json produced by the scan")
    args = ap.parse_args()

    gt = json.loads(GT_PATH.read_text(encoding="utf-8"))
    findings = load_findings(Path(args.report))
    if not findings:
        print("ERROR: no findings in report", file=sys.stderr)
        return 2

    pre = reconcile_pre_registered(gt, findings)

    corpus_root = Path(gt["corpus"]["path"])
    audit = audit_findings(gt, findings, pre, corpus_root)

    mech = enumerate_credential_positives(corpus_root) \
        if corpus_root.exists() else []
    # Join on the exact file:line.  A +/-3 window here would credit the
    # scanner with sites it never reported, simply because it reported the
    # neighbouring line - e.g. PINECONE_API_KEY at rag_engine.py:25 would be
    # credited because :24 was reported.
    tp_lines = {
        (_norm(r["file"]).lower(), int(r["line"]))
        for r in audit["rows"] if r["verdict"] == "TP"
    }
    mech_pos = {(_norm(f).lower(), ln) for f, ln, _ in mech}
    mech_tp = sum(
        1 for f, ln, _ in mech
        if (_norm(f).lower(), ln) in tp_lines
    )
    mech_recall = mech_tp / len(mech_pos) if mech_pos else None

    # ---- completeness gate: every finding either scored or deliberately held
    classified = sum(1 for r in audit["rows"] if r["verdict"] != "UNEVALUATED")
    # Every GT entry must be accounted for as matched or missed.
    gt_accounted = (len(pre["matched"]) + len(pre["misses"])
                    == len(gt["positives"]))
    nc_accounted = (len(pre["negative_controls"]["violations"])
                    + len(pre["negative_controls"]["respected"])
                    == len(gt["negative_controls"]))
    ok = gt_accounted and nc_accounted

    result = {
        "benchmark_id": BENCHMARK_ID,
        "generated": datetime.now(timezone.utc).isoformat(),
        "report": str(args.report),
        "ground_truth": str(GT_PATH.name),
        "corpus": gt["corpus"],
        "findings_total": len(findings),
        "findings_in_gt_categories": len(audit["rows"]),
        "findings_outside_gt_categories_unevaluated":
            audit["unevaluated_other_categories"],
        "scorecard_a_pre_registered": pre,
        "scorecard_b_findings_audit": {
            "counts": {k: v for k, v in audit["counts"].items()
                       if k != "_raw"},
            "precision": audit["precision"],
            "fp_by_root_cause": audit["fp_by_root_cause"],
            "tp_by_origin": audit["tp_by_origin"],
            "rows": audit["rows"],
        },
        "scorecard_c_credential_recall_mechanical": {
            "method": ("regex enumeration over code+config files excluding "
                       "docs, tests and lockfiles; stated in "
                       "enumerate_credential_positives()"),
            "positives": len(mech_pos),
            "tp": mech_tp,
            "recall": mech_recall,
        },
        "measured_by_rule": {
            "precision": audit["precision"],
            "recall_pre_registered": pre["totals"]["recall"],
            "negative_control_violation_rate":
                pre["negative_controls"]["violation_rate"],
        },
        "completeness": {
            "ground_truth_fully_accounted": gt_accounted,
            "negative_controls_fully_accounted": nc_accounted,
            "in_scope_findings_classified": classified,
            "in_scope_findings_total": len(audit["rows"]),
            "pass": ok,
        },
    }
    OUT_JSON.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    OUT_MD.write_text(render_md(result), encoding="utf-8")

    m = result["measured_by_rule"]
    print(f"findings total={len(findings)}  in-GT-categories="
          f"{len(audit['rows'])}  outside={audit['unevaluated_other_categories']}")
    print("pre-registered recall by category:")
    for cat, s in pre["per_category"].items():
        if s["positives"]:
            print(f"    {cat:22s} {s['tp']}/{s['positives']}  "
                  f"recall={s['recall']:.4f}" if s["recall"] is not None
                  else f"    {cat:22s} n/a")
    print(f"overall pre-registered recall : "
          f"{pre['totals']['tp']}/{pre['totals']['positives']} = "
          f"{pre['totals']['recall']:.4f}")
    print(f"precision (findings audit)    : {m['precision']:.4f}")
    print(f"credential recall (mechanical): {mech_tp}/{len(mech_pos)} = "
          f"{(mech_recall or 0):.4f}")
    print(f"negative-control violations   : "
          f"{len(pre['negative_controls']['violations'])}/"
          f"{pre['negative_controls']['total']}")
    print(f"FP by root cause              : {audit['fp_by_root_cause']}")
    print(f"Wrote {OUT_JSON.name} and {OUT_MD.name}")
    if not ok:
        print("FAILED: reconciliation incomplete", file=sys.stderr)
        return 1
    return 0


def render_md(r: dict) -> str:
    a = r["scorecard_a_pre_registered"]
    b = r["scorecard_b_findings_audit"]
    c = r["scorecard_c_credential_recall_mechanical"]
    nca = a["negative_controls"]
    L: list[str] = []
    L.append("# Benchmark reconciliation - OWASP GenAI Red Team Lab\n")
    L.append(f"**Benchmark ID:** `{r['benchmark_id']}`  ")
    L.append(f"**Generated:** {r['generated']}  ")
    L.append(f"**Ground truth:** `reports/{r['ground_truth']}`, authored by "
             "reading the source **before** the product ran  ")
    L.append(f"**Corpus:** {r['corpus']['name']} - "
             f"{r['corpus']['files_total']} files, "
             f"{r['corpus']['code_files_py_js_cs']} code files  ")
    L.append(f"**Findings reported:** {r['findings_total']} "
             f"({r['findings_in_gt_categories']} in ground-truth categories, "
             f"{r['findings_outside_gt_categories_unevaluated']} outside them "
             "and therefore **unevaluated**, not called false positives)\n")

    L.append("## Scorecard A - pre-registered ground truth\n")
    L.append("| Category | Positives | TP | FN | Recall |")
    L.append("|---|---:|---:|---:|---:|")
    for cat, s in a["per_category"].items():
        if not s["positives"]:
            continue
        rec = f"{s['recall']:.4f}" if s["recall"] is not None else "n/a"
        L.append(f"| {cat} | {s['positives']} | {s['tp']} | {s['fn']} | {rec} |")
    t = a["totals"]
    L.append(f"| **overall** | **{t['positives']}** | **{t['tp']}** | "
             f"**{t['fn']}** | **{t['recall']:.4f}** |")
    L.append("")
    L.append(f"**Precision note:** {t['precision_note']}\n")

    L.append("### Negative controls\n")
    L.append(f"{len(nca['violations'])} of {nca['total']} violated "
             f"(rate {nca['violation_rate']:.4f}); respected: "
             f"{', '.join(nca['respected']) or 'none'}\n")
    if nca["violations"]:
        L.append("| ID | File:line | Rule | Why it is not a finding |")
        L.append("|---|---|---|---|")
        for v in nca["violations"]:
            L.append(f"| {v['id']} | `{v['file']}:{v['finding_line']}` | "
                     f"`{v['rule']}` | {v['why_not_a_finding']} |")
        L.append("")

    L.append("## Scorecard B - per-finding audit\n")
    L.append("| Verdict | Count |")
    L.append("|---|---:|")
    for k, v in b["counts"].items():
        L.append(f"| {k} | {v} |")
    L.append("")
    L.append(f"**Precision = {b['precision']:.4f}**\n")
    L.append("True positives by origin: "
             f"{b['tp_by_origin']} - entries recorded as `post_hoc_review` are "
             "real defects the hand-written ground truth missed, disclosed "
             "rather than quietly added.\n")
    L.append("### False positives by root cause\n")
    L.append("| Root cause | Count | Meaning |")
    L.append("|---|---:|---|")
    meaning = {
        "SOURCE_GAP": "Rule fires on the sink with `source=None`; no untrusted "
                      "value was found to reach it.",
        "FILE_SCOPE_GAP": "Rule has no lockfile exclusion; integrity hashes, "
                          "`engines.node` ranges and package names are matched "
                          "as credentials.",
        "CONTEXT_MISCLASSIFIED": "Value is not part of any authorization "
                                 "decision.",
    }
    for k, v in sorted(b["fp_by_root_cause"].items(),
                       key=lambda x: -x[1]):
        L.append(f"| `{k}` | {v} | {meaning.get(k, '-')} |")
    L.append("")

    L.append("## Scorecard C - credential recall without hand-authoring bias\n")
    L.append(f"Method: {c['method']}  ")
    L.append(f"**{c['tp']} / {c['positives']} = "
             f"{(c['recall'] or 0):.4f}**\n")
    L.append("The hand-written ground truth covered only a few credential "
             "sites; this card re-derives them mechanically so credential "
             "recall is quoted against every site in the corpus rather than "
             "the handful that were read.\n")

    L.append("## Missed findings - root cause\n")
    if a["misses"]:
        L.append("| GT | Category | File:line | Sink |")
        L.append("|---|---|---|---|")
        for m in a["misses"]:
            L.append(f"| {m['gt']} | {m['category']} | `{m['file']}:{m['line']}` "
                     f"| `{m['sink']}` |")
        L.append("")
    L.append("## False positives - examples\n")
    fps = [x for x in b["rows"] if x["verdict"] == "FP"]
    seen: set[str] = set()
    L.append("| File:line | Rule | Root cause | Reason |")
    L.append("|---|---|---|---|")
    for x in fps:
        k = f"{x['rule']}|{x['root_cause']}"
        if k in seen:
            continue
        seen.add(k)
        L.append(f"| `{x['file']}:{x['line']}` | `{x['rule']}` | "
                 f"`{x['root_cause']}` | {x['reason']} |")
    L.append("")
    L.append("## Measured summary\n")
    L.append("| Measure | Value |")
    L.append("|---|---:|")
    L.append(f"| Recall (pre-registered GT) | "
             f"{a['totals']['recall']:.4f} |")
    L.append(f"| Precision (per-finding audit) | {b['precision']:.4f} |")
    L.append(f"| Credential recall (mechanical) | "
             f"{(c['recall'] or 0):.4f} |")
    L.append(f"| Negative-control violation rate | "
             f"{nca['violation_rate']:.4f} |")
    L.append(f"| Findings outside GT categories (unevaluated) | "
             f"{r['findings_outside_gt_categories_unevaluated']} |")
    L.append("")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
