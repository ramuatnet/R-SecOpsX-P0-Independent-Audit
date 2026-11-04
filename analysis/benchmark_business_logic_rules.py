"""Dry-run benchmark for the 14 unwired business-logic rules (G-062).

What this is
------------
`scanner/business_logic_patterns.py` holds 14 BL_ regex rules that nothing
imports, so they have never executed (G-062). Before wiring them in - which
would switch 14 detections on at once and could move precision either way -
this harness applies them to corpora we already benchmark and reports what
they would find.

It is deliberately a DRY RUN: the product pipeline is not modified, nothing is
wired, no finding is added to any report. The number produced here is an input
to the wire-or-retire decision, not a score that can be gamed.

The rules live in `scanner/` normally and in `quarantine/scanner/` since the
dead-file sweep; either location is accepted so the harness keeps working
across that move.

Verdicts (structural only -- match volume is reported as data, never scored):
    v1_rule_module_locatable      the table must be loadable
    v2_every_rule_exercised       all 14 rules must be exercised somewhere,
                                  otherwise the corpus says nothing about them

Output (distinct names, nothing else overwritten):
    reports/benchmark_reconciliation_business_logic.json
    reports/benchmark_reconciliation_business_logic.md
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_2, WINDOW_80, WINDOW_M5, WINDOW_SNIPPET
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_2, WINDOW_80, WINDOW_M5, WINDOW_SNIPPET

import argparse
import importlib.util
import io
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scanner.walk import walk

CANDIDATES = [
    REPO / "scanner" / "business_logic_patterns.py",
    REPO / "quarantine" / "scanner" / "business_logic_patterns.py",
]
SOURCE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php",
              ".rb", ".cs", ".kt", ".scala", ".vue", ".svelte"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "venv",
             ".venv", "__pycache__", "backup", "quarantine", "reports",
             "Working folder", "dump"}
SKIP_FILE_PREFIX = ("test_", "spec_", ".min.")


def locate() -> Path:
    for p in CANDIDATES:
        if p.exists():
            return p
    raise SystemExit(
        "business_logic_patterns.py not found in scanner/ or "
        f"quarantine/scanner/ -- looked in: {[str(p) for p in CANDIDATES]}")


def load_rules(path: Path):
    name = "_bl_rule_table"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod          # required for @dataclass on 3.14+
    spec.loader.exec_module(mod)
    getter = getattr(mod, "get_business_logic_rules", None)
    rules = getter() if callable(getter) else getattr(mod, "BUSINESS_LOGIC_RULES")
    return list(rules)


def iter_source(root: Path):
    for p, _s, _m in walk(root, exts=None, ignore=frozenset(), max_bytes=None):
        if not p.is_file() or p.suffix.lower() not in SOURCE_EXT:
            continue
        parts = set(p.parts)
        if parts & SKIP_DIRS:
            continue
        if p.name.startswith(SKIP_FILE_PREFIX):
            continue
        try:
            yield p
        except OSError:
            continue


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Dry-run the unwired business-logic rules (G-062)")
    ap.add_argument("--target", action="append", default=None,
                    help="corpus root to apply the rules to (repeatable)")
    ap.add_argument("--out", default=str(
        REPO / "reports" / "benchmark_reconciliation_business_logic"))
    args = ap.parse_args()

    problems: list[str] = []
    path = locate()
    try:
        rules = load_rules(path)
    except Exception as exc:                      # noqa: BLE001
        raise SystemExit(f"could not load rule table from {path}: {exc}")
    if not rules:
        problems.append("rule table loaded but is empty")

    targets = args.target or [
        r"D:\Data\Code test\prodtest\juice-shop-git",
        r"D:\Data\Code test\prodtest\GenAI-Red-Team-Lab-main",
    ]
    targets = [t for t in targets if Path(t).exists()]
    if not targets:
        raise SystemExit("no target corpus exists; pass --target")

    compiled = []
    for r in rules:
        try:
            compiled.append((r, re.compile(r["pattern"])))
        except re.error as exc:
            problems.append(f"{r.get('rule_id')}: invalid regex: {exc}")
    if problems and not compiled:
        raise SystemExit("; ".join(problems))

    per_rule = {r["rule_id"]: {
        "title": r.get("title", ""), "severity": r.get("severity", ""),
        "confidence": r.get("confidence", ""), "matches": 0,
        "files": set(), "samples": [],
    } for r, _ in compiled}
    files_scanned = 0

    for tgt in targets:
        for p in iter_source(Path(tgt)):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1
            for lineno, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                for r, rx in compiled:
                    m = rx.search(line)
                    if not m:
                        continue
                    acc = per_rule[r["rule_id"]]
                    acc["matches"] += 1
                    acc["files"].add(str(p))
                    if len(acc["samples"]) < 3:
                        acc["samples"].append({
                            "file": str(p), "line": lineno,
                            "matched": m.group(0)[:WINDOW_80],
                            "snippet": line.strip()[:WINDOW_SNIPPET],
                        })

    exercised = sorted(k for k, v in per_rule.items() if v["matches"] > 0)
    idle = sorted(k for k, v in per_rule.items() if v["matches"] == 0)
    total = sum(v["matches"] for v in per_rule.values())
    if len(exercised) != len(rules):
        problems.append(
            f"{len(idle)} of {len(rules)} rules matched nothing on these "
            f"corpora, so their behaviour is unmeasured: {idle}")

    verdict = {
        "v1_rule_module_locatable": True,
        "v2_every_rule_exercised": len(exercised) == len(rules),
    }

    payload = {
        "benchmark": "business-logic-dryrun-2026-10",
        "root_causes": ["G-062"],
        "mode": "DRY RUN - the product pipeline was not modified and no "
                "finding was added to any report",
        "rule_source": str(path),
        "targets": targets,
        "files_scanned": files_scanned,
        "rules_total": len(rules),
        "rules_exercised": len(exercised),
        "total_matches": total,
        "per_rule": {k: {kk: (sorted(vv) if isinstance(vv, set) else vv)
                         for kk, vv in v.items()}
                     for k, v in sorted(per_rule.items())},
        "unexercised_rules": idle,
        "verdict": verdict,
        "problems": problems,
        "decision_input": (
            "Match volume is a noise estimate, not a quality score. A high "
            "count here means wiring these rules would add findings that no "
            "ground truth currently validates -- which argues for measuring "
            "against a labelled corpus first, not for enabling them silently."
        ),
    }

    out_json = args.out if args.out.endswith(".json") else args.out + ".json"
    out_md = out_json[:WINDOW_M5] + ".md"
    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(out_json).write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                              encoding="utf-8")

    lines = [
        "# Business-logic rules — dry run", "",
        f"Root cause: {', '.join(payload['root_causes'])}", "",
        f"**Mode:** {payload['mode']}", "",
        f"Rule table: `{payload['rule_source']}`  ",
        f"Corpora: {len(targets)} · source files scanned: {files_scanned}", "",
        f"Rules: **{len(exercised)}/{len(rules)} exercised** · "
        f"total matches: **{total}**", "",
        "| rule | severity | confidence | matches | files |",
        "|---|---|---|---:|---:|",
    ]
    for k, v in payload["per_rule"].items():
        lines.append(f"| {k} | {v['severity']} | {v['confidence']} "
                     f"| {v['matches']} | {len(v['files'])} |")
    lines += ["", "## Samples", ""]
    for k, v in payload["per_rule"].items():
        if not v["samples"]:
            continue
        lines.append(f"**{k}**")
        for s in v["samples"][:WINDOW_2]:
            lines.append(f"- `{Path(s['file']).name}:{s['line']}` "
                         f"`{s['matched']}`")
        lines.append("")
    lines += ["## Verdict", ""]
    for k, v in verdict.items():
        lines.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    if problems:
        lines += ["", "## Problems", ""] + [f"- {p}" for p in problems]
    lines += ["", "## Decision input", "", payload["decision_input"], ""]
    Path(out_md).write_text("\n".join(lines), encoding="utf-8")

    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    print(f"  rules {len(exercised)}/{len(rules)} exercised, "
          f"files={files_scanned}, total matches={total}")
    for k, v in payload["per_rule"].items():
        print(f"    {k:<34} {v['matches']:>4}")
    for k, v in verdict.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    for p in problems:
        print(f"  problem: {p}")
    return 0 if all(verdict.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
