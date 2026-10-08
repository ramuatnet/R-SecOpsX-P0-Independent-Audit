from __future__ import annotations

import sys
from pathlib import Path
import re

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import scanner.llm_security_optimized as llm
from scanner.llm_context_precision import classify_findings

TARGET = Path(r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64")

files = {}
for p in TARGET.rglob("*"):
    if not p.is_file():
        continue
    if hasattr(llm, "_should_scan") and not llm._should_scan(p):
        continue
    try:
        files[str(p)] = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass

raw = []
for filepath, content in files.items():
    raw.extend(llm.scan_llm_file(filepath, content))

classified = classify_findings(raw, files)
actionable = [x for x in classified if x.get("actionable") is True]

print("=" * 100)
print("R-SecOpsX LLM TWO-CANDIDATE SOURCE/SINK AUDIT")
print("=" * 100)
print(f"Raw findings:       {len(raw)}")
print(f"Actionable:         {len(actionable)}")
print()

for idx, finding in enumerate(actionable, 1):
    filepath = str(finding.get("file", ""))
    line_no = int(finding.get("line") or 0)
    content = files.get(filepath, "")
    lines = content.splitlines()

    print("#" * 100)
    print(f"[{idx}] {finding.get('rule_id')} | {finding.get('vuln_type')}")
    print(f"FILE: {filepath}")
    print(f"LINE: {line_no}")
    print(f"SNIPPET: {finding.get('snippet')}")
    print("-" * 100)

    # Show ±25 lines around candidate.
    start = max(1, line_no - 25)
    end = min(len(lines), line_no + 25)
    for n in range(start, end + 1):
        marker = " >>> " if n == line_no else "     "
        print(f"{marker}{n:5}: {lines[n-1]}")

    # Search for likely source/sink identifiers in the complete file.
    print()
    print("LIKELY SOURCE/SINK REFERENCES IN SAME FILE:")

    terms = [
        "orderLinesData", "safeEval", "runInContext", "eval",
        "streamText", "generateText", "generateObject", "model",
        "messages", "systemPrompt", "buildSystemPrompt",
        "req.body", "req.query", "req.params", "response",
        "res.json", "res.send", "res.write", "console.log",
        "logger", "return"
    ]

    seen = set()
    for term in terms:
        for m in re.finditer(re.escape(term), content, re.IGNORECASE):
            ln = content.count("\n", 0, m.start()) + 1
            if ln in seen:
                continue
            seen.add(ln)
            print(f"  line {ln:5}: {lines[ln-1].strip()}")

    print()
    print("PRELIMINARY DECISION CRITERIA:")
    print("  TRUE_LLM_FLOW       = user/model-controlled data reaches LLM and then reaches the reported sink")
    print("  GENERIC_SECURITY    = vulnerability exists but no LLM data-flow relationship is established")
    print("  FALSE_POSITIVE      = reported rule semantics are not supported")
    print("  CHALLENGE_ARTIFACT   = benchmark challenge/training behavior")
    print("  UNCERTAIN            = insufficient evidence")
    print()

print("=" * 100)
print("END AUDIT")
print("=" * 100)
