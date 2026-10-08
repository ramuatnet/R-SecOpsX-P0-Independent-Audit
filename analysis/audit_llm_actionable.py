from __future__ import annotations

import sys
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import scanner.llm_security_context_aware as llm
from scanner.llm_context_precision import classify_findings

TARGET = Path(
    r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64"
)

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

print("=" * 88)
print("R-SecOpsX LLM ACTIONABLE CANDIDATE AUDIT")
print("=" * 88)
print(f"Raw findings:       {len(raw)}")
print(f"Actionable:         {len(actionable)}")
print()

for idx, finding in enumerate(actionable, 1):
    filepath = str(finding.get("file", ""))
    line_no = int(finding.get("line") or 0)
    content = files.get(filepath, "")
    lines = content.splitlines()

    start = max(1, line_no - 12)
    end = min(len(lines), line_no + 12)

    print()
    print("#" * 88)
    print(
        f"[{idx}/{len(actionable)}] "
        f"{finding.get('rule_id')} | {finding.get('vuln_type')}"
    )
    print(f"Severity: {finding.get('severity')}")
    print(f"Context: {finding.get('context_class')}")
    print(f"Relevance: {finding.get('security_relevance')}")
    print(f"FILE: {filepath}")
    print(f"TARGET LINE: {line_no}")
    print("-" * 88)

    for n in range(start, end + 1):
        marker = " >>> " if n == line_no else "     "
        print(f"{marker}{n:5}: {lines[n-1]}")

print()
print("=" * 88)
print("AUDIT SUMMARY")
print("=" * 88)

print("Rule distribution:")
for rule, count in Counter(x.get("rule_id") for x in actionable).most_common():
    print(f"  {rule}: {count}")

print()
print("Suggested validation labels:")
print("  TRUE_LLM_VULNERABILITY")
print("  GENERIC_SECURITY_ISSUE")
print("  CHALLENGE_ARTIFACT")
print("  FALSE_POSITIVE")
print("  DUPLICATE")
print("  UNCERTAIN")
