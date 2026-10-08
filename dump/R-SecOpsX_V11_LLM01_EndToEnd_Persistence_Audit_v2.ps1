$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Tests = Join-Path $Root "tests"
New-Item -ItemType Directory -Force -Path $Tests | Out-Null

$AuditPy = Join-Path $Tests "test_v11_llm01_end_to_end_persistence_audit_v2.py"

$py = @'
from pathlib import Path
import ast
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FIELDS = [
    "llm01_decision_policy_version",
    "llm01_decision_signals",
    "llm01_decision_policy_applied",
    "llm01_taint_validated",
    "llm01_decision_state",
    "llm01_contextual_severity",
    "llm01_contextual_priority",
    "llm01_decision_reason",
]

def keys(value, result=None):
    if result is None:
        result = set()
    if isinstance(value, dict):
        result.update(str(k) for k in value.keys())
        for v in value.values():
            keys(v, result)
    elif isinstance(value, (list, tuple)):
        for v in value:
            keys(v, result)
    return result

def scan_runtime():
    from scanner.llm_security import scan_llm_file
    from core.finding_model import normalize_finding, normalize_payload

    fixture = """
def generate(prompt):
    user_text = request.get("prompt")
    return llm.generate(user_text)
"""

    findings = scan_llm_file("audit_fixture.py", fixture)
    assert findings, "LLM01 scanner produced no finding"

    raw = findings[0]
    normalized = normalize_finding(dict(raw))
    payload = normalize_payload({"findings": [dict(raw)]})

    stages = {
        "scanner_finding": keys(raw),
        "normalize_finding": keys(normalized),
        "normalize_payload": keys(payload),
    }

    print("\nRUNTIME FIELD TRACE")
    for stage, stage_keys in stages.items():
        present = [f for f in FIELDS if f in stage_keys]
        missing = [f for f in FIELDS if f not in stage_keys]
        print(f"[{stage}] {len(present)}/{len(FIELDS)} present")
        if present:
            print("  PRESENT:", ", ".join(present))
        if missing:
            print("  MISSING :", ", ".join(missing))

    return stages

def static_trace():
    print("\nSTATIC FIELD TRACE")
    roots = [
        ROOT / "scanner",
        ROOT / "core",
        ROOT / "analysis",
        ROOT / "reporting",
    ]

    references = {field: [] for field in FIELDS}

    for base in roots:
        if not base.exists():
            continue
        files = [base] if base.is_file() else list(base.rglob("*.py"))
        for path in files:
            try:
                text = path.read_text(encoding="utf-8-sig")
            except Exception:
                continue
            for field in FIELDS:
                count = text.count(field)
                if count:
                    references[field].append(
                        (str(path.relative_to(ROOT)), count)
                    )

    for field in FIELDS:
        print(f"\n{field}")
        if not references[field]:
            print("  [REVIEW] no source reference")
        else:
            for path, count in references[field]:
                print(f"  [REF] {count}x {path}")

    return references

def syntax_check():
    print("\nSYNTAX VALIDATION")
    targets = [
        ROOT / "scanner" / "llm_security.py",
        ROOT / "core" / "finding_model.py",
        ROOT / "core" / "evidence_adapter.py",
    ]
    for path in targets:
        if not path.exists():
            print("[REVIEW] missing:", path)
            continue
        ast.parse(
            path.read_text(encoding="utf-8-sig"),
            filename=str(path),
        )
        print("[PASS]", path.relative_to(ROOT))

def main():
    print("=" * 72)
    print("R-SecOpsX V11 - LLM01 END-TO-END PERSISTENCE AUDIT v2")
    print("READ-ONLY - NO PRODUCTION SOURCE MODIFICATION")
    print("=" * 72)

    runtime = scan_runtime()
    static = static_trace()
    syntax_check()

    print("\nDECISION")
    raw_missing = [f for f in FIELDS if f not in runtime["scanner_finding"]]
    normalized_missing = [f for f in FIELDS if f not in runtime["normalize_finding"]]
    payload_missing = [f for f in FIELDS if f not in runtime["normalize_payload"]]

    if raw_missing:
        print("[REVIEW] Scanner boundary missing:", ", ".join(raw_missing))
    elif normalized_missing:
        print("[REVIEW] normalize_finding loses:", ", ".join(normalized_missing))
    elif payload_missing:
        print("[REVIEW] normalize_payload loses:", ", ".join(payload_missing))
    else:
        print("[PASS] All LLM01 decision fields survived runtime normalization")

    print("\nAUDIT COMPLETE - NO PRODUCTION SOURCE WAS MODIFIED")

if __name__ == "__main__":
    main()
'@

Set-Content -LiteralPath $AuditPy -Value $py -Encoding UTF8
Write-Host "[PASS] Read-only audit test installed: $AuditPy"

python $AuditPy
if ($LASTEXITCODE -ne 0) {
    throw "Read-only LLM01 persistence audit failed."
}

Write-Host ""
Write-Host "============================================================"
Write-Host "R-SecOpsX V11 - LLM01 PERSISTENCE AUDIT v2 COMPLETE"
Write-Host "============================================================"
Write-Host "[PASS] Read-only audit"
Write-Host "[PASS] No production source modification"
