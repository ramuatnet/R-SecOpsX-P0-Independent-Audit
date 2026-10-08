$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Tests = Join-Path $Root "tests"
New-Item -ItemType Directory -Force -Path $Tests | Out-Null

$AuditPy = Join-Path $Tests "test_v11_llm01_end_to_end_persistence_audit_v3.py"

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

def candidate_sources():
    roots = [
        ROOT / "tests" / "fixtures",
        ROOT / "tests",
    ]
    seen = set()
    extensions = {".py", ".js", ".ts", ".tsx", ".jsx", ".txt", ".json", ".yaml", ".yml"}
    for base in roots:
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in extensions:
                continue
            if p.resolve() in seen:
                continue
            seen.add(p.resolve())
            try:
                text = p.read_text(encoding="utf-8-sig")
            except Exception:
                continue
            if len(text) > 500000:
                continue
            yield p, text

def find_known_good_finding():
    from scanner.llm_security import scan_llm_file

    candidates = list(candidate_sources())
    print(f"[INFO] Candidate fixture/test files inspected: {len(candidates)}")

    preferred = sorted(
        candidates,
        key=lambda item: (
            0 if "fixture" in str(item[0]).lower() else 1,
            0 if "llm" in str(item[0]).lower() else 1,
            len(item[1]),
        )
    )

    for path, text in preferred:
        try:
            findings = scan_llm_file(str(path.relative_to(ROOT)), text)
        except Exception:
            continue
        if findings:
            print("[PASS] Known-good runtime source located:", path.relative_to(ROOT))
            print("[PASS] Scanner produced", len(findings), "finding(s)")
            return findings[0], path, text

    # Fallback: execute the existing real traceability test so we never
    # replace its known-good source with an invented fixture.
    real_test = ROOT / "tests" / "test_v11_real_llm_finding_traceability.py"
    if real_test.exists():
        print("[INFO] Existing real traceability test exists:", real_test.relative_to(ROOT))

    raise AssertionError(
        "No existing V11 test/fixture source produced an LLM01 finding. "
        "No synthetic fixture was introduced by this audit."
    )

def runtime_trace():
    from core.finding_model import normalize_finding, normalize_payload

    raw, path, text = find_known_good_finding()
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

    if "finding_id" in raw:
        print("[PASS] scanner finding has finding_id:", raw["finding_id"])
    else:
        print("[REVIEW] scanner finding has no finding_id")

    evidence = raw.get("evidence")
    if isinstance(evidence, dict):
        related = evidence.get("related_finding_id")
        print("[INFO] evidence.related_finding_id:", related)
        if raw.get("finding_id") and related == raw.get("finding_id"):
            print("[PASS] evidence linkage matches finding_id")
        else:
            print("[REVIEW] evidence linkage does not match finding_id")

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
    print("R-SecOpsX V11 - LLM01 END-TO-END PERSISTENCE AUDIT v3")
    print("READ-ONLY - USES EXISTING V11 TEST/FIXTURE SOURCES")
    print("NO SYNTHETIC LLM01 FIXTURE / NO PRODUCTION MODIFICATION")
    print("=" * 72)

    runtime = runtime_trace()
    static_trace()
    syntax_check()

    raw_missing = [f for f in FIELDS if f not in runtime["scanner_finding"]]
    normalized_missing = [f for f in FIELDS if f not in runtime["normalize_finding"]]
    payload_missing = [f for f in FIELDS if f not in runtime["normalize_payload"]]

    print("\nDECISION")
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
Write-Host "R-SecOpsX V11 - LLM01 PERSISTENCE AUDIT v3 COMPLETE"
Write-Host "============================================================"
Write-Host "[PASS] Read-only audit"
Write-Host "[PASS] Existing V11 source/fixtures used"
Write-Host "[PASS] No production source modification"
