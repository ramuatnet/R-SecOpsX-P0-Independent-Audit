$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path $Root)) {
    throw "V11 root not found: $Root"
}

$Tests = Join-Path $Root "tests"
$Dump = Join-Path $Root "dump"
New-Item -ItemType Directory -Force -Path $Tests | Out-Null
New-Item -ItemType Directory -Force -Path $Dump | Out-Null

$AuditPy = Join-Path $Tests "test_v11_llm01_end_to_end_persistence_audit_v1.py"

@'
from pathlib import Path
import ast
import json
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

SCAN_DIRS = ["scanner", "core", "analysis", "reporting"]

def flatten_keys(value, out=None):
    if out is None:
        out = set()
    if isinstance(value, dict):
        out.update(value.keys())
        for v in value.values():
            flatten_keys(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            flatten_keys(v, out)
    return out

def source_reference_audit():
    rows = []
    for d in SCAN_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            try:
                text = p.read_text(encoding="utf-8-sig")
            except Exception:
                continue
            for field in FIELDS:
                count = text.count(field)
                if count:
                    rows.append((str(p.relative_to(ROOT)), field, count))
    return rows

def runtime_audit():
    from scanner.llm_security import scan_llm_file
    from core.finding_model import normalize_finding, normalize_payload

    source = 