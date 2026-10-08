"""
Feature 10 — Historical Security Finding Intelligence.

Correlates an explicitly supplied historical findings file with current
findings. It does not invent historical records or lifecycle states.
"""
from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _norm_path(value: Any) -> str:
    if not value:
        return ""

    p = str(value).replace("\\", "/").strip()

    while p.startswith("./"):
        p = p[2:]

    return p.lstrip("/")


def _identity(f: Dict[str, Any]) -> str:
    for k in ("finding_id", "id"):
        if f.get(k) not in (None, ""):
            return "ID:" + str(f[k])

    rule = str(f.get("rule_id") or f.get("rule") or "").strip().lower()
    path = _norm_path(f.get("file") or f.get("path") or f.get("source_file"))
    msg = str(f.get("message") or f.get("title") or "").strip().lower()

    if not (rule or path or msg):
        return ""

    basis = f"{rule}|{path}|{msg}"
    return "FP:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _load(path: str) -> Tuple[List[Dict[str, Any]] | None, str | None]:
    p = Path(path).expanduser().resolve()

    if not p.is_file():
        return None, "HISTORY_FILE_NOT_FOUND"

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        return None, f"HISTORY_JSON_INVALID: {str(e)}"

    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)], None

    if isinstance(data, dict):
        for k in ("findings", "results", "items", "history"):
            records = data.get(k)
            if isinstance(records, list):
                return [x for x in records if isinstance(x, dict)], None

    return None, "HISTORY_FINDINGS_ARRAY_NOT_FOUND"


def enrich_historical_finding_intelligence(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return payload

    result = deepcopy(payload)
    path = os.environ.get("RSECOPSX_FINDING_HISTORY", "")

    if not path:
        result["historical_finding_intelligence"] = {
            "status": "UNAVAILABLE",
            "reason": "HISTORY_NOT_CONFIGURED",
            "records": [],
            "read_only": True,
        }
        return result

    records, error = _load(path)

    if records is None:
        result["historical_finding_intelligence"] = {
            "status": "UNAVAILABLE",
            "reason": error,
            "records": [],
            "read_only": True,
        }
        return result

    # Aggregate every historical occurrence by stable finding identity.
    hist_counts: Dict[str, int] = {}

    for f in records:
        ident = _identity(f)
        if ident:
            hist_counts[ident] = hist_counts.get(ident, 0) + 1

    current_findings = result.get("findings", [])

    if not isinstance(current_findings, list):
        current_findings = []

    current_set = set()

    for f in current_findings:
        if isinstance(f, dict):
            ident = _identity(f)
            if ident:
                current_set.add(ident)

    rows: List[Dict[str, Any]] = []

    all_identities = sorted(set(hist_counts.keys()) | current_set)

    for ident in all_identities:
        hist_count = hist_counts.get(ident, 0)

        rows.append(
            {
                "finding_identity": ident,
                "historical_present": hist_count > 0,
                "current_present": ident in current_set,
                "historical_record_count": hist_count,
            }
        )

    result["historical_finding_intelligence"] = {
        "status": "AVAILABLE",
        "history_file": path,
        "records": rows,
        "summary": {
            "historical_findings": len(hist_counts),
            "current_findings": len(current_set),
            "historical_matches": sum(
                1
                for x in rows
                if x["historical_present"] and x["current_present"]
            ),
        },
        "read_only": True,
    }

    return result


if __name__ == "__main__":
    # Feature module; orchestration is performed by the main R-SecOpsX pipeline.
    pass
