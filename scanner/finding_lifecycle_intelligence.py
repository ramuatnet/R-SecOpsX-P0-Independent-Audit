"""
R-SecOpsX Finding Lifecycle Intelligence v1.

Explicit baseline-to-current finding correlation.

This module deliberately separates:
- finding identity
- presence in baseline/current
- explicit lifecycle evidence

It does not infer severity, exploitability, risk, or decision changes.

Lifecycle semantics:
- NEW: current finding has no matching baseline finding.
- FIXED: baseline finding has no matching current finding.
- UNCHANGED: matching finding exists in both and no explicit state transition is evidenced.
- REINTRODUCED: only when the baseline record explicitly states that the finding was
  previously resolved/fixed and the current finding is present again.
- REGRESSED: only when the baseline record explicitly carries a prior lifecycle state
  that identifies the finding as fixed/resolved and the current record explicitly
  identifies it as active again with a regression/reintroduced transition. Otherwise
  regression is NOT_INFERRED.

No lifecycle status is fabricated from Git diff alone.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


_WS_RE = re.compile(r"\s+")


def _norm(value: Any) -> str:
    if value is None:
        return ""
    return _WS_RE.sub(" ", str(value).strip()).lower()


def _path(value: Any) -> str:
    if value is None:
        return ""
    value = str(value).replace("\\", "/").strip()
    if value.startswith("./"):
        value = value[2:]
    return value


def _explicit_id(finding: Dict[str, Any]) -> str:
    for key in ("finding_id", "id"):
        value = finding.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def finding_identity(finding: Dict[str, Any]) -> str:
    """
    Prefer an existing canonical finding identifier.

    Otherwise construct a deterministic semantic identity from stable fields.
    Line numbers are intentionally excluded so moving the same finding does not
    automatically create a NEW finding.
    """
    explicit = _explicit_id(finding)
    if explicit:
        return "ID:" + explicit

    rule = ""
    for key in ("rule_id", "rule", "check_id", "vulnerability_id", "type", "category"):
        if finding.get(key) not in (None, ""):
            rule = _norm(finding.get(key))
            if rule:
                break

    file_path = ""
    for key in ("file", "path", "source_file", "filename"):
        if finding.get(key) not in (None, ""):
            file_path = _path(finding.get(key))
            if file_path:
                break

    sink = ""
    for key in ("sink", "sink_type", "function", "symbol"):
        if finding.get(key) not in (None, ""):
            sink = _norm(finding.get(key))
            if sink:
                break

    message = ""
    for key in ("title", "message", "description"):
        if finding.get(key) not in (None, ""):
            message = _norm(finding.get(key))
            if message:
                break

    basis = "|".join((rule, file_path, sink, message))
    if not basis.replace("|", ""):
        # No stable identity evidence exists. Do not silently create a
        # pseudo-identity from list position.
        return ""

    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return "FP:" + digest


def _state(record: Dict[str, Any]) -> str:
    for key in (
        "lifecycle_status",
        "status",
        "state",
        "finding_status",
        "resolution_status",
        "decision_state",
    ):
        value = record.get(key)
        if value not in (None, ""):
            return _norm(value)
    return ""


def _explicitly_resolved(record: Dict[str, Any]) -> bool:
    for key in ("resolved", "fixed", "is_fixed", "closed"):
        value = record.get(key)
        if isinstance(value, bool):
            if value:
                return True
        elif isinstance(value, str) and _norm(value) in ("true", "yes", "fixed", "resolved", "closed"):
            return True

    state = _state(record)
    return state in {
        "fixed", "resolved", "closed", "remediated",
        "not_present", "absent", "previously_fixed",
    }


def _explicitly_active(record: Dict[str, Any]) -> bool:
    for key in ("active", "is_active"):
        value = record.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return _norm(value) in ("true", "yes", "active", "open")

    state = _state(record)
    if state in ("active", "open", "present", "confirmed", "unresolved"):
        return True
    return False


def _load_baseline(path: str) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    if not path:
        return None, "BASELINE_NOT_CONFIGURED"

    p = Path(path).expanduser().resolve()
    if not p.is_file():
        return None, "BASELINE_FILE_NOT_FOUND"

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, "BASELINE_JSON_INVALID: " + str(exc)

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("findings")
        if records is None:
            records = data.get("results")
        if records is None:
            records = data.get("items")
        if records is None:
            return None, "BASELINE_FINDINGS_ARRAY_NOT_FOUND"
    else:
        return None, "BASELINE_UNSUPPORTED_SHAPE"

    if not isinstance(records, list):
        return None, "BASELINE_FINDINGS_NOT_ARRAY"

    return [x for x in records if isinstance(x, dict)], None


def _index(records: Iterable[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    unidentified: List[Dict[str, Any]] = []

    for record in records:
        identity = finding_identity(record)
        if not identity:
            unidentified.append(record)
            continue

        # Do not silently overwrite duplicates. Keep the first deterministic
        # identity and mark duplicates for explicit reporting.
        if identity not in indexed:
            indexed[identity] = record
        else:
            duplicate = dict(record)
            duplicate["_duplicate_identity"] = identity
            unidentified.append(duplicate)

    return indexed, unidentified


def _classify(
    baseline: Optional[Dict[str, Any]],
    current: Optional[Dict[str, Any]],
) -> Tuple[str, str]:
    if baseline is None and current is not None:
        return "NEW", "NO_MATCHING_BASELINE_FINDING"

    if baseline is not None and current is None:
        return "FIXED", "BASELINE_FINDING_ABSENT_FROM_CURRENT_SCAN"

    if baseline is None or current is None:
        return "UNDETERMINED", "INSUFFICIENT_FINDING_STATE"

    # Reintroduction/regression requires explicit historical state evidence.
    if _explicitly_resolved(baseline) and _explicitly_active(current):
        prior = _state(baseline)
        current_state = _state(current)
        if prior in ("fixed", "resolved", "closed", "remediated", "previously_fixed"):
            if current_state in ("reintroduced", "regressed", "active", "open", "present", "confirmed", "unresolved"):
                return "REINTRODUCED", "EXPLICIT_PRIOR_RESOLUTION_AND_CURRENT_REAPPEARANCE"

    return "UNCHANGED", "MATCHING_BASELINE_AND_CURRENT_FINDING"


def correlate_findings(
    baseline_findings: Iterable[Dict[str, Any]],
    current_findings: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    baseline = list(baseline_findings or [])
    current = list(current_findings or [])

    base_idx, base_unidentified = _index(baseline)
    cur_idx, cur_unidentified = _index(current)

    identities = sorted(set(base_idx).union(cur_idx))
    rows: List[Dict[str, Any]] = []

    for identity in identities:
        b = base_idx.get(identity)
        c = cur_idx.get(identity)
        lifecycle, reason = _classify(b, c)

        rows.append({
            "finding_identity": identity,
            "lifecycle_status": lifecycle,
            "lifecycle_reason": reason,
            "baseline_present": b is not None,
            "current_present": c is not None,
            "baseline_state": _state(b or {}),
            "current_state": _state(c or {}),
        })

    rows.sort(key=lambda x: x["finding_identity"])

    counts = {
        "new": sum(1 for x in rows if x["lifecycle_status"] == "NEW"),
        "fixed": sum(1 for x in rows if x["lifecycle_status"] == "FIXED"),
        "unchanged": sum(1 for x in rows if x["lifecycle_status"] == "UNCHANGED"),
        "reintroduced": sum(1 for x in rows if x["lifecycle_status"] == "REINTRODUCED"),
        "regressed": sum(1 for x in rows if x["lifecycle_status"] == "REGRESSED"),
        "undetermined": sum(1 for x in rows if x["lifecycle_status"] == "UNDETERMINED"),
    }

    return {
        "status": "AVAILABLE",
        "baseline_finding_count": len(baseline),
        "current_finding_count": len(current),
        "correlated_finding_count": len(rows),
        "results": rows,
        "summary": counts,
        "identity": {
            "explicit_ids_preferred": True,
            "line_numbers_excluded_from_fallback_identity": True,
            "unidentified_baseline_count": len(base_unidentified),
            "unidentified_current_count": len(cur_unidentified),
        },
        "semantics": {
            "regression_inferred_without_explicit_history": False,
            "reintroduction_inferred_without_explicit_prior_resolution": False,
            "severity_modified": False,
            "exploitability_modified": False,
            "decision_modified": False,
        },
        "read_only": True,
    }


def enrich_report_payload_with_finding_lifecycle(
    payload: Dict[str, Any],
    baseline_path: Optional[str] = None,
) -> Dict[str, Any]:
    configured = baseline_path or os.environ.get("RSECOPSX_BASELINE_FINDINGS", "")
    baseline, error = _load_baseline(configured)

    if baseline is None:
        payload["finding_lifecycle"] = {
            "status": "UNAVAILABLE",
            "reason": error,
            "baseline_path": configured or None,
            "current_finding_count": len(payload.get("findings", []) or []),
            "results": [],
            "summary": {
                "new": 0,
                "fixed": 0,
                "unchanged": 0,
                "reintroduced": 0,
                "regressed": 0,
                "undetermined": 0,
            },
            "read_only": True,
        }
        return payload

    payload["finding_lifecycle"] = correlate_findings(
        baseline,
        payload.get("findings", []) or [],
    )
    payload["finding_lifecycle"]["baseline_path"] = configured
    return payload
