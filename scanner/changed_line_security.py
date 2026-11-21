"""
Feature 4 — Changed-Line Security Findings.

Consumes existing findings + Feature 2 change intelligence without changing
canonical finding semantics.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _clean_path(value: Any) -> str:
    if not value:
        return ""

    p = str(value).replace("\\", "/").strip()

    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]

    while p.startswith("./"):
        p = p[2:]

    return p


def _path(f: Dict[str, Any]) -> str:
    for k in ("file", "path", "source_file", "filename"):
        if f.get(k):
            return _clean_path(f[k])

    return ""


def _lines(f: Dict[str, Any]) -> List[int]:
    vals = []

    for k in ("line", "start_line", "end_line", "line_number"):
        v = f.get(k)

        if isinstance(v, int):
            vals.append(v)

        elif isinstance(v, str) and v.isdigit():
            vals.append(int(v))

    return sorted(set(v for v in vals if v > 0))


def enrich_changed_line_findings(
    payload: Dict[str, Any]
) -> Dict[str, Any]:

    if not isinstance(payload, dict):
        return payload

    ci = payload.get("change_intelligence") or {}

    if not isinstance(ci, dict):
        ci = {}

    ci_files = ci.get("files", [])

    if not isinstance(ci_files, list):
        ci_files = []

    files: Dict[str, set] = {}

    for x in ci_files:

        if not isinstance(x, dict):
            continue

        p = _clean_path(x.get("path"))

        if not p:
            continue

        added_lines = x.get("added_lines", []) or []

        if not isinstance(added_lines, (list, set, tuple)):
            added_lines = []

        files[p] = set(
            line
            for line in added_lines
            if isinstance(line, int) and line > 0
        )

    rows = []

    for f in payload.get("findings", []) or []:

        if not isinstance(f, dict):
            continue

        p = _path(f)
        ls = _lines(f)

        changed = sorted(
            set(ls).intersection(files.get(p, set()))
        )

        on_changed_line = bool(changed)
        in_changed_file = bool(p and p in files)

        if on_changed_line:
            scope = "CHANGED_LINE"

        elif in_changed_file:
            scope = "CHANGED_FILE"

        else:
            scope = "UNCHANGED_FILE"

        finding_id = str(
            f.get("finding_uid")  # B3-ID Phase B Wave 2 prepend (contract §6.2 #2)
            or f.get("finding_id")
            or f.get("id")
            or ""
        ).strip()

        rows.append({
            "finding_id": finding_id or None,
            "path": p,
            "finding_lines": ls,
            "changed_lines": changed,
            "on_changed_line": on_changed_line,
            "in_changed_file": in_changed_file,
            "change_scope": scope,
        })

    rows.sort(
        key=lambda x: (
            x["path"],
            x["finding_id"] or "",
            x["finding_lines"],
        )
    )

    ci_status = ci.get("status")

    payload["changed_line_security"] = {
        "status": (
            "AVAILABLE"
            if ci_status == "AVAILABLE"
            else "UNAVAILABLE"
        ),

        "findings": rows,

        "summary": {
            "findings_on_changed_lines":
                sum(
                    1
                    for x in rows
                    if x["on_changed_line"]
                ),

            "findings_in_changed_files":
                sum(
                    1
                    for x in rows
                    if x["in_changed_file"]
                ),

            "findings_outside_changed_files":
                sum(
                    1
                    for x in rows
                    if not x["in_changed_file"]
                ),
        },

        "read_only": True,
    }

    return payload
