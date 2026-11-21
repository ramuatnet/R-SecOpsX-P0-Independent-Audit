"""
R-SecOpsX PR / Git Diff Change Intelligence.

Read-only change intelligence:
- extracts deterministic Git diff metadata
- records changed files, hunks, added/removed lines
- maps existing findings to added/changed lines
- distinguishes changed-line findings from findings in changed files
- does NOT infer NEW/REGRESSED/FIXED/REINTRODUCED lifecycle states
- does NOT change finding severity, classification, exploitability, or decision state
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


_PATH_RE = re.compile(r"^[ab]/(.*)$")
_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


def _run_git(root: Path, args: Sequence[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root)] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as exc:
        return 127, "", str(exc)


def _clean_path(value: str) -> str:
    value = value.strip()

    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]

    value = value.replace("\\", "/")

    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]

    while value.startswith("./"):
        value = value[2:]

    return value


def _parse_numstat(line: str) -> Optional[Tuple[str, int, int]]:
    parts = line.split("\t")
    if len(parts) < 3:
        return None
    added, deleted, path = parts[0], parts[1], parts[2]
    if added == "-" or deleted == "-":
        return None
    try:
        return _clean_path(path), int(added), int(deleted)
    except ValueError:
        return None


def _parse_name_status(line: str) -> Optional[Tuple[str, str, Optional[str]]]:
    parts = line.split("\t")
    if not parts:
        return None
    status = parts[0]
    code = status[0] if status else "?"
    if code in ("R", "C") and len(parts) >= 3:
        return code, _clean_path(parts[1]), _clean_path(parts[2])
    if len(parts) >= 2:
        return code, _clean_path(parts[1]), None
    return None


def _parse_hunk_header(header: str) -> Optional[Dict[str, int]]:
    match = _HUNK_RE.match(header)
    if not match:
        return None
    return {
        "old_start": int(match.group("old_start")),
        "old_count": int(match.group("old_count") or 1),
        "new_start": int(match.group("new_start")),
        "new_count": int(match.group("new_count") or 1),
    }


def _line_set(start: int, count: int) -> List[int]:
    if count <= 0:
        return []
    return list(range(start, start + count))


def _parse_zero_context_diff(diff_text: str) -> Tuple[List[Dict[str, Any]], Dict[str, Set[int]]]:
    files: List[Dict[str, Any]] = []
    added_by_file: Dict[str, Set[int]] = {}
    current: Optional[Dict[str, Any]] = None
    old_line = 0
    new_line = 0

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            current = None
            continue

        if raw.startswith("+++ "):
            path = _clean_path(raw[4:].strip())
            if path == "/dev/null":
                path = ""
            if current is not None:
                current["new_path"] = path
            continue

        if raw.startswith("--- "):
            path = _clean_path(raw[4:].strip())
            if path == "/dev/null":
                path = ""
            if current is None:
                current = {
                    "old_path": path,
                    "new_path": path,
                    "status": "M",
                    "hunks": [],
                }
                files.append(current)
            else:
                current["old_path"] = path
            continue

        if raw.startswith("@@ "):
            hunk = _parse_hunk_header(raw)
            if hunk is None:
                continue
            if current is None:
                current = {
                    "old_path": "",
                    "new_path": "",
                    "status": "M",
                    "hunks": [],
                }
                files.append(current)
            current["hunks"].append({
                "old_start": hunk["old_start"],
                "old_count": hunk["old_count"],
                "new_start": hunk["new_start"],
                "new_count": hunk["new_count"],
                "added_lines": [],
                "removed_lines": [],
            })
            old_line = hunk["old_start"]
            new_line = hunk["new_start"]
            continue

        if current is None or not current.get("hunks"):
            continue

        hunk = current["hunks"][-1]
        if raw.startswith("+") and not raw.startswith("+++"):
            hunk["added_lines"].append(new_line)
            path = current.get("new_path") or current.get("old_path") or ""
            added_by_file.setdefault(path, set()).add(new_line)
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            hunk["removed_lines"].append(old_line)
            old_line += 1
        else:
            old_line += 1
            new_line += 1

    return files, added_by_file


def _apply_statuses(files: List[Dict[str, Any]], name_status_text: str) -> None:
    by_path: Dict[str, Dict[str, Any]] = {}
    for item in files:
        path = item.get("new_path") or item.get("old_path") or ""
        if path:
            by_path[path] = item

    for raw in name_status_text.splitlines():
        parsed = _parse_name_status(raw)
        if not parsed:
            continue
        code, old_path, new_path = parsed
        path = new_path or old_path
        item = by_path.get(path)
        if item is None:
            item = {
                "old_path": old_path if code in ("D", "R", "C") else path,
                "new_path": new_path or ("" if code == "D" else path),
                "status": code,
                "hunks": [],
            }
            files.append(item)
            by_path[path] = item
        item["status"] = code
        if code == "R":
            item["old_path"] = old_path
            item["new_path"] = new_path or path


def _normalize_files(files: Iterable[Dict[str, Any]], numstat: Dict[str, Tuple[int, int]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()

    for item in files:
        old_path = item.get("old_path") or ""
        new_path = item.get("new_path") or ""
        path = new_path or old_path
        if not path:
            continue
        key = (old_path, new_path)
        if key in seen:
            continue
        seen.add(key)
        added, removed = numstat.get(path, (0, 0))

        hunks = []
        for h in item.get("hunks", []) or []:
            hunks.append({
                "old_start": int(h.get("old_start", 0)),
                "old_count": int(h.get("old_count", 0)),
                "new_start": int(h.get("new_start", 0)),
                "new_count": int(h.get("new_count", 0)),
                "added_lines": sorted(set(int(x) for x in h.get("added_lines", []) or [])),
                "removed_lines": sorted(set(int(x) for x in h.get("removed_lines", []) or [])),
            })

        hunks.sort(key=lambda x: (x["new_start"], x["old_start"]))
        normalized.append({
            "path": path,
            "old_path": old_path,
            "new_path": new_path,
            "status": item.get("status") or "M",
            "added_lines": sorted(set(
                line for h in hunks for line in h["added_lines"]
            )),
            "removed_lines": sorted(set(
                line for h in hunks for line in h["removed_lines"]
            )),
            "added_count": added,
            "removed_count": removed,
            "hunks": hunks,
        })

    normalized.sort(key=lambda x: (x["path"], x["status"], x["old_path"], x["new_path"]))
    return normalized


def _finding_path(finding: Dict[str, Any]) -> str:
    for key in ("file", "path", "source_file", "filename", "location"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            value = value.replace("\\", "/")
            if ":" in value[:4] and value[1:3] == ":/":
                value = value.split(":", 1)[1]
            return value.lstrip("./")
    return ""


def _finding_lines(finding: Dict[str, Any]) -> List[int]:
    values: List[int] = []
    for key in ("line", "start_line", "end_line", "line_number"):
        value = finding.get(key)
        if isinstance(value, int):
            values.append(value)
        elif isinstance(value, str) and value.isdigit():
            values.append(int(value))

    occurrences = finding.get("occurrences")
    if isinstance(occurrences, list):
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                continue
            for key in ("line", "start_line", "end_line", "line_number"):
                value = occurrence.get(key)
                if isinstance(value, int):
                    values.append(value)
                elif isinstance(value, str) and value.isdigit():
                    values.append(int(value))

    return sorted(set(x for x in values if x > 0))


def _finding_id(finding: Dict[str, Any], index: int) -> str:
    # B3-ID Phase B Wave 2 (contract §6.1 #7 + §3.3): the universal §3.3
    # precedence is composed with EVERY legacy fallback field and the exact
    # positional fallback retained byte-verbatim. Disclosed C-3 nuance: the
    # legacy chain checked `id` before `finding_id`; the composed chain
    # follows §3.3 (`finding_id` before `id`).
    for key in ("finding_uid", "finding_id", "id", "rule_id", "key"):
        value = finding.get(key)
        if value not in (None, ""):
            return str(value)
    return "UNIDENTIFIED_FINDING_%06d" % (index + 1)


def build_change_intelligence(project_root: str, findings: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
    root = Path(project_root).resolve()
    base = os.environ.get("RSECOPSX_DIFF_BASE", "").strip()
    head = os.environ.get("RSECOPSX_DIFF_HEAD", "").strip()

    if base and head:
        diff_args = ["diff", "--unified=0", "%s...%s" % (base, head), "--"]
        mode = "commit_range"
        comparison = "%s...%s" % (base, head)
    elif base:
        diff_args = ["diff", "--unified=0", base, "--"]
        mode = "base_to_worktree"
        comparison = "%s..WORKTREE" % base
    else:
        diff_args = ["diff", "--unified=0", "HEAD", "--"]
        mode = "HEAD_to_worktree"
        comparison = "HEAD..WORKTREE"

    code, diff_text, diff_err = _run_git(root, diff_args)
    if code != 0:
        return {
            "status": "UNAVAILABLE",
            "reason": "GIT_DIFF_FAILED",
            "git_exit_code": code,
            "git_error": diff_err.strip(),
            "comparison": comparison,
            "mode": mode,
            "files": [],
            "summary": {
                "changed_files": 0,
                "added_lines": 0,
                "removed_lines": 0,
                "added_files": 0,
                "modified_files": 0,
                "deleted_files": 0,
                "renamed_files": 0,
                "findings_on_changed_lines": 0,
                "findings_in_changed_files": 0,
            },
            "read_only": True,
        }

    ns_code, numstat_text, _ = _run_git(root, ["diff", "--numstat", comparison.split("..", 1)[0] if False else "HEAD", "--"])
    # Use the same comparison semantics without trying to reinterpret a range.
    if base and head:
        ns_code, numstat_text, _ = _run_git(root, ["diff", "--numstat", "%s...%s" % (base, head), "--"])
        ns_code2, status_text, _ = _run_git(root, ["diff", "--name-status", "%s...%s" % (base, head), "--"])
    elif base:
        ns_code, numstat_text, _ = _run_git(root, ["diff", "--numstat", base, "--"])
        ns_code2, status_text, _ = _run_git(root, ["diff", "--name-status", base, "--"])
    else:
        ns_code, numstat_text, _ = _run_git(root, ["diff", "--numstat", "HEAD", "--"])
        ns_code2, status_text, _ = _run_git(root, ["diff", "--name-status", "HEAD", "--"])

    numstat: Dict[str, Tuple[int, int]] = {}
    if ns_code == 0:
        for line in numstat_text.splitlines():
            parsed = _parse_numstat(line)
            if parsed:
                path, added, removed = parsed
                numstat[path] = (added, removed)

    files, _ = _parse_zero_context_diff(diff_text)
    if ns_code2 == 0:
        _apply_statuses(files, status_text)
    files = _normalize_files(files, numstat)

    changed_paths = {f["path"] for f in files}
    added_files = sum(1 for f in files if f["status"] == "A")
    modified_files = sum(1 for f in files if f["status"] == "M")
    deleted_files = sum(1 for f in files if f["status"] == "D")
    renamed_files = sum(1 for f in files if f["status"] == "R")

    finding_rows: List[Dict[str, Any]] = []
    changed_line_count = 0
    changed_file_count = 0
    finding_items = list(findings or [])

    added_by_file = {
        f["path"]: set(f["added_lines"]) for f in files
    }

    for index, finding in enumerate(finding_items):
        if not isinstance(finding, dict):
            continue
        path = _finding_path(finding)
        path_norm = path.replace("\\", "/").lstrip("./")
        lines = _finding_lines(finding)
        in_changed_file = path_norm in changed_paths
        changed_lines = sorted(set(lines).intersection(added_by_file.get(path_norm, set())))
        on_changed_line = bool(changed_lines)
        if in_changed_file:
            changed_file_count += 1
        if on_changed_line:
            changed_line_count += 1

        finding_rows.append({
            "finding_id": _finding_id(finding, index),
            "path": path_norm,
            "finding_lines": lines,
            "in_changed_file": in_changed_file,
            "on_added_changed_line": on_changed_line,
            "changed_lines": changed_lines,
            "lifecycle_status": "UNCLASSIFIED_BY_DIFF",
        })

    finding_rows.sort(key=lambda x: (x["path"], x["finding_id"], x["finding_lines"]))
    total_added = sum(f["added_count"] for f in files)
    total_removed = sum(f["removed_count"] for f in files)

    return {
        "status": "AVAILABLE",
        "mode": mode,
        "comparison": comparison,
        "base_ref": base or None,
        "head_ref": head or "WORKTREE",
        "files": files,
        "finding_change_map": finding_rows,
        "summary": {
            "changed_files": len(files),
            "added_files": added_files,
            "modified_files": modified_files,
            "deleted_files": deleted_files,
            "renamed_files": renamed_files,
            "added_lines": total_added,
            "removed_lines": total_removed,
            "findings_on_changed_lines": changed_line_count,
            "findings_in_changed_files": changed_file_count,
        },
        "semantics": {
            "new_regressed_fixed_reintroduced": "NOT_INFERRED",
            "severity_modified": False,
            "classification_modified": False,
            "exploitability_modified": False,
            "decision_modified": False,
        },
        "read_only": True,
    }


def enrich_report_payload_with_change_intelligence(
    payload: Dict[str, Any],
    project_root: str,
) -> Dict[str, Any]:
    payload["change_intelligence"] = build_change_intelligence(
        project_root,
        payload.get("findings", []),
    )
    return payload

