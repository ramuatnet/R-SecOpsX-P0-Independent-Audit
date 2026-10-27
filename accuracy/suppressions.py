"""User-controlled suppression mechanisms for the accuracy layer.

Three mechanisms, each logged in the audit output with its source:

  1. Inline:   ``// sast-ignore RULE_ID reason`` (also ``#`` for Python)
               within +/- 2 lines of the finding.
  2. File:     ``.sastignore`` at the target root, gitignore-style:
               ``RULE_ID`` or ``path/glob`` per line; comments with ``#``.
  3. Baseline: ``baseline/sast_baseline.json`` mapping rule_id -> list of
               {file, line} entries; matching findings are known/accepted.

A suppressed finding is never deleted: it keeps its verdict
(SUPPRESSED_USER / SUPPRESSED_KNOWN), reason and confidence in the audit.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_INLINE = re.compile(
    r"(?://|#|--)\s*sast-ignore\s+([A-Za-z0-9_\-,*\s]+?)(?:\s+(.+))?$",
    re.IGNORECASE)
_BASELINE_FILE = "baseline/sast_baseline.json"


def _inline_ignores(file_text: str | None, line_no: int | None
                    ) -> list[tuple[str, str]]:
    """(rule_id_or_glob, reason) within +/- 2 lines of the finding."""
    if not file_text or not line_no:
        return []
    lines = file_text.splitlines()
    lo = max(0, line_no - 3)
    hi = min(len(lines), line_no + 2)
    out = []
    for i in range(lo, hi):
        m = _INLINE.search(lines[i])
        if m:
            out.append((m.group(1).strip(), (m.group(2) or "user request")))
    return out


def _load_sastignore(target: str | None) -> list[str]:
    if not target:
        return []
    p = Path(target) / ".sastignore"
    if not p.is_file():
        return []
    rules = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(line)
    return rules


def _matches_ignore(rule_id: str, file_path: str, patterns: list[str]
                    ) -> str | None:
    for pat in patterns:
        if pat == rule_id:
            return "matched .sastignore rule %s" % pat
        base = Path(file_path).as_posix()
        if pat.endswith("/") and base.startswith(pat):
            return "matched .sastignore path %s" % pat
        if pat in file_path or pat in base:
            return "matched .sastignore substring %s" % pat
    return None


def _load_baseline(target: str | None) -> dict:
    if not target:
        return {}
    p = Path(target) / _BASELINE_FILE
    if not p.is_file():
        # Also accept a repo-root baseline/ directory layout.
        alt = Path(target).parent / _BASELINE_FILE
        if alt.is_file():
            p = alt
        else:
            return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def suppression_check(finding: dict, target: str | None,
                      file_text: str | None) -> tuple[str, str] | None:
    """(verdict, reason) if a user mechanism suppresses this finding."""
    rid = str(finding.get("rule_id") or "")
    fpath = str(finding.get("file") or "")
    line_no = finding.get("line") if isinstance(finding.get("line"), int) \
        else None

    for pat, reason in _inline_ignores(file_text, line_no):
        if pat == "*" or pat == rid:
            return ("SUPPRESSED_USER", "inline sast-ignore (%s)" % reason)

    ignore_rules = _load_sastignore(target)
    hit = _matches_ignore(rid, fpath, ignore_rules)
    if hit:
        return ("SUPPRESSED_USER", hit)

    baseline = _load_baseline(target)
    entries = baseline.get(rid) or []
    for e in entries:
        if not isinstance(e, dict):
            continue
        entry_file = Path(str(e.get("file") or "??")).as_posix()
        finding_file = Path(fpath).as_posix()
        if finding_file.endswith(entry_file) and (
                e.get("line") in (None, line_no)):
            return ("SUPPRESSED_KNOWN",
                    "known finding in baseline (accepted by the team)")
    return None


__all__ = ["suppression_check"]
