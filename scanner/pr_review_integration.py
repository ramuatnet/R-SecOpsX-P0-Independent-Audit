"""
Feature 13 — Inline PR Finding / Review Integration.

Creates deterministic review comments as structured data. It does not call a
remote SCM API and does not post comments automatically.
"""
from __future__ import annotations
from typing import Any, Dict

def enrich_pr_review_integration(payload: Dict[str, Any]) -> Dict[str, Any]:
    rows=[]
    changed=(payload.get("changed_line_security") or {}).get("findings",[]) or []
    for row in changed:
        if not isinstance(row,dict) or not row.get("on_changed_line"):
            continue
        fid=str(row.get("finding_uid") or row.get("finding_id") or "UNIDENTIFIED_FINDING")
        path=str(row.get("path") or "")
        lines=row.get("changed_lines") or []
        rows.append({
            "comment_id":"PR-COMMENT-"+fid,
            "finding_id":fid,
            "path":path,
            "lines":lines,
            "review_comment":"Security finding detected on changed code; review the finding evidence before merge.",
            "posting_performed":False,
            "human_review_required":True,
        })
    rows.sort(key=lambda x:(x["path"],x["comment_id"]))
    payload["pr_review_integration"]={
        "status":"AVAILABLE",
        "review_comments":rows,
        "summary":{"candidate_comments":len(rows),"comments_posted":0},
        "read_only":True,
        "remote_api_called":False,
        "automatic_posting":False,
    }
    return payload
