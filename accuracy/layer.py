"""Accuracy layer orchestrator.

apply_accuracy_layer(payload, target) runs AFTER the UFIB stage and BEFORE
reporting. It never removes findings: every finding gets an ``accuracy``
block (verdict, confidence, reason, checks) and the payload gains a
``accuracy`` section with the filtered list (finding ids) and the full audit
list. Zero silent loss holds here too.

Legacy equivalence: with RSECOPSX_ACCURACY_LAYER=0 the function returns the
payload untouched (asserted by the snapshot regression test).
"""
from __future__ import annotations

import re
from pathlib import Path

from accuracy.config import (
    ACCURACY_SCHEMA,
    CONFIDENCE,
    POLICY_VERSION,
    filtered_include_needs_review,
    layer_enabled,
    context_window,
)
from accuracy import validators as V
from accuracy import suppressions as S

# UFIB verdicts -> accuracy verdicts (never the reverse).
_UFIB_MAP = {
    "CONFIRMED": "TRUE_POSITIVE",
    "LIKELY": "NEEDS_REVIEW",
    "NEEDS_REVIEW": "NEEDS_REVIEW",
    "INSUFFICIENT_EVIDENCE": "NEEDS_REVIEW",
    "REJECTED_FALSE_POSITIVE": "LIKELY_FALSE_POSITIVE",
    "SUPPRESSED": "SUPPRESSED_USER",
    "DUPLICATE": "DUPLICATE",
    "ANALYSIS_ERROR": "NEEDS_REVIEW",
}

# Findings whose evidence is provenance metadata rather than source.
_CONTENT_EXPORT = re.compile(r"result\.json|SASTSBOMSCA", re.IGNORECASE)


def _window_text(finding: dict, target: str | None) -> tuple[str, str | None]:
    """(window text, file text). Bounded and cached."""
    file_text = None
    try:
        from analysis.ufib_brain import read_source
        file_text = read_source(finding.get("file"), target)
    except Exception:
        file_text = None
    line_no = finding.get("line") if isinstance(finding.get("line"), int) \
        else None
    if file_text is None:
        return (str(finding.get("snippet") or "") +
                str(finding.get("evidence") or "")), None
    lines = file_text.splitlines()
    ctx = context_window()
    if line_no and 1 <= line_no <= len(lines):
        lo = max(0, line_no - 1 - ctx)
        hi = min(len(lines), line_no + ctx)
        return "\n".join(lines[lo:hi]), file_text
    return file_text[:20000], file_text


def _decide(finding: dict, hints: list, ufib_verdict: str) -> tuple[str, int, str]:
    """Combine validator hints with the UFIB verdict. The LOWEST confidence
    wins (false-negative-safe: a suppression needs a specific logged reason,
    everything else stays visible). User suppressions win unconditionally."""
    verdict = _UFIB_MAP.get(ufib_verdict, "NEEDS_REVIEW")
    conf = CONFIDENCE.get(verdict, 40)
    reasons = ["ufib verdict: %s" % ufib_verdict]

    for v, delta, reason in hints:
        # The reason always lands in the audit; only a verdict opinion
        # changes the verdict (None = the validator abstained).
        reasons.append(reason)
        if v is None:
            continue
        conf += delta
        if v in ("SUPPRESSED_USER", "SUPPRESSED_KNOWN"):
            # A user decision outranks every validator (mission: suppress
            # only via explicit, logged mechanisms).
            return v, CONFIDENCE.get(v, 5), " | ".join(reasons)
        rank = {"TRUE_POSITIVE": 4, "NEEDS_REVIEW": 3,
                "LIKELY_FALSE_POSITIVE": 1, "MISLABELED": 2}
        cur_rank = rank.get(verdict, 3)
        new_rank = rank.get(v, 3)
        if new_rank < cur_rank:
            verdict = v
    conf = max(0, min(100, conf))
    return verdict, conf, " | ".join(reasons)


def apply_accuracy_layer(payload: dict, target: str | None = None) -> dict:
    """Attach accuracy verdicts and the filtered/audit sections. Additive
    only; with the layer disabled this is a no-op."""
    if not layer_enabled():
        payload.setdefault("metadata", {})[
            "accuracy_layer"] = "disabled (legacy output)"
        return payload

    findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
    filtered_ids: list[str] = []
    audit: list[dict] = []
    by_key: dict[tuple, list[dict]] = {}
    include_review = filtered_include_needs_review()

    for f in findings:
        window, file_text = _window_text(f, target)
        line_no = f.get("line") if isinstance(f.get("line"), int) else None
        hints: list[tuple] = []

        # User suppression first -- it wins over everything.
        sup = S.suppression_check(f, target, file_text)
        if sup:
            hints.append((sup[0], -80, sup[1]))
        else:
            v = V.minified_check(f, file_text)
            if v:
                hints.append(v)
            v = V.layer_gate(f)
            if v:
                hints.append(v)
            # Context-dependent validators (sink consistency, mitigation)
            # ABSTAIN when the source file cannot be read: the finding's
            # own text may be a summary line, not the construct. The VA
            # run proved this failure mode -- rejecting without context
            # produced 0 TRUE_POSITIVE on a real scan. The UFIB verdict
            # remains the floor in that case.
            if file_text is not None:
                v = V.sink_consistency(f, window)
                if v:
                    hints.append(v)
                v = V.mitigation_check(f, window)
                if v:
                    hints.append(v)
                v = V.upload_check(f, window)
                if v:
                    hints.append(v)
            else:
                hints.append((None, 0,
                              "source file unreadable; context validators "
                              "abstained (UFIB verdict stands)"))
            v = V.absence_check(f, window)
            if v:
                hints.append(v)
            v = V.secret_check(f, window)
            if v:
                hints.append(v)

        verdict, conf, reason = _decide(
            f, hints, str(f.get("disposition") or "NEEDS_REVIEW"))

        # Never TRUE_POSITIVE without a traced path (mission working rule).
        if verdict == "TRUE_POSITIVE":
            tstate = V.taint_confirm(f, file_text, line_no)
            if tstate in (None, "unconfirmed"):
                verdict = "NEEDS_REVIEW"
                reason += (" | no traced source-to-sink path in evidence; "
                           "capped at NEEDS_REVIEW")
            elif tstate == "confirmed_filescope":
                reason += " | source boundary confirmed in-file"

        # Dedup: keep the first occurrence, mark later ones.
        key = V.dedup_key(f)
        f.setdefault("accuracy", {
            "schema": ACCURACY_SCHEMA,
            "policy_version": POLICY_VERSION,
        })
        acc = f["accuracy"]
        acc.update({
            "verdict": verdict,
            "confidence": conf,
            "reason": reason,
        })
        if key in by_key:
            acc["verdict"] = "DUPLICATE"
            acc["reason"] = ("duplicate of an earlier finding with the same "
                             "file+line+rule (kept in audit)")
            acc["confidence"] = 0
            verdict = "DUPLICATE"
            conf = 0
        by_key.setdefault(key, []).append(f)

        fid = str(f.get("finding_uid") or  # B3-ID Wave 2 prepend (contract §6.2 #10)
                  f.get("finding_id") or f.get("group_key") or
                  "%s|%s|%s" % (f.get("rule_id"), f.get("file"), f.get("line")))
        audit.append({
            "finding_id": fid,
            "rule_id": f.get("rule_id"),
            "file": f.get("file"),
            "line": f.get("line"),
            "verdict": verdict,
            "confidence": conf,
            "reason": reason,
        })
        if verdict == "TRUE_POSITIVE" or (
                include_review and verdict == "NEEDS_REVIEW"):
            filtered_ids.append(fid)

    # Provenance-only exports (scanner output inside the tree) are audit-only.
    for f in findings:
        fname = str(f.get("file") or "")
        if _CONTENT_EXPORT.search(fname):
            f.setdefault("accuracy", {})["verdict"] = "LIKELY_FALSE_POSITIVE"
            f["accuracy"]["reason"] = ("finding source is a scanner-result "
                                       "export, not application source")
            fid = str(f.get("finding_id") or f.get("group_key") or
                      "%s|%s" % (f.get("rule_id"), f.get("file")))
            if fid in filtered_ids:
                filtered_ids.remove(fid)

    payload["accuracy"] = {
        "schema": ACCURACY_SCHEMA,
        "policy_version": POLICY_VERSION,
        "flag": "RSECOPSX_ACCURACY_LAYER",
        "filtered_finding_ids": filtered_ids,
        "filtered_count": len(filtered_ids),
        "audit": audit,
        "counts": {
            v: sum(1 for a in audit if a["verdict"] == v)
            for v in sorted({a["verdict"] for a in audit})
        },
    }
    meta = payload.setdefault("metadata", {})
    meta["accuracy_summary"] = {
        "total": len(findings),
        "filtered": len(filtered_ids),
        "verdicts": payload["accuracy"]["counts"],
    }
    return payload
