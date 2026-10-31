"""T-7.1: scoring service -- score = f(base, modifiers, feedback).

Headline (task.md PHASE 7):

  base          = CVSS4.  Vectors go through the official FIRST
                  calculator (scanner.cvss4).  Findings without a
                  vector fall back to an explicit numeric cvss_score,
                  then to a DISCLOSED severity-default table -- never
                  a silent guess (base.source says which path ran).
  modifiers     = eight signed, bounded factors in fixed spec order:
                  reachability, internet_exposure, verification, kev,
                  epss, age, control_gaps, blast_radius.
  feedback      = triage outcome (tp/fp/wontfix) as a signed delta.

  Deterministic.  Explainable.  Every score emits ALL eight per-factor
  signed contributions (zero deltas included) plus the feedback row;
  raw = base + sum(contributions) + feedback; score = round(clamp(raw,
  0, 10), 1).  clamp + rounding are monotone, which is what the
  monotonicity tests lean on: REPRODUCED (+1.0 over unverified) can
  never lower a score, unreachable (-1.0) can never raise one.

Caps (MAX_FINDINGS) surface as skip rows, never silent drops.
Pure stdlib + scanner.cvss4; no I/O in this module.
"""
from __future__ import annotations

from datetime import datetime, timezone

from scanner.cvss4 import cvss_v4_base_score

SCHEMA = "rsecopsx.score/v1"
MAX_FINDINGS = 5000

# Disclosed severity fallback (base.source == "severity_default").
SEVERITY_BASE = {"critical": 9.0, "high": 7.5, "medium": 4.5,
                 "low": 2.0, "info": 0.0, "none": 0.0}

# Fixed spec order -- deterministic and matches task.md's listing
# (reachability, internet exposure, verification status, KEV, EPSS,
# age, control gaps, blast radius).
FACTOR_ORDER = ("reachability", "internet_exposure", "verification",
                "kev", "epss", "age", "control_gaps", "blast_radius")

_VERIFICATION_KNOWN = ("reproduced", "unverified", "disproven")
_BLAST_RADIUS = {"none": 0.0, "local": 0.5, "service": 1.0,
                 "data": 1.5}


def band_of(value: float) -> str:
    """Severity band for a 0..10 score."""
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value >= 0.1:
        return "low"
    return "none"


def _as_dt(value, default_now: bool = True) -> datetime:
    """Normalize as_of (datetime | ISO string) to aware UTC."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    elif value is None and default_now:
        dt = datetime.now(timezone.utc)
    else:
        raise ValueError(f"unparseable as_of: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_when(value) -> tuple[datetime | None, str | None]:
    """Parse a timestamp field -> (datetime, note-on-failure)."""
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt, None
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None, "unparseable_first_seen"
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt, None
    return None, "unparseable_first_seen" if value is not None else None


def _cvss4(vector: str) -> float | None:
    try:
        return cvss_v4_base_score(vector)
    except Exception:  # malformed vector must never raise
        return None


def _base_of(finding: dict) -> dict:
    """base = CVSS4 vector -> explicit numeric score -> severity.

    Every path discloses itself in base.source; failed vectors and
    unknown severities carry a note (invalid_vector beats
    unknown_severity when both apply).
    """
    note = None
    vec = finding.get("cvss_vector")
    if isinstance(vec, str) and vec:
        val = _cvss4(vec)
        if val is not None:
            return {"source": "cvss4_vector", "vector": vec,
                    "value": float(val)}
        note = "invalid_vector"
    elif vec is not None:
        note = "invalid_vector"
    score = finding.get("cvss_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        row = {"source": "cvss_score", "value": float(score)}
        if note:
            row["note"] = note
        return row
    sev = finding.get("severity")
    key = sev.strip().lower() if isinstance(sev, str) else None
    if key in SEVERITY_BASE:
        row = {"source": "severity_default",
               "value": SEVERITY_BASE[key]}
        if note:
            row["note"] = note
        return row
    row = {"source": "severity_default", "value": 0.0,
           "note": note or "unknown_severity"}
    return row


# -- the eight modifier families (signed, bounded, explained) -------------

def _c_reachability(ctx: dict) -> dict:
    val = ctx.get("reachable")
    if isinstance(val, bool):
        return {"factor": "reachability", "delta": 1.0 if val else -1.0,
                "detail": {"reachable": val}}
    return {"factor": "reachability", "delta": 0.0,
            "detail": {"reachable": None}}


def _c_exposure(ctx: dict) -> dict:
    val = ctx.get("internet_exposed")
    if isinstance(val, bool):
        return {"factor": "internet_exposure",
                "delta": 1.5 if val else 0.0,
                "detail": {"internet_exposed": val}}
    return {"factor": "internet_exposure", "delta": 0.0,
            "detail": {"internet_exposed": None}}


def _c_verification(ctx: dict) -> dict:
    raw = ctx.get("verification")
    if not (isinstance(raw, str) and raw.strip()):
        return {"factor": "verification", "delta": 0.0,
                "detail": {"verification": None}}
    val = raw.strip().lower()
    if val == "reproduced":
        return {"factor": "verification", "delta": 1.0,
                "detail": {"verification": val}}
    if val == "disproven":
        return {"factor": "verification", "delta": -3.0,
                "detail": {"verification": val}}
    detail = {"verification": val}
    if val not in _VERIFICATION_KNOWN:
        detail["note"] = "unknown_verification"
    return {"factor": "verification", "delta": 0.0, "detail": detail}


def _c_kev(ctx: dict) -> dict:
    val = ctx.get("kev")
    if val is True or (isinstance(val, (list, tuple)) and val):
        detail = {"kev": True}
        if isinstance(val, (list, tuple)):
            detail["count"] = len(val)
        return {"factor": "kev", "delta": 2.0, "detail": detail}
    return {"factor": "kev", "delta": 0.0, "detail": {"kev": False}}


def _c_epss(ctx: dict) -> dict:
    val = ctx.get("epss")
    if not (isinstance(val, (int, float)) and not isinstance(val, bool)):
        return {"factor": "epss", "delta": 0.0,
                "detail": {"epss": None}}
    clamped = min(1.0, max(0.0, float(val)))
    detail = {"epss": clamped}
    if clamped != float(val):
        detail["note"] = "clamped"
    return {"factor": "epss", "delta": round(clamped * 2.0, 2),
            "detail": detail}


def _c_age(ctx: dict, as_of: datetime) -> dict:
    when = ctx.get("first_seen")
    if when is None:
        return {"factor": "age", "delta": 0.0,
                "detail": {"days": None,
                           "note": "missing_first_seen"}}
    first, note = _parse_when(when)
    if first is None:
        return {"factor": "age", "delta": 0.0,
                "detail": {"days": None, "note": note}}
    delta_days = (as_of - first).days
    if delta_days < 0:
        return {"factor": "age", "delta": 0.0,
                "detail": {"days": 0, "note": "future_first_seen"}}
    delta = round(-min(2.0, delta_days * 2.0 / 180.0), 2)
    return {"factor": "age", "delta": delta, "detail": {"days": delta_days}}


def _c_control_gaps(ctx: dict) -> dict:
    val = ctx.get("control_gaps")
    if isinstance(val, bool):
        count = 0
    elif isinstance(val, int):
        count = max(0, val)
    elif isinstance(val, (list, tuple)):
        count = len(val)
    else:
        count = 0
    delta = min(1.5, 0.5 * count)
    detail = {"gaps": count}
    if count > 3:
        detail["capped"] = True
    return {"factor": "control_gaps", "delta": float(delta),
            "detail": detail}


def _c_blast_radius(ctx: dict) -> dict:
    val = ctx.get("blast_radius")
    if not (isinstance(val, str) and val.strip()):
        return {"factor": "blast_radius", "delta": 0.0,
                "detail": {"blast_radius": None}}
    key = val.strip().lower()
    if key in _BLAST_RADIUS:
        return {"factor": "blast_radius", "delta": _BLAST_RADIUS[key],
                "detail": {"blast_radius": key}}
    return {"factor": "blast_radius", "delta": 0.0,
            "detail": {"blast_radius": key,
                       "note": "unknown_blast_radius"}}


def _feedback_of(feedback: dict) -> dict:
    """Triage outcome -> signed delta (T-7.2 adds decay machinery)."""
    raw = feedback.get("triage")
    if not (isinstance(raw, str) and raw.strip()):
        return {"delta": 0.0, "detail": {"triage": None}}
    val = raw.strip().lower()
    if val == "fp":
        return {"delta": -2.0, "detail": {"triage": val}}
    if val == "tp":
        return {"delta": 0.5, "detail": {"triage": val}}
    detail = {"triage": val}
    if val == "wontfix":
        detail["note"] = "wontfix_no_score_change"
    else:
        detail["note"] = "unknown_triage"
    return {"delta": 0.0, "detail": detail}


def score_finding(finding: dict, context: dict | None = None,
                  feedback: dict | None = None,
                  as_of: datetime | str | None = None) -> dict:
    """Score ONE finding; emit the full explain row.

    Row keys (stable): rule_id, score, band, base, contributions
    (all eight factors, fixed order, signed deltas), feedback, raw,
    clamped.  finding["score_context"]/["score_feedback"] override
    the shared defaults, so per-finding state travels with the row.
    """
    as_dt = _as_dt(as_of)
    shared_ctx = context if isinstance(context, dict) else {}
    shared_fb = feedback if isinstance(feedback, dict) else {}
    row_ctx = finding.get("score_context")
    if not isinstance(row_ctx, dict):
        row_ctx = {}
    row_fb = finding.get("score_feedback")
    if not isinstance(row_fb, dict):
        row_fb = {}
    ctx = {**shared_ctx, **row_ctx}
    fb = {**shared_fb, **row_fb}

    base = _base_of(finding)
    contribs = [
        _c_reachability(ctx),
        _c_exposure(ctx),
        _c_verification(ctx),
        _c_kev(ctx),
        _c_epss(ctx),
        _c_age(ctx, as_dt),
        _c_control_gaps(ctx),
        _c_blast_radius(ctx),
    ]
    # emission order == spec order (fixed tuple, fully deterministic)
    order = {name: i for i, name in enumerate(FACTOR_ORDER)}
    contribs.sort(key=lambda c: order[c["factor"]])
    fb_row = _feedback_of(fb)

    raw = round(float(base["value"])
                + sum(c["delta"] for c in contribs)
                + fb_row["delta"], 2)
    clamped = raw < 0.0 or raw > 10.0
    final = round(min(10.0, max(0.0, raw)), 1)
    return {
        "rule_id": str(finding.get("rule_id") or ""),
        "score": final,
        "band": band_of(final),
        "base": base,
        "contributions": contribs,
        "feedback": fb_row,
        "raw": raw,
        "clamped": clamped,
    }


def _extract_rows(payload) -> tuple[list, dict | None]:
    if isinstance(payload, list):
        return payload, None
    if isinstance(payload, dict):
        if isinstance(payload.get("findings"), list):
            return payload["findings"], None
        # a bare object is one finding row (CLI --finding help)
        return [payload], None
    return [], {"stage": "scoring", "target": "findings",
                "reason": "bad_findings_shape", "detail": {}}


def score_findings(payload, context: dict | None = None,
                   feedback: dict | None = None,
                   as_of: datetime | str | None = None,
                   explain: bool = True) -> dict:
    """Score a batch -> artifact {schema, as_of, scores, skips, stats}.

    explain=True keeps the full contribution rows (default -- callers
    and the --explain-score CLI path); explain=False compacts each row
    to {rule_id, score, band}.  Non-dict rows and over-cap batches
    become machine-readable skips, never silent drops.
    """
    as_dt = _as_dt(as_of)
    rows, shape_skip = _extract_rows(payload)
    skips: list[dict] = []
    if shape_skip is not None:
        skips.append(shape_skip)
        rows = []
    bad = [r for r in rows if not isinstance(r, dict)]
    if bad:
        skips.append({"stage": "scoring", "target": "findings",
                      "reason": "finding_rows_not_objects",
                      "detail": {"count": len(bad)}})
        rows = [r for r in rows if isinstance(r, dict)]
    if len(rows) > MAX_FINDINGS:
        skips.append({"stage": "scoring", "target": "findings",
                      "reason": f"cap_findings_{MAX_FINDINGS}",
                      "detail": {"total": len(rows)}})
        rows = rows[:MAX_FINDINGS]
    scores = []
    for row in rows:
        full = score_finding(row, context=context, feedback=feedback,
                             as_of=as_dt)
        if explain:
            scores.append(full)
        else:
            scores.append({"rule_id": full["rule_id"],
                           "score": full["score"],
                           "band": full["band"]})
    skips.sort(key=lambda s: (str(s.get("stage", "")),
                              str(s.get("target", "")),
                              str(s.get("reason", ""))))
    return {
        "schema": SCHEMA,
        "as_of": as_dt.isoformat(),
        "scores": scores,
        "skips": skips,
        "stats": {"scored": len(scores), "skips": len(skips)},
    }
