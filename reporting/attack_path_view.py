"""One canonical view over attack-path records, for every renderer.

THE DEFECT THIS FIXES
---------------------
The section WAS published -- babyagi-main's Security_Report.pdf has
"4. Attack Path Correlation" on page 10 and correctly states "the following 8
attack paths were identified" -- but every path rendered as:

    Chain #01   MEDIUM   Risk: 0
    Chain:
    (empty)
    PATTERN-ONLY - Candidate attack path. Manual validation is required

while the artifact held all eight as `attack_path_status: confirmed` with real
source-to-sink nodes, e.g.

    {"path": ["route parameter {function_name}", "function_name",
              "g.functionz.executor.execute"],
     "source": "route parameter {function_name}",
     "sink": "g.functionz.executor.execute",
     "attack_path_status": "confirmed", "evidence_valid": true,
     "rule_id": "TAINT_SQL_INJECTION"}

Three separate wrongnesses, and the third is the serious one:

  1. EMPTY CHAIN. The renderer read `steps`, which the current producer does not
     emit, and defaulted to `[]`.
  2. "Risk: 0". It read `risk_score`, which the current producer does not emit,
     and formatted the default. A fabricated 0 looks like a measurement.
  3. WRONG EVIDENCE LABEL. It read `evidence_type`, defaulting to
     "pattern-detected", so EIGHT TAINT-CONFIRMED paths were labelled
     "PATTERN-ONLY ... Manual validation is required". In a security report that
     understates validated evidence and tells the reader to redo work that was
     already done.

Cause: producer and consumer disagree on the record shape. Old artifacts
(2026-09-23) carry `steps` / `narrative` / `risk_score` / `evidence_type` /
`chains_to`, produced by an earlier pattern-driven implementation. The current
`core/attack_graph.py::get_attack_paths` emits `path` / `source` / `sink` /
`attack_path_status` / `evidence_valid`.

WHY A NORMALISER RATHER THAN "JUST UPDATE THE RENDERER"
-------------------------------------------------------
Both shapes are real and present: three corpus report directories still hold
old-shape artifacts, and the newest hold new-shape ones. A renderer that handles
only one silently empties the other. So every renderer now asks this module for a
canonical view, and the shape is recorded on the view rather than guessed per
renderer. That is the same fix as G-096 applied on the consuming side.

TWO RULES THIS ENCODES, BOTH NON-NEGOTIABLE
-------------------------------------------
  * A confirmed path must never be labelled PATTERN-ONLY. Understating validated
    evidence is as much a false statement as overstating it.
  * An absent risk score must render as absent. "Risk: 0" is a fabricated
    measurement, so the field becomes None and the renderer omits it.
"""
from __future__ import annotations

import re

# Record shapes present in the corpus.
SHAPE_CURRENT = "CURRENT"   # path / source / sink / attack_path_status
SHAPE_LEGACY = "LEGACY"     # steps / narrative / risk_score / evidence_type

CONFIRMED = "CONFIRMED"
CANDIDATE = "CANDIDATE"

# "route parameter {function_name}" -> "route parameter function_name"
_ROUTE_PARAM_BRACES = re.compile(r"\b(route parameter(?:s)?)\s*\{([^{}]*)\}")

_BRACE_FIELDS = ("source", "sink", "narrative")


def _strip_route_param_braces(ap: dict) -> dict:
    """Remove the template-looking braces around a route parameter name.

    Applied to a shallow copy, and to every field a renderer displays, because the
    braces make an observed code identifier read as an unfilled placeholder. A
    placeholder in a CONFIRMED evidence chain is worse than cosmetic: it implies
    the scanner did not identify the source, which is the opposite of what the
    record asserts.
    """
    out = dict(ap)

    for field in _BRACE_FIELDS:
        value = out.get(field)
        if isinstance(value, str) and "{" in value:
            out[field] = _ROUTE_PARAM_BRACES.sub(r"\1 \2", value)

    for field in ("path", "steps"):
        seq = out.get(field)
        if isinstance(seq, (list, tuple)):
            out[field] = [
                _ROUTE_PARAM_BRACES.sub(r"\1 \2", str(x)) if isinstance(x, str) else x
                for x in seq
            ]

    return out


def attack_path_view(ap: dict) -> dict:
    """Normalise one attack-path record into a shape every renderer can read.

    Never invents a chain, a severity, or a score. Anything the record does not
    carry comes back as None so the renderer can omit it instead of formatting a
    default that reads as a measurement.
    """
    ap = ap if isinstance(ap, dict) else {}

    # --- route-parameter brace form ----------------------------------------
    # `scanner/taint_engine.py` used to label a route-parameter source as
    # "route parameter {name}". `name` is already the identifier, so the braces
    # made every rendered surface read "route parameter {function_name}" as an
    # unfilled template placeholder rather than as code -- in the PDF narrative it
    # looked like a bug in the report rather than in the finding. The producer no
    # longer emits it; this strips the form from anything already on disk so the
    # three corpus directories holding pre-fix artifacts read correctly too.
    ap = _strip_route_param_braces(ap)

    # --- shape detection -------------------------------------------------
    has_current = bool(ap.get("path")) or bool(ap.get("source")) or bool(ap.get("sink"))
    has_legacy = bool(ap.get("steps")) or bool(ap.get("chains_to"))
    shape = SHAPE_CURRENT if has_current else (SHAPE_LEGACY if has_legacy else SHAPE_CURRENT)

    # --- chain -----------------------------------------------------------
    chain = []
    if isinstance(ap.get("path"), (list, tuple)):
        chain = [str(x) for x in ap["path"] if x is not None and str(x).strip()]
    elif isinstance(ap.get("steps"), (list, tuple)):
        chain = [str(x) for x in ap["steps"] if x is not None and str(x).strip()]
    if not chain and ap.get("source") and ap.get("sink"):
        # Salvage the two endpoints if `path` was absent. Still observed nodes,
        # not an inferred edge: both were explicitly recorded.
        chain = [str(ap["source"]), str(ap["sink"])]

    # --- evidence status --------------------------------------------------
    # `attack_path_status` / `evidence_valid` are authoritative when present.
    # `evidence_type` is the legacy field. A confirmed current-shape record must
    # never fall back to PATTERN-ONLY.
    status = None
    if str(ap.get("attack_path_status") or "").strip():
        status = (CONFIRMED
                  if str(ap.get("attack_path_status")).strip().lower() == "confirmed"
                  else CANDIDATE)
    elif ap.get("evidence_valid") is True:
        status = CONFIRMED
    elif str(ap.get("evidence_type") or "").strip():
        status = (CONFIRMED
                  if str(ap["evidence_type"]).strip().lower() == "taint-confirmed"
                  else CANDIDATE)
    elif has_legacy:
        status = CANDIDATE

    # --- severity and risk --------------------------------------------------
    # Absent stays None. `ap.get('risk_score', 0)` is how a fabricated 0 reached
    # a report.
    risk = ap.get("risk_score")
    risk = risk if isinstance(risk, (int, float)) else None

    severity = ap.get("severity") or ap.get("severity_display") or None

    title = ap.get("title") or ""
    rule_id = ap.get("rule_id") or ""
    if not title:
        if rule_id:
            title = f"Attack Path: {rule_id}"
        elif chain:
            title = f"Attack Path: {chain[-1]}"
        else:
            title = "Attack Path"

    return {
        "shape": shape,
        "chain": chain,
        "source": ap.get("source") or (chain[0] if chain else None),
        "sink": ap.get("sink") or (chain[-1] if chain else None),
        "chains_to": [str(x) for x in (ap.get("chains_to") or [])],
        "status": status,
        "confirmed": status == CONFIRMED,
        "severity": severity,
        "risk_score": risk,
        "title": title,
        "rule_id": rule_id,
        # B3-ID Phase B Wave 2 (contract §6.2 #6): uid-preferred; legacy tail retained.
        "finding_id": (ap.get("finding_uid") or ap.get("finding_id")
                       or ap.get("id") or ""),
        "file": ap.get("file") or "",
        "line": ap.get("line") or "",
        "narrative": ap.get("narrative") or "",
        "evidence_note": ap.get("evidence_note") or "",
        "evidence_valid": ap.get("evidence_valid"),
    }


def attack_path_views(paths) -> list:
    return [attack_path_view(p) for p in (paths or []) if isinstance(p, dict)]


def evidence_label(view: dict) -> str:
    """Render the evidence state from the view, never from a defaulted field.

    The distinction matters more than the wording: a taint-confirmed path must
    not tell the reader that manual validation is still required.
    """
    if view.get("status") == CONFIRMED:
        return ("CONFIRMED - Source-to-sink evidence validated by the finding's "
                "own taint path.")
    if view.get("status") == CANDIDATE:
        return ("PATTERN-ONLY - Candidate attack path. Manual validation is "
                "required before exploitability is established.")
    return ("STATUS NOT RECORDED - this record carries no evidence state. It is "
            "neither confirmed nor asserted to be a candidate.")


def introduction(views) -> str:
    """Lead paragraph, derived from the actual mix rather than asserted."""
    views = list(views or [])
    if not views:
        return ""
    n_conf = sum(1 for v in views if v.get("status") == CONFIRMED)
    n_cand = sum(1 for v in views if v.get("status") == CANDIDATE)
    n_unk = len(views) - n_conf - n_cand
    plural = "s were" if len(views) > 1 else " was"

    parts = [f"The following {len(views)} attack path{plural} identified by "
             f"correlating vulnerability findings into exploit chains."]
    if n_conf and n_cand:
        parts.append(
            f"{n_conf} carry validated source-to-sink evidence and are CONFIRMED; "
            f"{n_cand} are pattern-level candidates requiring manual validation.")
    elif n_conf:
        parts.append(
            f"All {n_conf} carry validated source-to-sink evidence and are "
            f"CONFIRMED. No manual validation is required for reachability; "
            f"exploitability in a live environment is a separate question.")
    elif n_cand:
        parts.append(
            f"All {n_cand} are pattern-level candidates. Manual validation is "
            f"required before exploitability is established.")
    if n_unk:
        parts.append(
            f"{n_unk} carry no recorded evidence state and are neither confirmed "
            f"nor asserted to be candidates.")
    return " ".join(parts)


def shape_mix(views) -> dict:
    """Record-shape census, so a renderer change cannot silently break one."""
    views = list(views or [])
    return {
        "total": len(views),
        "by_shape": {
            SHAPE_CURRENT: sum(1 for v in views if v["shape"] == SHAPE_CURRENT),
            SHAPE_LEGACY: sum(1 for v in views if v["shape"] == SHAPE_LEGACY),
        },
        "confirmed": sum(1 for v in views if v["status"] == CONFIRMED),
        "candidate": sum(1 for v in views if v["status"] == CANDIDATE),
        "no_evidence_state": sum(1 for v in views if v["status"] is None),
        "with_chain": sum(1 for v in views if v["chain"]),
        "with_risk_score": sum(1 for v in views if v["risk_score"] is not None),
        "with_severity": sum(1 for v in views if v["severity"]),
    }