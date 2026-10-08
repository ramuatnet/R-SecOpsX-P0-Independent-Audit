"""
core/risk_scorer.py  v4

FIX LOG (v3 v4):
  1. BUG   score_finding() now clamps individual scores to 100.0 (previously
             only compute_portfolio_score() clamped at portfolio level)
  2. BUG   intermediate raw_score computed once and reused in both the final
             score and the explanation string    eliminates any divergence
  3. MAP   debug_exposure added to SENSITIVE_DATA_VULNS and INTERNET_FACING_VULNS:
             Flask debugger is web-accessible and exposes source code + console
"""
from __future__ import annotations
from core.config import RISK_MODEL

SCORING_MODEL_DESCRIPTION = {
    "model":   RISK_MODEL,
    "scale":   "100 (higher = more risk)",
    "factors": {
        "severity":         "Base severity (Critical=10, High=7, Medium=4, Low=2)",
        "exploitability":   "Ease of exploitation (High=9, Medium=5, Low=2)",
        "data_sensitivity": "Sensitivity of data at risk (8 for data-exposing vulns)",
        "exposure":         "Internet-accessible attack surface (8 for web vulns)",
        "privilege":        "Privilege required to exploit (8 if unauthenticated)",
        "confidence":       "Taint analysis confidence (High=1.0—, Medium=0.85—, Low=0.70—)",
    },
    "weights": {
        "severity":         "30%",
        "exploitability":   "25%",
        "data_sensitivity": "20%",
        "exposure":         "15%",
        "privilege":        "10%",
    },
    "portfolio_method": "70% — avg(top-3 scores) + 30% — overall average",
}

WEIGHTS = {
    "severity":         0.30,
    "exploitability":   0.25,
    "data_sensitivity": 0.20,
    "exposure":         0.15,
    "privilege":        0.10,
}

SEVERITY_SCORE      = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Info": 1}
EXPLOITABILITY_SCORE = {"High": 9, "Medium": 5, "Low": 2, "None": 1}
CONFIDENCE_MULTIPLIER = {"High": 1.0, "Medium": 0.85, "Low": 0.70, "": 0.85}

# FIX #3: debug_exposure added to both sets.
# Flask debug=True is internet-facing (web-accessible debugger) and exposes
# sensitive data (source code, env vars, application internals).
SENSITIVE_DATA_VULNS: frozenset[str] = frozenset({
    "sql_injection", "hardcoded_secret", "sensitive_logging",
    "path_traversal", "auth_bypass", "debug_exposure",
})

INTERNET_FACING_VULNS: frozenset[str] = frozenset({
    "sql_injection", "xss", "open_redirect", "command_injection",
    "code_injection", "auth_bypass", "csrf", "debug_exposure",
})

LOW_PRIVILEGE_VULNS: frozenset[str] = frozenset({
    "xss", "open_redirect", "sql_injection", "command_injection",
    "code_injection", "csrf",
})


def score_finding(finding: dict) -> dict:
    """
    Score a single finding using the 6-factor weighted model.
    Returns a NEW dict (copy of finding) with risk_score and score_breakdown added.

    FIX #1: individual score clamped to 100.0 (not just portfolio total).
    FIX #2: raw_score computed once, reused in both final score and explanation.
    """
    result = dict(finding)  # non-mutating copy

    vuln_type  = result.get("vuln_type", "")
    sev        = result.get("severity", "Medium")
    expl_str   = str(result.get("exploitability", "Medium") or "Medium").title()
    if expl_str not in EXPLOITABILITY_SCORE:
        expl_str = "Medium"
    # V17.9.1: canonical exploitability value is the sole source of the score factor.
    result["exploitability"] = expl_str
    confidence = str(result.get("confidence", "Medium") or "Medium").title()

    fs = SEVERITY_SCORE.get(sev, 4)
    fe = EXPLOITABILITY_SCORE[expl_str]
    fd = 8 if vuln_type in SENSITIVE_DATA_VULNS else 4
    fx = 8 if vuln_type in INTERNET_FACING_VULNS else 3
    fp = 8 if vuln_type in LOW_PRIVILEGE_VULNS else 4

    raw       = fs * 0.30 + fe * 0.25 + fd * 0.20 + fx * 0.15 + fp * 0.10
    raw_score = round((raw / 10) * 100, 1)   # FIX #2: computed once
    cm        = CONFIDENCE_MULTIPLIER.get(confidence, 0.85)
    score     = min(100.0, round(raw_score * cm, 1))  # FIX #1: clamp here

    category = (
        "Critical" if score >= 75 else
        "High"     if score >= 50 else
        "Medium"   if score >= 25 else
        "Low"
    )

    result["risk_score"]    = score
    result["risk_category"] = category
    result["score_breakdown"] = {
        "severity_factor":        fs,
        "exploitability_factor":  fe,
        "data_sensitivity_factor": fd,
        "exposure_factor":        fx,
        "privilege_factor":       fp,
        "confidence_multiplier":  cm,
        "final_score":            score,
        "explanation": (
            f"Severity({sev}={fs})—30% + Exploitability({expl_str}={fe})—25% + "
            f"DataSensitivity({fd})—20% + Exposure({fx})—15% + Privilege({fp})—10% "
            f"= {raw:.2f}/10 †’ {raw_score} — {cm} confidence = {score}"
        ),
    }
    return result


def compute_portfolio_score(findings: list[dict]) -> float:
    """
    Portfolio score: 70% weight on the top-3 findings, 30% on overall average.
    Findings should already be scored by score_finding().
    """
    if not findings:
        return 0.0
    scores = sorted([f.get("risk_score", 0) for f in findings], reverse=True)
    top3   = sum(scores[:3]) / min(3, len(scores))
    avg    = sum(scores) / len(scores)
    return min(100.0, round(top3 * 0.7 + avg * 0.3, 1))

