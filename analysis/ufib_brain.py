"""UFIB multi-gate validation engine and counterevidence analysis.

SCHEMA: UFIB-BRAIN-1

A central state machine that evaluates one normalized finding at a time
against its category contract (ufib_contracts.py) and records an explicit,
auditable gate history. It never replaces the detectors and never rewrites
detector output: it adds `ufib` (the audit block), `disposition` and
`release_eligible` to the finding and nothing else.

Gates (mission 5):
  G1  raw detection validity      the observation is well-formed and in scope
  G2  semantic claim validation   what the observation can honestly claim
  G3  evidence contract           every mandatory requirement, per requirement
  G4  data-flow validation        source-to-sink where the category needs it
  G5  security-control context    does the claimed-missing control exist here
  G6  contradiction analysis      counterevidence that weakens or defeats
  G7  correlation/deduplication   preserve roots; record dedup state
  G8  severity/confidence         recorded separately, never an override
  G9  release authorization       disposition + eligibility under policy

Iron laws (asserted by tests):
  * UNKNOWN mandatory evidence is never treated as satisfied.
  * A decisive contradiction blocks CONFIRMED regardless of severity or
    confidence.
  * An unmatched category is never silently confirmed (DEFAULT contract is
    manual-review).
  * Existing finding keys are never overwritten.
  * A brain crash on one finding becomes ANALYSIS_ERROR for that finding and
    must never abort the scan (fail-soft, loud).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from analysis.ufib_contracts import (
    CONTRACTS,
    CONTRADICTED,
    DEFAULT_CONTRACT,
    INFERRED,
    OBSERVED,
    SCOPE_FILE,
    UNKNOWN,
    VALIDATED,
    UFIB_EVIDENCE_SCHEMA,
    _has_value_evidence,
    build_claim,
    get_contract,
    resolve_category,
)

UFIB_BRAIN_SCHEMA = "UFIB-BRAIN-1"

# Bounded source reading: the counterevidence collectors may need the file
# beside the match. 256 KB is generous for source files and caps adversarial
# inputs; the cache is per-call-tree (one scan), keyed by resolved path.
_MAX_FILE_BYTES = 256 * 1024
_FILE_CACHE: dict[str, str] = {}


def read_source(file_value: Any, target: str | None) -> str | None:
    """Bounded, cached source read. Returns None when the file cannot be
    read -- the brain records that as UNKNOWN, never as evidence of safety.

    Fallback: when the recorded path is unreadable (e.g. a temp-copy path
    that was already cleaned up), retry against ``target/basename`` -- the
    production layout where findings carry target-relative names."""
    if not file_value:
        return None
    p = Path(str(file_value))
    if not p.is_absolute() and target:
        candidate = Path(target) / p
        p = candidate if candidate.is_file() else p
    key = str(p)
    if key in _FILE_CACHE:
        return _FILE_CACHE[key]
    try:
        if not p.is_file() or p.stat().st_size > _MAX_FILE_BYTES:
            text = None
        else:
            text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = None
    if text is None and target:
        try:
            alt = Path(target) / Path(str(file_value)).name
            if alt.is_file() and alt.stat().st_size <= _MAX_FILE_BYTES:
                text = alt.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = None
    _FILE_CACHE[key] = text
    return text


def clear_source_cache() -> None:
    _FILE_CACHE.clear()


# ---------------------------------------------------------------------------
# T-2.3: rule-declared barriers (contract-driven suppression)
# ---------------------------------------------------------------------------
# A barrier is a construct the RULE declares as proving its finding not
# exploitable when present (an allowlist assignment, an authz guard, ...).
# Rules may add barriers; they can never REMOVE the contract's own
# counterevidence.  Compiled lazily from core.rule_loader (validate_doc
# already proved each pattern compiles).  With no rule declaring a barrier
# (the production pack) this is empty -> G6 sees only its contract
# counterevidence, keeping every oracle byte-identical.
_RULE_BARRIERS: dict[str, tuple] | None = None


def _load_rule_barriers() -> dict[str, tuple]:
    """rule id -> tuple of compiled barrier patterns (T-2.3).

    Patterns use the same default flags the rule's main pattern uses
    (ims).  A barrier is file-scope counterevidence, so it is matched
    against the analyzed source like the contract's SCOPE_FILE entries.
    """
    try:
        from core import rule_loader
        decls = rule_loader.load_barrier_overrides()
    except Exception:  # noqa: BLE001 - a broken rule pack must not kill UFIB
        return {}
    flags = re.IGNORECASE | re.MULTILINE | re.DOTALL
    out: dict[str, tuple] = {}
    for rule_id, patterns in decls.items():
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, flags))
            except re.error:
                continue  # validate_doc already rejected bad ones; defensive
        if compiled:
            out[rule_id] = tuple(compiled)
    return out


def _rule_barriers(rule_id: Any) -> tuple:
    """Compiled barriers for ``rule_id`` (cached); () when none."""
    global _RULE_BARRIERS
    if _RULE_BARRIERS is None:
        _RULE_BARRIERS = _load_rule_barriers()
    if not rule_id:
        return ()
    return _RULE_BARRIERS.get(str(rule_id), ())


def _g6_rule_barriers(finding: dict, file_text: str | None,
                      ev: list[dict]) -> list[str]:
    """Additive decisive counterevidence from the finding's rule barriers.

    Deliberately NOT subject to the multipath downgrade below: a barrier
    is a gate the value must pass (a control present in the file), not a
    per-path safe construct, so its presence defeats every grouped path.
    Unreadable file -> no barrier applied (they are additive, so this
    never flips the contract's own context-unverifiable cap).
    """
    pats = _rule_barriers(finding.get("rule_id"))
    if not pats or file_text is None:
        return []
    kinds: list[str] = []
    for pat in pats:
        if pat.search(file_text):
            ev.append({"kind": "counterevidence:rule_barrier",
                       "state": CONTRADICTED,
                       "provenance": "collector:rule_barrier",
                       "detail": "rule-declared barrier matched: %s"
                                 % pat.pattern})
            kinds.append("rule_barrier")
    return kinds


def _observed_text(finding: dict) -> str:
    """The OBSERVED material only: what the detector matched. Deliberately
    excludes title/description/remediation prose -- an engine that writes
    'example: user:pass@host' in its description must not have its own
    illustrative text counted as counterevidence against the finding."""
    return " ".join(str(finding.get(k) or "") for k in
                    ("snippet", "evidence", "evidence_match",
                     "sink_call", "source_expr"))


def _finding_text(finding: dict) -> str:
    return " ".join(str(finding.get(k) or "") for k in
                    ("snippet", "evidence", "evidence_match", "title",
                     "description", "taint_path", "source_expr", "sink_call"))


# ---------------------------------------------------------------------------
# Gate implementations. Each returns (result, reason) and may append evidence.
# Results: PASS / FAIL / UNKNOWN / NOT_APPLICABLE
# ---------------------------------------------------------------------------
def _g1_raw_validity(finding: dict, ev: list[dict]) -> tuple[str, str]:
    rid = str(finding.get("rule_id") or "").strip()
    file_v = str(finding.get("file") or finding.get("path") or "").strip()
    package = str(finding.get("package") or finding.get("name") or "").strip()
    version = str(finding.get("version") or "").strip()
    text = _finding_text(finding)
    # Graph-level identities: an advisory-backed dependency (package+CVE) and
    # a component inventory entry (package+version) are claims ABOUT a
    # component, not about a source line -- line 0 is their legal anchor
    # (finding_model documents line 0 as "not line-addressable" for exactly
    # these families). Rejecting them for a missing line was a G1 defect the
    # corpus guard caught: all 24 labelled SBOM entries scored REJECTED.
    cve = str(finding.get("cve") or "").strip()
    sca_like = bool(package and (cve or version))
    if not rid:
        ev.append({"kind": "missing_rule_id", "state": UNKNOWN,
                   "provenance": "gate:G1",
                   "detail": "finding carries no rule identity"})
        return "FAIL", "no rule_id"
    if not sca_like and not file_v:
        return "FAIL", "no source artifact"
    if not text.strip() and not sca_like:
        return "FAIL", "no matched construct or evidence text"
    if not sca_like and not re.search(r"\d", str(finding.get("line") or "")):
        # Line 0 is legal only for graph-level findings (SCA/SBOM families);
        # source findings must point somewhere.
        return "FAIL", "no source location"
    ev.append({"kind": "raw_detection", "state": OBSERVED,
               "provenance": "rule:%s" % rid,
               "detail": "detector observation accepted unchanged"})
    return "PASS", "observation well-formed"


def _g2_semantic_claim(finding: dict, category: str, ev: list[dict],
                       file_value_evidence: bool | None = None) -> tuple[str, str, str]:
    claim, strength = build_claim(category, finding, file_value_evidence)
    ev.append({"kind": "security_claim", "state": INFERRED,
               "provenance": "contract:%s" % category,
               "detail": claim})
    ev.append({"kind": "claim_strength", "state": INFERRED,
               "provenance": "contract:%s" % category,
               "detail": strength})
    if strength == "WEAK":
        return "FAIL", ("evidence supports only an identifier/keyword-level "
                        "observation, not the claimed construct"), strength
    return "PASS", "claim strength: %s" % strength, strength


def _value_evidence_in_file(finding: dict, target: str | None) -> bool | None:
    """Consult the SOURCE FILE for a literal value when the finding object is
    value-blind. The secrets engine emits identifier-only (often redacted)
    evidence while the literal sits in the scanned file. Returns True/False,
    or None when the file cannot be read (UNKNOWN -- never treated as
    satisfied)."""
    file_text = read_source(finding.get("file"), target)
    if file_text is None:
        return None
    probe = dict(finding)
    probe["snippet"] = file_text[:8192]
    probe["evidence"] = ""
    return _has_value_evidence(probe)


def _satisfied(key: str, finding: dict, target: str | None = None,
               ev: list | None = None) -> bool | None:
    """Is mandatory requirement `key` established by the finding's own fields?
    True / False / None (=UNKNOWN -- never treated as satisfied)."""
    has = lambda k: bool(str(finding.get(k) or "").strip())  # noqa: E731
    if key in ("sink", "sink_call"):
        if has("sink_call") or has("sink"):
            return True
        # The evidex stage validates sink candidates; a VALIDATED sink is
        # evidence even when the raw detector field did not survive
        # normalization into this finding.
        if finding.get("sink_validated") is True or (
                isinstance(finding.get("evidence_validation_detail"), dict)
                and finding["evidence_validation_detail"].get("sink_valid") is True):
            return True
        # The observed material IS the detector's sink-shaped match: a
        # lexical sink rule by construction matched a call construct. G3
        # asks "was a sink construct observed" (yes); whether that construct
        # is effectively safe is G6's counterevidence question.
        observed = _observed_text(finding)
        if re.search(r"\w+\s*\(", observed):
            return True
        return None if key == "sink" else False
    if key in ("source", "source_expr"):
        return True if has("source_expr") or has("source") else None
    if key == "data_flow":
        detail = finding.get("evidence_validation_detail")
        if finding.get("taint_validated") or (isinstance(detail, dict)
                                              and detail.get("taint_validated")):
            return True
        if has("taint_path") or has("taint_chain"):
            return True
        return None
    if key in ("query_construction", "command_construction", "path_construction",
               "url_construction", "api_usage", "config_declaration",
               "endpoint_context", "pattern_match"):
        return bool(_finding_text(finding).strip())
    if key == "value_evidence":
        from analysis.ufib_contracts import _has_value_evidence
        if _has_value_evidence(finding):
            return True
        # The finding object may be value-blind (identifier-only evidence);
        # the literal may still be observable in the source file.
        file_hit = _value_evidence_in_file(finding, target)
        if file_hit and ev is not None:
            ev.append({"kind": "required:value_evidence", "state": OBSERVED,
                       "provenance": "gate:G3",
                       "detail": "literal value observed in the source file"})
        return file_hit
    if key == "credential_context":
        return bool(has("rule_id") or has("vuln_type"))
    if key == "format_validation":
        # The secret engine stamps validity separately; absent is UNKNOWN.
        return True if finding.get("validated_live") is True else None
    if key == "advisory":
        return True if has("cve") else False
    if key == "package_identity":
        return bool(has("package") and (has("version")))
    if key == "reachability":
        return True if finding.get("reachability_status") else None
    return None


def _g3_contract(finding: dict, contract: dict, target: str | None,
                 ev: list[dict]) -> tuple[str, str]:
    results = {}
    failed, unknown = [], []
    for key in contract["required_evidence"]:
        state = _satisfied(key, finding, target, ev)
        if state is True:
            results[key] = "SATISFIED"
            ev.append({"kind": "required:%s" % key, "state": OBSERVED,
                       "provenance": "gate:G3", "detail": "satisfied"})
        elif state is False:
            results[key] = "FAILED"
            failed.append(key)
            ev.append({"kind": "required:%s" % key, "state": CONTRADICTED,
                       "provenance": "gate:G3", "detail": "explicitly failed"})
        else:
            results[key] = "UNKNOWN"
            unknown.append(key)
            ev.append({"kind": "required:%s" % key, "state": UNKNOWN,
                       "provenance": "gate:G3",
                       "detail": ("not established by available analysis "
                                  "-- UNKNOWN is never treated as satisfied")})
    finding.setdefault("ufib_data", {})["required_evidence"] = results
    if failed:
        return "FAIL", "mandatory evidence explicitly failed: %s" % failed
    if unknown:
        return "UNKNOWN", "mandatory evidence unknown: %s" % unknown
    return "PASS", "all mandatory evidence satisfied"


def _g4_dataflow(finding: dict, contract: dict,
                 ev: list[dict]) -> tuple[str, str]:
    if not contract["requires_dataflow"]:
        return "NOT_APPLICABLE", "category claim does not require data flow"
    detail = finding.get("evidence_validation_detail")
    if finding.get("taint_validated") or (isinstance(detail, dict)
                                          and detail.get("taint_validated")):
        ev.append({"kind": "data_flow", "state": VALIDATED,
                   "provenance": "evidex",
                   "detail": "source-to-sink validated by the evidex stage"})
        return "PASS", "taint validated"
    if str(finding.get("taint_path") or "").strip() or finding.get("taint_chain"):
        ev.append({"kind": "data_flow", "state": OBSERVED,
                   "provenance": "detector",
                   "detail": "taint path reported by the detector"})
        return "PASS", "taint path observed"
    ev.append({"kind": "data_flow", "state": UNKNOWN,
               "provenance": "gate:G4",
               "detail": ("no source-to-sink path established; UNKNOWN never "
                          "counts as flow")})
    return "UNKNOWN", "no data flow established"


def _g5_control_context(finding: dict, contract: dict, target: str | None,
                        ev: list[dict]) -> tuple[str, str]:
    """Does the control the finding claims is missing/weak actually exist in
    the same file? Decisive only for control-gap categories (mission F: do
    not report a missing control when an equivalent control exists in the
    execution path we can see)."""
    if contract["category"] != "control_gap":
        return "NOT_APPLICABLE", "no control-presence question for this category"
    file_text = read_source(finding.get("file"), target)
    if file_text is None:
        ev.append({"kind": "control_context", "state": UNKNOWN,
                   "provenance": "gate:G5",
                   "detail": "source file unreadable; control presence unknown"})
        return "UNKNOWN", "file unreadable"
    for ce in contract["counterevidence"]:
        if ce["scope"] != SCOPE_FILE:
            continue
        if ce["pattern"].search(file_text):
            ev.append({"kind": "control_present:%s" % ce["kind"],
                       "state": CONTRADICTED, "provenance": "collector:%s" % ce["kind"],
                       "detail": ce.get("note") or ce["kind"]})
            return "FAIL", "the claimed-missing control exists in this file"
    ev.append({"kind": "control_context", "state": OBSERVED,
               "provenance": "gate:G5",
               "detail": "no equivalent control found in the analyzed file"})
    return "PASS", "no visible equivalent control"


def _g6_contradiction(finding: dict, contract: dict, target: str | None,
                      ev: list[dict]) -> tuple[str, str]:
    """Category-aware counterevidence: decisive matches reject, the rest
    qualify. K8S_MISSING_* gets the exact pod-level inheritance check.

    Guards:
      * a live-validated secret (validated_live=True) is never rejected by
        the placeholder collectors;
      * shape collectors (<>, {{}}, ${}) apply to the FINDING's value text
        only -- `<iostream>` in a C++ include and Rust generics are language
        syntax, not template placeholders (the corpus's cpp/php/rust fixtures
        proved this exact failure mode);
      * keyword collectors may escalate to the file, where the redacted
        finding's real value lives;
      * CONTEXT-UNVERIFIABLE cap: when a category's counterevidence is
        context-dependent and the source file cannot be read, the check
        returns UNKNOWN -- it never reads as "no counterevidence found".
        A finding whose context could not be examined is released at LIKELY
        at most, never CONFIRMED (mission 5: UNKNOWN is never satisfied).
    """
    decisive, qualifying = [], []
    text = _observed_text(finding)
    file_text = read_source(finding.get("file"), target)
    live_validated = finding.get("validated_live") is True
    context_dependent = bool(contract["counterevidence"])
    for ce in contract["counterevidence"]:
        if (live_validated and contract["category"] == "hardcoded_secret"):
            ev.append({"kind": "counterevidence_guard:live_validated_secret",
                       "state": OBSERVED, "provenance": "gate:G6",
                       "detail": "placeholder collectors not applied: the "
                                 "secret engine validated this value live"})
            break
        escalate = ce["kind"] in ("placeholder_value", "synthetic_context_marker")
        scope_text = None
        if ce["scope"] == SCOPE_FILE:
            if file_text is None:
                ev.append({"kind": "counterevidence_skipped:%s" % ce["kind"],
                           "state": UNKNOWN, "provenance": "gate:G6",
                           "detail": "file unreadable; collector not applied"})
                continue
            scope_text = file_text
        else:
            scope_text = text + (file_text or "" if escalate else "")
        if scope_text and ce["pattern"].search(scope_text):
            entry = {"kind": "counterevidence:%s" % ce["kind"],
                     "state": CONTRADICTED,
                     "provenance": "collector:%s" % ce["kind"],
                     "detail": ce.get("note") or ce["kind"]}
            ev.append(entry)
            (decisive if ce["decisive"] else qualifying).append(ce["kind"])

    if context_dependent and file_text is None and not decisive:
        ev.append({"kind": "context_unverifiable", "state": UNKNOWN,
                   "provenance": "gate:G6",
                   "detail": ("the source file could not be read; context "
                              "counterevidence was NOT examined -- the "
                              "finding is capped at LIKELY, never CONFIRMED")})
        return "UNKNOWN", ("context unverifiable (source file unreadable); "
                           "claim strength capped")

    pod_hits = []
    if file_text is not None:
        pod_hits = _k8s_pod_level_evidence(finding, file_text)
    ev.extend(pod_hits)
    decisive.extend(h["kind"] for h in pod_hits)

    # Mission G6's own rule: do not let one apparent safe path suppress a
    # separate vulnerable path. When the finding groups MULTIPLE paths
    # (several occurrences, or a multi-hop taint enumeration), a
    # parameterized/safe construct mentioned in the grouped text may belong
    # to ONE path while another path stays vulnerable. Decisive finding-text
    # counterevidence therefore downgrades to qualifying on multi-path
    # findings; single-path findings keep the decisive rejection.
    multipath = (int(finding.get("instances") or 0) > 1
                 or str(finding.get("taint_path") or "").count("->") >= 2
                 or bool(finding.get("occurrences")))
    if decisive and multipath:
        downgraded = []
        for ce in contract["counterevidence"]:
            if not ce["decisive"]:
                continue
            scope_text = file_text if ce["scope"] == SCOPE_FILE else text
            if scope_text and ce["pattern"].search(scope_text):
                downgraded.append(ce["kind"])
        ev.append({"kind": "mixed_paths_qualification", "state": UNKNOWN,
                   "provenance": "gate:G6",
                   "detail": ("grouped finding carries %d path(s); the safe "
                              "construct cannot be attributed to every "
                              "path, so the group is qualified rather "
                              "than rejected" % max(
                                  int(finding.get("instances") or 1),
                                  str(finding.get("taint_path") or "")
                                  .count("->")))})
        qualifying.extend(downgraded)
        decisive = [d for d in decisive
                    if d in {h["kind"] for h in pod_hits}]

    # T-2.3 rule barriers: additive decisive counterevidence, applied
    # after the multipath downgrade (a barrier is a gate, not a per-path
    # safe construct).  Empty when the finding's rule declares none.
    decisive.extend(_g6_rule_barriers(finding, file_text, ev))

    if decisive:
        return "FAIL", "decisive counterevidence: %s" % sorted(set(decisive))
    if qualifying:
        return "UNKNOWN", ("qualifying counterevidence (not decisive): %s"
                           % sorted(set(qualifying)))
    return "PASS", "no counterevidence found"


def _k8s_pod_level_evidence(finding: dict, file_text: str) -> list[dict]:
    from analysis.ufib_contracts import _k8s_pod_level_context
    return _k8s_pod_level_context(finding, file_text)


def _g7_correlation(finding: dict, ev: list[dict]) -> tuple[str, str]:
    instances = int(finding.get("instances") or 0)
    group = str(finding.get("group_key") or "").strip()
    if instances > 1 and group:
        ev.append({"kind": "occurrence_deduplication", "state": OBSERVED,
                   "provenance": "gate:G7",
                   "detail": "%d occurrences grouped under one root; distinct "
                             "roots stay distinct" % instances})
        return "PASS", "grouped occurrences preserved under one root"
    if group:
        return "PASS", "single-occurrence root"
    ev.append({"kind": "correlation_state", "state": UNKNOWN,
               "provenance": "gate:G7",
               "detail": "no group key; dedup state not established"})
    return "UNKNOWN", "no group key recorded"


def _g8_severity_confidence(finding: dict, ev: list[dict]) -> tuple[str, str]:
    sev = str(finding.get("severity") or "").strip()
    legal = {"Critical", "High", "Medium", "Low", "Info"}
    if sev not in legal:
        ev.append({"kind": "severity_vocabulary", "state": CONTRADICTED,
                   "provenance": "gate:G8",
                   "detail": "illegal severity %r" % sev})
        return "FAIL", "illegal severity %r" % sev
    # Recorded separately, never overriding gates (mission 5 G8): severity,
    # confidence, reachability and exposure travel as distinct dimensions.
    dims = {
        "severity": sev,
        "confidence": str(finding.get("confidence") or "UNKNOWN"),
        "reachability": str(finding.get("reachability_status") or
                            ("NOT_APPLICABLE" if not finding.get("cve")
                             else "UNKNOWN")),
        "environmental_applicability": "STATIC_ANALYSIS_SCOPE",
    }
    finding.setdefault("ufib_data", {})["dimensions"] = dims
    ev.append({"kind": "decision_dimensions", "state": OBSERVED,
               "provenance": "gate:G8",
               "detail": "severity/confidence/reachability recorded as "
                         "separate dimensions; none overrides a failed gate"})
    return "PASS", "dimensions recorded"


def _decide(contract: dict, g1: str, g2: str, g3: str, g4: str,
            g5: str, g6: str) -> str:
    """G9 policy. Deterministic; no score can override a failed gate."""
    cat = contract["category"]
    if g1 == "FAIL" or g2 == "FAIL":
        return "REJECTED_FALSE_POSITIVE"
    if g6 == "FAIL" or g5 == "FAIL":
        return "REJECTED_FALSE_POSITIVE"
    if g3 == "FAIL":
        return "INSUFFICIENT_EVIDENCE"
    if contract.get("manual_review") or cat == "_default":
        return "NEEDS_REVIEW"
    if g3 == "UNKNOWN" or (contract["requires_dataflow"] and g4 == "UNKNOWN"):
        return "INSUFFICIENT_EVIDENCE"
    if contract["confirmation_policy"] == "MANUAL_REVIEW_ONLY":
        return "NEEDS_REVIEW"
    if g6 == "UNKNOWN":
        return "LIKELY"
    return "CONFIRMED"


RELEASE_DISPOSITIONS = {
    "CONFIRMED": True,
    "LIKELY": True,
    "NEEDS_REVIEW": False,
    "INSUFFICIENT_EVIDENCE": False,
    "REJECTED_FALSE_POSITIVE": False,
    "SUPPRESSED": False,
    "DUPLICATE": False,
    "ANALYSIS_ERROR": False,
}


def evaluate_finding(finding: dict, target: str | None = None) -> dict:
    """Evaluate one finding in place (additively) and return its disposition.

    Contract: existing keys are NEVER overwritten; the brain adds
    `ufib` (audit), `disposition` and `release_eligible`, and `ufib_data`
    scratch fields. Any internal error becomes ANALYSIS_ERROR for THIS
    finding, with the exception recorded as evidence -- the scan continues.
    """
    existing_snapshot = {k: finding.get(k) for k in
                         ("rule_id", "severity", "confidence", "cve", "package",
                          "version", "line", "file", "snippet", "evidence")}
    try:
        category = resolve_category(finding)
        contract = get_contract(category)
        # Value-blind findings get ONE file consult, computed FIRST and
        # reused by both G2's claim strength and G3's value_evidence
        # requirement. (Computing it after _satisfied made G2 reject before
        # the file evidence existed in its view.)
        file_value_hint = None
        if "value_evidence" in contract["required_evidence"]:
            if not _has_value_evidence(finding):
                file_value_hint = _value_evidence_in_file(finding, target)
            else:
                file_value_hint = True
        claim, _strength = build_claim(category, finding, file_value_hint)
        ev: list[dict] = [{"kind": "schema", "state": OBSERVED,
                           "provenance": "ufib",
                           "detail": UFIB_EVIDENCE_SCHEMA}]

        g1, r1 = _g1_raw_validity(finding, ev)
        g2, r2, strength = _g2_semantic_claim(finding, category, ev, file_value_hint)
        g3, r3 = _g3_contract(finding, contract, target, ev)
        g4, r4 = _g4_dataflow(finding, contract, ev)
        g5, r5 = _g5_control_context(finding, contract, target, ev)
        g6, r6 = _g6_contradiction(finding, contract, target, ev)
        g7, r7 = _g7_correlation(finding, ev)
        g8, r8 = _g8_severity_confidence(finding, ev)

        gates = [
            {"gate": "G1", "name": "raw_detection_validity", "result": g1, "reason": r1},
            {"gate": "G2", "name": "semantic_claim_validation", "result": g2, "reason": r2},
            {"gate": "G3", "name": "evidence_contract", "result": g3, "reason": r3},
            {"gate": "G4", "name": "dataflow_validation", "result": g4, "reason": r4},
            {"gate": "G5", "name": "security_control_context", "result": g5, "reason": r5},
            {"gate": "G6", "name": "contradiction_analysis", "result": g6, "reason": r6},
            {"gate": "G7", "name": "correlation_dedup", "result": g7, "reason": r7},
            {"gate": "G8", "name": "severity_confidence_applicability", "result": g8, "reason": r8},
        ]
        disposition = _decide(contract, g1, g2, g3, g4, g5, g6)
        rationale = {
            "REJECTED_FALSE_POSITIVE":
                "a mandatory validity gate failed or decisive counterevidence "
                "was found; the observation is preserved with its reason",
            "INSUFFICIENT_EVIDENCE":
                "mandatory evidence is UNKNOWN/FAILED for this category; the "
                "claim cannot be confirmed from available analysis",
            "NEEDS_REVIEW":
                "the category contract routes this claim to manual review "
                "(control-gap/lexical/AI categories, or no contract matched)",
            "LIKELY":
                "mandatory evidence satisfied; qualifying (non-decisive) "
                "counterevidence recorded",
            "CONFIRMED":
                "all mandatory gates passed with no counterevidence under the "
                "category's confirmation policy",
        }[disposition]

        finding["ufib"] = {
            "schema": UFIB_BRAIN_SCHEMA,
            "contract_schema": contract["schema"],
            "category": category,
            "claim": claim,
            "claim_strength": strength,
            "evidence": ev,
            "gates": gates,
            "limitations": list(contract["known_limitations"]),
            "confirmation_policy": contract["confirmation_policy"],
            "disposition_rationale": rationale,
            "original_detector_fields": existing_snapshot,
        }
        finding["disposition"] = disposition
        finding["release_eligible"] = RELEASE_DISPOSITIONS[disposition]
        return disposition
    except Exception as exc:  # noqa: BLE001 - fail-soft, loud, per finding
        finding["ufib"] = {
            "schema": UFIB_BRAIN_SCHEMA,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "disposition_rationale": ("the brain could not evaluate this "
                                      "finding; it is held, never released "
                                      "as confirmed"),
        }
        finding["disposition"] = "ANALYSIS_ERROR"
        finding["release_eligible"] = False
        return "ANALYSIS_ERROR"


# Exported for tests/reporting: the closed disposition vocabulary.
DISPOSITIONS = frozenset(RELEASE_DISPOSITIONS)
