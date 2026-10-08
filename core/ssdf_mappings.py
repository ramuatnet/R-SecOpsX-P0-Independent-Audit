"""NIST SSDF (SP 800-218) evidence alignment for V11.

Why this is not a rule-to-practice mapping
------------------------------------------
ATLAS and the OWASP catalogues map a *detection* to a technique or risk, so a
per-finding identifier is meaningful. SSDF is different: it describes
organisational and lifecycle PRACTICES, most of which a scanner cannot observe
at all. Emitting ``ssdf_practice="PS.1"`` on a hardcoded-credential finding
would claim the organisation protected its code from tampering, which no scan
can establish. That is precisely the absence-to-assurance upgrade this project
forbids.

So SSDF is aligned the other way round: for each practice this module asks what
evidence in a produced artifact would demonstrate it, and records the answer as
OBSERVED or NOT_OBSERVED with the evidence path that decided it. Nothing is
inferred from a finding.

Source
------
NIST SP 800-218, *Secure Software Development Framework (SSDF) Version 1.1:
Recommendations for Mitigating the Risk of Software Vulnerabilities*, published
2022-02-03, DOI 10.6028/NIST.SP.800-218. Supersedes CSWP 13.

Four practice groups: PO Prepare the Organization, PS Protect the Software,
PW Produce Well-Secured Software, RV Respond to Vulnerabilities.

Scope note, and it matters
--------------------------
Only practices whose existence was confirmed from SP 800-218 v1.1 in this
session are listed. A later EO 14144 revision adds PO.6 (Continuous
Improvement) and PW.10 (Robust and Reliable Updates); those are NOT v1.1 and
are deliberately absent here. Where a practice id could not be confirmed it is
not listed rather than guessed -- an unconfirmed identifier in a compliance
table is worse than an omission.
"""
from __future__ import annotations

SSDF_DOCUMENT = "NIST SP 800-218"
SSDF_VERSION = "1.1"
SSDF_TITLE = (
    "Secure Software Development Framework (SSDF) Version 1.1: Recommendations "
    "for Mitigating the Risk of Software Vulnerabilities"
)
SSDF_PUBLISHED = "2022-02-03"
SSDF_DOI = "10.6028/NIST.SP.800-218"
SSDF_SOURCE_URL = "https://csrc.nist.gov/pubs/sp/800/218/final"
SSDF_DATASET_LABEL = f"{SSDF_DOCUMENT} v{SSDF_VERSION} ({SSDF_PUBLISHED})"

SSDF_ALIGNMENT_OBSERVED = "OBSERVED"
SSDF_ALIGNMENT_NOT_OBSERVED = "NOT_OBSERVED"
SSDF_ALIGNMENT_ORGANISATIONAL = "NOT_ATTESTABLE_BY_A_SCANNER"

SSDF_PRACTICE_GROUPS = {
    "PO": "Prepare the Organization",
    "PS": "Protect the Software",
    "PW": "Produce Well-Secured Software",
    "RV": "Respond to Vulnerabilities",
}

# Practices confirmed present in v1.1. Names are given only where the name was
# confirmed from the document; where only the identifier was confirmed, name is
# empty rather than reconstructed.
SSDF_PRACTICES = {
    "PO.1": {"group": "PO", "name": "Define Security Requirements for Software Development"},
    "PO.2": {"group": "PO", "name": "Implement Roles and Responsibilities"},
    "PO.3": {"group": "PO", "name": "Supporting Toolchains"},
    "PO.4": {"group": "PO", "name": ""},
    "PO.5": {"group": "PO", "name": "Implement and Maintain Secure Environments for Software Development"},
    "PS.1": {"group": "PS", "name": "Protect All Forms of Code from Unauthorized Access and Tampering"},
    "PS.2": {"group": "PS", "name": "Provide a Mechanism for Verifying Software Release Integrity"},
    "PS.3": {"group": "PS", "name": "Archive and Protect Each Software Release"},
    "PW.1": {"group": "PW", "name": "Design Software to Meet Security Requirements and Mitigate Security Risks"},
    "PW.2": {"group": "PW", "name": "Review the Software Design to Verify Compliance with Security Requirements"},
    "PW.4": {"group": "PW", "name": ""},
    "PW.5": {"group": "PW", "name": "Create Source Code by Adhering to Secure Coding Practices"},
    "RV.1": {"group": "RV", "name": "Identify and Confirm Vulnerabilities on an Ongoing Basis"},
    "RV.2": {"group": "RV", "name": "Assess, Prioritize, and Remediate Vulnerabilities"},
    "RV.3": {"group": "RV", "name": ""},
}


def _label(practice_id: str) -> str:
    name = (SSDF_PRACTICES.get(practice_id) or {}).get("name") or ""
    return f"{practice_id}: {name}" if name else practice_id


# ---------------------------------------------------------------------------
# Evidence probes.
#
#   paths        dotted paths into clean_report.json; a non-empty resolution is
#                the evidence
#   observed_when: every listed path must resolve for the practice to count
# ---------------------------------------------------------------------------
SSDF_EVIDENCE = {
    "PS.1": {
        "paths": ["secret_intelligence_summary", "metadata.sast_findings"],
        "why": (
            "Secret scanning and code-integrity findings are evidence that "
            "software components are being checked for unauthorised access and "
            "tampering. This is partial evidence for the practice, not proof of "
            "it."
        ),
    },
    "PS.2": {
        "paths": ["runtime_artifact_integrity_summary"],
        "why": (
            "Runtime artifact integrity plus the emitted VEX and CycloneDX "
            "documents constitute a mechanism for verifying release integrity."
        ),
    },
    "PS.3": {
        "paths": ["sbom", "sbom_summary"],
        "why": (
            "An SBOM with CycloneDX provenance output is the archival and "
            "provenance record for a release (PS.3.2 collects provenance data)."
        ),
    },
    "PW.1": {
        "paths": [],
        "why": (
            "Designing software to meet security requirements is a design-time "
            "activity. A static scanner runs after the design exists and holds "
            "no design artefact, so no evidence can be produced either way."
        ),
    },
    "PW.2": {
        "paths": [],
        "why": (
            "Reviewing a design against requirements needs the design and the "
            "requirements. Neither is in scope for a code scanner."
        ),
    },
    "PW.5": {
        "paths": ["findings", "metadata.sast_findings"],
        "why": (
            "SAST and taint detections are evidence of secure-coding practice, "
            "with the caveat that absence of findings is not evidence of secure "
            "code."
        ),
    },
    "RV.1": {
        "paths": [
            "kev_intelligence_summary",
            "epss_intelligence_summary",
            "vulnerability_age_summary",
        ],
        "why": (
            "Live KEV and EPSS feeds, vulnerability-age and outbreak state are "
            "ongoing vulnerability identification and confirmation."
        ),
    },
    "RV.2": {
        "paths": [
            "reachability_vulnerability_summary",
            "release_readiness",
            "exploitability_summary",
        ],
        "why": (
            "Reachability-aware prioritisation, exploitability fusion and the "
            "release-readiness gates are assessment, prioritisation and "
            "remediation planning."
        ),
    },
}

# Practices a scanner cannot attest to. Recorded explicitly so their absence
# from the evidence table is a decision, not an oversight.
SSDF_NOT_ATTESTABLE = {
    "PO.1": (
        "Organisational policy practice. Establishing and maintaining security "
        "requirements for a development infrastructure is an organisational "
        "commitment; no scan output can evidence it."
    ),
    "PO.2": (
        "Roles and responsibilities, including role-based training. Not "
        "observable from source or artifact."
    ),
    "PO.3": (
        "The practice is about establishing and using supporting toolchains. "
        "V11 being installed is not evidence that the organisation established "
        "or uses one as SSDF intends."
    ),
    "PO.4": {"note": "Practice identifier confirmed in v1.1; purpose not confirmed in this session."},
    "PO.5": (
        "Maintaining secure development environments is an environment "
        "property, not a source property."
    ),
    "PW.4": {"note": "Practice identifier confirmed in v1.1; purpose not confirmed in this session."},
    "RV.3": {"note": "Practice identifier confirmed in v1.1; purpose not confirmed in this session."},
}


def _resolve(payload, dotted):
    cur = payload
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _is_populated(value) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, dict, str)):
        return len(value) > 0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # A zero count is present-but-empty; a summary key existing proves the
        # engine ran, so presence of the key (handled by _resolve) is what
        # matters, and zero is accepted.
        return True
    return bool(value)


def evaluate_ssdf_alignment(payload) -> dict:
    """Per-practice SSDF alignment for one produced artifact."""
    practices = []
    for pid in sorted(SSDF_PRACTICES, key=lambda p: (p.split(".")[0], p)):
        spec = SSDF_PRACTICES[pid]
        group = spec["group"]

        if pid in SSDF_EVIDENCE:
            paths = SSDF_EVIDENCE[pid]["paths"]
            if not paths:
                status = SSDF_ALIGNMENT_NOT_OBSERVED
                resolved = []
                note = SSDF_EVIDENCE[pid]["why"]
            else:
                resolved = []
                for dotted in paths:
                    value = _resolve(payload, dotted)
                    ok = _is_populated(value)
                    resolved.append({
                        "path": dotted,
                        "resolved": ok,
                        "detail": (
                            "%d item(s)" % len(value)
                            if isinstance(value, (list, dict))
                            else ("present" if value is not None else "absent")
                        ),
                    })
                status = (
                    SSDF_ALIGNMENT_OBSERVED
                    if all(r["resolved"] for r in resolved)
                    else SSDF_ALIGNMENT_NOT_OBSERVED
                )
                note = SSDF_EVIDENCE[pid]["why"]
            practices.append({
                "practice_id": pid,
                "practice": _label(pid),
                "name": spec["name"],
                "group": group,
                "group_name": SSDF_PRACTICE_GROUPS[group],
                "status": status,
                "evidence": resolved,
                "rationale": note,
            })
            continue

        entry = SSDF_NOT_ATTESTABLE.get(pid)
        if isinstance(entry, dict):
            rationale = entry.get("note") or "No evidence probe declared."
        elif isinstance(entry, str):
            rationale = entry
        else:
            rationale = "No evidence probe declared."
        practices.append({
            "practice_id": pid,
            "practice": _label(pid),
            "name": spec["name"],
            "group": group,
            "group_name": SSDF_PRACTICE_GROUPS[group],
            "status": SSDF_ALIGNMENT_ORGANISATIONAL,
            "evidence": [],
            "rationale": rationale,
        })

    observed = [p for p in practices if p["status"] == SSDF_ALIGNMENT_OBSERVED]
    by_group = {}
    for p in practices:
        g = by_group.setdefault(p["group"], {"name": p["group_name"], "total": 0, "observed": 0})
        g["total"] += 1
        if p["status"] == SSDF_ALIGNMENT_OBSERVED:
            g["observed"] += 1

    return {
        "document": SSDF_DOCUMENT,
        "version": SSDF_VERSION,
        "dataset": SSDF_DATASET_LABEL,
        "doi": SSDF_DOI,
        "source_url": SSDF_SOURCE_URL,
        "published": SSDF_PUBLISHED,
        "method": (
            "Per-practice EVIDENCE alignment against a produced artifact. No "
            "practice identifier is attached to any finding: a scanner cannot "
            "evidence an organisational practice, and asserting one would "
            "convert absence into assurance."
        ),
        "scope_note": (
            "Limited to practices confirmed present in SSDF v1.1. PO.6 and "
            "PW.10 belong to a later EO 14144 revision and are excluded."
        ),
        "practices": practices,
        "by_group": by_group,
        "total_practices": len(practices),
        "observed": len(observed),
        "not_observed": sum(
            1 for p in practices if p["status"] == SSDF_ALIGNMENT_NOT_OBSERVED
        ),
        "not_attestable": sum(
            1 for p in practices
            if p["status"] == SSDF_ALIGNMENT_ORGANISATIONAL
        ),
        "observed_ids": [p["practice_id"] for p in observed],
    }