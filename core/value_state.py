# -*- coding: utf-8 -*-
"""core/value_state.py -- the single formatter for "we do not know" cells.

Why this exists (taskf.md DEF-B): three different missing-value states used
to look identical in the reports.  The producers seeded literal ``"unknown"``
/ ``"Unknown"`` placeholders into the payload, and the renderers added a
second layer of their own defaults (``or "UNKNOWN"``, ``default="Review"``,
a fixed "No fixed version identified ..." sentence), so a reader could not
tell "the field does not apply here" from "we looked and could not obtain
it" from "the producer never wrote it".

This module is the ONE formatter (taskf ground rule 6).  Renderers call
``cell()``; they never default to a string literal.  Every empty cell is
exactly one of two forms (ground rule 5):

    ``--``                    absent or not applicable
    ``unknown (<reason>)``    should exist, not obtainable -- the reason
                              is printed, never a bare "Unknown"

States
------
ABSENT          the field does not exist for this record
NOT_APPLICABLE  the field exists but the question does not apply here
UNKNOWN         should exist, not obtainable -- ``reason`` says why
VALUE           a real value, ready to print

Reasons
-------
MANIFEST_RANGE / NO_LOCKFILE / LOCAL_REFERENCE / TRANSITIVE_GUESS /
PROPERTY_UNRESOLVED   why a version could not be resolved (the Phase 3
                      producer ladder, taskf T-3.2)
NO_ADVISORY           no vulnerability, so an advisory-derived cell is
                      void -- renders ``--``, never printed as words
NOT_PUBLISHED         an advisory exists but does not publish this field

Resolution ladder (deterministic, no guessing)
----------------------------------------------
1. ``pkg["field_provenance"][field]`` decides when it carries a state.
2. Advisory-derived fields (severity, fixed versions, age, ...): with no
   advisory the cell dashes -- exactly as CVE/CVSS/EPSS do -- even if a
   producer seeded a placeholder into the field.  With an advisory, a
   meaningful value wins, else a provenance reason, else NOT_PUBLISHED.
3. Any other field: a meaningful value wins, else a provenance reason,
   else ABSENT.

Refuses to do:
  * Guess.  A placeholder string is treated as absent, never promoted.
  * Print a bare unknown word.  UNKNOWN without a reason renders ``--``.
  * Reach the network or read anything but the dict handed to it.
  * Invent enum vocabulary: ``quantum_status`` is a classifier OUTPUT
    whose ``UNKNOWN`` is a real answer (taskf DoD targets placeholder
    defaults, not genuine enum values), so a present value always prints.
"""
from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------- states ---
ABSENT = "ABSENT"
NOT_APPLICABLE = "NOT_APPLICABLE"
UNKNOWN = "UNKNOWN"
VALUE = "VALUE"

# ---------------------------------------------------------------- reasons ---
MANIFEST_RANGE = "MANIFEST_RANGE"
LOCAL_REFERENCE = "LOCAL_REFERENCE"
NO_LOCKFILE = "NO_LOCKFILE"
TRANSITIVE_GUESS = "TRANSITIVE_GUESS"
PROPERTY_UNRESOLVED = "PROPERTY_UNRESOLVED"
NO_ADVISORY = "NO_ADVISORY"
NOT_PUBLISHED = "NOT_PUBLISHED"

# --- dependency provenance reasons (R1/W2, GAP-14) ---
# Shared vocabulary for the per-field provenance entries written by
# scanner/sbom.py (purl, cvss, dependency_type) and the join's parent
# provenance stamp (scanner/dependency_intelligence.py). Provenance entries
# for populated fields are REASON-ONLY: value_state.resolve() lets a
# provenance ``state`` override its ladder, so a state-bearing entry on a
# populated field would change rendered values.
PURL_DERIVED = "PURL_DERIVED"
PURL_UNRESOLVABLE = "PURL_UNRESOLVABLE"
OFFLINE_CVSS_TABLE = "OFFLINE_CVSS_TABLE"
GATE_MANIFEST_DIRECT = "GATE_MANIFEST_DIRECT"
GATE_NAMED_PARENT = "GATE_NAMED_PARENT"
GATE_PATH_HEAD = "GATE_PATH_HEAD"
GATE_LOCKFILE_MEMBERSHIP = "GATE_LOCKFILE_MEMBERSHIP"
GATE_VERIFIED_TRANSITIVE = "GATE_VERIFIED_TRANSITIVE"
GATE_NO_EVIDENCE = "GATE_NO_EVIDENCE"
VERIFIED_PARENT_EDGE = "VERIFIED_PARENT_EDGE"
PARENT_AMBIGUOUS_MULTIPLE_VERSIONS = "PARENT_AMBIGUOUS_MULTIPLE_VERSIONS"
PARENT_AMBIGUOUS_MULTIPLE_PARENTS = "PARENT_AMBIGUOUS_MULTIPLE_PARENTS"
PARENT_ROOT_DECLARED = "PARENT_ROOT_DECLARED"

#: Reader-facing wording per reason.  MANIFEST_RANGE is pinned verbatim by
#: taskf T-0.3 (``unknown (manifest declares a range, no lockfile pin)``).
REASON_TEXT: dict[str, str] = {
    MANIFEST_RANGE: "manifest declares a range, no lockfile pin",
    NO_LOCKFILE: "no lockfile to pin the version",
    LOCAL_REFERENCE: "local or VCS reference",
    TRANSITIVE_GUESS: "transitive guess",
    PROPERTY_UNRESOLVED: "unresolved manifest property",
    NO_ADVISORY: "no advisory",          # never printed: renders "--"
    NOT_PUBLISHED: "not published",
    PURL_DERIVED: "derived from identity coordinates",
    PURL_UNRESOLVABLE: "identity has no honest purl",
    OFFLINE_CVSS_TABLE: "score from the offline CVSS table",
    GATE_MANIFEST_DIRECT: "declared direct in a manifest",
    GATE_NAMED_PARENT: "named by a parent record",
    GATE_PATH_HEAD: "dependency path starts at a package",
    GATE_LOCKFILE_MEMBERSHIP: "resolved lockfile row",
    GATE_VERIFIED_TRANSITIVE: "verified lockfile edge",
    GATE_NO_EVIDENCE: "no classification evidence",
    VERIFIED_PARENT_EDGE: "verified lockfile edge (single hop)",
    PARENT_AMBIGUOUS_MULTIPLE_VERSIONS: "parent name at several verified versions",
    PARENT_AMBIGUOUS_MULTIPLE_PARENTS: "several verified parents",
    PARENT_ROOT_DECLARED: "declared at the tree root",
}

#: Strings that mean "the producer had nothing to write".  Matched
#: case-insensitively on the whole cell, plus the one long sentence a
#: producer synthesizes as a stand-in for an absent fixed version.
PLACEHOLDERS: frozenset[str] = frozenset({
    "", "unknown", "none", "n/a", "na", "null", "-", "--",
})
_FIXED_SENTENCE_PREFIX = "no fixed version identified"

#: Fields whose value is a claim about a vulnerability.  With no advisory
#: the question does not apply (renders ``--``); with an advisory a missing
#: value is a real data gap (``unknown (not published)``).  Membership is
#: checked on the canonical field name passed to ``cell()``.
ADVISORY_FIELDS: frozenset[str] = frozenset({
    "severity", "cvss", "cvss_version",
    "epss", "epss_score",
    "fixed_versions", "fixed_in",
    "published_date", "published",
    "vulnerability_age", "vulnerability_age_days", "vulnerability_age_bucket",
    "exploitability_decision", "exploitability_action",
    "patch_urgency",
    "cve", "advisory_id",
})

#: Fields where ``UNKNOWN`` is a classifier OUTPUT, not a placeholder.
#: ``scanner.qbom_model.classify_quantum_status`` legitimately returns
#: "UNKNOWN" for an algorithm it could not classify, and the CBOM section
#: prose tells the reader that is what the word means there.  A present
#: value therefore prints as VALUE; only a missing field dashes.
ENUM_UNKNOWN_FIELDS: frozenset[str] = frozenset({"quantum_status"})

#: Field-name fallbacks, preserving the ``or`` chains the renderers used
#: to hand-code.  The first MEANINGFUL value across the chain wins, so a
#: seeded placeholder in the primary key can no longer mask a real value
#: in a secondary key.
ALIASES: dict[str, tuple[str, ...]] = {
    "version": ("version", "current_version"),
    "fixed_versions": ("fixed_versions", "fixed_in"),
    "severity": ("severity", "highest_vulnerability_severity"),
    "cvss": ("cvss", "cvss_score"),
    "epss": ("epss_score", "epss"),
    "purl": ("purl", "package_url", "package_purl"),
    "license": ("license", "license_name", "licenses"),
    "license_declared": ("license_declared", "declared_license", "license"),
    "license_resolved": ("license_resolved", "normalized_license", "license"),
    "normalized_license": ("normalized_license", "license"),
    "exploitability_decision": (
        "exploitability_decision", "exploitability_action",
    ),
    "published_date": ("published_date", "published"),
}


# ------------------------------------------------------------- internals ---
def _scalar_meaningful(value: Any) -> bool:
    """True when ``value`` is a real answer rather than a placeholder."""
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        text = value.strip().casefold()
        if text in PLACEHOLDERS:
            return False
        if text.startswith(_FIXED_SENTENCE_PREFIX):
            return False
        return True
    # Dicts / sets / anything unrenderable through a cell: refuse.
    return False


def _has_value(value: Any, field: str) -> bool:
    """Meaningful-value check with the quantum enum exception."""
    if field in ENUM_UNKNOWN_FIELDS:
        if isinstance(value, str) and value.strip():
            return True
        if value is not None and not isinstance(value, (str, list, tuple)):
            return True
    if isinstance(value, (list, tuple)):
        return any(_scalar_meaningful(v) for v in value)
    return _scalar_meaningful(value)


def _raw_value(pkg: dict, field: str) -> Any:
    """First present value across the field's alias chain.

    Placeholders are skipped so a seeded ``"unknown"`` in the primary key
    cannot mask a real value in a secondary key; if every present value is
    a placeholder, the first one is returned for the ladder to reject.
    """
    keys = ALIASES.get(field) or (field,)
    seen = False
    first_present: Any = None
    for key in keys:
        if key not in pkg:
            continue
        val = pkg[key]
        if not seen:
            first_present = val
            seen = True
        if _has_value(val, field):
            return val
    return first_present if seen else None


def _normalize(value: Any) -> Any:
    """VALUE payload ready for ``render``: lists stripped of placeholders."""
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if _scalar_meaningful(v)]
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str):
        return value.strip()
    return value


# ------------------------------------------------------------------ API ----
def resolve(pkg: Any, field: str, *, has_advisory: bool = True
            ) -> tuple[str, str | None, Any]:
    """Classify ``field`` on ``pkg`` as ``(state, reason, value)``.

    Deterministic and offline: reads only ``pkg`` (its ``field_provenance``
    when present) and the module tables.  Never guesses a value.
    """
    if not isinstance(pkg, dict):
        return ABSENT, None, None

    prov = pkg.get("field_provenance")
    prov = prov.get(field) if isinstance(prov, dict) else None
    prov_state: str | None = None
    prov_reason: str | None = None
    if isinstance(prov, dict):
        raw_state = str(prov.get("state") or "").strip().upper()
        if raw_state in (ABSENT, NOT_APPLICABLE, UNKNOWN, VALUE):
            prov_state = raw_state
        raw_reason = str(prov.get("reason") or "").strip()
        if raw_reason:
            prov_reason = raw_reason.upper()

    # 1. Provenance state decides when present.  A provenance VALUE whose
    #    field has since become a placeholder falls through to the ladder
    #    rather than printing a phantom.
    if prov_state == VALUE:
        candidate = _raw_value(pkg, field)
        if _has_value(candidate, field):
            return VALUE, None, _normalize(candidate)
    elif prov_state == UNKNOWN:
        return UNKNOWN, prov_reason, None
    elif prov_state in (ABSENT, NOT_APPLICABLE):
        return prov_state, None, None

    candidate = _raw_value(pkg, field)

    # 2. Advisory-derived cells are claims about a vulnerability: no
    #    advisory, no question -- dash exactly as CVE/CVSS/EPSS do, even
    #    when a producer seeded a placeholder (or a stray grade) here.
    if field in ADVISORY_FIELDS:
        if not has_advisory:
            return UNKNOWN, NO_ADVISORY, None
        if _has_value(candidate, field):
            return VALUE, None, _normalize(candidate)
        if prov_reason:
            return UNKNOWN, prov_reason, None
        return UNKNOWN, NOT_PUBLISHED, None

    # 3. A real value wins.
    if _has_value(candidate, field):
        return VALUE, None, _normalize(candidate)

    # 4. A provenance reason names the gap.
    if prov_reason:
        return UNKNOWN, prov_reason, None

    # 5. Nothing to say: the cell is absent.
    return ABSENT, None, None


def render(state: str, reason: str | None, value: Any) -> str:
    """Turn a ``(state, reason, value)`` triple into the printed cell.

    ``--`` for absent / not applicable / no advisory / reasonless unknown;
    ``unknown (<human reason>)`` for every other UNKNOWN; the value itself
    for VALUE (lists joined with ``", "``).  A bare unknown word is never
    produced -- ground rule 5.
    """
    if state == VALUE:
        if value is None:
            return "--"
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value)
        return str(value)
    if state == UNKNOWN:
        key = str(reason or "").upper()
        if not reason or key == NO_ADVISORY:
            return "--"
        text = REASON_TEXT.get(key) or str(reason)
        return f"unknown ({text})"
    return "--"


def cell(pkg: Any, field: str, *, has_advisory: bool = True) -> str:
    """Resolve ``field`` on ``pkg`` and render it -- the renderer entry point."""
    state, reason, value = resolve(pkg, field, has_advisory=has_advisory)
    return render(state, reason, value)
