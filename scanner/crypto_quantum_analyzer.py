"""Correlate cryptographic assets (CBOM) to post-quantum exposure (QBOM).

WHY THIS MODULE EXISTS
----------------------
A CBOM says what cryptographic primitives an application uses. A QBOM asks the
separate question of which of those a cryptographically relevant quantum
computer breaks, and what the migration order should be. The two are different
axes: AES-128 is impact-assessed rather than broken (Grover halves the key), and
ed25519 is broken (Shor breaks it precisely because it is strong). Anything that
conflates the two -- a key-size threshold, most obviously -- gets both wrong.

THE SCHEMA BRIDGE, AND WHY IT IS MARKED
----------------------------------------
This correlator originally read `asset.get("algorithm")` and skipped anything
without it. Measured against the prodtest corpus, `scanner/cbom.py` emits

    {bom_type, category, component, evidence, file, line, recommendation, risk}

Of the ten fields this function read, only `evidence` existed. Against 200 real
entries it produced ZERO QBOM assets -- not a bad result, an empty one. The
function was written against a schema this product does not emit.

So an entry's algorithm is now DERIVED from whatever it does carry, and the
provenance travels on the asset:

    algorithm_provenance = EXPLICIT                  the entry named an algorithm
    algorithm_provenance = INFERRED_FROM_DISPLAY_NAME  read off `component`

That distinction is the whole point. An explicit `algorithm` is an assertion the
scanner made; `component` is a human-readable label like "DES / 3DES" and
anything inferred from it is a reading of that label. A consumer that cannot tell
the two apart will treat a guess as a finding.

This is the third instance of one defect class. The PQ handoff already records
two: `crypto_misuse_engine.py` and `security_control_coverage_engine.py` read
`component["algorithm"]` / `["primitive"]`, keys `cbom.py` never emits, so both
enrichment paths are dead today. The durable fix is to widen `cbom.py`'s item
shape into a superset; this module derives what it can in the meantime and says
so, rather than depending on a field that does not exist.
"""
from __future__ import annotations

from typing import Any

from .qbom_model import (
    classify_quantum_status,
    create_qbom_asset,
    normalize_algorithm,
    pqc_family_of,
    stable_qbom_id,
)

# Occurrence locations retained per aggregated asset. The true count always
# travels in `occurrence_count`, so truncating the list loses detail, never
# information.
_MAX_OCCURRENCES = 25

# Fields that may carry an explicit algorithm on an incoming asset, in priority
# order. `algorithm` first because an explicit assertion outranks any inference.
_ALGORITHM_FIELDS = ("algorithm", "primitive", "crypto_algorithm", "algorithm_name")

# Labels that are not algorithms at all. "Hardcoded Private Key" names a defect,
# not a primitive; classifying it would mean inventing a quantum claim about key
# management. Such an entry is carried through unclassified.
_NON_ALGORITHM_LABELS = {
    "private-key",
    "hardcoded-private-key",
    "key-material",
    "tls-ssl",
    "unknown",
    "n-a",
    "na",
}


def derive_algorithm(asset: dict[str, Any]) -> tuple[str | None, str]:
    """Resolve an algorithm for an asset, and say how it was resolved.

    Returns (algorithm, provenance). `algorithm` is None when the entry carries
    nothing that names a primitive, which is not the same as naming an unknown
    one -- the difference between "no primitive here" and "a primitive we cannot
    name", and the two must not collapse.
    """
    for field in _ALGORITHM_FIELDS:
        value = asset.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip(), "EXPLICIT"

    # `component` is this product's own display label for the primitive.
    for field in ("component", "crypto_component", "name"):
        value = asset.get(field)
        if isinstance(value, str) and value.strip():
            normalized = normalize_algorithm(value)
            if normalized and normalized not in _NON_ALGORITHM_LABELS:
                return value.strip(), "INFERRED_FROM_DISPLAY_NAME"

    return None, "NOT_APPLICABLE"


def correlate_cbom_to_qbom(
    cbom_assets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Correlate CBOM assets into QBOM assets.

    Identical cryptographic assets are aggregated rather than repeated, because a
    project using 3DES in 3,111 places has one cryptographic asset and 3,111 use
    sites, and reporting 3,111 rows would bury the four assets that matter.

    The aggregation is EXPLICIT, never silent. Each output carries
    `occurrence_count` and the locations behind it, so the reader can always see
    the difference between "this project uses one weak cipher" and "this project
    uses one weak cipher 3,111 times". A previous version deduplicated on
    identity alone and emitted no count, which turned 3,111 CBOM entries into a
    4-asset inventory with no indication that anything had been dropped -- a 99.9%
    reduction presented as an inventory, which is worse than no inventory.

    Entries naming no primitive are skipped rather than guessed at: an absent
    algorithm is not an UNKNOWN algorithm, and reporting it as one would put an
    unverifiable claim in a security inventory.
    """
    by_id: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for asset in cbom_assets or []:
        if not isinstance(asset, dict):
            continue

        algorithm, provenance = derive_algorithm(asset)

        if not algorithm:
            continue

        # `component` is a display label, not an identity, so it must not leak
        # into the id -- two entries labelled "RSA" for the same library are one
        # asset, not two. Key size stays in the digest because it is identity.
        resolved_for_id = (
            algorithm if provenance == "EXPLICIT" else normalize_algorithm(algorithm)
        )

        qbom = create_qbom_asset(
            algorithm=algorithm,
            key_size=asset.get("key_size"),
            application=asset.get("application"),
            library=asset.get("library"),
            library_version=asset.get("library_version"),
            protocol=asset.get("protocol"),
            certificate=asset.get("certificate"),
            evidence=_normalize_evidence(asset.get("evidence")),
            confidence=asset.get("confidence", 0.0),
            cbom_asset_id=asset.get("asset_id"),
        )

        # Re-key on the resolved identity, since create_qbom_asset hashed the
        # display string.
        qbom.qbom_id = stable_qbom_id(
            resolved_for_id,
            asset.get("application"),
            asset.get("asset_id"),
            asset.get("key_size"),
        )

        existing = by_id.get(qbom.qbom_id)

        if existing is None:
            result = qbom.to_dict()
            result["normalized_algorithm"] = normalize_algorithm(algorithm)
            result["algorithm_provenance"] = provenance

            # An inferred label is weaker evidence than an asserted algorithm, so
            # it carries a lower confidence ceiling. Confidence is the field that
            # tells a reader how much weight to put on the classification.
            if provenance == "INFERRED_FROM_DISPLAY_NAME":
                result["confidence"] = min(result.get("confidence") or 0.0, 0.5)
                result["classification_basis"] = (
                    "derived from the CBOM display label, not from a parsed "
                    "algorithm identifier"
                )

            result["occurrence_count"] = 0
            result["occurrences"] = []
            result["relationship"] = {
                "source": asset.get("asset_id")
                or asset.get("file")
                or f"{asset.get('category', 'cbom-entry')}",
                "target": qbom.qbom_id,
                "type": "CBOM_CORRELATES_WITH_QBOM",
            }
            by_id[qbom.qbom_id] = result
            order.append(qbom.qbom_id)
            existing = result

        existing["occurrence_count"] += 1
        if len(existing["occurrences"]) < _MAX_OCCURRENCES:
            existing["occurrences"].append(
                {
                    "file": asset.get("file"),
                    "line": asset.get("line"),
                    "component": asset.get("component") or asset.get("algorithm"),
                }
            )

    for qbom_id in order:
        asset = by_id[qbom_id]
        if asset["occurrence_count"] > len(asset["occurrences"]):
            asset["occurrences_truncated"] = (
                asset["occurrence_count"] - len(asset["occurrences"])
            )

    return [by_id[q] for q in order]


def _normalize_evidence(value: Any) -> list[dict[str, Any]]:
    """Evidence is typed as a list of dicts; the corpus hands us strings.

    A bare string is not a finding, so it is wrapped with its own shape rather
    than discarded -- dropping it would strip the only field the real schema
    actually provides.

    Every string is PEM-redacted first. The CBOM private-key rule's evidence
    is the PEM block itself, and this list is serialized verbatim into
    Security_QBOM.pq.json -- without redaction the PQ migration document
    republished the key material the scan exists to report, which the leak
    audit (probe_leak_audit) caught scanning every artifact a run produces.
    """
    from core.redaction import redact_pem_deep

    if value is None:
        return []
    if isinstance(value, list):
        return [redact_pem_deep(v) if isinstance(v, dict)
                else {"detail": redact_pem_deep(str(v))} for v in value]
    return [{"detail": redact_pem_deep(str(value))}]


def summarize_quantum_exposure(
    correlated: list[dict[str, Any]],
) -> dict[str, Any]:
    """Counts by quantum status, plus the migration queue.

    UNKNOWN is reported as its own bucket rather than folded into a safe one.
    A summary that says "0 at risk" because everything was unclassifiable is the
    most dangerous artifact this could produce.
    """
    counts: dict[str, int] = {}
    for asset in correlated:
        status = asset.get("quantum_status", "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1

    queue = sorted(
        (
            {
                "qbom_id": a.get("qbom_id"),
                "algorithm": a.get("algorithm"),
                "key_size": a.get("key_size"),
                "application": a.get("application"),
                "migration_priority": a.get("migration_priority"),
                "algorithm_provenance": a.get("algorithm_provenance"),
                "classification_note": a.get("classification_note"),
            }
            for a in correlated
            if a.get("quantum_status") in {"QUANTUM_VULNERABLE",
                                          "QUANTUM_MARGIN_CRITICAL"}
        ),
        key=lambda a: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "NONE": 3, "UNKNOWN": 4}.get(
                a.get("migration_priority", "UNKNOWN"), 5
            ),
            str(a.get("algorithm") or ""),
        ),
    )

    classified = sum(v for k, v in counts.items() if k != "UNKNOWN")
    usage_sites = sum(int(a.get("occurrence_count") or 0) for a in correlated)

    return {
        "total_assets": len(correlated),
        "total_usage_sites": usage_sites,
        "classified": classified,
        "unclassified": counts.get("UNKNOWN", 0),
        "needs_migration": counts.get("QUANTUM_VULNERABLE", 0)
        + counts.get("QUANTUM_MARGIN_CRITICAL", 0),
        "by_quantum_status": counts,
        "migration_queue": queue,
        "aggregation_note": (
            f"{usage_sites} CBOM usage sites resolve to {len(correlated)} distinct "
            "cryptographic assets. Each asset carries its occurrence_count."
        ) if usage_sites != len(correlated) else None,
        "coverage_note": (
            f"{classified} of {len(correlated)} assets could be classified; "
            f"{counts.get('UNKNOWN', 0)} could not and are reported as UNKNOWN "
            "rather than assumed safe."
            if counts.get("UNKNOWN")
            else f"all {len(correlated)} assets were classified"
        ),
    }


# The quantum statuses a pack must cover. Semantic order (broken classes
# first, then already-post-quantum, then impact-assessed, then unknown) so the
# emitted status_grid reads the same way the migration queue does.
_POLICY_STATUSES = (
    "QUANTUM_VULNERABLE",
    "QUANTUM_MARGIN_CRITICAL",
    "PQC",
    "QUANTUM_IMPACT_ASSESSED",
    "UNKNOWN",
)


def _policy_token(normalized_algorithm: str | None) -> str:
    """The token the policy packs match on.

    Family-reduced for a PQC observation, so ML-KEM-768 and Kyber768 both
    arrive as their family and a pack can rule on the family rather than on a
    parameter spelling. Symmetric and hash tokens pass through unchanged --
    their parameter IS the policy-relevant fact (AES-256 versus AES-128 is
    precisely what CNSA and ANSSI care about), so it must never be stripped.
    """
    normalized = (normalized_algorithm or "").strip().lower()
    return pqc_family_of(normalized) or normalized


def _override_matches(token: str, entry: str) -> bool:
    """Exact token match, or the token as a hyphen-separated prefix.

    "aes" matches "aes" and "aes-128" but not "aesgcm"; "ml-kem" matches
    "ml-kem-768". Packs relying on prefix shadowing (a generic "aes" REVIEW
    row after a specific "aes-256" ACCEPTABLE row) depend on declaration
    order -- see verdict_for_asset.
    """
    if not token or not entry:
        return False
    return token == entry or token.startswith(entry + "-")


def verdict_for_asset(asset: dict[str, Any], pack: dict[str, Any]) -> dict[str, Any]:
    """One pack's verdict for one correlated QBOM asset.

    Evaluation order is deliberate and documented in the artifact:
    algorithm_overrides first (in declaration order, FIRST MATCH WINS), then
    the pack's status grid. The override layer exists to prevent false
    passes -- SHA-1 classifies QUANTUM_IMPACT_ASSESSED, which would read
    ACCEPTABLE in a naive status-only matrix even though SHA-1 has been
    collision-broken since 2017, and CNSA's suite is AES-256 specifically,
    not "AES". The status grid alone would pass both.

    The returned cell carries `rule` so a reader can always see WHICH layer
    produced the verdict, and `matched` when an override fired.
    """
    token = _policy_token(asset.get("normalized_algorithm"))

    for rule in pack.get("algorithm_overrides") or ():
        if any(_override_matches(token, str(m).lower())
               for m in rule.get("match_any") or ()):
            return {
                "verdict": rule["verdict"],
                "note": rule["note"],
                "rule": "algorithm",
                "matched": token,
            }

    status = asset.get("quantum_status") or "UNKNOWN"
    grid = pack.get("position_by_status") or {}
    row = grid.get(status) or grid.get("UNKNOWN") or {
        "verdict": "REVIEW",
        "note": "Pack has no position for this status.",
    }
    return {"verdict": row["verdict"], "note": row["note"], "rule": "status"}


def build_pqc_verdict_matrix(
    correlated: list[dict[str, Any]],
) -> dict[str, Any]:
    """Multi-jurisdiction PQC verdict matrix over this scan's QBOM assets.

    For every asset the correlator produced and every policy pack
    (BSI/ANSSI/NIST IR 8547/CNSA 2.0 -- see core.qbom_mappings), one cell of
    {verdict, note, rule}. The matrix also ships the status grid (pack x
    quantum-status, computed without any asset) so the cross-product is
    visible even for an empty inventory, the shared verdict vocabulary, the
    rollup counts, and the citations for each pack.

    Honesty properties, in the order they would fail if dropped:

    * Packs are static transcriptions with document, date and URL. Nothing
      is fetched at scan time; a date that could not be confirmed against
      the primary document is absent rather than carried from secondary
      reporting.
    * A verdict is a DERIVATION of this scan's classification and a pack's
      published position -- not a compliance certification, not legal
      advice. The limits say so.
    * UNKNOWN stays REVIEW everywhere. No pack is allowed to turn an
      unclassifiable observation into a pass.
    * Only identity fields travel (qbom_id, algorithm names, status, key
      size, count). Evidence strings -- the place PEM lives -- are not
      copied in, and the algorithm strings are PEM-redacted anyway on the
      way in, so the matrix cannot republish key material even if an
      upstream CBOM field carried some.
    * Deterministic: pack order, asset order and rollup keys are fixed, so
      two runs over the same payload produce byte-identical matrices.
    """
    from core.qbom_mappings import (  # local: avoids an import cycle with
        PQC_POLICY_PACKS,             # core.qbom_mappings' own deferred
        PQC_VERDICT_VOCABULARY,       # import of this module
    )
    from core.redaction import redact_pem_deep

    packs = PQC_POLICY_PACKS
    correlated = correlated or []

    rollup: dict[str, dict[str, int]] = {
        pack["id"]: {v: 0 for v in sorted(PQC_VERDICT_VOCABULARY)}
        for pack in packs
    }

    asset_rows: list[dict[str, Any]] = []
    for asset in correlated:
        verdicts: dict[str, dict[str, Any]] = {}
        for pack in packs:
            cell = verdict_for_asset(asset, pack)
            verdicts[pack["id"]] = cell
            rollup[pack["id"]][cell["verdict"]] = rollup[pack["id"]].get(
                cell["verdict"], 0) + 1

        raw_algorithm = asset.get("algorithm")
        raw_normalized = asset.get("normalized_algorithm")
        asset_rows.append({
            "qbom_id": asset.get("qbom_id"),
            "algorithm": (redact_pem_deep(raw_algorithm)
                          if isinstance(raw_algorithm, str)
                          else raw_algorithm),
            "normalized_algorithm": (redact_pem_deep(raw_normalized)
                                     if isinstance(raw_normalized, str)
                                     else raw_normalized),
            "quantum_status": asset.get("quantum_status") or "UNKNOWN",
            "key_size": asset.get("key_size"),
            "occurrence_count": asset.get("occurrence_count"),
            "verdicts": verdicts,
        })

    status_grid: dict[str, dict[str, dict[str, str]]] = {}
    for pack in packs:
        grid = pack.get("position_by_status") or {}
        status_grid[pack["id"]] = {
            status: dict(grid.get(status) or grid.get("UNKNOWN") or {
                "verdict": "REVIEW",
                "note": "Pack has no position for this status.",
            })
            for status in _POLICY_STATUSES
        }

    return {
        "question": (
            "For each cryptographic asset this scan observed, what does each "
            "cited jurisdiction's published post-quantum policy position say "
            "about it?"
        ),
        "derivation": (
            "cell = this scan's quantum_status classification x each pack's "
            "status grid, with pack-specific algorithm overrides applied "
            "FIRST when the observed family or parameter is named by the "
            "pack (first match wins, declaration order). Packs are static "
            "transcriptions from the primary sources cited; no external "
            "service is consulted at scan time."
        ),
        "packs": [
            {
                "id": pack["id"],
                "jurisdiction": pack["jurisdiction"],
                "authority": pack["authority"],
                "document": pack["document"],
                "document_status": pack["document_status"],
                "published": pack["published"],
                "source_url": pack["source_url"],
                "related_sources": pack.get("related_sources") or [],
                "scope": pack["scope"],
                "hybrid_position": pack["hybrid_position"],
                "key_dates": pack.get("key_dates") or {},
                "approved_pqc": pack.get("approved_pqc") or [],
            }
            for pack in packs
        ],
        "vocabulary": PQC_VERDICT_VOCABULARY,
        "status_grid": status_grid,
        "assets": asset_rows,
        "rollup": rollup,
        "totals": {
            "assets": len(asset_rows),
            "verdict_cells": len(asset_rows) * len(packs),
            "jurisdictions": len(packs),
        },
        "limits": [
            "A derivation, not a compliance certification: verdicts combine "
            "this scan's own quantum classification with each pack's "
            "published position as transcribed on the pack's document date. "
            "Not legal advice.",
            "Packs are snapshots. Policy moves; verify against the cited "
            "source before relying on a date or an algorithm list.",
            "NIST IR 8547 is an INITIAL PUBLIC DRAFT (comments closed "
            "2025-01-10): its dates are NIST's expected approach, not a "
            "standard in force.",
            "CNSA 2.0 binds US National Security Systems only; elsewhere it "
            "is a direction-of-travel reference, not a requirement.",
            "Hybrid usage (BSI, ANSSI) is not observable from static source "
            "analysis: an ALIGNED PQC verdict does not confirm hybrid "
            "deployment.",
            "Verdicts cover the assets this scan observed, within the "
            "CBOM's scope. Absence from this matrix is not evidence of "
            "absence in the deployed system.",
            "REVIEW is never a pass. It means the observation could not be "
            "mapped to the pack's position and a human must decide.",
        ],
    }


__all__ = [
    "build_pqc_verdict_matrix",
    "correlate_cbom_to_qbom",
    "derive_algorithm",
    "summarize_quantum_exposure",
    "verdict_for_asset",
    "classify_quantum_status",
]