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
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [v if isinstance(v, dict) else {"detail": str(v)} for v in value]
    return [{"detail": str(value)}]


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


__all__ = [
    "correlate_cbom_to_qbom",
    "derive_algorithm",
    "summarize_quantum_exposure",
    "classify_quantum_status",
]