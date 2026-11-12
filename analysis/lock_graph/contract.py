"""Common lock-graph contract (R2.1, approved R2.0).

One edge schema and one extraction envelope for every ecosystem extractor;
the npm engine's proven shape is a strict subset, mapped at the ADAPTER layer
(`analysis/lock_graph/npm_adapter.py`) only -- the engine itself is not
modified (master prompt §5).

Honesty is structural, not aspirational:

- Only VERIFIED edges may join (the join filters on confidence).
- VERIFIED requires a four-part identity (both names, both exact versions);
  anything weaker downgrades to UNRESOLVED -- never guessed into VERIFIED.
- AMBIGUOUS carries the candidate instances and never mints a parent.
- UNSUPPORTED / INVALID are counted and disclosed, never bridged.
- PURLs come from the single authority (scanner.purl); an unresolvable
  identity yields an empty purl, not an invented one.
- Fingerprints hash the canonical identity tuple only, so lockfile paths and
  section labels cannot move them (run-to-run determinism).
"""

from __future__ import annotations

import hashlib
import re

from scanner.purl import purl as _purl


def norm_pypi(name: str) -> str:
    """PEP 503 canonical PyPI identity: ``[-_.]+ -> -``, casefolded.

    Single source for the R2 extractors (poetry/uv) -- the verified-edge
    join normalizes with the same rule (its own inlined copy, import-light
    by design); the equivalence of the two spellings is pinned by test
    (test_lock_graph_contract.py::test_norm_pypi_matches_join_identity).
    """
    return re.sub(r"[-_.]+", "-", str(name or "").strip()).casefold()

VERIFIED = "VERIFIED"
AMBIGUOUS = "AMBIGUOUS"
UNRESOLVED = "UNRESOLVED"
UNSUPPORTED = "UNSUPPORTED"
INVALID = "INVALID"

#: Envelope status vocabulary (npm engine's statuses are a subset).
VERIFIED_EDGES_AVAILABLE = "VERIFIED_EDGES_AVAILABLE"
NO_VERIFIED_EDGES = "NO_VERIFIED_EDGES"
UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
EXTRACTION_ERROR = "EXTRACTION_ERROR"

_EVIDENCE_POLICY = "AUTHORITATIVE_RELATIONSHIP_FIELDS_ONLY"


def edge_fingerprint(ecosystem: str, parent_name: str, parent_version: str,
                     child_name: str, child_version: str) -> str:
    """Stable identity hash over the five identity fields, in this order.

    Source paths and section labels deliberately do not participate: the
    same resolved relationship must produce the same fingerprint regardless
    of where the lockfile lived or how the record was labelled.
    """
    canonical = "\x1f".join((
        str(ecosystem), str(parent_name), str(parent_version),
        str(child_name), str(child_version),
    ))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_edge(*, ecosystem: str, parent_name: str, parent_version: str,
               child_name: str, child_version: str, source: str,
               source_location: str, evidence_source: str,
               scope: str = "runtime", qualifiers: dict | None = None,
               confidence: str = "", ambiguity: dict | None = None,
               resolution_status: str = "", kind: str = "") -> dict:
    """Build one contract edge; downgrade confidence when identity is weak.

    ``confidence`` semantics (R2_GRAPH_CONTRACT.md §3):
    - empty (default): VERIFIED when the four identity parts are present,
      else UNRESOLVED -- a versionless or nameless endpoint is disclosed,
      never promoted;
    - explicit AMBIGUOUS/UNSUPPORTED/INVALID pass through (the extractor
      decided); AMBIGUOUS edges carry ``ambiguity`` and resolve no child
      version.
    """
    parent_name = str(parent_name or "").strip()
    child_name = str(child_name or "").strip()
    parent_version = str(parent_version or "").strip()
    child_version = str(child_version or "").strip()

    ecosystem = str(ecosystem or "").strip().casefold()
    parent_purl = ""
    if parent_name and parent_version:
        parent_purl = _purl(parent_name, parent_version, ecosystem) or ""
    child_purl = ""
    if child_name and child_version:
        child_purl = _purl(child_name, child_version, ecosystem) or ""

    conf = str(confidence or "").strip().upper()
    if conf == VERIFIED:
        # VERIFIED demands an honestly expressible identity on both sides:
        # presence is not enough -- a version the PURL authority cannot
        # resolve ("unknown", a range, a URL) yields no purl and no
        # VERIFIED edge.
        if not (parent_purl and child_purl):
            conf = UNRESOLVED
    elif conf not in (AMBIGUOUS, UNSUPPORTED, INVALID):
        conf = VERIFIED if (parent_purl and child_purl) else UNRESOLVED

    edge = {
        "ecosystem": ecosystem,
        "parent_name": parent_name,
        "parent_version": parent_version,
        "child_name": child_name,
        "child_version": child_version,
        "parent_purl": parent_purl,
        "child_purl": child_purl,
        "source": str(source or ""),
        "source_location": str(source_location or ""),
        "evidence_source": str(evidence_source or ""),
        "scope": str(scope or "runtime"),
        "qualifiers": dict(qualifiers or {}),
        "kind": str(kind or ""),
        "resolution_status": str(resolution_status or ""),
        "confidence": conf,
    }
    if ambiguity:
        edge["ambiguity"] = dict(ambiguity)
    if conf == VERIFIED:
        edge["fingerprint"] = edge_fingerprint(
            ecosystem, parent_name, parent_version, child_name, child_version)
    return edge


def extraction_result(*, engine: str, source: str, format_version: str,
                      graph_status: str, edges: list,
                      tallies: dict | None = None,
                      limitations: list | None = None,
                      membership_packages: int | None = None) -> dict:
    """Extraction envelope -- same top-level shape as the npm engine's, so
    main.py's per-file merge and disclosures are unchanged."""
    edges = list(edges or [])
    counts: dict[str, int] = {
        "verified": 0, "ambiguous": 0, "unresolved": 0,
        "unsupported": 0, "invalid": 0,
    }
    for edge in edges:
        conf = str((edge or {}).get("confidence") or "").strip().upper()
        conf_key = conf.casefold()
        if conf_key in counts:
            counts[conf_key] += 1
        else:
            counts["invalid"] += 1
    counts.setdefault("duplicate_records_dropped", 0)
    if tallies:
        for key, value in tallies.items():
            if key in counts and isinstance(value, int):
                counts[key] = value
    result = {
        "engine": str(engine),
        "source": str(source),
        "format_version": str(format_version),
        "graph_status": str(graph_status),
        "verified_edge_count": counts["verified"],
        "edges": edges,
        "tallies": counts,
        "evidence_policy": _EVIDENCE_POLICY,
        "limitations": [str(l) for l in (limitations or [])],
    }
    if membership_packages is not None:
        result["membership_packages"] = int(membership_packages)
    return result
