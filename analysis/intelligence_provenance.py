"""Provenance tokens for offline / static threat-intelligence values.

Why this module exists
----------------------
R-SecOpsX currently derives **every** EPSS score and **every** CISA KEV match
from small seed tables baked into this repository
(``STATIC_EPSS_SCORES`` in ``analysis/epss_intelligence_engine.py`` and
``KNOWN_EXPLOITED_CVES`` in ``analysis/kev_intelligence_engine.py``).  It does
**not** query the live FIRST.org EPSS API or the live CISA KEV catalog; those
are gap-register items **G-001** and **G-002**.

A report reader looking at ``EPSS 0.975`` or ``KEV No`` cannot tell whether the
number came from a live feed or from an eight-entry offline table.  That is an
active honesty defect (**G-003**), so every EPSS/KEV value must travel with an
explicit provenance token that every report surface renders.

Token vocabulary
----------------
``STATIC_REFERENCE``
    The value came from an offline table compiled into the build.  It is a
    reference point, not a current exploit-probability statement.
``LIVE_FEED``
    The value came from a live upstream feed, with a dated fetch or catalog
    version travelling alongside it.  Produced by
    :mod:`analysis.live_intel_feeds` when G-001/G-002 are wired and reachable;
    every other path is forbidden to assert it (see
    ``tests/test_v11_g003_static_reference_labelling.py::test_03``).
``NOT_AVAILABLE``
    No value could be produced (for example, no EPSS row matched, or the item
    carries no vulnerability identifier to have looked up at all).

Contract
--------
* Provenance is an **honesty label only**.  It never alters a score, bucket,
  priority, severity, reachability state or release decision.
* Provenance never gates anything: it does not turn UNKNOWN into UNREACHABLE
  and does not turn an offline miss into "not exploited".
* A ``kev_status`` of ``False`` with ``kev_provenance == STATIC_REFERENCE``
  means "absent from the offline table", **not** "absent from the live CISA
  KEV catalog".  The same ``False`` with ``kev_provenance == LIVE_FEED``
  *does* mean absent from the catalog, and says so with its catalog version.
* Only :func:`known_provenance` may launder an inherited value into the
  vocabulary; anything unrecognised degrades to ``NOT_AVAILABLE`` rather than
  being passed through.
"""

from __future__ import annotations

__all__ = [
    "STATIC_REFERENCE",
    "LIVE_FEED",
    "NOT_AVAILABLE",
    "PROVENANCE_TOKENS",
    "EPSS_PROVENANCE",
    "KEV_PROVENANCE",
    "STATIC_INTELLIGENCE_NOTE",
    "intelligence_note",
    "known_provenance",
    "provenance_pair",
    "note_from_payload",
]

STATIC_REFERENCE = "STATIC_REFERENCE"
LIVE_FEED = "LIVE_FEED"
NOT_AVAILABLE = "NOT_AVAILABLE"

# The closed set any provenance-bearing field may ever hold.
PROVENANCE_TOKENS = frozenset({STATIC_REFERENCE, LIVE_FEED, NOT_AVAILABLE})

# Default label for a value resolved from the compiled-in seed tables.  A live
# lookup never consults these constants — it writes LIVE_FEED directly with its
# own dated snapshot — so flipping them would mislabel the offline path.
EPSS_PROVENANCE = STATIC_REFERENCE
KEV_PROVENANCE = STATIC_REFERENCE

# Single human-readable sentence used verbatim by the PDF and Excel renderers
# so the two cannot drift apart.
STATIC_INTELLIGENCE_NOTE = (
    "EPSS and KEV values in this report carry provenance "
    f"'{STATIC_REFERENCE}': they are read from offline seed tables compiled into "
    "the R-SecOpsX build, not from the live FIRST.org EPSS API or the live CISA "
    "KEV catalog. A KEV flag of 'No' therefore means 'not present in the offline "
    "table', not 'confirmed not exploited'."
)


def intelligence_note(epss_provenance: str, kev_provenance: str,
                      *, epss_as_of: str | None = None,
                      kev_as_of: str | None = None) -> str:
    """The honesty sentence for *this* payload.

    G-001/G-002 wired the live feeds, so the note can no longer be a constant:
    claiming "not from the live feed" when the value **is** live would be the
    same class of defect as the reverse.  The sentence is therefore derived
    from the provenance actually observed in the data, per field, and any
    field still on the seed tables keeps the full offline caveat.
    """
    parts: list[str] = []

    if epss_provenance == LIVE_FEED:
        dated = f" (as of {epss_as_of})" if epss_as_of else ""
        parts.append(
            f"EPSS scores carry provenance '{LIVE_FEED}'{dated}: read from the "
            "live FIRST.org EPSS API."
        )
    elif epss_provenance == NOT_AVAILABLE:
        parts.append(
            f"EPSS provenance is '{NOT_AVAILABLE}': no score could be resolved "
            "for this payload - the feed returned none for the identifier, or "
            "there was no identifier to ask about - so no score is shown."
        )
    else:
        parts.append(
            f"EPSS scores carry provenance '{epss_provenance}': read from an "
            "offline seed table compiled into the R-SecOpsX build, not from the "
            "live FIRST.org EPSS API."
        )

    if kev_provenance == LIVE_FEED:
        dated = f" (catalog {kev_as_of})" if kev_as_of else ""
        parts.append(
            f"KEV flags carry provenance '{LIVE_FEED}'{dated}: checked against "
            "the live CISA Known Exploited Vulnerabilities catalog, so a 'No' "
            "means the identifier is absent from that catalog."
        )
    elif kev_provenance == NOT_AVAILABLE:
        parts.append(
            f"KEV provenance is '{NOT_AVAILABLE}': no catalog lookup was made "
            "for this payload - there was nothing to look up, or no "
            "vulnerability identifier to look up - so the flag shown is the "
            "absence of a question rather than an answer."
        )
    else:
        parts.append(
            f"KEV flags carry provenance '{kev_provenance}': checked against "
            "an offline seed table compiled into the R-SecOpsX build, not the "
            "live CISA KEV catalog. A KEV flag of 'No' therefore means 'not "
            "present in the offline table', not 'confirmed not exploited'."
        )

    return " ".join(parts)


def known_provenance(value: object, default: str = NOT_AVAILABLE) -> str:
    """Return ``value`` if it is a canonical token, else ``default``.

    The one legitimate way for a downstream engine to inherit a provenance
    written by an upstream one.  Without it, a caller that smuggled in an
    arbitrary string would have that string rendered verbatim into the PDF,
    Excel, VEX and CycloneDX outputs, and the vocabulary would be a convention
    rather than a closed set.  Unrecognised degrades to ``NOT_AVAILABLE`` —
    "we do not know where this came from" — never to ``STATIC_REFERENCE``,
    because relabelling an unknown as offline would itself be a false claim.
    """
    return value if value in PROVENANCE_TOKENS else default


def provenance_pair(payload: object) -> tuple[str, str]:
    """``(epss_provenance, kev_provenance)`` for a payload, honestly defaulted.

    Reads the payload-root banner first (one authoritative statement), then the
    per-engine summaries, and only then falls back to ``STATIC_REFERENCE`` —
    which is the correct default because an *unknown* payload in this product
    is one that has not been through a live feed.
    """
    if not isinstance(payload, dict):
        return STATIC_REFERENCE, STATIC_REFERENCE

    meta = payload.get("metadata")
    banner = (meta or {}).get("epss_kev_provenance") or {}
    eis = payload.get("epss_intelligence_summary") or {}
    kis = payload.get("kev_intelligence_summary") or {}

    epss = known_provenance(
        banner.get("epss") or eis.get("provenance"), STATIC_REFERENCE
    )
    kev = known_provenance(
        banner.get("kev") or kis.get("kev_provenance") or kis.get("provenance"),
        STATIC_REFERENCE,
    )
    return epss, kev


def note_from_payload(payload: object) -> str:
    """The honesty sentence for *this* payload.

    The PDF and Excel renderers both call this instead of reading
    :data:`STATIC_INTELLIGENCE_NOTE` directly, so the caption above a table of
    scores is derived from the provenance those very scores carry.  Reading the
    constant would reintroduce G-003's mirror-image defect the moment a feed
    went live: a workbook full of ``LIVE_FEED`` values captioned "not from the
    live feed".

    Falls back to :data:`STATIC_INTELLIGENCE_NOTE` when the payload carries no
    intelligence summaries at all, which is the honest description of a
    payload that never consulted one.
    """
    if not isinstance(payload, dict):
        return STATIC_INTELLIGENCE_NOTE

    meta = payload.get("metadata")
    note = (meta or {}).get("epss_kev_provenance")
    if isinstance(note, dict) and note.get("note"):
        return str(note["note"])

    eis = payload.get("epss_intelligence_summary") or {}
    kis = payload.get("kev_intelligence_summary") or {}
    if not (eis or kis):
        return STATIC_INTELLIGENCE_NOTE

    epss, kev = provenance_pair(payload)
    return intelligence_note(
        epss,
        kev,
        epss_as_of=eis.get("as_of"),
        kev_as_of=kis.get("catalog_version") or kis.get("as_of"),
    )
