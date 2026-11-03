# -*- coding: utf-8 -*-
"""scanner/purl.py -- offline package-URL generation for SBOM rows.

Why this exists (taskf.md DEF-B / T-3.1): no parser ever wrote ``purl``, so
the PURL column in the Excel SBOM and SCA sheets was permanently ``--``
while the same rows claimed package identity everywhere else.  A purl is
only useful when it pins the SAME component the row describes, so this
module returns ``None`` rather than a versionless or range-versioned URL:
``pkg:npm/express`` without ``@4.17.4`` names every version of express (a
different component), and ``pkg:npm/express@^4.17.4`` is not a version at
all.

Contract: ``purl(name, version, ecosystem) -> str | None``.

  * ``None`` when the version is unresolvable -- placeholder words
    (``unknown`` & friends, one vocabulary with ``core.value_state``),
    ranges/globs/interval specifiers, URLs and VCS/workspace references;
  * ``None`` when the ecosystem has no purl type here, or the name is a
    placeholder; Maven names must split ``group:artifact`` or they are not
    a coordinate at all;
  * npm scope names are percent-encoded (``pkg:npm/%40scope/name@v``);
  * deterministic and offline -- string arithmetic only, no network, no
    clock, no mutation of the inputs (ground rule 8).

Refuses to do: guess a version, invent an ecosystem type, or emit a purl
whose version the manifest could not resolve.
"""
from __future__ import annotations

import re
from urllib.parse import quote

from core.value_state import PLACEHOLDERS

#: Ecosystem spellings the manifest parsers actually write
#: (scanner/sbom.py, scanner/manifests/*) -> purl type.  Lookup is
#: case-insensitive; an unknown ecosystem yields ``None`` rather than a
#: purl type we would have to invent.
_PURL_TYPE_BY_ECOSYSTEM: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "maven": "maven",
    "cargo": "cargo",
    "crates.io": "cargo",
    "nuget": "nuget",
    "gem": "gem",
    "rubygems": "gem",
    "composer": "composer",
    "packagist": "composer",
    "golang": "golang",
    "go": "golang",
}

#: Prefixes that mark a string as NOT a version (URLs, VCS checkouts,
#: workspace/file links, npm aliases).  Checked before the range markers
#: so a URL never sneaks through as a range.
_NON_VERSION_PREFIXES = (
    "git+", "git:", "http://", "https://", "file:", "link:",
    "workspace:", "npm:",
)

#: Characters that only appear in ranges, globs and Maven intervals
#: (``^4.17.4``, ``[1.0,2.0)``, ``>=1,<2``).  An exact pin never
#: contains any of them.
_RANGE_MARKERS = tuple("^~*<>=[](),")

#: npm-style version GLOBS live in the version CORE (``1.x``, ``x``,
#: ``1.2.X``): a bare ``x`` component before any pre-release/build
#: separator is a range, while ``1.0.0-beta.x`` is a real pin.
_GLOB_CORE_RE = re.compile(r"(^|\.)[xX]($|\.)")


def _resolvable(version) -> bool:
    """True when ``version`` is an exact pin a purl may carry."""
    if version is None:
        return False
    text = str(version).strip()
    if not text or text.casefold() in PLACEHOLDERS:
        return False
    if any(ch.isspace() for ch in text):
        return False
    if text.startswith(_NON_VERSION_PREFIXES) or "://" in text:
        return False
    if text.startswith("#") or text.endswith("*"):
        return False
    if any(ch in text for ch in _RANGE_MARKERS):
        return False
    core = text.split("-", 1)[0].split("+", 1)[0]
    if _GLOB_CORE_RE.search(core):
        return False
    return True


def purl(name, version, ecosystem) -> str | None:
    """Package URL for one component, or ``None`` when it cannot be one.

    Deterministic, offline, pure: the same inputs always yield the same
    string and nothing is mutated.  ``None`` means "no honest purl exists
    here" -- a versionless or range-versioned purl would name a different
    component than the row it sits on (taskf T-3.1).
    """
    if not _resolvable(version):
        return None

    name_s = str(name or "").strip()
    if not name_s or name_s.casefold() in PLACEHOLDERS:
        return None

    eco_s = str(ecosystem or "").strip().casefold()
    ptype = _PURL_TYPE_BY_ECOSYSTEM.get(eco_s)
    if ptype is None:
        return None

    ver_s = str(version).strip()

    if ptype == "maven":
        # The parser always writes ``group:artifact``; without the colon
        # there is no coordinate, and a maven purl cannot be built honestly.
        if ":" not in name_s:
            return None
        group, artifact = (part.strip() for part in name_s.split(":", 1))
        if (not group or group.casefold() in PLACEHOLDERS
                or not artifact or artifact.casefold() in PLACEHOLDERS):
            return None
        return "pkg:maven/%s/%s@%s" % (
            quote(group, safe=""),
            quote(artifact, safe=""),
            quote(ver_s, safe=""),
        )

    # Every other type: the name travels whole (npm scopes keep their
    # slash, ``@`` percent-encodes to %40; go/composer names keep their
    # path separators), the version is percent-encoded fully.
    return "pkg:%s/%s@%s" % (
        ptype,
        quote(name_s, safe="/"),
        quote(ver_s, safe=""),
    )
