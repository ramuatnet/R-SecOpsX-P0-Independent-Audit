"""FND-03: the span table — a name for every slice bound in analysis/.

ftasks Phase 0, FND-03: "Named windows replace magic numbers."  A slice
bound written as a bare integer is a width nobody can look up, grep, or
audit; this module gives each width exactly one name so the Accept —
"no bare integer in a slice in ``analysis/``" — is enforceable by test
(``tests/test_report_parity.py::test_fnd03_no_bare_int_in_analysis_slice``)
and the number itself is declared once.

Canonical windows (ftasks FND-03 — exact names and values):

    WINDOW_REDACT         40   redaction context around a secret
    WINDOW_EVIDENCE      160   evidence string cap in rendered output
    WINDOW_SNIPPET       120   snippet cap in tables and summaries
    WINDOW_LONGEST_LINE 2000   longest line retained for hashing/display
    WINDOW_PROXIMITY      5    line-proximity radius for match grouping

Every other slice bound follows the spelling convention:

  * ``WINDOW_<n>``     — a non-negative bound whose value is exactly ``<n>``
  * ``WINDOW_M<n>``    — a negative bound (position-from-end) ``-<n>``
  * ``WINDOW_TOP_5``   — top-N sample truncation; aliases WINDOW_PROXIMITY
                         so the literal 5 is still written in one place

Values are byte-for-byte the integers the code used before FND-03 — this
is a naming pass, not a behaviour change; the measured deltas for the
phase stay at zero for this item.

This module is stdlib-free and imports nothing from the project, so any
analysis/ module — package import or standalone script — can load it.
"""
from __future__ import annotations

# -- canonical windows (ftasks FND-03) -------------------------------
WINDOW_REDACT = 40
WINDOW_EVIDENCE = 160
WINDOW_SNIPPET = 120
WINDOW_LONGEST_LINE = 2000
WINDOW_PROXIMITY = 5

# Top-N sample lists (errors, duplicates, stale modules, ...) cut at the
# same width as the proximity radius; alias so the literal lives once.
WINDOW_TOP_5 = WINDOW_PROXIMITY

# -- non-negative slice bounds (value spelled by name) ----------------
WINDOW_0 = 0
WINDOW_1 = 1
WINDOW_2 = 2
WINDOW_3 = 3
WINDOW_4 = 4
WINDOW_5 = 5
WINDOW_6 = 6
WINDOW_8 = 8
WINDOW_10 = 10
WINDOW_12 = 12
WINDOW_15 = 15
WINDOW_16 = 16
WINDOW_20 = 20
WINDOW_24 = 24
WINDOW_28 = 28
WINDOW_32 = 32
WINDOW_50 = 50
WINDOW_55 = 55
WINDOW_56 = 56
WINDOW_60 = 60
WINDOW_63 = 63
WINDOW_64 = 64
WINDOW_80 = 80
WINDOW_82 = 82
WINDOW_180 = 180
WINDOW_200 = 200
WINDOW_220 = 220
WINDOW_240 = 240
WINDOW_250 = 250
WINDOW_300 = 300
WINDOW_400 = 400
WINDOW_500 = 500
WINDOW_800 = 800
WINDOW_8192 = 8192
WINDOW_16384 = 16384

# -- negative slice bounds (position-from-end; sign is part of value) -
WINDOW_M1 = -1
WINDOW_M2 = -2
WINDOW_M3 = -3
WINDOW_M4 = -4
WINDOW_M5 = -5
WINDOW_M200 = -200
WINDOW_M400 = -400
WINDOW_M500 = -500
WINDOW_M600 = -600
WINDOW_M1000 = -1000
WINDOW_M1500 = -1500
WINDOW_M2000 = -2000
WINDOW_M4000 = -4000
