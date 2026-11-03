# -*- coding: utf-8 -*-
"""taskf.md Phase 2 -- the renderer literal ban (T-2.2).

Why this test exists: ground rule 6 says renderers may not default to a
string literal -- they call ``value_state``.  The four patterns below were
DEF-B's second placeholder layer: each one silently invented an answer
("UNKNOWN", "Review", the fixed "No fixed version identified ..." sentence)
where the cell should have named its absence.  This file greps the three
renderer modules and fails on any occurrence, comments included, so the
patterns cannot creep back through a "temporary" fallback or a stale
comment quoting one.

Refuses to do: judge other modules.  Producers (scanner/, analysis/) and
the export adapters are out of this gate's scope -- their sentinel strings
are what ``value_state`` classifies at the render boundary.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

RENDERERS = (
    "reporting/pdf_report.py",
    "reporting/excel_report.py",
    "reporting/triage_spa.py",
)

#: The four banned literal-default patterns (taskf T-2.2), matched as raw
#: substrings anywhere in the file -- code AND comments.
BANNED = (
    'or "UNKNOWN"',
    'or "Unknown"',
    'default="Review"',
    '"No fixed version identified',
)


def test_no_renderer_literal_defaults():
    root = pathlib.Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for rel in RENDERERS:
        path = root / rel
        assert path.is_file(), f"renderer missing: {rel}"
        for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            for pattern in BANNED:
                if pattern in line:
                    offenders.append(
                        f"{rel}:{lineno}: banned pattern {pattern!r} -> "
                        f"{line.strip()}")
    assert not offenders, (
        "renderer literal defaults (taskf T-2.2, ground rule 6) -- route "
        "these cells through core.value_state:\n" + "\n".join(offenders)
    )
