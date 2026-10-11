"""Validation infrastructure for technique & logic correctness (Phase V0).

V0.1 -- the golden corpus and its contract -- lives in :mod:`corpus`.

The phase order is deliberate and mirrors the questions being asked:

    V0.1  corpus.py      "do we have labels we can score against?"
    V0.2  normalize.py   "can findings from any tool be compared?"
    V0.2  compare.py     "what did we miss, and what did we invent?"
    V0.3  differential   "where do we disagree with a peer tool, and why?"

V0.2 and V0.3 are not built yet. Importing them by name today raises
ImportError, which is the honest signal; a stub that returned empty results
would have reported perfect agreement with every peer tool.

See ``analysis/validation/corpus.py`` for the label contract and, importantly,
for what qualifies as ground truth. The rule is that the truth must not come
from the scanner: OSV advisories, a fixture's own observable behaviour, and a
configuration's semantics all qualify. A label derived from a scan run is a
record of what the tool did, not of what is true.
"""
from __future__ import annotations

__all__ = ["corpus"]
