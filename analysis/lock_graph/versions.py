"""Minimal PEP-440-flavored constraint evaluation for R2 lockfiles (R2.1).

Self-contained on purpose: the `packaging` distribution is not available in
this environment, and honesty requires that a constraint the matcher cannot
understand be REPORTED rather than approximated. ``satisfies`` therefore
returns True / False / None -- None means "unparseable constraint", which
callers must surface as UNRESOLVED (never as a match).

Supported forms (the vocabulary Poetry/uv lockfiles actually emit, verified
on the R2.0 corpus):

- ``*`` or empty -> any version
- caret ``^X.Y.Z`` (semver bump: major, or minor when major is 0, or patch
  when both are 0)
- tilde ``~X.Y.Z`` / ``~=X.Y.Z`` (patch-level floor: < X.(Y+1).0)
- wildcard ``X.*`` / ``X.Y.*`` (range up to the next segment)
- ``==X`` / ``=X`` / bare ``X`` (exact), ``!=X`` (exclusion)
- ``>=`` ``>`` ``<=`` ``<`` comparisons
- comma-separated conjunctions of the above

Versions compare by numeric release tuple; pre-release suffixes
(``1.0.0rc1``) compare as their release prefix -- a disclosed approximation
sufficient for resolved-lockfile pins, which are exact in practice.
"""

from __future__ import annotations

import re

from analysis.spans import WINDOW_1, WINDOW_M1, WINDOW_M2

_CLAUSE = re.compile(
    r"^\s*(\^|~=|~|==|!=|>=|<=|>|<|=)?\s*([0-9][0-9A-Za-z.*_-]*)\s*$")
_NUMERIC_PREFIX = re.compile(r"^(\d+(?:\.\d+)*)")


def _release(version: str) -> tuple[int, ...] | None:
    """Numeric release tuple, or None when the version has no numeric head."""
    text = str(version or "").strip()
    text = text.split("!", 1)[-1]        # epoch
    text = text.split("+", 1)[0]         # local segment
    m = _NUMERIC_PREFIX.match(text)
    if not m:
        return None
    try:
        return tuple(int(part) for part in m.group(1).split("."))
    except ValueError:
        return None


def _caret_bounds(core: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    lo = core + (0,) * max(0, 3 - len(core))
    major, minor, patch = lo[0], lo[1], lo[2]
    if major > 0:
        hi = (major + 1, 0, 0)
    elif minor > 0:
        hi = (0, minor + 1, 0)
    else:
        hi = (0, 0, patch + 1)
    return lo, hi


def _tilde_bounds(core: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    padded = core + (0,) * max(0, 2 - len(core))
    lo = padded + ((0,) if len(padded) == 2 else ())
    hi = (padded[0], padded[1] + 1) if len(padded) >= 2 else (padded[0] + 1,)
    return lo, hi


def _wildcard_bounds(core: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    hi = core[:WINDOW_M1] + (core[WINDOW_M1] + WINDOW_1,)
    return core, hi


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    # Pad to equal length: 1.2 == 1.2.0 for range purposes.
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def satisfies(version: str, constraint: str) -> bool | None:
    """True/False when the constraint is understood; None when it is not.

    A version with no numeric head never satisfies any understood
    constraint (False), because a match would be a guess. ``||`` unions
    (PEP 508, emitted by mainstream packages -- e.g. the pylint isort pin)
    are exact OR-semantics over comma-AND branches; a union with ANY
    unparseable branch refuses the whole constraint (partial understanding
    is not understanding).
    """
    constraint = str(constraint or "").strip()
    if constraint in ("", "*"):
        return _release(version) is not None

    branches = constraint.split("||")
    if len(branches) > 1:
        results = [_eval_branch(version, b) for b in branches]
        if any(r is None for r in results):
            return None
        return any(r is True for r in results)
    return _eval_branch(version, constraint)


def _eval_branch(version: str, constraint: str) -> bool | None:
    constraint = constraint.strip()
    if constraint in ("", "*"):
        return _release(version) is not None

    ver = _release(version)
    for clause in constraint.split(","):
        m = _CLAUSE.match(clause)
        if not m:
            return None
        op, body = m.group(1) or "", m.group(2)

        if op in ("", "=", "=="):
            if body.endswith(".*"):
                bounds = _wildcard_bounds(_release(body[:WINDOW_M2]) or (WINDOW_1,))
                if ver is None or _cmp(ver, bounds[0]) < 0 or _cmp(ver, bounds[1]) >= 0:
                    return False
                continue
            core = _release(body)
            if core is None:
                return None
            if ver is None or _cmp(ver, core) != 0:
                return False
            continue
        if op == "!=":
            if body.endswith(".*"):
                bounds = _wildcard_bounds(_release(body[:WINDOW_M2]) or (WINDOW_1,))
                if ver is None:
                    return False
                if bounds[0] <= ver < bounds[1]:
                    return False
                continue
            core = _release(body)
            if core is None:
                return None
            if ver is None:
                # R2.2 F-1: an unparseable version must never satisfy any
                # understood branch (mirrors == and wildcard-!= above).
                return False
            if _cmp(ver, core) == 0:
                return False
            continue
        if op == "^":
            core = _release(body)
            if core is None:
                return None
            lo, hi = _caret_bounds(core)
            if ver is None or _cmp(ver, lo) < 0 or _cmp(ver, hi) >= 0:
                return False
            continue
        if op in ("~", "~="):
            core = _release(body)
            if core is None:
                return None
            lo, hi = _tilde_bounds(core)
            if ver is None or _cmp(ver, lo) < 0 or _cmp(ver, hi) >= 0:
                return False
            continue
        if body.endswith(".*"):
            # comparisons against wildcards (e.g. ">=1.2.*") are not a form
            # real lockfiles emit; refuse rather than guess.
            return None
        core = _release(body)
        if core is None:
            return None
        if ver is None:
            return False
        c = _cmp(ver, core)
        if op == ">=" and c < 0:
            return False
        if op == ">" and c <= 0:
            return False
        if op == "<=" and c > 0:
            return False
        if op == "<" and c >= 0:
            return False

    return True
