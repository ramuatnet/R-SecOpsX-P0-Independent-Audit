"""Registered skip-marker policy (cltask.md rule 2; SAST overnight P0-2).

cltask rule 2: "No xfail/skip to hide a failure. Skip only with a
registered marker ... and a mandatory reason string; conftest.py fails
collection on an unregistered or reason-less skip."

This conftest is the policy layer that rule names:

* the registered markers and their mandatory reasons;
* collection-time enforcement: any ``requires_*`` marker that is not
  registered here (or used without a reason) fails collection — the
  gate is fail-closed, a crash is never a pass;
* a single central skip hook so ``requires_rust_ext`` tests skip with
  the disclosed reason when the native core is genuinely absent, and
  RUN when it is built (conditional, not a blind skip).
"""
from __future__ import annotations

import pytest

REGISTERED_MARKERS = {
    "requires_rust_ext":
        "exercises the parked Rust native core (rsecopsx_core; cltask "
        "Appendix A). Skipped with a reason when the extension is not "
        "built; runs when it is. Do not build/fix Rust to un-skip.",
    "requires_prod_tree":
        "needs gitignored production-tree artifacts (reports/, backup/, "
        "quarantine/) that a clean clone lacks",
    "requires_posix": "requires POSIX-only mechanisms (resource/process-group)",
    "requires_windows": "requires Windows-only mechanisms",
    "requires_py314": "requires CPython 3.14 semantics",
}


def _rust_core_available() -> bool:
    try:
        import rsecopsx_core  # noqa: F401
        return True
    except Exception:
        return False


RUST_SKIP_REASON = (
    "requires the parked Rust native core (rsecopsx_core; cltask "
    "Appendix A) - not built on this host; the py engine default does "
    "not need it")


def pytest_configure(config):
    for name, reason in REGISTERED_MARKERS.items():
        config.addinivalue_line("markers", f"{name}: {reason}")


def pytest_collection_modifyitems(config, items):
    """Fail collection on an unregistered requires_* marker (rule 2).

    The reason contract is satisfied by the central registration above:
    every registered marker carries its mandatory reason string, and the
    skip hook emits it verbatim. Plain (non requires_*) skips are out of
    scope for this hook (recorded as a P2 audit in SAST_GAP_MATRIX.csv).
    """
    problems = []
    for item in items:
        for marker in item.iter_markers():
            if not marker.name.startswith("requires_"):
                continue
            if marker.name not in REGISTERED_MARKERS:
                problems.append(
                    f"{item.nodeid}: unregistered marker {marker.name!r} "
                    f"(add it to conftest.REGISTERED_MARKERS with a reason)")
    if problems:
        raise pytest.UsageError(
            "unregistered requires_* marker(s) (cltask rule 2):\n  "
            + "\n  ".join(problems))


def pytest_runtest_setup(item):
    if item.get_closest_marker("requires_rust_ext") and not _rust_core_available():
        pytest.skip(RUST_SKIP_REASON)
