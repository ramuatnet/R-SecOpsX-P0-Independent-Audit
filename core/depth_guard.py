"""T-0.4: iterative traversal with depth cap and cycle detection.

task.md section 3, T-0.4; ground rule 12 (resource bounds are mandatory
for anything parsing untrusted input: depth cap, size cap, time cap).

The three legacy report walkers -- ``_clean_node``,
``_redact_secret_evidence`` and ``_normalize_record`` -- were recursive.
Measured baseline (Python 3.14, recursionlimit 1000):

  * a 10,000-deep nested structure raised RecursionError inside
    ``_cleanup_report_noise`` (killing the scan during report formatting);
  * a cyclic dict raised RecursionError in every one of the three.

This module supplies the shared bounds:

  * explicit-stack (iterative) traversal -- nesting depth never touches
    the Python call stack;
  * ``MAX_DEPTH`` cap -- structures nested deeper than the cap are not
    descended and the truncation is COUNTED, never silent;
  * cycle detection -- a container already on the active path is not
    re-entered; the cycle is COUNTED and surfaced to the payload.

All detection counts land in a ``TraversalReport``; callers surface
non-empty reports as ``metadata['depth_guard']`` so a violation is
explainable from the payload (ground rule 3/11).
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Iterable, Optional

#: T-0.4 acceptance walks 10,000-deep structures; the cap sits exactly at
#: that depth so the acceptance case completes and only beyond-cap input
#: is truncated.
MAX_DEPTH = 10_000

# Only dict/list are descended. The legacy _clean_node never entered
# tuples (they fall through its isinstance chain), so the shared walker
# preserves that shape; _redact_secret_evidence keeps its own tuple arm.
_CONTAINERS = (dict, list)


class TraversalReport:
    """Counts of bounded-traversal violations for one top-level walk."""

    __slots__ = ("depth_truncated", "cycles_detected")

    def __init__(self) -> None:
        self.depth_truncated = 0
        self.cycles_detected = 0

    def __bool__(self) -> bool:
        return bool(self.depth_truncated or self.cycles_detected)

    def as_dict(self) -> dict:
        return {
            "depth_truncated": self.depth_truncated,
            "cycles_detected": self.cycles_detected,
            "max_depth": MAX_DEPTH,
            "traversal": "iterative",
        }


_local = threading.local()


def set_last_report(report: TraversalReport) -> None:
    _local.last_report = report


def last_report() -> Optional[TraversalReport]:
    """Report of the most recent walk on this thread (None if clean)."""
    return getattr(_local, "last_report", None)


def clear_last_report() -> None:
    _local.last_report = None


def _children(node: Any) -> list:
    if isinstance(node, dict):
        return list(node.values())
    if isinstance(node, list):
        return list(node)
    return []


def process_containers(root: Any,
                       visit: Callable[[Any, int], None],
                       max_depth: int = MAX_DEPTH) -> TraversalReport:
    """Pre-order iterative walk over every dict/list/tuple container.

    ``visit(container, depth)`` is called exactly once per reachable
    container *before* its children are examined (mirrors the old
    recursion order). Containers beyond ``max_depth`` and containers that
    close a cycle are neither visited nor descended; both are counted in
    the returned report, which is also stored as ``last_report()``.

    Non-container roots are ignored (nothing to visit).
    """
    report = TraversalReport()
    if not isinstance(root, _CONTAINERS):
        set_last_report(report)
        return report

    # Frame: [container, depth, children (None until first touch), next_idx]
    stack: list[list] = [[root, 0, None, 0]]
    on_path = {id(root)}
    try:
        while stack:
            frame = stack[-1]
            node, depth, children, idx = frame
            if children is None:
                # Pre-order: mutate/observe the container before descending.
                visit(node, depth)
                frame[2] = children = _children(node)
            if idx >= len(children):
                stack.pop()
                on_path.discard(id(node))
                continue
            child = children[idx]
            frame[3] = idx + 1
            if not isinstance(child, _CONTAINERS):
                continue
            child_id = id(child)
            if child_id in on_path:
                report.cycles_detected += 1
                continue
            if depth + 1 > max_depth:
                report.depth_truncated += 1
                continue
            on_path.add(child_id)
            stack.append([child, depth + 1, None, 0])
    finally:
        set_last_report(report)
    return report
