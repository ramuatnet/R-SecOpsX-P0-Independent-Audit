"""T-0.4 gate: recursion -> iterative with depth cap + cycle detection.

task.md section 3, T-0.4 and ground rule 12 (resource bounds are mandatory
for anything parsing untrusted input):

    Files: _clean_node, _redact_secret_evidence, _normalize_record
    Accept: 10,000-deep nested JSON parses without error; cyclic dict
    detected.

The three walkers were recursive. Measured baseline before the fix
(2026-10-28, Python 3.14, recursionlimit 1000):

  * json.loads('[' * 10000 + ']' * 10000)      -> OK (C scanner)
  * _clean_node on a cyclic dict                -> RecursionError
  * (any of the three on a 10k-deep structure)  -> RecursionError

A RecursionError is not a graceful rejection: it kills the whole scan
mid-report from inside a formatting pass. The contract after the fix:

  * any nesting depth up to and past 10k is walked iteratively (explicit
    stack) without error;
  * a cyclic structure is *detected* (counted and surfaced), never walked
    forever and never crashed on;
  * depth truncation beyond the cap is *reported*, not silent (ground
    rule 3).

ftasks Phase 0, FND-04 tightened the contract T-0.4 shipped with: the
cap is now ``MAX_DEPTH=64`` (not 10_000) and an overflowing walk sets
the ``truncated`` marker on ``metadata['depth_guard']``.  Deep walks
still complete without error; content past the cap is the explicit
fail-closed placeholder (redact) or untouched-but-counted (clean /
normalise) -- never silent.  The 10k cases below stay as the
any-depth-no-error proof; ``test_redact_walks_10k_deep_dicts`` pins the
new boundary.
"""
from __future__ import annotations

import importlib
import json
import random
import sys
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


@pytest.fixture(scope="module")
def main_module():
    return importlib.import_module("main")


def _deep_lists(depth: int):
    """depth-nested JSON lists -- the shape json.loads builds natively."""
    return json.loads("[" * depth + "]" * depth)


def _deep_dicts(depth: int):
    node = {"leaf": "value"}
    for _ in range(depth):
        node = {"n": node}
    return node


def _cyclic_dict():
    node = {"name": "cycle"}
    node["self"] = node
    return node


def _cyclic_list():
    node = ["cycle"]
    node.append(node)
    return node


# ---------------------------------------------------------------------------
# 1. 10,000-deep nested JSON walks without error
# ---------------------------------------------------------------------------
def test_clean_node_walks_10k_deep_json(main_module):
    payload = {"findings": [], "deep": _deep_lists(10_000)}
    main_module._cleanup_report_noise(payload)  # runs _clean_node


def test_clean_node_walks_10k_deep_dicts(main_module):
    payload = {"findings": [], "deep": _deep_dicts(10_000)}
    main_module._cleanup_report_noise(payload)


def test_redact_walks_10k_deep_json(main_module):
    out = main_module._redact_secret_evidence(_deep_lists(10_000))
    assert isinstance(out, list)


def test_redact_walks_10k_deep_dicts(main_module):
    out = main_module._redact_secret_evidence(_deep_dicts(10_000))
    assert isinstance(out, dict)
    # FND-04 (cap 64): the chain survives intact to MAX_DEPTH; past the
    # cap the remainder is the explicit fail-closed placeholder -- never
    # silent garbage -- and the truncation is counted, not swallowed.
    from core import depth_guard

    node = out
    hops = 0
    while isinstance(node, dict) and "n" in node:
        node = node["n"]
        hops += 1
        assert hops <= depth_guard.MAX_DEPTH + 1, (
            "chain walked past the FND-04 cap without truncating"
        )
    assert node == "<depth_guard: depth limit reached; subtree omitted>", node
    # root (depth 0) .. dict at MAX_DEPTH, whose child is the placeholder
    assert hops == depth_guard.MAX_DEPTH + 1, hops
    report = _last_depth_report()
    assert report and report.get("depth_truncated"), (
        "FND-04: an overflowing redact must count the truncation"
    )
    assert report.get("truncated") is True


def _deep_advisory_chain(depth: int) -> dict:
    """SBOM shape _normalize_record descends: vulnerabilities -> records."""
    record = {"name": "pkg0", "fixed_versions": ["1.0.0"]}
    for i in range(1, depth):
        record = {"name": f"pkg{i}",
                  "vulnerabilities": [record]}
    return record


def test_normalize_record_walks_10k_deep_chain(main_module):
    payload = {"sbom": [_deep_advisory_chain(10_000)]}
    main_module._normalize_fixed_version_fields(payload)


# ---------------------------------------------------------------------------
# 2. Cyclic structures are detected, not crashed on
# ---------------------------------------------------------------------------
def test_clean_node_detects_cycle(main_module):
    payload = {"findings": [], "deep": _cyclic_dict()}
    main_module._cleanup_report_noise(payload)  # must not raise
    report = _last_depth_report()
    assert report and report.get("cycles_detected"), (
        "the cyclic dict was walked without detection"
    )


def test_clean_node_detects_cyclic_list(main_module):
    payload = {"findings": [], "deep": _cyclic_list()}
    main_module._cleanup_report_noise(payload)
    report = _last_depth_report()
    assert report and report.get("cycles_detected")


def test_redact_detects_cycle(main_module):
    out = main_module._redact_secret_evidence(_cyclic_dict())
    assert isinstance(out, dict)
    report = _last_depth_report()
    assert report and report.get("cycles_detected"), (
        "the cyclic dict was walked without detection"
    )


def test_normalize_record_detects_cycle(main_module):
    pkg = {"name": "pkg", "fixed_versions": ["1.0"]}
    pkg["vulnerabilities"] = [pkg]  # cycle through the descended key
    main_module._normalize_fixed_version_fields({"sbom": [pkg]})
    report = _last_depth_report()
    assert report and report.get("cycles_detected")


def test_depth_report_surfaces_in_metadata(main_module):
    """Violations reach the payload (ground rule 3: annotate, not silent)."""
    payload = {"findings": [], "deep": _cyclic_dict(), "metadata": {}}
    main_module._cleanup_report_noise(payload)
    meta = payload.get("metadata") or {}
    guard = meta.get("depth_guard")
    assert guard, f"depth_guard metadata missing: {sorted(meta)}"
    assert guard.get("cycles_detected", 0) >= 1


def _last_depth_report() -> dict | None:
    from core import depth_guard
    report = depth_guard.last_report()
    return report.as_dict() if report else None


# ---------------------------------------------------------------------------
# 3. Fuzz seed: random shapes must terminate without error
# ---------------------------------------------------------------------------
def _random_structure(rng: random.Random, depth: int = 0):
    kind = rng.randint(0, 4 if depth < 6 else 2)
    if kind == 0:
        return [ _random_structure(rng, depth + 1) for _ in range(rng.randint(0, 3)) ]
    if kind == 1:
        return { f"k{i}": _random_structure(rng, depth + 1)
                 for i in range(rng.randint(0, 3)) }
    if kind == 2:
        return rng.choice(["secret", "", 42, None, True, "PW=abc"])
    if kind == 3:
        return "x" * rng.randint(0, 20)
    # deep chain tail
    node = {"leaf": 1}
    for _ in range(rng.randint(100, 2000)):
        node = {"n": node}
    return node


@pytest.mark.parametrize("seed", [0, 1, 2, 3, 4])
def test_fuzz_random_structures_terminate(main_module, seed):
    rng = random.Random(seed)
    for _ in range(5):
        root = _random_structure(rng)
        # inject a cycle half the time
        if seed % 2 == 0 and isinstance(root, dict):
            root["cycle"] = root
        main_module._cleanup_report_noise({"findings": [], "deep": root,
                                           "metadata": {}})
        main_module._redact_secret_evidence(root)


def test_fuzz_seed_fixed_cycle_terminates(main_module):
    """The documented fuzz seed: a cycle reached only after deep nesting."""
    node = {"leaf": "secret"}
    for _ in range(5000):
        node = {"n": node}
    node["back"] = node  # closes the ring at depth 5000
    payload = {"findings": [], "deep": node, "metadata": {}}
    main_module._cleanup_report_noise(payload)
    main_module._redact_secret_evidence(payload)
    report = _last_depth_report()
    assert report is not None
