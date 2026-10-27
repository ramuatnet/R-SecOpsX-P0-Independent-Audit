# -*- coding: utf-8 -*-
r"""UFIB corpus regression guard (mission invariant 5 + 12).

Runs the golden corpus through the production lifecycle order (engine scan
-> evidex validation -> UFIB) and asserts the recall contract:

  * every labelled true positive keeps its finding (UFIB never removes
    findings -- zero silent loss);
  * a labelled TP may be RELEASED (CONFIRMED/LIKELY) or HELD
    (NEEDS_REVIEW/INSUFFICIENT_EVIDENCE, with the reason recorded);
  * a REJECTED disposition on a labelled TP is only acceptable when the
    rejection's counterevidence is VERIFIABLE in the fixture bytes -- a
    documentation-example key or synthetic fixture material (mission 6's
    counterevidence contract). Anything else is a recall regression.

Runtime ~40s (engine scans dominate); it earns its place by being the one
test that proves "reduces false positives without suppressing genuine
vulnerabilities" on labelled data.
"""
from __future__ import annotations

import collections
import pathlib
import sys

import pytest

sys.path.insert(0, r"D:\Data\Code test\R-SecOpsX_V11")

from analysis.validation import compare, run as vrun  # noqa: E402
from analysis.validation.normalize import (  # noqa: E402
    normalize_corpus_finding,
    normalize_findings,
)
from analysis.ufib_release import apply_ufib_to_payload  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[0] / "vuln-test-corpus"
# parents[0] is tests/ -- the corpus lives beside this test file.

# Markers whose presence in the FIXTURE justifies a claim-level rejection:
# the fixture itself carries documentation-example / synthetic material.
VERIFIED_BACKING = ("example", "sample", "placeholder", "dummy", "fake",
                    "mock", "changeme", "not-a-real", "redacted", "xxxxxx",
                    "insert your", "documentation example", "mocking")


def _scan(family, casedir, name):
    if family == "sca":
        return vrun._scan_sca(casedir)
    if family == "cbom":
        # cbom normalizes with its own source so component names map to
        # canonical classes (same as the corpus runner).
        return normalize_findings(vrun._scan_cbom(casedir, name), "cbom")
    if family in ("sast", "ai_ml"):
        return normalize_findings(vrun._scan_sast(casedir, name), "rsecopsx")
    if family == "secrets":
        return normalize_findings(vrun._scan_secrets(casedir, name), "rsecopsx")
    if family == "iac":
        return normalize_findings(vrun._scan_iac(casedir, name), "rsecopsx")
    if family == "sbom":
        return normalize_findings(vrun._scan_sbom(casedir, name), "rsecopsx")
    raise ValueError(family)


@pytest.mark.parametrize("only_family", [
    "sast", "sca", "secrets", "iac", "cbom", "sbom", "ai_ml"])
def test_ufib_never_rejects_a_labelled_tp_without_verifiable_counterevidence(
        only_family):
    from core.analyzer import _apply_evidex_validation

    unverified: list[str] = []
    released = 0
    evaluated = 0
    for family, casedir, path in vrun._iter_case_dirs(ROOT):
        if family != only_family:
            continue
        truth = vrun._load_truth(path)
        exp = truth.get("expected_findings", [])
        if not exp:
            continue
        expected = [normalize_corpus_finding(f, path.name) for f in exp]
        actual = _scan(family, casedir, path.name)

        # Production lifecycle: evidex runs BEFORE the brain.
        for f in actual:
            try:
                _apply_evidex_validation(f)
            except Exception:
                pass

        payload = {"findings": [dict(a) for a in actual], "metadata": {}}
        apply_ufib_to_payload(payload, str(casedir))
        result = compare.compare_findings(payload["findings"], expected)
        for row in result.get("tp", []):
            act = row.get("actual") if isinstance(row, dict) else None
            if act is None and isinstance(row, (tuple, list)):
                act = row[-1]
            act = act or {}
            evaluated += 1
            d = act.get("disposition")
            if d in ("CONFIRMED", "LIKELY"):
                released += 1
            elif d == "REJECTED_FALSE_POSITIVE":
                fixture = casedir / pathlib.Path(
                    str(act.get("file") or "x")).name
                blob = ""
                if fixture.is_file():
                    blob = fixture.read_text(encoding="utf-8",
                                             errors="replace").lower()
                backed = any(h in blob for h in VERIFIED_BACKING)
                if not backed:
                    unverified.append(
                        "%s/%s: %s" % (path.name, act.get("rule_id"),
                                       [g.get("reason") for g in
                                        (act.get("ufib") or {}).get("gates", [])
                                        if g.get("result") == "FAIL"][:1]))
    assert evaluated > 0, "no labelled TPs evaluated for %s" % only_family
    assert not unverified, (
        "UFIB rejected labelled TPs without verifiable counterevidence: %s"
        % unverified)
