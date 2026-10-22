"""Bucket D — DOCKER_MISSING_HEALTHCHECK becomes labelled truth (2026-10-22).

All three docker fixtures declare CMD and lack HEALTHCHECK, so the row
``DOCKER_MISSING_HEALTHCHECK`` fires (Low, CWE-1059, anchored at the
first FROM — Checkov CKV_DOCKER_2 parity) is a verified TRUE positive
the corpus could not express: the vocabulary lacked the class and the
CWE had no mapping, so every firing was scored spurious by definition.
Closing it is a LABEL addition — expected_count grows by one per
fixture (126 -> 129) and no rule changes — because the detection was
right all along.

The veracity test pins each new label row against the engine's own row
(rule, line, severity, cwe): a label the scanner does not emit would be
invented ground truth, exactly what ``validate_ground_truth`` exists
to prevent.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.validation.corpus import (  # noqa: E402
    CANONICAL_RULES,
    SEVERITIES,
    validate_ground_truth,
)
from analysis.validation.normalize import canonical_class  # noqa: E402

CORPUS = Path(__file__).parent / "vuln-test-corpus"

#: fixture -> expected_count after the label lands (2 -> 3, 1 -> 2, 1 -> 2).
DOCKER_GT = {
    "curl_pipe_shell.Dockerfile": 2,
    "latest_tag.Dockerfile": 2,
    "root_user.Dockerfile": 3,
}


def test_cwe_1059_maps_to_the_healthcheck_class():
    assert canonical_class("CWE-1059") == "IAC-MISSING-HEALTHCHECK"


def test_missing_healthcheck_is_a_canonical_class():
    assert "IAC-MISSING-HEALTHCHECK" in CANONICAL_RULES
    assert "Low" in SEVERITIES


def _truth(name: str) -> tuple[dict, Path]:
    root = CORPUS / "iac" / "docker"
    return (json.loads((root / f"{name}.ground_truth.json").read_text(
        encoding="utf-8")), root / name)


@pytest.mark.parametrize("name", sorted(DOCKER_GT))
def test_healthcheck_label_present_and_valid(name):
    truth, fixture = _truth(name)
    rows = [f for f in truth["expected_findings"]
            if f["rule_id"] == "IAC-MISSING-HEALTHCHECK"]
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["line"] == 1
    assert row["severity"] == "Low"
    assert row["cwe"] == "CWE-1059"
    assert row["evidence"].startswith("FROM ")
    assert canonical_class(row["cwe"]) == "IAC-MISSING-HEALTHCHECK"
    assert truth["expected_count"] == DOCKER_GT[name] == len(
        truth["expected_findings"])
    assert validate_ground_truth(truth, fixture) == []


@pytest.mark.parametrize("name", sorted(DOCKER_GT))
def test_healthcheck_label_matches_the_engine_row(name):
    """Every label row must describe a row the scanner actually emits."""
    from scanner.iac_docker import scan_docker

    truth, _ = _truth(name)
    label = next(f for f in truth["expected_findings"]
                 if f["rule_id"] == "IAC-MISSING-HEALTHCHECK")
    rows = [f for f in scan_docker(str(CORPUS / "iac" / "docker")) or []
            if Path(str(f.get("file", ""))).name == name
            and f.get("rule_id") == "DOCKER_MISSING_HEALTHCHECK"]
    assert rows, "the fixture must still fire the healthcheck rule"
    assert int(rows[0].get("line") or 0) == label["line"], rows
    assert str(rows[0].get("severity")) == label["severity"], rows
    assert str(rows[0].get("cwe")) == label["cwe"], rows
