"""The corpus harness must not present an old artifact as a current result.

WHAT WAS MEASURED
-----------------
The sweep reported

    projects scanned cleanly : 8 / 9

Every one of those eight came from an existing artifact rather than a scan, and all
nine artifacts turned out to predate the current production source. Concretely,
`transformers-main`'s clean_report.json was generated at 06:02Z and was missing
payload['qbom'], payload['qbom_pq'] and payload['sbom_advisory_status'] -- three
layers shipped hours later. `llama_index-main` was from 03:38Z.

So the tally described code from earlier in the day while appearing current, and the
totals it produced (findings per kloc) were attributed to a build that has never
been measured. A killed scan also leaves a partial artifact behind, which the next
run then trusts, so a timeout silently becomes a "result".

This is G-091 recurring at the harness level. There the artifact predated three
shipped framework modules and nothing in the tooling noticed; here the same thing
happened to nine projects at once.

THE RULE
--------
An artifact older than the newest production source cannot describe current
behaviour. It is still re-derived -- it may be the best data available and a
rescan can cost hours -- but it is marked stale, named with the modules that
changed since, and excluded from the totals. The tally a reader quotes must not
include it.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.compare_ai_benchmarks import (  # noqa: E402
    artifact_staleness,
    newest_production_source_mtime,
)


def test_newest_production_source_is_actually_production():
    """The comparison must be against code that decides report content.

    Excluding tests/, docs/, reports/ and analysis/ is deliberate: a benchmark
    measures the system, so editing the benchmark must not make every existing
    result look stale.
    """
    newest, names = newest_production_source_mtime()

    assert newest > 0, "no production source found -- the staleness check would "
    assert names, "newest_production_source_mtime reported no filenames"

    joined = " ".join(names)
    assert "tests/" not in joined and "docs/" not in joined


def test_missing_artifact_is_stale():
    """No artifact is not 'fine', it is unknown."""
    out = artifact_staleness(Path("no-such-dir/clean_report.json"))

    assert out["stale"] is True
    assert out["reason"] == "no artifact"


def test_freshly_written_artifact_is_not_stale(tmp_path):
    art = tmp_path / "clean_report.json"
    art.write_text("{}", encoding="utf-8")

    out = artifact_staleness(art)

    assert out["stale"] is False
    assert out["reason"] is None


def test_artifact_older_than_production_source_is_stale(tmp_path):
    """The core rule, tested by backdating a file.

    Writing a file with an old mtime is the only way to construct this state
    without waiting hours, and it is the state the corpus is actually in.
    """
    art = tmp_path / "clean_report.json"
    art.write_text("{}", encoding="utf-8")
    newest, _ = newest_production_source_mtime()
    # Backdate relative to the newest production SOURCE, never to wall-clock now.
    # A fixed 6h offset from now only lands before the source within 6h of a
    # source edit, so this went red on any machine that had not touched
    # production code that morning - while looking like a staleness regression.
    old = newest - (60 * 60 * 6)
    import os

    os.utime(art, (old, old))
    assert art.stat().st_mtime < newest, "test setup failed: artifact is not old"

    out = artifact_staleness(art)

    assert out["stale"] is True
    assert "newest production source" in out["reason"]
    assert out["age_seconds"] > 0


def test_staleness_names_the_modules_that_changed(tmp_path):
    """A reader told only "stale" cannot act. Told which modules moved, they can."""
    art = tmp_path / "clean_report.json"
    art.write_text("{}", encoding="utf-8")
    import os

    # Same as above: relative to the newest source so the fixture does not
    # depend on how recently production code was edited.
    newest, _ = newest_production_source_mtime()
    old = newest - (60 * 60 * 6)
    os.utime(art, (old, old))

    out = artifact_staleness(art)

    assert out["stale"] is True
    newer = out.get("newer_modules") or []
    assert newer, "staleness was reported without naming any changed module"
    assert all("/" in m or m == "main.py" for m in newer)


def test_staleness_carries_both_timestamps(tmp_path):
    art = tmp_path / "clean_report.json"
    art.write_text("{}", encoding="utf-8")

    out = artifact_staleness(art)

    assert out["artifact_mtime"] == art.stat().st_mtime
    assert out["newest_source_mtime"] > 0


# ------------------------------- the corpus in its real, measured state -----

CORPUS = Path(r"D:\Data\Code test\prodtest\reports\ai_benchmarks")


@pytest.mark.skipif(not CORPUS.is_dir(),
                    reason="prodtest corpus artifacts are not present")
def test_corpus_artifacts_are_classified_consistently_with_their_mtime():
    """Detection agrees with the filesystem for every real artifact.

    Deliberately NOT a test that the corpus is fresh. A rescan costs hours and the
    corpus is external state, so asserting freshness here would leave the main suite
    permanently red for a condition already disclosed in the sweep JSON and printed
    by the harness. A gate that always fails teaches people to ignore it, which is
    how a real regression gets missed later.

    So this asserts the DETECTOR is right about each artifact -- the part this
    codebase owns -- and leaves the freshness question to the sweep, which reports
    the stale count separately and excludes those rows from its totals.
    """
    newest, _ = newest_production_source_mtime()
    misclassified = []

    for art in sorted(CORPUS.glob("*/clean_report.json")):
        out = artifact_staleness(art)
        # Recomputed here rather than trusted, so this checks the rule and not just
        # that the function returns something.
        should_be_stale = art.stat().st_mtime < newest
        if out["stale"] != should_be_stale:
            misclassified.append(art.parent.name)

    assert not misclassified, (
        f"artifact_staleness disagrees with the mtime rule for: {misclassified}"
    )


@pytest.mark.skipif(not CORPUS.is_dir(),
                    reason="prodtest corpus artifacts are not present")
def test_current_corpus_artifacts_carry_every_shipped_layer():
    """Whatever IS counted as clean must be complete.

    Only artifacts the staleness rule accepts are inspected, so this passes while the
    corpus is wholly stale and starts doing real work the moment part of it is
    rescanned. transformers-main's artifact was previously counted as clean while
    missing payload['qbom'], payload['qbom_pq'] and
    payload['sbom_advisory_status'] -- three layers shipped hours later.
    """
    EXPECTED = ("qbom", "qbom_pq", "sbom_advisory_status")
    missing = {}
    checked = 0

    for art in sorted(CORPUS.glob("*/clean_report.json")):
        if artifact_staleness(art)["stale"]:
            continue
        checked += 1
        try:
            payload = json.loads(art.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            missing[art.parent.name] = f"unparseable: {type(exc).__name__}"
            continue
        gaps = [k for k in EXPECTED if k not in payload]
        if gaps:
            missing[art.parent.name] = f"missing {gaps}"

    assert not missing, (
        f"of {checked} artifact(s) counted as current, these are incomplete: "
        f"{missing}"
    )