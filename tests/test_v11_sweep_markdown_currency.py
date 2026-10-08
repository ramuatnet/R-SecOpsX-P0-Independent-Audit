"""Render the sweep markdown from synthetic rows and read what a person would read.

The console summary was fixed for G-139; the rendered document was not. This
generates the markdown the way write_reports does and asserts on the OUTPUT, because
the defect is precisely that the output did not distinguish stale rows from current
ones -- checking the source would have passed while the document stayed wrong.

Rows are synthetic so both currencies can be present at once. A real sweep has only
one project being scanned at a time, so the mixture that matters cannot be produced on
demand from the corpus.
"""
from __future__ import annotations

import importlib
import json
import re
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

mod = importlib.import_module("analysis.compare_ai_benchmarks")


def _row(project, *, stale, findings, kloc=100, rc=0, seconds=0, scanned=False):
    r = {
        "project": project,
        "returncode": rc,
        "findings_len": findings,
        "kloc": kloc,
        "unique_rules": 5,
        "findings_per_kloc": round(findings / kloc, 2),
        "attack_paths": 3,
        "source_files": 50,
        "seconds": seconds,
        "scanned_this_run": scanned,
        "severity": {"High": findings, "Low": 1},
        "top_rules": [["RULE_A", findings]],
        "ai_mapping": {"sans:DIRECT": findings},
    }
    r["stale"] = stale
    if stale is True:
        r["staleness"] = {"stale": True,
                          "reason": "artifact is 5.7h older than main.py"}
    elif stale is None:
        r["staleness"] = {"stale": None, "reason": "no clean_report.json on disk"}
    return r


def _render(tmp_path, monkeypatch, rows):
    monkeypatch.setattr(mod, "SWEEP_JSON", tmp_path / "sweep.json")
    monkeypatch.setattr(mod, "SWEEP_MD", tmp_path / "sweep.md")
    mod.write_reports(rows)
    return (tmp_path / "sweep.md").read_text(encoding="utf-8")


# ------------------------------------------------------------------ columns --

def test_every_row_carries_a_currency_value(tmp_path, monkeypatch):
    md = _render(tmp_path, monkeypatch, [
        _row("current-proj", stale=False, findings=10),
        _row("stale-proj", stale=True, findings=20),
        _row("unknown-proj", stale=None, findings=30),
    ])
    assert "| project | currency | rc |" in md, "the table has no currency column"
    for name, value in (("current-proj", "current"),
                        ("stale-proj", "stale"),
                        ("unknown-proj", "unverified")):
        line = next(ln for ln in md.splitlines() if ln.startswith(f"| {name} "))
        assert f"**{value}**" in line, (
            f"{name} should be labelled {value!r}, rendered row: {line}")


def test_unverified_is_not_labelled_as_current_or_stale(tmp_path, monkeypatch):
    """Three states, not two. Absence of information is its own value."""
    md = _render(tmp_path, monkeypatch, [_row("unknown-proj", stale=None, findings=5)])
    line = next(ln for ln in md.splitlines() if ln.startswith("| unknown-proj "))
    assert "**unverified**" in line, line
    assert "**current**" not in line and "**stale**" not in line, line


# --------------------------------------------------------------- aggregates --

def test_aggregates_exclude_stale_findings(tmp_path, monkeypatch):
    """The core of it. Severity mix blended stale and current into one count."""
    rows = [_row("fresh-a", stale=False, findings=10),
            _row("stale-b", stale=True, findings=1000)]
    md = _render(tmp_path, monkeypatch, rows)
    sev = md.split("## Severity mix")[1].split("##")[0]
    # fresh-a contributes High=10, Low=1. The stale row would add High=1000, Low=1.
    assert "| High | 10 |" in sev, f"severity mix should count only fresh rows:\n{sev}"
    assert "1000" not in sev


def test_top_rules_exclude_stale_projects(tmp_path, monkeypatch):
    rows = [_row("fresh-a", stale=False, findings=10),
            _row("stale-b", stale=True, findings=777)]
    md = _render(tmp_path, monkeypatch, rows)
    rules = md.split("## Top rules across the corpus")[1].split("##")[0]
    assert "| RULE_A | 10 |" in rules, rules
    assert "777" not in rules


def test_ai_mapping_excludes_stale_projects(tmp_path, monkeypatch):
    rows = [_row("fresh-a", stale=False, findings=10),
            _row("stale-b", stale=True, findings=555)]
    md = _render(tmp_path, monkeypatch, rows)
    sec = md.split("## AI mapping engagement")[1].split("##")[0]
    assert "| sans:DIRECT | 10 |" in sec, sec
    assert "555" not in sec


def test_each_aggregate_states_its_population(tmp_path, monkeypatch):
    """A count with no stated denominator is not auditable.

    The caption's number is extracted and compared against the real current-build
    count, rather than matched against wording. The three captions are phrased
    differently, and over-fitting to any of them breaks on a cosmetic reword instead
    of on a real regression. What matters is that the denominator is stated AND
    correct.
    """
    rows = [_row("fresh-a", stale=False, findings=10),
            _row("stale-b", stale=True, findings=99),
            _row("fresh-c", stale=False, findings=5)]
    md = _render(tmp_path, monkeypatch, rows)
    expected = sum(1 for r in rows if r["stale"] is False)   # 2
    assert expected == 2

    for header in ("## Severity mix", "## Top rules across the corpus",
                   "## AI mapping engagement"):
        sec = md.split(header)[1].split("\n## ")[0]
        caption = next((ln for ln in sec.splitlines() if ln.strip()), "")
        m = re.search(r"\b(\d+)\b", caption)
        assert m, f"{header} states no population size: {caption!r}"
        assert int(m.group(1)) == expected, (
            f"{header} claims {m.group(1)} project(s) but {expected} rows describe "
            f"the current build: {caption!r}")
        assert "project" in caption.lower(), caption


# ----------------------------------------------------------- excluded rows ---

def test_excluded_rows_are_named_with_their_reason(tmp_path, monkeypatch):
    md = _render(tmp_path, monkeypatch, [
        _row("fresh-a", stale=False, findings=10),
        _row("stale-b", stale=True, findings=99),
        _row("unknown-c", stale=None, findings=88),
    ])
    assert "## Rows excluded from the aggregates above" in md
    sec = md.split("## Rows excluded from the aggregates above")[1]
    sec = sec.split("## Reading a LOW")[0]
    assert "stale-b" in sec and "5.7h older" in sec, sec
    assert "unknown-c" in sec and "no clean_report.json" in sec, sec
    assert "Currency never established" in sec, sec


def test_a_failed_row_is_still_reported_separately(tmp_path, monkeypatch):
    """Regression guard: rc!=0 rows have their own section and must keep it."""
    rows = [_row("fresh-a", stale=False, findings=10),
            _row("broken-b", stale=None, findings=0, rc=-9)]
    rows[-1]["error"] = "TIMEOUT after 2700s"
    md = _render(tmp_path, monkeypatch, rows)
    assert "## Projects that did not complete cleanly" in md
    assert "TIMEOUT after 2700s" in md
    line = next(ln for ln in md.splitlines() if ln.startswith("| broken-b "))
    assert "**-9**" in line, line


def test_clean_corpus_still_renders(tmp_path, monkeypatch):
    """Nothing to exclude must not produce an empty or broken section."""
    md = _render(tmp_path, monkeypatch, [_row("only-a", stale=False, findings=10,
                                              scanned=True)])
    assert "| only-a | **current** |" in md
    assert "Rows excluded from the aggregates above" not in md, (
        "with nothing stale and nothing unverified there is no excluded population "
        "and the section should be absent, not empty")


def test_json_records_the_currency_of_every_row(tmp_path, monkeypatch):
    """The JSON is the machine-readable half; it must agree with the table."""
    monkeypatch.setattr(mod, "SWEEP_JSON", tmp_path / "sweep.json")
    monkeypatch.setattr(mod, "SWEEP_MD", tmp_path / "sweep.md")
    rows = [_row("fresh-a", stale=False, findings=10),
            _row("stale-b", stale=True, findings=99),
            _row("unknown-c", stale=None, findings=88)]
    mod.write_reports(rows)
    doc = json.loads((tmp_path / "sweep.json").read_text(encoding="utf-8"))
    got = {r["project"]: r["stale"] for r in doc["projects"]}
    assert got == {"fresh-a": False, "stale-b": True, "unknown-c": None}, got
    assert doc["pdfs_not_rendered"] is True
    assert doc["rendering_note"], "the rendering omission must be disclosed in the doc"
