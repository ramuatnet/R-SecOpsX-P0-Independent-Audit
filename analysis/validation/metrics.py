"""Aggregate per-fixture comparisons into metrics a reader can act on
(Phase V0.2).

An overall recall of 44% tells you something is wrong. It does not tell you
what, and a reader cannot act on it. The breakdowns below exist so the number
names its own cause:

    by_language   which language families are under-served
    by_rule       which vulnerability classes are missed, which are noisy
    by_severity   whether the misses are critical or cosmetic

Each bucket reports the raw counts alongside the ratios, because a precision
of 1.0 built on two findings and a precision of 1.0 built on four hundred are
not the same statement, and only one of them should change anyone's mind.

CONVENTION FOR EMPTY BUCKETS
----------------------------
A bucket with no expectations scores 0.0 rather than 1.0, matching
``compare``. The alternative makes a language the tool has no rules for look
like a language it solves perfectly, which is the single most misleading
thing a validation harness can report -- and is precisely the trap the C++
and Rust fixtures fell into during V0.1, where 8 findings scored as misses
when the truth was that no rules exist for those languages at all.
"""
from __future__ import annotations

import logging
from typing import Any

_LOG = logging.getLogger("rsx.analysis.validation.metrics")

_LANG_OF_SUFFIX = {
    ".java": "java",
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".cs": "csharp",
    ".php": "php",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".c": "c",
    ".rs": "rust",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".dockerfile": "dockerfile",
}


def language_of(finding: dict) -> str:
    """Language bucket for a finding, from its file extension.

    Derived rather than declared: a tool does not always state a language,
    and a label that had to declare one would drift from the file it sits
    beside. Manifest-backed findings fall through to ``manifest``.
    """
    path = str(finding.get("file") or finding.get("basename") or "")
    name = path.rsplit("/", 1)[-1].lower()

    if name in ("requirements.txt", "package.json", "pom.xml", "go.mod",
                "cargo.lock", "gemfile.lock", "composer.lock"):
        return "manifest"

    for suffix, lang in _LANG_OF_SUFFIX.items():
        if name.endswith(suffix):
            return lang
    return "other"


def _blank() -> dict:
    return {"tp": 0, "fp": 0, "fn": 0, "expected": 0, "actual": 0,
            "precision": 0.0, "recall": 0.0, "f1": 0.0}


def _ratio(num: int, den: int) -> float:
    """Zero denominator scores 0.0, never 1.0.

    Silence is not success. A tool that reports nothing about a class it has
    no rules for would otherwise show 100% precision there.
    """
    return (num / den) if den else 0.0


def _finalise(bucket: dict) -> dict:
    tp, fp, fn = bucket["tp"], bucket["fp"], bucket["fn"]
    bucket["precision"] = _ratio(tp, tp + fp)
    bucket["recall"] = _ratio(tp, tp + fn)
    p, r = bucket["precision"], bucket["recall"]
    bucket["f1"] = (2 * p * r / (p + r)) if (p and r) else 0.0
    return bucket


def metrics(comparisons: list[dict]) -> dict:
    """Aggregate comparisons into overall, per-language, per-rule and
    per-severity metrics.

    Each element of ``comparisons`` is a ``compare.findings`` result carrying
    the context needed to bucket it:

        {
          "fixture": "vulnerable_app.py",
          "family": "sast",
          "language": "python",          # optional; derived if absent
          ...compare_findings fields...
        }

    Buckets that receive no expectations are absent from the output rather
    than present with zeros. An absent bucket says "nothing was measured
    here"; a zeroed bucket says "measured and failed", and conflating the two
    is how a harness invents evidence.
    """
    overall = _blank()
    by_language: dict[str, dict] = {}
    by_rule: dict[str, dict] = {}
    by_severity: dict[str, dict] = {}

    comparisons = comparisons or []
    _LOG.info("aggregating %d comparisons", len(comparisons))

    for comp in comparisons:
        counts = comp.get("counts") or {}
        tp = counts.get("tp", len(comp.get("tp") or []))
        fp = counts.get("fp", len(comp.get("fp") or []))
        fn = counts.get("fn", len(comp.get("fn") or []))

        for bucket in (overall,):
            bucket["tp"] += tp
            bucket["fp"] += fp
            bucket["fn"] += fn
            bucket["expected"] += counts.get("expected", tp + fn)
            bucket["actual"] += counts.get("actual", tp + fp)

        lang = comp.get("language") or "unknown"
        by_language.setdefault(lang, _blank())
        _add(by_language[lang], tp, fp, fn, counts)

        sev = comp.get("severity_context")
        if sev:
            by_severity.setdefault(sev, _blank())
            _add(by_severity[sev], tp, fp, fn, counts)

        # Per-rule buckets come from the matched pairs and the misses, so a
        # rule that finds nothing still appears -- with recall 0. Omitting
        # it would hide exactly the classes worth worrying about.
        for pair in comp.get("tp") or []:
            exp = pair.get("expected") or {}
            key = _rule_key(exp)
            by_rule.setdefault(key, _blank())
            by_rule[key]["tp"] += 1
            by_rule[key]["expected"] += 1
            by_rule[key]["actual"] += 1

        for exp in comp.get("fn") or []:
            key = _rule_key(exp)
            by_rule.setdefault(key, _blank())
            by_rule[key]["fn"] += 1
            by_rule[key]["expected"] += 1

        for act in comp.get("fp") or []:
            key = _rule_key(act)
            by_rule.setdefault(key, _blank())
            by_rule[key]["fp"] += 1
            by_rule[key]["actual"] += 1

    _finalise(overall)
    for bucket in by_language.values():
        _finalise(bucket)
    for bucket in by_rule.values():
        _finalise(bucket)
    for bucket in by_severity.values():
        _finalise(bucket)

    return {
        "overall": overall,
        "by_language": dict(sorted(by_language.items())),
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "comparisons": len(comparisons),
    }


def _add(bucket: dict, tp: int, fp: int, fn: int, counts: dict) -> None:
    bucket["tp"] += tp
    bucket["fp"] += fp
    bucket["fn"] += fn
    bucket["expected"] += counts.get("expected", tp + fn)
    bucket["actual"] += counts.get("actual", tp + fp)


def _rule_key(finding: dict) -> str:
    """Bucket key for a finding: canonical class, then CWE, then rule ID.

    The class comes first because it survives across tools. A bucket keyed on
    ``JAVA_JDBC_SQL_CONCAT`` and another on ``TAINT_SQL_INJECTION`` would both
    be named SAST-SQLI here, which is the only way to see that the class as a
    whole is being found or missed regardless of which rule fired.
    """
    for value in (finding.get("class"), finding.get("cwe"), finding.get("rule_id")):
        if value and str(value).strip():
            return str(value).strip()
    return "(unidentified)"


def format_table(result: dict) -> str:
    """Render metrics as a fixed-width table for the CLI.

    Kept here rather than in ``run`` so the same table can be printed by a
    test and by the command line, and so a formatting change is reviewable in
    one place instead of being duplicated into a script nobody runs.
    """
    lines: list[str] = []

    def row(label: str, bucket: dict) -> str:
        return "%-34s %5d %5d %5d  %7.1f%% %7.1f%% %6.1f" % (
            label, bucket["expected"], bucket["tp"], bucket["fp"],
            bucket["precision"] * 100, bucket["recall"] * 100,
            bucket["f1"] * 100)

    header = "%-34s %5s %5s %5s  %8s %8s %6s" % (
        "", "exp", "tp", "fp", "precision", "recall", "f1")
    lines.append(header)
    lines.append("-" * len(header))
    lines.append(row("OVERALL", result["overall"]))

    if result.get("by_language"):
        lines.append("")
        lines.append("by language:")
        for lang, bucket in result["by_language"].items():
            lines.append(row("  " + lang, bucket))

    if result.get("by_rule"):
        lines.append("")
        lines.append("by rule (canonical class / CWE):")
        for rule, bucket in sorted(result["by_rule"].items()):
            lines.append(row("  " + rule, bucket))

    if result.get("by_severity"):
        lines.append("")
        lines.append("by severity:")
        for sev, bucket in result["by_severity"].items():
            lines.append(row("  " + sev, bucket))

    return "\n".join(lines)


def summarise_gaps(result: dict, max_items: int = 12) -> str:
    """Name the classes and languages driving the misses.

    Precision and recall describe how much was missed. This names WHAT,
    because "recall 44%" does not tell a reader whether to write rules for
    Rust or to stop firing Java J5 rules on PreparedStatement lines.
    """
    lines: list[str] = []

    missed = sorted(
        ((k, b) for k, b in result.get("by_rule", {}).items() if b["fn"]),
        key=lambda kv: -kv[1]["fn"])
    if missed:
        lines.append("classes with misses:")
        for key, bucket in missed[:max_items]:
            lines.append("  %-30s %d missed of %d expected"
                         % (key, bucket["fn"], bucket["expected"]))

    noisy = sorted(
        ((k, b) for k, b in result.get("by_rule", {}).items() if b["fp"]),
        key=lambda kv: -kv[1]["fp"])
    if noisy:
        lines.append("")
        lines.append("classes producing false positives:")
        for key, bucket in noisy[:max_items]:
            lines.append("  %-30s %d false positives" % (key, bucket["fp"]))

    return "\n".join(lines)


def has_expectations(result: dict) -> bool:
    """Whether anything at all was scored.

    Used by the CLI to distinguish "measured and found nothing wrong" from
    "measured nothing". The second must never exit 0 silently, or an empty
    corpus reads as a passing gate.
    """
    overall: Any = result.get("overall") or {}
    return bool(overall.get("expected"))
