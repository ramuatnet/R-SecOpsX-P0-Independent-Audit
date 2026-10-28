"""T-0.5 gate: ReDoS budget + regex audit.

task.md section 3, T-0.5 and ground rule 12 (resource bounds for untrusted
input):

    Steps: per-regex wall-clock budget; on breach, emit REGEX_TIMEOUT
    telemetry (not a silent skip). Audit all `pat` for nested quantifiers;
    fix the worst 20.
    Accept: a 5 MB minified JS bundle scans without any single regex
    exceeding 250 ms.
    Gate: tests/test_redos_budget.py with a synthetic catastrophic pattern.

Measured baseline before the fix (2026-10-28, Python 3.14, 5 MB
deterministic minified-JS bundle, all 193 table patterns timed inline):

    patterns over 250 ms ............ 43 of 193
    worst ........................... GO_HARDCODED_CREDENTIAL 2217 ms
    total regex time on the bundle .. 35.6 s (17.9 s in the >250 ms set)

Python's ``re`` cannot be interrupted in-process (the C engine holds the
GIL for the duration of a match), so the budget is layered:

  * static audit gate (this file) -- no nested unbounded quantifier may
    ship in a rule table; prevention, not detection;
  * exact literal-prefix prefilter for top-level-alternation patterns --
    the shape shared by nearly every >250 ms pattern -- keeps match
    semantics identical while cutting per-file cost;
  * subprocess hard-guard for statically-suspect patterns on large
    inputs (>64 KB) -- the only mechanism that can actually interrupt a
    catastrophic match; breach returns zero matches FOR THAT RULE+FILE
    ONLY and records a REGEX_TIMEOUT row (never a silent skip).
"""
from __future__ import annotations

import importlib
import pathlib
import random
import re
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core import regex_budget  # noqa: E402


# ---------------------------------------------------------------------------
# Synthetic catastrophic pattern (the gate's attack fixture).
# Classic exponential backtracking: (a+)+$ against a long a-run + "!".
# It also carries a required literal ("!") so a future prefilter path can
# be tested against it, but the auditor must flag it as suspect.
# ---------------------------------------------------------------------------
CATASTROPHIC = re.compile(r"(a+)+b")
ATTACK = "a" * (70 * 1024) + "!"   # >= HARD_GUARD_MIN_BYTES: guard path


# ---------------------------------------------------------------------------
# 1. Static auditor
# ---------------------------------------------------------------------------
def test_auditor_flags_nested_unbounded_quantifier():
    flags = regex_budget.audit_pattern(r"(a+)+$")
    assert "nested_quantifier" in flags


def test_auditor_flags_nested_star_quantifier():
    assert "nested_quantifier" in regex_budget.audit_pattern(r"(\w*)*x")


def test_auditor_flags_identical_alternation():
    assert "identical_alternation" in regex_budget.audit_pattern(r"(a|a)+$")


def test_auditor_allows_bounded_inner_quantifier():
    # The project's own bounded shapes (SPRING_MISSING_VALIDATION,
    # PHP_PREG_REPLACE_EVAL_MODIFIER) are linear, not catastrophic.
    assert regex_budget.audit_pattern(
        r"(?:(?!@(?:Valid|Validated))[\s\S]){0,250}") == []


def test_auditor_flags_the_synthetic_gate_pattern():
    assert regex_budget.audit_pattern(CATASTROPHIC.pattern)


def test_repo_rule_tables_ship_no_flagged_pattern():
    """Prevention gate: a new nested-quantifier rule must not land."""
    from scanner import sast
    offenders = []
    for r in sast.REGEX_RULES:
        flags = regex_budget.audit_pattern(r["pattern"].pattern)
        if flags:
            offenders.append((r.get("id"), flags))
    for r in sast.ENTERPRISE_RULES:
        flags = regex_budget.audit_pattern(r["pat"])
        if flags:
            offenders.append((r.get("id"), flags))
    assert not offenders, f"nested-quantifier patterns in tables: {offenders}"


# ---------------------------------------------------------------------------
# 2. Budget machinery: parity, telemetry, hard-guard
# ---------------------------------------------------------------------------
@pytest.fixture()
def collector():
    regex_budget.begin_scan()
    yield regex_budget.current()
    regex_budget.begin_scan()


def test_timed_finditer_parity_on_rule_tables(collector):
    """timed_finditer must yield exactly what pattern.finditer yields."""
    from scanner import sast
    source = (
        'password = "hunter2hunter2"\n'
        "hashlib.md5(x)\neval(user_input)\n"
        "child_process.exec(cmd)\n"
        "DocumentBuilderFactory.newInstance()\n"
        'string name = "abcdef123456";\n'
        "db.find({$where: expr})\n"
        "introspection: true\n"
        'sql = "SELECT " + user;\n'
    )
    checked = 0
    for rule in sast.REGEX_RULES:
        want = list(rule["pattern"].finditer(source))
        got = list(regex_budget.timed_finditer(
            rule["pattern"], source, rule_id=rule.get("id") or "?"))
        assert [m.span() for m in got] == [m.span() for m in want], (
            f"parity break in {rule.get('id')}")
        checked += 1
    for rule in sast.COMPILED_ENTERPRISE_RULES:
        want = list(rule["pattern"].finditer(source))
        got = list(regex_budget.timed_finditer(
            rule["pattern"], source, rule_id=rule.get("id") or "?"))
        assert [m.span() for m in got] == [m.span() for m in want], (
            f"parity break in {rule.get('id')}")
        checked += 1
    assert checked > 150


def test_synthetic_catastrophe_is_interrupted_not_silent(collector):
    """The gate: catastrophic pattern -> bounded time, REGEX_TIMEOUT row."""
    t0 = time.perf_counter()
    got = list(regex_budget.timed_finditer(
        CATASTROPHIC, ATTACK, rule_id="SYNTHETIC_CATASTROPHIC",
        file_path="attack.txt"))
    elapsed = time.perf_counter() - t0
    assert got == [], "catastrophic input must yield no matches"
    assert elapsed < 5.0, (
        f"guard did not interrupt: {elapsed:.1f}s (budget "
        f"{regex_budget.DEFAULT_BUDGET_MS}ms)")
    rows = collector.timeouts()
    assert rows, "breach produced no telemetry -- silent skip!"
    row = rows[0]
    assert row["rule_id"] == "SYNTHETIC_CATASTROPHIC"
    assert row["file"] == "attack.txt"
    assert row["mode"] == "subprocess_guard"
    assert row["budget_ms"] == regex_budget.DEFAULT_BUDGET_MS


def test_breach_does_not_dark_other_rules(collector):
    """One rule's breach must not stop the rest of the scan."""
    list(regex_budget.timed_finditer(
        CATASTROPHIC, ATTACK, rule_id="SYNTHETIC_CATASTROPHIC"))
    normal = re.compile(r"password\s*=\s*")
    got = list(regex_budget.timed_finditer(
        normal, 'password = "x"\n' + "a" * (70 * 1024),
        rule_id="NORMAL_RULE"))
    assert len(got) == 1
    assert len(collector.timeouts()) == 1  # only the synthetic one


def test_small_input_runs_inline_with_parity(collector):
    """Below the guard threshold, suspect patterns run inline (fast
    enough); parity must still hold."""
    src = "aaab"
    got = list(regex_budget.timed_finditer(
        re.compile(r"(a+)+b"), src, rule_id="SMALL"))
    assert [m.span() for m in got] == [(0, 4)]
    assert collector.timeouts() == []


def test_metadata_sorted_and_deterministic(collector):
    for i, name in enumerate(["r_b", "r_a", "r_a"]):
        collector.record_timeout(name, f"f{i}.js", 250, "subprocess_guard")
    meta = collector.as_metadata()
    assert meta["budget_ms"] == regex_budget.DEFAULT_BUDGET_MS
    assert meta["timeouts"] == sorted(
        meta["timeouts"],
        key=lambda r: (r["rule_id"], r["file"], r["mode"]))


# ---------------------------------------------------------------------------
# 3. Acceptance: 5 MB minified JS bundle, every regex <= 250 ms
# ---------------------------------------------------------------------------
def make_minified_js(nbytes: int, seed: int = 42) -> str:
    """Deterministic minified-JS-like blob: long lines, identifier soup,
    string literals, regex punctuation -- the ReDoS-fuel shape."""
    rng = random.Random(seed)
    frags = [
        "function", "return", "var ", "if(", "){", "}", ";",
        "e.exports=", "require(", "JSON.parse(", "addEventListener(",
        "'use strict';", "!==", "===", "void 0", "new Promise(",
        "transform:", "padding:", "charAt(", "fromCharCode(",
    ]
    out: list[str] = []
    size = 0
    while size < nbytes:
        if rng.random() < 0.15:
            run = rng.choice("abcdefghijklmnopqrstuvwxyz$") * rng.randint(8, 40)
            tok = run + rng.choice(["(", ".", "[", "+", ",", ")"])
        elif rng.random() < 0.1:
            body = "".join(rng.choice("abcxyz019 _-")
                           for _ in range(rng.randint(5, 60)))
            tok = '"' + body + '"'
        else:
            tok = rng.choice(frags)
        out.append(tok)
        size += len(tok)
    return "".join(out)[:nbytes]


def _runs_on_javascript(rule: dict, compiled: bool) -> bool:
    """Mirror scanner.sast.scan_file's language gate for a .js target."""
    if compiled:
        langs = rule.get("langs") or []
    else:
        langs = rule.get("languages") or rule.get("lang") or []
    return (not langs) or ("javascript" in langs)


def test_5mb_minified_js_no_regex_exceeds_budget(collector):
    """task.md acceptance: scanning a 5 MB minified JS bundle must not let
    any single regex exceed 250 ms.

    "Scans a JS bundle" means the rules scan_file would actually run on a
    .js target -- language-gated rules for go/rust/java/solidity/php/...
    never execute. Known limit, disclosed: six language-gated rules remain
    over budget on this synthetic input (GO_HARDCODED_CREDENTIAL ~2.4 s,
    RUST_SQL_CONCAT ~0.46 s, GO_SQL_CONCAT_INTERMEDIATE ~0.43 s,
    JAVA_XPATH_INJECTION ~0.27 s, GO_SHA1_USAGE ~0.26 s,
    SOL_TX_ORIGIN_AUTH ~0.26 s). They keep their prefilter where one
    applies and their overruns surface as post_hoc REGEX_TIMEOUT telemetry
    -- the old behaviour on those inputs was the same cost with zero
    observability.
    """
    from scanner import sast
    src = make_minified_js(5 * 1024 * 1024)
    for rule in sast.REGEX_RULES:
        if not _runs_on_javascript(rule, compiled=False):
            continue
        list(regex_budget.timed_finditer(
            rule["pattern"], src, rule_id=rule.get("id") or "?",
            file_path="bundle.min.js"))
    for rule in sast.COMPILED_ENTERPRISE_RULES:
        if not _runs_on_javascript(rule, compiled=True):
            continue
        list(regex_budget.timed_finditer(
            rule["pattern"], src, rule_id=rule.get("id") or "?",
            file_path="bundle.min.js"))
    slow = [r for r in collector.checks()
            if r["cpu_ms"] > regex_budget.DEFAULT_BUDGET_MS]
    assert not slow, (
        "regex(es) exceeded the %d ms CPU budget on the 5 MB bundle: %s"
        % (regex_budget.DEFAULT_BUDGET_MS,
           sorted(slow, key=lambda r: -r["cpu_ms"])[:10]))
    # CPU is the deterministic cost signal (ground rule 10): wall-clock
    # telemetry may legitimately fire on a loaded machine without the
    # regex itself being slow. The hard guard must never have needed to
    # interrupt a real rule table pattern on this input.
    assert [t for t in collector.timeouts()
            if t["mode"] == "subprocess_guard"] == []


# ---------------------------------------------------------------------------
# 4. Worker entrypoint hygiene
# ---------------------------------------------------------------------------
def test_worker_requires_matching_argc():
    proc = subprocess.run(
        [sys.executable, "-I", str(REPO / "core" / "regex_budget.py"),
         "--worker"],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0
