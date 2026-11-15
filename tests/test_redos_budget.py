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

import contextlib
import importlib
import pathlib
import random
import re
import subprocess
import sys
import threading
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


# ---------------------------------------------------------------------------
# 5. F-R3 concurrency isolation matrix (12 scenarios, red-first, additive)
#
# Approved proposal: audit_output/F_R3_CPU_BUDGET_REMEDIATION_PROPOSAL.md
# (2026-11-15).  Root cause: the budget gate's CPU measurement is process-wide
# (time.process_time) so unrelated in-process threads inflate the recorded
# per-regex cost; the fix (separate commit) switches the six measurement
# lines to per-thread time.thread_time.  Thresholds below are calibrated on
# Python 3.14.3 / win32 from the PRE-FIX contamination profiles in
# audit_output/fr3/logs/ (phase1_calibration.txt, phase1b_calibration.txt):
#
#   * 8-spinner 5 MB acceptance-shape scan, pre-fix: worst row 1343.8 ms
#     (14.3x its quiet value), 8 rows over the 250 ms budget.
#   * 1-spinner 5 MB scan, pre-fix: whole-scan cpu total 1.87x its quiet
#     value (budget itself not breached -- hence the partial-red band).
#   * 1 MB per-row scan, pre-fix: 7 rows outside a 2.5x+floor band (worst
#     406.2 ms against a 50 ms band).
#
# Windows thread clocks tick at 15.625 ms (GetThreadTimes, 64 Hz) -- every
# band carries an absolute floor cushion (>= 2 ticks + scheduler slop).
# R-FR3-1 correction note (2026-11-15): the calling thread's own GIL-switch
# overhead under contention is real thread CPU and reaches ~1.7-2.3x of the
# quiet cost (the original "post-fix inflation <= ~1.2x" assumption in this
# header was WRONG and was corrected by the independent review + the
# fr3_s2 distribution study).  S2 was therefore redesigned (v3) around a
# load-adaptive envelope invariant instead of a quiet-relative ratio band;
# S3/S5 keep quiet-relative per-row bands, which are empirically stable at
# 8-spinner contention (their assertion targets the absence of
# contamination-scale inflation, not the overhead envelope).
# ---------------------------------------------------------------------------
_FR3_BAND_MULT = 2.5        # per-row isolation band multiplier vs quiet value
_FR3_BAND_FLOOR = 50.0      # 5 MB-scale band floor (ticks + scheduler slop)
_FR3_S5_FLOOR = 75.0        # 1 MB-scale band floor (small quiet rows)
# S2 v3 (R-FR3-1 correction) envelope constants -- calibrated from the
# 12+12-pass distribution study in
# audit_output/fr3_s2/logs/s2_distribution_study.py/.txt (2026-11-15):
#   post-fix excess (recorded_total - external thread envelope) over 12
#   passes: [-31.2, +0.0] ms;  pre-fix excess over 12 passes:
#   [+671.9, +1390.6] ms.  300 ms sits ~10x above the observed post-fix
#   maximum and >= 2.2x below the pre-fix minimum.  The proposed
#   2.5xquiet+150 relative threshold was REJECTED by the same study: it
#   passes 6/12 pre-fix runs (detection lost half the time) because the
#   1-spinner pre-fix contamination ratio (1.96-3.53x) overlaps the
#   post-fix GIL-overhead ratio (0.90-1.73x).
_FR3_S2_ENVELOPE_MS = 300.0     # recorded_total <= external_thread + this
_FR3_S2_SPINNER_FLOOR_MS = 250.0  # spinner must accrue >= this (min observed
#                                 # 687.5 ms pre-fix / 953.1 ms post-fix)

_FR3_BUNDLES: dict[int, str] = {}


def _fr3_bundle(nbytes: int) -> str:
    """Deterministic shared bundle (seed 42), generated once per process."""
    bundle = _FR3_BUNDLES.get(nbytes)
    if bundle is None:
        bundle = make_minified_js(nbytes)
        _FR3_BUNDLES[nbytes] = bundle
    return bundle


class _Spinner:
    """One pure-Python CPU-bound thread (the GIL-bound contamination
    source from the approved proposal's decisive experiment)."""

    def __init__(self):
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        x = 1.0
        while not self._stop.is_set():
            for _ in range(5000):
                x = x * 1.0000001 + 0.1

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise RuntimeError("fr3 spinner did not stop")


@contextlib.contextmanager
def _spinners(n: int):
    """n concurrent spinner threads; always stopped, even on test failure."""
    group = [_Spinner() for _ in range(n)]
    for s in group:
        s.start()
    try:
        yield
    finally:
        for s in group:
            s._stop.set()
        for s in group:
            s._thread.join(timeout=10)
    alive = [s for s in group if s._thread.is_alive()]
    if alive:
        raise RuntimeError("fr3 spinner(s) did not stop")


class _SpinnerCpu:
    """S2-only spinner with CPU accounting (records the CPU the
    contamination source actually consumed, so the envelope assertion is
    provably meaningful).  Kept separate from :class:`_Spinner` so the
    other scenarios' helper code path stays byte-identical."""

    def __init__(self):
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.cpu = 0.0

    def _run(self):
        c0 = time.thread_time()
        x = 1.0
        while not self._stop.is_set():
            for _ in range(5000):
                x = x * 1.0000001 + 0.1
        self.cpu = (time.thread_time() - c0) * 1000

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise RuntimeError("fr3 s2 spinner did not stop")


def _run_js_rules(src: str) -> list[dict]:
    """Scan every JS-relevant rule over src through the production path --
    the same shape as the existing 5 MB acceptance gate.  Returns the
    collector's check rows."""
    from scanner import sast
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
    return regex_budget.current().checks()


def test_fr3_s1_single_thread_baseline(collector):
    """Scenario 1 (preservation): the quiet single-threaded 5 MB acceptance
    scan keeps every per-rule cpu under the 250 ms budget with no hard-guard
    intervention."""
    src = _fr3_bundle(5 * 1024 * 1024)
    rows = _run_js_rules(src)
    over = [r for r in rows if r["cpu_ms"] > regex_budget.DEFAULT_BUDGET_MS]
    assert not over, (
        "quiet scan over budget: %s"
        % sorted(over, key=lambda r: -r["cpu_ms"])[:5])
    assert [t for t in collector.timeouts()
            if t["mode"] == "subprocess_guard"] == []


def test_fr3_s2_one_spinner_thread_envelope(collector):
    """Scenario 2 (red-first; v3 = R-FR3-1 correction): scanning under ONE
    unrelated CPU-bound thread.

    v3 redesign rationale (evidence: audit_output/fr3_s2/logs/
    s2_distribution_study.py/.txt, 12+12 passes): the v1 whole-scan ratio
    band (1.4x quiet + 100) is unstable post-fix (observed post-fix ratios
    0.90-1.73x) because the calling thread's own GIL-switch/descheduling
    overhead is real thread CPU that grows with contention -- and that
    ratio OVERLAPS the pre-fix contamination ratio (1.96-3.53x), so any
    relative quiet-based threshold wide enough to pass post-fix reliably
    also passes pre-fix sometimes (2.5xquiet+150 passes 6/12 pre-fix
    runs).  The v1 scenario is therefore replaced by a LOAD-ADAPTIVE
    envelope invariant, which separates the implementations by
    construction:

        recorded_total <= (calling-thread time.thread_time delta around
                           the contended phase) + ENVELOPE_MS

    * post-fix the recorded rows ARE the calling thread's CPU, so the
      excess is only clock quantization: observed [-31.2, +0.0] ms over
      12 passes (ENVELOPE_MS=300 sits ~10x above it);
    * pre-fix the recorded rows additionally contain the spinner's CPU:
      observed excess [+671.9, +1390.6] ms over 12 passes -- the
      assertion fails deterministically (12/12 in the study);
    * the spinner's own CPU is asserted to prove the contamination source
      was genuinely active during the measurement (floor 250 ms; minimum
      observed 687.5 ms).

    Budget preservation is retained: every row stays under 250 ms.
    """
    src = _fr3_bundle(5 * 1024 * 1024)
    tt0 = time.thread_time()
    with _SpinnerCpu() as spinner:
        regex_budget.begin_scan()
        rows = _run_js_rules(src)
    external_thread_ms = (time.thread_time() - tt0) * 1000
    recorded_total = sum(r["cpu_ms"] for r in rows)
    over = [r for r in rows if r["cpu_ms"] > regex_budget.DEFAULT_BUDGET_MS]
    assert not over, f"rows over budget under 1-spinner load: {over[:10]}"
    assert spinner.cpu >= _FR3_S2_SPINNER_FLOOR_MS, (
        f"contamination source too weak: spinner consumed only "
        f"{spinner.cpu:.1f} ms (floor {_FR3_S2_SPINNER_FLOOR_MS:.0f} ms) "
        f"-- the envelope assertion would not be meaningful")
    assert recorded_total <= external_thread_ms + _FR3_S2_ENVELOPE_MS, (
        f"recorded cpu total {recorded_total:.1f} ms exceeds the calling "
        f"thread's own CPU envelope ({external_thread_ms:.1f} ms + "
        f"{_FR3_S2_ENVELOPE_MS:.0f} ms allowance) by "
        f"{recorded_total - external_thread_ms:.1f} ms -- the budget "
        f"metric charged CPU the calling thread did not consume "
        f"(process-wide contamination; spinner consumed "
        f"{spinner.cpu:.1f} ms during the same phase)")


def test_fr3_s3_eight_spinner_isolation(collector):
    """Scenario 3 (red-first, decisive): the 5 MB acceptance scan under
    EIGHT unrelated CPU-bound threads.  Pre-fix the recorded per-rule cpu
    absorbs the whole process's spinner CPU (observed: worst row 1343.8 ms,
    8 rows over budget); per-thread measurement must keep every row under
    the 250 ms budget and within 2.5x+floor of its own quiet value."""
    src = _fr3_bundle(5 * 1024 * 1024)
    regex_budget.begin_scan()
    quiet = {r["rule_id"]: r["cpu_ms"] for r in _run_js_rules(src)}
    with _spinners(8):
        regex_budget.begin_scan()
        rows = _run_js_rules(src)
    over = [r for r in rows if r["cpu_ms"] > regex_budget.DEFAULT_BUDGET_MS]
    assert not over, (
        "rows over the %d ms budget under 8-spinner load: %s"
        % (regex_budget.DEFAULT_BUDGET_MS,
           sorted(over, key=lambda r: -r["cpu_ms"])[:10]))
    blown = []
    for r in rows:
        limit = (_FR3_BAND_MULT * quiet.get(r["rule_id"], 0.0)
                 + _FR3_BAND_FLOOR)
        if r["cpu_ms"] > limit:
            blown.append((r["rule_id"], r["cpu_ms"], limit))
    assert not blown, f"rows outside the isolation band: {blown[:10]}"


def test_fr3_s4_genuine_overbudget_still_detected(collector):
    """Scenario 4 (preservation): a regex genuinely exceeding its budget is
    still detected after the correction -- the timeout path is wall-driven,
    so no measurement change can silence it.  A non-suspect match-dense
    pattern (inline path, no prefilter skip) forced through a 1 ms budget
    on the 512 KB bundle breaches, produces a post_hoc REGEX_TIMEOUT row,
    and its matches stay KEPT (telemetry, never a discard).  (v2: the
    first cut picked a rule table entry by a wall threshold, which is
    boundary-noise-flaky and could pick a rule whose budgeted path is
    prefiltered below the probe budget -- a synthetic pattern with a
    ~15-40 ms window is deterministic.)"""
    pattern = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\s*\(")
    src = _fr3_bundle(512 * 1024)
    want = list(pattern.finditer(src))
    assert len(want) > 100, "probe pattern must be match-dense"
    got = list(regex_budget.timed_finditer(
        pattern, src, rule_id="FR3_S4_OVERBUDGET", file_path="b.js",
        budget_ms=1))
    assert [m.span() for m in got] == [m.span() for m in want], (
        "breached rule's matches must be kept, not discarded")
    tos = [t for t in collector.timeouts()
           if t["rule_id"] == "FR3_S4_OVERBUDGET"]
    assert tos, "breach produced no telemetry -- silent skip!"
    assert tos[0]["mode"] == "post_hoc"
    assert tos[0]["budget_ms"] == 1


def test_fr3_s5_below_budget_under_concurrent_load(collector):
    """Scenario 5 (red-first): every JS-relevant rule stays below the 250 ms
    budget AND within its own 2.5x+floor band of its quiet value while eight
    unrelated CPU threads run.  Pre-fix seven rows blew their bands (worst
    406.2 ms against a 50 ms band)."""
    src = _fr3_bundle(1024 * 1024)
    regex_budget.begin_scan()
    quiet = {r["rule_id"]: r["cpu_ms"] for r in _run_js_rules(src)}
    with _spinners(8):
        regex_budget.begin_scan()
        rows = _run_js_rules(src)
    over = [r for r in rows if r["cpu_ms"] > regex_budget.DEFAULT_BUDGET_MS]
    assert not over, f"rows over budget under concurrent load: {over[:10]}"
    blown = []
    for r in rows:
        limit = (_FR3_BAND_MULT * quiet.get(r["rule_id"], 0.0)
                 + _FR3_S5_FLOOR)
        if r["cpu_ms"] > limit:
            blown.append((r["rule_id"], r["cpu_ms"], limit))
    assert not blown, f"rows outside band under concurrent load: {blown[:10]}"


def test_fr3_s6_multiple_regex_calls_collector_consistent(collector):
    """Scenario 6 (preservation): multiple regex calls in one scan produce
    one check row per call with match spans identical to plain finditer,
    and the metadata totals account for every call."""
    from scanner import sast
    src = 'password = "hunter2"\nhashlib.md5(x)\neval(user_input)\n'
    picked = []
    for rule in sast.REGEX_RULES:
        rid = rule.get("id") or "?"
        want = list(rule["pattern"].finditer(src))
        got = list(regex_budget.timed_finditer(
            rule["pattern"], src, rule_id=rid))
        assert [m.span() for m in got] == [m.span() for m in want], (
            f"parity break in {rid}")
        picked.append(rid)
        if len(picked) >= 5:
            break
    meta = collector.as_metadata()
    assert meta["checks"] == len(picked)
    ids = {r["rule_id"] for r in collector.checks()}
    assert set(picked) <= ids


def test_fr3_s7_measurement_is_per_thread_by_construction():
    """Scenario 7 (structural pin, red-first): all six CPU measurement lines
    use per-thread time.thread_time and time.process_time is fully gone
    from the module, with the per-thread semantics disclosed in the
    docstrings.  Pins the F-R3 correction against silent regression."""
    source = (REPO / "core" / "regex_budget.py").read_text(encoding="utf-8")
    assert "time.process_time()" not in source, (
        "process-wide CPU measurement still present -- F-R3 regression")
    assert source.count("time.thread_time()") == 6, (
        "expected the six measurement lines on time.thread_time()")
    assert "per-thread" in source, (
        "per-thread measurement semantics must be disclosed in the "
        "module/function docstrings")


def test_fr3_s8_subprocess_hard_guard_preserved(collector):
    """Scenario 8 (preservation): the catastrophic-pattern probe on a
    guard-threshold input is still interrupted by the killable child and
    produces a subprocess_guard REGEX_TIMEOUT row (never a silent skip)."""
    t0 = time.perf_counter()
    got = list(regex_budget.timed_finditer(
        CATASTROPHIC, ATTACK, rule_id="FR3_S8_GUARD", file_path="attack.txt"))
    elapsed = time.perf_counter() - t0
    assert got == [], "catastrophic input must yield no matches"
    assert elapsed < 5.0, f"guard did not interrupt: {elapsed:.1f}s"
    rows = [t for t in collector.timeouts()
            if t["rule_id"] == "FR3_S8_GUARD"]
    assert rows, "breach produced no telemetry -- silent skip!"
    assert rows[0]["mode"] == "subprocess_guard"
    assert rows[0]["budget_ms"] == regex_budget.DEFAULT_BUDGET_MS


def test_fr3_s9_windows_thread_time_resolution():
    """Scenario 9 (preservation): time.thread_time behaves as the gate
    metric needs on Python 3.14.3 / win32 -- available, excludes sleep,
    tracks CPU work, and its GetThreadTimes tick (calibrated 15.625 ms,
    64 Hz) is far below the 250 ms budget."""
    assert hasattr(time, "thread_time")
    t0 = time.thread_time()
    time.sleep(0.2)
    assert (time.thread_time() - t0) * 1000 <= 15.7, (
        "sleep was counted as CPU -- thread_time excludes idle time")
    t0 = time.thread_time()
    x = 1.0
    while (time.thread_time() - t0) < 0.15:
        for _ in range(1000):
            x = x * 1.0000001 + 0.1
    busy = (time.thread_time() - t0) * 1000
    assert 100.0 <= busy <= 300.0, f"busy work not tracked: {busy:.1f} ms"
    # resolution: the first positive delta sampled while busy-spinning is
    # one GetThreadTimes tick; allow up to two ticks for sampling slop --
    # either bound is far below the 250 ms budget.
    t0 = time.thread_time()
    x = 1.0
    first = None
    deadline = time.perf_counter() + 2.0
    while time.perf_counter() < deadline:
        for _ in range(1000):
            x = x * 1.0000001 + 0.1
        cur = time.thread_time()
        if cur > t0:
            first = (cur - t0) * 1000
            break
    assert first is not None, "thread_time never advanced while busy"
    assert 0.0 < first <= 31.3, (
        f"thread_time resolution unusable for the budget: {first:.3f} ms")


def test_fr3_s10_telemetry_row_shapes_unchanged(collector):
    """Scenario 10 (preservation): check/timeout/metadata telemetry keeps
    its exact shape under load and after a breach; only the cpu values'
    scope changes to per-thread (disclosed behavioural correction)."""
    src = _fr3_bundle(256 * 1024)
    with _spinners(8):
        regex_budget.begin_scan()
        _run_js_rules(src)
        list(regex_budget.timed_finditer(
            CATASTROPHIC, ATTACK, rule_id="FR3_S10", budget_ms=1))
    rows = regex_budget.current().checks()
    assert rows, "no telemetry rows"
    for r in rows:
        assert set(r) == {"rule_id", "file", "wall_ms", "cpu_ms", "matches"}
        assert r["cpu_ms"] >= 0.0 and r["wall_ms"] >= 0.0
        assert isinstance(r["matches"], int)
    meta = regex_budget.current().as_metadata()
    assert set(meta) == {"budget_ms", "checks", "total_ms", "timeouts"}
    assert meta["budget_ms"] == regex_budget.DEFAULT_BUDGET_MS
    tos = regex_budget.current().timeouts()
    assert tos, "forced breach produced no timeout telemetry"
    assert any(t["mode"] == "subprocess_guard" for t in tos)
    for t in tos:
        assert set(t) >= {"rule_id", "file", "budget_ms", "mode", "line"}


def test_fr3_s11_production_line_path_under_contention(collector):
    """Scenario 11 (preservation): the production rule_finditer line path
    keeps parity, per-line wall enforcement and the line_guard subprocess
    kill under concurrent load -- a guard-threshold line is killed with the
    offending line number while the other lines keep their matches."""
    pat = re.compile(r"password")
    src = ('password = "x"\n' + "a" * (70 * 1024) + "!\n" + "b\n")
    lines = src.splitlines(keepends=True)
    # quiet parity on the line path
    regex_budget.begin_scan()
    want = list(pat.finditer(src))
    got = list(regex_budget.rule_finditer(
        pat, src, rule_id="FR3_S11", file_path="m.js", lines=lines))
    assert [m.span() for m in got] == [m.span() for m in want]
    assert regex_budget.current().timeouts() == []
    # quiet guard: the suspect pattern on the 70 KB line is killed by the
    # killable child with the offending line number
    got = list(regex_budget.rule_finditer(
        CATASTROPHIC, src, rule_id="FR3_S11G", file_path="m.js",
        lines=lines))
    assert got == [], "guard-threshold line must yield no matches"
    tos = [t for t in regex_budget.current().timeouts()
           if t["mode"] == "line_guard"]
    assert tos, "no line_guard row -- hard prevention missing"
    assert tos[0]["line"] == 2
    assert tos[0]["budget_ms"] == regex_budget.LINE_BUDGET_MS
    # contended: the child process is immune to parent-thread contention
    with _spinners(8):
        regex_budget.begin_scan()
        got = list(regex_budget.rule_finditer(
            pat, src, rule_id="FR3_S11C", file_path="m.js", lines=lines))
        assert [m.span() for m in got] == [m.span() for m in want]
        got = list(regex_budget.rule_finditer(
            CATASTROPHIC, src, rule_id="FR3_S11G2", file_path="m.js",
            lines=lines))
    assert got == []
    tos = [t for t in regex_budget.current().timeouts()
           if t["mode"] == "line_guard"]
    assert tos and tos[0]["line"] == 2, (
        "line_guard enforcement broke under concurrent load")


def test_fr3_s12_existing_redos_protections_regress():
    """Scenario 12 (preservation): the existing ReDoS protection layers are
    untouched by the correction -- the static audit still flags nested
    quantifiers, no rule table ships a flagged pattern, small-input inline
    parity holds, and the -I worker hygiene contract still holds."""
    assert regex_budget.audit_pattern(CATASTROPHIC.pattern)
    from scanner import sast
    offenders = []
    for r in sast.REGEX_RULES:
        if regex_budget.audit_pattern(r["pattern"].pattern):
            offenders.append(r.get("id"))
    for r in sast.ENTERPRISE_RULES:
        if regex_budget.audit_pattern(r["pat"]):
            offenders.append(r.get("id"))
    assert not offenders, f"flagged patterns in tables: {offenders}"
    got = list(regex_budget.timed_finditer(
        re.compile(r"(a+)+b"), "aaab", rule_id="FR3_S12"))
    assert [m.span() for m in got] == [(0, 4)]
    proc = subprocess.run(
        [sys.executable, "-I", str(REPO / "core" / "regex_budget.py"),
         "--worker"],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0
