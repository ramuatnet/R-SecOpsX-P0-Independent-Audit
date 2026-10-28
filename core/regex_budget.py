"""T-0.5: per-regex wall-clock budget + nested-quantifier audit.

task.md section 3, T-0.5. Ground rule 12 (resource bounds for untrusted
input) and ground rule 3 (a loss is annotated, never silent):

  * every finditer through :func:`timed_finditer` is measured against
    DEFAULT_BUDGET_MS (250 ms); a breach records a REGEX_TIMEOUT row in
    the per-scan collector -- surfaced in report metadata when present;
  * statically-suspect patterns (nested unbounded quantifiers, the
    catastrophic-backtracking signature) are additionally run through a
    subprocess hard-guard on large inputs (>= _GUARD_MIN_BYTES). Python's
    C ``re`` engine holds the GIL for the duration of a match, so an
    in-process watchdog cannot interrupt it -- a subprocess kill can;
  * :func:`audit_pattern` is the static gate used by
    tests/test_redos_budget.py to keep new nested-quantifier rules out of
    the rule tables.

Parity contract (ground rule 7): the literal-prefix prefilter yields the
EXACT match set of ``pattern.finditer(source)``. It only engages when
every top-level alternative starts with a required literal (after
zero-width assertion stripping / small alternation-group expansion), so
every match start is a candidate position; candidates are then replayed
with ``pattern.match`` in leftmost non-overlapping order, replicating
finditer's empty-match advance. When in doubt the prefilter disables
itself and the plain finditer runs.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

DEFAULT_BUDGET_MS = 250

# Prefilter engages only on inputs where whole-file scanning actually
# costs something; below this the plain finditer is already fast.
_PREFILTER_MIN = 32 * 1024
# Candidate explosion guard: if more than 1/len(source)/_CANDIDATE_CAP_DIV
# positions are candidates, the prefilter loses its value -> plain finditer.
_CANDIDATE_CAP_DIV = 8
_MAX_LITERALS = 48
_GROUP_EXPAND_DEPTH = 4
# Shortest required-anywhere literal worth a presence probe (a common
# 3-letter token is almost always present, so the probe would rarely pay).
_ANYWHERE_MIN_LEN = 4

# Subprocess hard-guard: statically-suspect patterns on inputs at least
# this large (characters) run in a killable child process. Grace covers
# interpreter spawn + stdin transfer, not matching time -- the child gets
# budget_ms to produce spans, then it is killed.
_GUARD_MIN_BYTES = 64 * 1024
_GUARD_GRACE_S = 2.0

# Collector keeps the slowest _KEEP_CHECKS rows to bound memory on large
# scans; every breach row is kept in full.
_KEEP_CHECKS = 500


# ---------------------------------------------------------------------------
# Static auditor
# ---------------------------------------------------------------------------
def _group_spans(pat: str, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """(open, close, body_start, body_end) for every group in pat[start:end].

    close/body_end are exclusive-of-')' for the body; escapes and
    character classes are skipped so parens inside them are not groups.
    """
    spans = []
    i = start
    n = min(end, len(pat))
    while i < n:
        c = pat[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and pat[j] == "^":
                j += 1
            if j < n and pat[j] == "]":  # leading ] is literal
                j += 1
            while j < n and pat[j] != "]":
                j += 2 if pat[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            depth = 1
            j = i + 1
            while j < n and depth:
                d = pat[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "[":
                    k = j + 1
                    if k < n and pat[k] == "^":
                        k += 1
                    if k < n and pat[k] == "]":
                        k += 1
                    while k < n and pat[k] != "]":
                        k += 2 if pat[k] == "\\" else 1
                    j = k + 1
                    continue
                if d == "(":
                    depth += 1
                elif d == ")":
                    depth -= 1
                j += 1
            if depth:  # unbalanced -- refuse to audit
                return []
            spans.append((i, j - 1, i + 1, j - 1))
            i = j
            continue
        i += 1
    # innermost first: longest bodies first
    spans.sort(key=lambda s: (s[2], -s[3]))
    return spans


def _skip_atom(pat: str, i: int, end: int) -> int:
    """Index just past the atom starting at i (class/escape/group/char)."""
    if i >= end:
        return i
    c = pat[i]
    if c == "\\":
        return i + 2
    if c == "[":
        j = i + 1
        if j < end and pat[j] == "^":
            j += 1
        if j < end and pat[j] == "]":
            j += 1
        while j < end and pat[j] != "]":
            j += 2 if pat[j] == "\\" else 1
        return j + 1
    if c == "(":
        spans = _group_spans(pat, i, end)
        if not spans:
            return i + 1
        for op, cl, _, _ in spans:
            if op == i:
                return cl + 1
        return i + 1
    return i + 1


def _quantifier_at(pat: str, i: int, end: int) -> tuple[bool, int]:
    """(unbounded_quantifier_here?, index just past it)."""
    if i >= end:
        return False, i
    c = pat[i]
    if c in "*+":
        # nested quantifier like *+ / ++ (possessive) -- still unbounded
        return True, i + 1 + (1 if i + 1 < end and pat[i + 1] in "+*" else 0)
    if c == "{":
        j = pat.find("}", i, end)
        if j == -1:
            return False, i
        body = pat[i + 1:j]
        if re.fullmatch(r"\d+,", body):  # {m,} open-ended -> unbounded
            return True, j + 1
        return False, j + 1  # {n}, {m,n}, {,n} are bounded
    return False, i


def _body_has_unbounded(pat: str, bstart: int, bend: int) -> bool:
    """Does any direct atom in the body carry an unbounded quantifier?"""
    i = bstart
    while i < bend:
        if pat[i] == "|":
            i += 1
            continue
        nxt = _skip_atom(pat, i, bend)
        unb, past = _quantifier_at(pat, nxt, bend)
        if unb:
            return True
        if nxt == i:  # safety against stalls
            i += 1
        else:
            i = nxt
    return False


def _nested_unbounded(pat: str) -> bool:
    for op, cl, bs, be in _group_spans(pat, 0, len(pat)):
        if not _body_has_unbounded(pat, bs, be):
            continue
        unb, _ = _quantifier_at(pat, cl + 1, len(pat))
        if unb:
            return True
    return False


def _identical_alternation(pat: str) -> bool:
    for op, cl, bs, be in _group_spans(pat, 0, len(pat)):
        unb, _ = _quantifier_at(pat, cl + 1, len(pat))
        if not unb:
            continue
        body = pat[bs:be]
        # top-level split of the group body
        parts, depth, i, last = [], 0, 0, 0
        ok = True
        while i < len(body):
            c = body[i]
            if c == "\\":
                i += 2
                continue
            if c == "[":
                j = i + 1
                if j < len(body) and body[j] == "^":
                    j += 1
                if j < len(body) and body[j] == "]":
                    j += 1
                while j < len(body) and body[j] != "]":
                    j += 2 if body[j] == "\\" else 1
                i = j + 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "|" and depth == 0:
                parts.append(body[last:i])
                last = i + 1
            i += 1
        if not ok or not parts:
            continue
        parts.append(body[last:])
        stripped = [p.strip() for p in parts]
        if len(set(stripped)) < len(stripped) and len(stripped) > 1:
            return True
    return False


def audit_pattern(pat: str) -> list[str]:
    """Static ReDoS signature audit of one pattern string.

    Returns a list of flags; empty means the pattern carries no known
    catastrophic-backtracking signature. Bounded inner quantifiers
    (``{0,250}`` etc.) are linear and intentionally not flagged -- that
    keeps the project's existing SPRING/PHP rules legal.
    """
    flags: list[str] = []
    try:
        if "(" in pat and _nested_unbounded(pat):
            flags.append("nested_quantifier")
        if "(" in pat and _identical_alternation(pat):
            flags.append("identical_alternation")
    except Exception:  # malformed pattern must not crash the audit gate
        flags.append("audit_error")
    return flags


# ---------------------------------------------------------------------------
# Per-scan collector
# ---------------------------------------------------------------------------
class RegexBudgetCollector:
    """Thread-safe REGEX_TIMEOUT / timing ledger for one scan."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._checks: list[dict] = []
        self._timeouts: list[dict] = []
        self._checks_total = 0
        self._total_ms = 0.0

    def record_check(self, rule_id: str, file: str, wall_ms: float,
                     cpu_ms: float, matches: int) -> None:
        with self._lock:
            self._checks_total += 1
            self._total_ms += wall_ms
            self._checks.append(
                {"rule_id": rule_id, "file": file,
                 "wall_ms": round(wall_ms, 3), "cpu_ms": round(cpu_ms, 3),
                 "matches": matches})
            if len(self._checks) > 2 * _KEEP_CHECKS:
                # Keep the slowest rows by CPU -- CPU is the machine-
                # independent cost signal; wall under load is noisy.
                self._checks.sort(key=lambda r: -r["cpu_ms"])
                del self._checks[_KEEP_CHECKS:]

    def record_timeout(self, rule_id: str, file: str, budget_ms: int,
                       mode: str, elapsed_ms: float | None = None) -> None:
        row = {"rule_id": rule_id, "file": file, "budget_ms": budget_ms,
               "mode": mode}
        if elapsed_ms is not None:
            row["elapsed_ms"] = round(elapsed_ms, 3)
        with self._lock:
            self._timeouts.append(row)

    def timeouts(self) -> list[dict]:
        with self._lock:
            return sorted(self._timeouts,
                          key=lambda r: (r["rule_id"], r["file"], r["mode"]))

    def checks(self) -> list[dict]:
        with self._lock:
            return list(self._checks)

    def as_metadata(self) -> dict:
        with self._lock:
            return {
                "budget_ms": DEFAULT_BUDGET_MS,
                "checks": self._checks_total,
                "total_ms": round(self._total_ms, 1),
                "timeouts": sorted(self._timeouts,
                                   key=lambda r: (r["rule_id"], r["file"],
                                                  r["mode"])),
            }


_COLLECTOR_LOCK = threading.Lock()
_COLLECTOR: RegexBudgetCollector | None = None


def begin_scan() -> RegexBudgetCollector:
    global _COLLECTOR
    with _COLLECTOR_LOCK:
        _COLLECTOR = RegexBudgetCollector()
    return _COLLECTOR


def current() -> RegexBudgetCollector:
    global _COLLECTOR
    with _COLLECTOR_LOCK:
        if _COLLECTOR is None:
            _COLLECTOR = RegexBudgetCollector()
        return _COLLECTOR


# ---------------------------------------------------------------------------
# Literal-prefix prefilter (exact finditer parity)
# ---------------------------------------------------------------------------
# Inline verbose/comment constructs that change how the pattern string
# itself must be parsed -- prefilter bails rather than misreading them.
# (Backreferences like (?P=q) do NOT disable: they cannot change that a
# required prefix literal must appear in every match.)
_DISABLE_PREFIX = re.compile(r"\(\?[xmsau]*-|\(\?#")
# Leading inline flag group, e.g. the "(?i)" head of SOL_WEAK_RANDOMNESS.
_LEADING_FLAGS = re.compile(r"^\(\?[imsx]+\)")


def _strip_leading_flags(pat: str) -> str:
    """Drop a leading inline flag group; its effect lives in pattern.flags."""
    while True:
        m = _LEADING_FLAGS.match(pat)
        if not m:
            return pat
        pat = pat[m.end():]


def _group_end(pat: str, i: int) -> int | None:
    """Index just past the ')' matching the '(' at i, else None."""
    spans = _group_spans(pat, i, len(pat))
    for op, cl, _, _ in spans:
        if op == i:
            return cl + 1
    return None


def _strip_zero_width(branch: str) -> int | None:
    """Index after leading zero-width tokens (\b, anchors, assertions)."""
    i = 0
    n = len(branch)
    while i < n:
        two = branch[i:i + 2]
        if two in ("\\b", "\\B", "\\A", "\\Z", "\\z"):
            i += 2
            continue
        if branch[i] == "^":
            i += 1
            continue
        if branch.startswith(("(?=", "(?!", "(?<=", "(?<!"), i):
            j = _group_end(branch, i)
            if j is None:
                return None
            i = j
            continue
        break
    return i


def _read_literal(branch: str, i: int) -> tuple[str, int]:
    """(literal run starting at i, index just past it). May be empty.

    A quantifier directly after the run quantifies its LAST character
    (``abc*`` requires only ``ab``), so that character is dropped --
    otherwise the "required" prefix would not actually be required and
    candidate positions could miss true match starts.
    """
    out = []
    n = len(branch)
    while i < n:
        c = branch[i]
        if c == "\\" and i + 1 < n:
            nxt = branch[i + 1]
            if nxt.isalnum() or nxt in "bBAZz":
                break  # class escape or zero-width -- not a literal
            out.append(nxt)
            i += 2
            continue
        if c in "*+?" and out:
            out.pop()  # this character is quantified -> not required
            i += 1
            break
        if c == "{":
            m = re.match(r"\{\d*,?\d*\}", branch[i:])
            if m:
                if out:
                    out.pop()
                i += m.end()
                break
            break  # literal-ish brace: stop conservatively
        if c in "()[]|^$.<":
            break
        out.append(c)
        i += 1
    return "".join(out), i


def _open_token_len(branch: str, i: int) -> int | None:
    """Length of the opening token of the group at i, or None if it is
    not a group we know how to expand (lookarounds handled by caller)."""
    if branch.startswith("(?:", i):
        return 3
    if branch.startswith("(?P<", i) or branch.startswith("(?<", i):
        gt = branch.find(">", i)
        return (gt - i + 1) if gt != -1 else None
    if branch.startswith("(?", i):
        # inline flag group (?i) / (?im:...) scoped group / unknown (?..
        # -- conservative: do not expand, do not misparse as plain '('
        return None
    if branch[i] == "(":
        return 1
    return None


def _branch_literals(branch: str, depth: int = 0) -> list[str] | None:
    """Required prefix literals of one alternative, or None if the
    alternative has no provable literal prefix."""
    if depth > _GROUP_EXPAND_DEPTH:
        return None
    i = _strip_zero_width(branch)
    if i is None:
        return None
    lit, j = _read_literal(branch, i)
    if lit:
        return [lit]
    if i < len(branch) and branch[i] == "(" and branch.startswith("(?", i):
        if not branch.startswith(("(?=", "(?!", "(?<=", "(?<!"), i):
            # expansion-capable group: (?:..), (?P<n>..), (?<n>..), plain (
            tok = _open_token_len(branch, i)
            if tok is None:
                return None
            end = _group_end(branch, i)
            if end is None:
                return None
            body = branch[i + tok:end - 1]
            lits: list[str] = []
            for sub in _split_top_alternatives(body):
                got = _branch_literals(sub, depth + 1)
                if not got:
                    return None
                lits.extend(got)
                if len(lits) > _MAX_LITERALS:
                    return None
            return lits or None
    return None


def _split_top_alternatives(pat: str) -> list[str]:
    parts, depth, i, last = [], 0, 0, 0
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and pat[j] == "^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 2 if pat[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append(pat[last:i])
            last = i + 1
        i += 1
    parts.append(pat[last:])
    return parts


_PREFILTER_CACHE: dict[tuple[str, int], tuple[str, ...] | None] = {}
_SUSPECT_CACHE: dict[tuple[str, int], bool] = {}
_ANYWHERE_CACHE: dict[tuple[str, int], frozenset[str] | None] = {}


def _branch_required_runs(branch: str) -> set[str]:
    """Literal runs at depth 0 that ANY match of this branch must contain.

    Conservative: groups and classes are skipped whole (their contents
    may be optional or alternate), a run broken by a quantifier loses its
    last character, and only runs of >= _ANYWHERE_MIN_LEN are kept.
    """
    out: set[str] = set()
    run: list[str] = []
    i, n = 0, len(branch)

    def close(drop_last: bool = False) -> None:
        if run:
            s = "".join(run[:-1] if drop_last else run)
            if len(s) >= _ANYWHERE_MIN_LEN:
                out.add(s)
        run.clear()

    while i < n:
        c = branch[i]
        if c == "\\" and i + 1 < n:
            nxt = branch[i + 1]
            if nxt.isalnum() or nxt in "bBAZz":
                close()  # class/zero-width escape ends the run
            else:
                run.append(nxt)
            i += 2
            continue
        if c == "[":
            close()
            j = i + 1
            if j < n and branch[j] == "^":
                j += 1
            if j < n and branch[j] == "]":
                j += 1
            while j < n and branch[j] != "]":
                j += 2 if branch[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            close()
            j = _group_end(branch, i)
            if j is None:
                return out
            i = j
            continue
        if c in "*+?":
            close(drop_last=True)
            i += 1
            continue
        if c == "{":
            m = re.match(r"\{\d*,?\d*\}", branch[i:])
            if m:
                close(drop_last=True)
                i += m.end()
                continue
            close()
            i += 1
            continue
        if c in ")|^":
            close()
            i += 1
            continue
        if c in ".^$<":
            close()
            i += 1
            continue
        run.append(c)
        i += 1
    close()
    return out


def required_anywhere_literals(pattern: re.Pattern) -> frozenset[str] | None:
    """Literals common to EVERY top-level alternative (or None).

    If any of these is absent from the source, the pattern provably has
    zero matches -- an exact skip, not an approximation.
    """
    key = (pattern.pattern, pattern.flags)
    hit = _ANYWHERE_CACHE.get(key, ...)
    if hit is not ...:
        return hit
    req: frozenset[str] | None = None
    pat = _strip_leading_flags(pattern.pattern)
    if not _DISABLE_PREFIX.search(pat) and pat.isascii():
        inter: set[str] | None = None
        for branch in _split_top_alternatives(pat):
            runs = _branch_required_runs(branch)
            if inter is None:
                inter = runs
            else:
                inter &= runs
            if not inter:
                break
        if inter:
            req = frozenset(inter)
    _ANYWHERE_CACHE[key] = req
    return req


def _absent_from_source(pattern: re.Pattern, source: str,
                        req: frozenset[str]) -> bool:
    """True when at least one required literal cannot occur in source."""
    ignore_case = bool(pattern.flags & re.IGNORECASE)
    if ignore_case:
        lowered = _lower_preserving(source)
        if lowered is not None:
            return any(lit.lower() not in lowered for lit in req)
        return any(
            re.search(re.escape(lit), source, re.I) is None for lit in req)
    return any(lit not in source for lit in req)


def prefilter_literals(pattern: re.Pattern) -> tuple[str, ...] | None:
    """Required prefix literals enabling the prefilter, or None."""
    key = (pattern.pattern, pattern.flags)
    hit = _PREFILTER_CACHE.get(key, ...)
    if hit is not ...:
        return hit
    lits: tuple[str, ...] | None = None
    pat = _strip_leading_flags(pattern.pattern)
    if not _DISABLE_PREFIX.search(pat) and pat.isascii():
        all_lits: list[str] = []
        ok = True
        for branch in _split_top_alternatives(pat):
            got = _branch_literals(branch)
            if not got or not all(g.isascii() and g for g in got):
                ok = False
                break
            all_lits.extend(got)
        if ok and all_lits and len(all_lits) <= _MAX_LITERALS:
            lits = tuple(dict.fromkeys(all_lits))  # dedupe, keep order
    _PREFILTER_CACHE[key] = lits
    return lits


_LOWER_SLOT: tuple = ()  # (source_ref, lowered) -- single atomic tuple


def _lower_preserving(source: str) -> str | None:
    """Lowercased source for case-insensitive candidate search.

    str.lower() can change string length for a few Unicode code points
    (positional drift would corrupt candidates); when that happens we
    return None and the caller falls back to per-literal re.finditer
    with re.I, which is always position-correct.

    The cache is one tuple swapped atomically (GIL-safe): scan_file runs
    on a ThreadPoolExecutor, and a torn (source, lowered) pair would
    hand one file's lowered text to another file's candidates.
    """
    global _LOWER_SLOT
    slot = _LOWER_SLOT
    if slot and slot[0] is source:
        return slot[1]
    lowered = source.lower()
    if len(lowered) != len(source):
        return None
    _LOWER_SLOT = (source, lowered)
    return lowered


def _candidate_positions(pattern: re.Pattern, source: str,
                         lits: tuple[str, ...]) -> list[int]:
    """Sorted candidate match-start positions (superset of true starts)."""
    if pattern.flags & re.IGNORECASE:
        lowered = _lower_preserving(source)
        if lowered is None:
            cands: set[int] = set()
            for lit in lits:
                for m in re.finditer(re.escape(lit), source, re.I):
                    cands.add(m.start())
            return sorted(cands)
        cands = set()
        for lit in lits:
            lo = lit.lower()
            start = 0
            while True:
                p = lowered.find(lo, start)
                if p < 0:
                    break
                cands.add(p)
                start = p + 1
        return sorted(cands)
    cands = set()
    for lit in lits:
        start = 0
        while True:
            p = source.find(lit, start)
            if p < 0:
                break
            cands.add(p)
            start = p + 1
    return sorted(cands)


def _prefilter_finditer(pattern: re.Pattern, source: str,
                        cands: list[int]) -> list[re.Match]:
    """Leftmost non-overlapping matches, finditer-identical."""
    import bisect
    out: list[re.Match] = []
    pos = 0
    n = len(cands)
    while True:
        idx = bisect.bisect_left(cands, pos)
        if idx >= n:
            break
        start = cands[idx]
        m = pattern.match(source, start)
        if m is not None:
            out.append(m)
            pos = m.end() if m.end() > m.start() else m.end() + 1
        else:
            pos = start + 1
    return out


def _is_suspect(pattern: re.Pattern) -> bool:
    key = (pattern.pattern, pattern.flags)
    hit = _SUSPECT_CACHE.get(key)
    if hit is None:
        hit = bool(audit_pattern(pattern.pattern))
        _SUSPECT_CACHE[key] = hit
    return hit


# ---------------------------------------------------------------------------
# Subprocess hard-guard (the only true interruption for stdlib re)
# ---------------------------------------------------------------------------
def _guarded_spans(pattern: re.Pattern, source: str,
                   budget_ms: int) -> tuple[list[list[int]] | None, bool, bool]:
    """Run finditer in a killable child.

    Returns (spans, timed_out, errored). On timeout the child is killed
    and no spans are returned -- the caller records REGEX_TIMEOUT, so the
    dropped matches are never silent.
    """
    cmd = [sys.executable, "-I", str(Path(__file__).resolve()), "--worker",
           pattern.pattern, str(pattern.flags), str(int(budget_ms))]
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL)
    except OSError:
        return None, False, True
    try:
        out, _ = proc.communicate(
            source.encode("utf-8", "surrogateescape"),
            timeout=budget_ms / 1000.0 + _GUARD_GRACE_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=_GUARD_GRACE_S)
        except Exception:
            pass
        return None, True, False
    if proc.returncode != 0:
        return None, False, True
    try:
        spans = json.loads(out.decode("utf-8"))
        assert isinstance(spans, list)
        return spans, False, False
    except Exception:
        return None, False, True


def _replay_spans(pattern: re.Pattern, source: str,
                  spans: list[list[int]]) -> list[re.Match]:
    """Rebuild match objects at child-reported start positions."""
    out: list[re.Match] = []
    for item in spans:
        start = int(item[0])
        m = pattern.match(source, start)
        if m is not None and m.start() == start:
            out.append(m)
    return out


# ---------------------------------------------------------------------------
# The budgeted finditer
# ---------------------------------------------------------------------------
def timed_finditer(pattern: re.Pattern, source: str, *, rule_id: str,
                   file_path: str = "<memory>",
                   budget_ms: int | None = None):
    """finditer with a wall-clock budget (DEFAULT_BUDGET_MS).

    Returns the match iterator. On breach a REGEX_TIMEOUT row is recorded
    (wall-clock -- the operator-facing signal from task.md T-0.5) --
    telemetry, never a silent skip (ground rule 3). Each check also
    records CPU time: CPU is the machine-independent per-regex cost and
    what the acceptance gate asserts on, so a loaded machine cannot flake
    the 5 MB budget while wall-clock telemetry stays faithful to spec.
    """
    budget = DEFAULT_BUDGET_MS if budget_ms is None else budget_ms
    coll = current()
    t0 = time.perf_counter()
    c0 = time.process_time()

    def _finish(matches: list[re.Match]) -> iter:
        wall = (time.perf_counter() - t0) * 1000
        cpu = (time.process_time() - c0) * 1000
        coll.record_check(rule_id, file_path, wall, cpu, len(matches))
        if wall > budget:
            # In-process re cannot be interrupted mid-match (GIL held by
            # the C engine); this row is post-hoc telemetry. Prevention
            # for this class of pattern is the static audit gate plus the
            # prefilter and the required-literal presence gate.
            coll.record_timeout(rule_id, file_path, budget, "post_hoc", wall)
        return iter(matches)

    # Exact skip: a literal required by EVERY alternative is absent from
    # this source, so the pattern has provably zero matches here.
    req = required_anywhere_literals(pattern)
    if req and _absent_from_source(pattern, source, req):
        return _finish([])

    if _is_suspect(pattern) and len(source) >= _GUARD_MIN_BYTES:
        spans, timed_out, errored = _guarded_spans(pattern, source, budget)
        wall = (time.perf_counter() - t0) * 1000
        cpu = (time.process_time() - c0) * 1000
        if timed_out:
            coll.record_timeout(rule_id, file_path, budget,
                                "subprocess_guard", wall)
            return iter(())
        if errored:
            coll.record_timeout(rule_id, file_path, budget,
                                "subprocess_error", wall)
            return iter(())
        matches = _replay_spans(pattern, source, spans or [])
        coll.record_check(rule_id, file_path, wall, cpu, len(matches))
        if wall > budget:
            coll.record_timeout(rule_id, file_path, budget,
                                "subprocess_slow", wall)
        return iter(matches)

    lits = prefilter_literals(pattern) if len(source) >= _PREFILTER_MIN else None
    matches: list[re.Match]
    if lits:
        cands = _candidate_positions(pattern, source, lits)
        if len(cands) <= max(1000, len(source) // _CANDIDATE_CAP_DIV):
            matches = _prefilter_finditer(pattern, source, cands)
        else:
            matches = list(pattern.finditer(source))
    else:
        matches = list(pattern.finditer(source))
    return _finish(matches)


# ---------------------------------------------------------------------------
# Worker entrypoint for the subprocess hard-guard (stdlib-only; run with
# -I by the parent, so it must not import the project).
# ---------------------------------------------------------------------------
def _worker_main(argv: list[str]) -> int:
    # argv is sys.argv[1:], so it starts with the literal "--worker".
    if len(argv) != 4 or argv[0] != "--worker":
        sys.stderr.write("usage: regex_budget.py --worker PATTERN FLAGS BUDGET_MS\n")
        return 2
    argv = argv[1:]
    try:
        compiled = re.compile(argv[0], int(argv[1]))
    except re.error as exc:
        sys.stderr.write(f"bad pattern: {exc}\n")
        return 2
    data = sys.stdin.buffer.read()
    source = data.decode("utf-8", "surrogateescape")
    spans = [[m.start(), m.end()] for m in compiled.finditer(source)]
    sys.stdout.write(json.dumps(spans))
    return 0


if __name__ == "__main__":
    sys.exit(_worker_main(sys.argv[1:]))
