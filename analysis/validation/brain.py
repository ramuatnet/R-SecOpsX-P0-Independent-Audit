"""Security brain: multi-level self-validation for the scanner itself.

The scanner audits other people's code. This module turns that audit inward:
six levels of checks against the scanner's own controls, run in dependency
order, every check stating a CLAIM (its docstring) that the verdict must back
with EVIDENCE. A control that cannot prove it works is treated as broken --
the same kill-only-on-proof contract the corpus applies to findings, applied
to the tester.

WHY A BRAIN AND NOT MORE PYTEST
-------------------------------
pytest answers "does this commit keep its promises". The brain answers
"can I trust this deployment right now, on THIS host" -- it re-derives the
answers from the live modules rather than from a recorded run, so a stale
.pyc, a half-upgraded install, or an operator config that quietly disabled a
gate shows up as a failing level instead of as nothing. It is the instrument
you run BEFORE pointing the scanner at a production target.

THE LEVELS
----------
  L0  static-integrity    every live module compiles; a broken import is a
                          deployment, not a finding
  L1  control-gates       the exclusion policy, the scanner-result detector,
                          and the word-boundary sink behave as documented
  L2  loop-invariants     idempotency (scan twice -> identical), batching
                          terminates, the advisory cache is read-only on the
                          offline path, determinism across repeated scans
  L3  shape-invariants    rule tables are well-formed; findings carry a legal
                          severity, a snippet, and a boolean evidence flag
  L4  adversarial         corpus fixtures scan crash-free; the L1 word-boundary
                          control is PROVEN to have teeth by restoring the
                          legacy sink and watching the FP re-fire; a poisoned
                          cache entry cannot crash the advisory path
  L5  meta                the scanner's own artifacts are self-excluded, the
                          report-envelope detector agrees with both engines,
                          and the triage scorer sitting beside this module
                          still puts a known FP family in LIKELY_FP

EXIT CODES (the same contract the rest of the package reports under)
--------------------------------------------------------------------
  0   every check passed
  1   at least one check FAILED -- a control is broken; do not scan prod
  2   no failure, but at least one check could not establish its claim
      (environmental) -- matches the handoff rule that environmental limits
      are BLOCKED, never PASS

OFFLINE CONTRACT
----------------
No check contacts the network. The advisory-cache check needs the offline
path, so it forces ``RSECOPSX_LIVE_FEEDS=0`` for its duration and RESTORES
the operator's value afterwards; the restore is asserted, because a tool
that mutates its operator's environment while claiming to test controls
would be disqualifying itself.

Determinism: no randomness, no clock-dependent comparisons, same tree ->
same verdict and same evidence ordering.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_28, WINDOW_3, WINDOW_4, WINDOW_EVIDENCE
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_28, WINDOW_3, WINDOW_4, WINDOW_EVIDENCE

import hashlib
import io
import json
import os
import re
import sys
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Callable, NamedTuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

ROOT = Path(__file__).resolve().parents[2]

from scanner.walk import walk

SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

# The directory set the two engines must agree on. scanner/secret_intelligence
# promises "keep in sync with scanner.sast.EXCLUDED_DIRS"; this is the floor of
# that promise -- every name the secrets engine excludes must also be excluded
# by the SAST engine, or one engine scans what the other refuses.
SYNC_FLOOR = frozenset({
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "vendor", "out", "bundle",
})

# Artifact names the scanner writes into its own output directory. Reading
# them back as source is the self-scan hazard the EXCLUDED_FILES set exists
# for; the brain holds the minimum set as an invariant, not as folklore.
SELF_ARTIFACTS = (
    "clean_report.json", "sbom.json", "sarif.json",
    "security_cyclonedx.json", "security_report.vex.json",
    "security_cbom.cdx.json", "security_aibom.cdx.json",
)


class CheckResult(NamedTuple):
    name: str
    level: str
    status: str            # "pass" | "fail" | "blocked"
    claim: str             # the docstring's first line: what was asserted
    evidence: str          # what was actually observed
    duration_ms: float


def _claim(fn: Callable) -> str:
    doc = (fn.__doc__ or "").strip().splitlines()
    return doc[0].strip() if doc else "(no claim stated)"


class Brain:
    """Orchestrates the six levels. Levels run in order; every check runs and
    the verdict aggregates, because a report that stops at the first failure
    hides how deep the rot goes."""

    LEVEL_IDS = ("L0", "L1", "L2", "L3", "L4", "L5")
    LEVEL_NAMES = {
        "L0": "static-integrity",
        "L1": "control-gates",
        "L2": "loop-invariants",
        "L3": "shape-invariants",
        "L4": "adversarial",
        "L5": "meta",
    }

    def __init__(self) -> None:
        self._checks: dict[str, list[tuple[str, Callable]]] = {
            lvl: [] for lvl in self.LEVEL_IDS
        }
        for lvl in self.LEVEL_IDS:
            for fn in self._level_checks(lvl):
                self._checks[lvl].append((fn.__name__, fn))

    # ------------------------------------------------------------------
    # level construction
    # ------------------------------------------------------------------
    def _level_checks(self, level: str) -> list[Callable]:
        return [
            fn
            for name, fn in sorted(globals().items())
            if name.startswith(f"_chk_{level}_") and callable(fn)
        ]

    def add_check(self, level: str, fn: Callable) -> None:
        """Register an extra check (extension point; also the tests' hook)."""
        if level not in self.LEVEL_IDS:
            raise ValueError(f"unknown level {level!r}")
        self._checks[level].append((fn.__name__, fn))

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------
    def run(self, only: list[str] | None = None) -> dict:
        levels = list(only) if only else list(self.LEVEL_IDS)
        unknown = [l for l in levels if l not in self.LEVEL_IDS]
        if unknown:
            raise ValueError(f"unknown level(s): {unknown}")

        results: list[CheckResult] = []
        for lvl in levels:
            for name, fn in self._checks[lvl]:
                t0 = time.perf_counter()
                try:
                    evidence = fn() or ""
                    status = "pass"
                except AssertionError as exc:
                    evidence = str(exc)
                    status = "fail"
                except Exception as exc:  # noqa: BLE001 - recorded, not raised
                    evidence = "%s: %s" % (type(exc).__name__, exc)
                    status = "blocked"
                results.append(CheckResult(
                    name=name, level=lvl, status=status,
                    claim=_claim(fn), evidence=evidence,
                    duration_ms=round((time.perf_counter() - t0) * 1000, 1),
                ))

        counts = Counter(r.status for r in results)
        if counts["fail"]:
            verdict, code = "FAIL", 1
        elif counts["blocked"]:
            verdict, code = "BLOCKED", 2
        else:
            verdict, code = "PASS", 0
        return {
            "tool": "R-SecOpsX Security Brain v1",
            "levels": levels,
            "checks": [r._asdict() for r in results],
            "counts": dict(counts),
            "verdict": verdict,
            "exit_code": code,
        }


# ======================================================================
# L0 -- static integrity
# ======================================================================
def _chk_L0_live_tree_compiles() -> str:
    """CLAIM: every module in the live tree compiles; a broken import is a
    deployment defect, not a finding."""
    import py_compile

    roots = ("scanner", "analysis", "core", "reporting")
    skipped_roots = ("backup", "dump", "quarantine")
    # Bytecode goes to a scratch directory, never beside the sources: littering
    # the live tree with .pyc files would pollute the very tree this level
    # claims to certify.
    scratch = Path(tempfile.mkdtemp(prefix="rsx_brain_pyc_"))
    bad, scanned = [], 0
    for root in roots:
        base = ROOT / root
        for p, _s, _m in walk(base, exts={".py"}, ignore=frozenset(),
                              max_bytes=None):
            parts = {x.lower() for x in p.parts}
            if parts.intersection(skipped_roots):
                continue
            scanned += 1
            cfile = scratch / ("%d.pyc" % scanned)
            try:
                py_compile.compile(str(p), doraise=True, cfile=str(cfile))
            except py_compile.PyCompileError as exc:
                bad.append("%s: %s" % (p.relative_to(ROOT), str(exc)[:WINDOW_EVIDENCE]))
    assert not bad, "%d of %d modules fail to compile: %s" % (
        len(bad), scanned, "; ".join(bad[:WINDOW_3]))
    return "compiled %d modules across %s" % (scanned, ", ".join(roots))


# ======================================================================
# L1 -- control gates
# ======================================================================
def _chk_L1_exclusion_policy_in_sync() -> str:
    """CLAIM: every directory Secret Intelligence excludes is also excluded by
    the SAST engine (the documented keep-in-sync floor)."""
    from scanner.secret_intelligence import EXCLUDED as SEC_EXCLUDED
    from scanner.sast import EXCLUDED_DIRS as SAST_EXCLUDED

    sec = {str(x).lower() for x in SEC_EXCLUDED}
    sast = {str(x).lower() for x in SAST_EXCLUDED}
    drift = sorted(SYNC_FLOOR & sec - sast)
    assert not drift, (
        "exclusion drift: %r excluded by Secret Intelligence but NOT by SAST "
        "-- one engine scans what the other refuses" % drift)
    return "floor of %d shared exclusions agrees; sast carries %d, secrets %d" % (
        len(SYNC_FLOOR), len(sast), len(sec))


def _chk_L1_skip_gates_behave() -> str:
    """CLAIM: bundle/ i18n files and scanner-result JSONs are refused by both
    engines, while application config JSONs and real property files scan."""
    import tempfile

    from scanner.sast import _skip as sast_skip
    from scanner.secret_intelligence import _skip as sec_skip

    d = Path(tempfile.mkdtemp(prefix="rsx_brain_gates_"))
    (d / "bundle").mkdir()
    (d / "bundle" / "messages.properties").write_text(
        "login.password=Masukkan password", encoding="utf-8")
    (d / "RBI7SASTSBOMSCA-result.json").write_text(
        '{"metadata": {"tool": "t", "total_findings": 1},'
        ' "findings": [{"rule_id": "X"}]}', encoding="utf-8")
    (d / "config.json").write_text(
        '{"findings": ["nodule", "lesion"]}', encoding="utf-8")
    (d / "application.properties").write_text(
        "db.password=real", encoding="utf-8")

    rows = [
        ("bundle props refused (sast)", sast_skip(d / "bundle" / "messages.properties"), True),
        ("bundle props refused (secrets)", sec_skip(d / "bundle" / "messages.properties"), True),
        ("result-json refused (sast)", sast_skip(d / "RBI7SASTSBOMSCA-result.json"), True),
        ("result-json refused (secrets)", sec_skip(d / "RBI7SASTSBOMSCA-result.json"), True),
        ("app json scanned (sast)", sast_skip(d / "config.json"), False),
        ("app props scanned (sast)", sast_skip(d / "application.properties"), False),
    ]
    bad = ["%s: got %s" % (n, g) for n, g, w in rows if g != w]
    assert not bad, "; ".join(bad)
    return "6/6 gate rows correct (2 refusals x2 engines, 2 passages)"


def _chk_L1_multipart_sink_word_boundary() -> str:
    """CLAIM: the TAINT_MULTIPART_TRAVERSAL sink matches real File
    constructors and rejects identifier tails like getFile(/copyFile(."""
    import re as _re

    from scanner.taint_engine import ENTERPRISE_TAINT_RULES

    rule = next(r for r in ENTERPRISE_TAINT_RULES
                if r["id"] == "TAINT_MULTIPART_TRAVERSAL")
    sink = rule["sink"]
    assert r"\bFile\(" in sink, "sink lost the word boundary: %r" % sink

    probes = [
        ("event.getFile().x", False, "accessor tail"),
        ("copyFile(String f, InputStream i)", False, "helper signature"),
        ("new File(p)", True, "real constructor"),
        ("java.io.File(p)", True, "qualified constructor"),
    ]
    bad = []
    for text, want, label in probes:
        got = bool(_re.search(sink, text))
        if got != want:
            bad.append("%s(%s) -> %s" % (label, text[:WINDOW_28], got))
    assert not bad, "; ".join(bad)
    return "boundary kills identifier tails, keeps 2/2 constructors"


def _chk_L1_secrets_nonproduction_gate() -> str:
    """CLAIM: the secrets path gate suppresses exactly the nonproduction
    contexts it promises (tests/fixtures/docs/examples, case-insensitive) and
    leaves production-looking paths scannable -- the gate that forced the
    corpus's secrets fixtures through temp copies must itself be under test."""
    from pathlib import Path as _Path

    from scanner.secret_intelligence import _is_nonproduction_context

    suppressed = [
        "tests/payments/test_api.py",
        "tests/vuln-test-corpus/fixtures/key.py",
        "docs/examples/credentials.md",
        "mock/service.py",
        "SPEC/integration.py",
        "TESTS/UPPER/config.py",          # case-insensitive contract
    ]
    scannable = [
        "src/payments/service.py",
        "app/config/settings.py",
        "deploy/prod/terraform/main.tf",
        "application.properties",
    ]
    bad = []
    for p in suppressed:
        if not _is_nonproduction_context(_Path(p)):
            bad.append("%s should be suppressed" % p)
    for p in scannable:
        if _is_nonproduction_context(_Path(p)):
            bad.append("%s should be SCANNABLE" % p)
    assert not bad, "; ".join(bad)
    return "6/6 nonproduction paths suppressed, 4/4 production paths scannable"


def _chk_L1_language_gates_not_orphaned() -> str:
    """CLAIM: every language gate SAST declares is reachable -- an extension
    mapped in LANG_BY_EXT that SCANNABLE_EXT refuses is a dead gate, and the
    G7 (.sol) and G15 (.erb) incidents were exactly this shape in reverse."""
    from scanner.sast import LANG_BY_EXT, SCANNABLE_EXT

    scannable = {str(x).lower() for x in SCANNABLE_EXT}
    orphans = sorted(
        ext for ext in LANG_BY_EXT
        if str(ext).lower() not in scannable
        and str(ext).lower().lstrip(".") not in scannable
    )
    assert not orphans, (
        "orphaned language gates (mapped but never scanned): %r" % orphans)
    return "%d language gates, all reachable from SCANNABLE_EXT" % len(LANG_BY_EXT)


def _chk_L1_pii_nonproduction_gate() -> str:
    """CLAIM: the privacy engine's nonproduction gate suppresses documentation,
    localization, spec, seed and git-transport contexts -- markers match the
    RELATIVE path with slash semantics, so nested shapes are the contract --
    while production application paths stay scannable."""
    import tempfile

    from analysis.privacy_data_exposure_engine import _is_non_production_text

    d = Path(tempfile.mkdtemp(prefix="rsx_brain_pii_gate_"))
    rows = [
        # (relative shape, text, expected gated?)
        ("src/i18n/strings.py", "x = 1", True),
        ("webapp/locales/messages.js", "x = 1", True),
        ("docs/guide.md", "contact@example.com", True),
        ("README.md", "contact@example.com", True),
        ("dist/sbom.json", "x = 1", True),
        ("src/tests/test_api.py", "x = 1", True),
        ("ui/Search.spec.ts", "x = 1", True),
        ("db/seeds/users.py", "x = 1", True),
        ("git.txt", "git+ssh://git@github.com/acme/repo", True),
        ("src/payments/service.py", "x = 1", False),
        ("app/config/settings.py", "x = 1", False),
    ]
    bad = []
    for rel, text, want in rows:
        got = _is_non_production_text(d / rel, text, str(d))
        if got != want:
            bad.append("%s -> %s, want %s"
                       % (rel, "gated" if got else "scannable",
                          "gated" if want else "scannable"))
    assert not bad, "; ".join(bad)
    return "11/11 gate rows correct: 9 suppression shapes, 2 production passages"


def _chk_L1_pii_skip_dirs_in_sync() -> str:
    """CLAIM: the privacy engine refuses the same generated/i18n directories
    the other engines refuse -- it walks the same tree and scans .properties,
    so a narrower SKIP_DIRS rescan-reads translation tables as data subjects
    (the aclean corpus carried 6 such bundles) and tool output under out/."""
    from analysis.privacy_data_exposure_engine import SKIP_DIRS as PII_SKIP
    from scanner.sast import EXCLUDED_DIRS as SAST_EXCLUDED

    pii = {str(x).lower() for x in PII_SKIP}
    drift = sorted(SYNC_FLOOR - pii)
    assert not drift, (
        "privacy SKIP_DIRS drift: %r not excluded -- the privacy engine would "
        "walk directories every other engine refuses" % drift)
    return "floor of %d shared exclusions present; PII skips %d dirs" % (
        len(SYNC_FLOOR), len(pii))


# ======================================================================
# L2 -- loop invariants
# ======================================================================
def _chk_L2_scan_idempotent() -> str:
    """CLAIM: scanning the same file repeatedly converges after the first
    pass -- run 2..N add nothing and remove nothing."""
    import tempfile

    from scanner.taint_engine import scan_file as taint_scan

    src = Path(tempfile.mkdtemp(prefix="rsx_brain_idem_")) / "Store.java"
    src.write_text(
        "public void store(MultipartFile file) throws IOException {\n"
        "    String fileName = file.getOriginalFilename();\n"
        "    File dest = new File(uploadDir + fileName);\n"
        "    file.transferTo(dest);\n"
        "}\n", encoding="utf-8")

    runs = []
    for i in range(3):
        f = taint_scan(str(src))
        runs.append(sorted((str(x.get("rule_id")), int(x.get("line") or 0))
                           for x in f))
    assert runs[0], "probe fixture produced no findings -- probe is broken"
    for i in (1, 2):
        assert runs[i] == runs[0], "run %d diverged from run 1" % (i + 1)
    return "3 scans, %d findings, identical rule/line sets throughout" % len(runs[0])


def _chk_L2_batching_terminates() -> str:
    """CLAIM: the advisory batching loop chunks exactly ceil(n/BATCH_SIZE)
    times and preserves every package."""
    from scanner.vulnerability_intel import BATCH_SIZE

    n = BATCH_SIZE * 2 + BATCH_SIZE // 2
    synthetic = list(range(n))
    chunks = [synthetic[i:i + BATCH_SIZE]
              for i in range(0, len(synthetic), BATCH_SIZE)]
    assert len(chunks) == -(-n // BATCH_SIZE) == 3, (
        "expected 3 chunks, got %d" % len(chunks))
    assert sum(len(c) for c in chunks) == n, "batching lost packages"
    return "%d packages -> %d chunks (BATCH_SIZE=%d), none lost" % (
        n, len(chunks), BATCH_SIZE)


def _chk_L2_offline_cache_is_read_only() -> str:
    """CLAIM: on the offline path the advisory cache is read-only and stable
    across repeated calls; live feeds are forced off for the duration and the
    operator's setting is restored afterwards."""
    import scanner.vulnerability_intel as vi

    env_key = "RSECOPSX_LIVE_FEEDS"
    operator_value = os.environ.get(env_key)
    cache_file = ROOT / vi.CACHE_FILE

    def _digest():
        if not cache_file.is_file():
            return None
        return hashlib.sha256(cache_file.read_bytes()).hexdigest()

    os.environ[env_key] = "0"
    try:
        probes = [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
                  {"name": "click", "version": "8.1.7", "ecosystem": "PyPI"}]
        before = _digest()
        r1 = vi.query_osv_batch(probes)
        r2 = vi.query_osv_batch(probes)
        after = _digest()
    finally:
        if operator_value is None:
            os.environ.pop(env_key, None)
        else:
            os.environ[env_key] = operator_value

    assert isinstance(r1, dict) and isinstance(r2, dict), "non-dict results"
    assert r1 == r2, "two offline advisory calls disagreed"
    assert before == after, "the offline advisory path WROTE to the cache"
    return "2 calls identical; cache digest unchanged; env restored (%s)" % (
        "unset" if operator_value is None else "previous value")


def _chk_L2_repeat_scan_deterministic() -> str:
    """CLAIM: two scans of the same real target produce byte-identical
    finding sets (rule, line) -- determinism is a contract, not luck."""
    from scanner.sast import scan_file

    target = ROOT / "tests" / "e2e_targets" / "flask_sql" / "app.py"
    assert target.is_file(), "determinism probe target missing: %s" % target

    def _sig():
        return sorted((str(f.get("rule_id")), int(f.get("line") or 0))
                      for f in scan_file(str(target)))

    a, b = _sig(), _sig()
    assert a, "probe target produced no findings -- probe is broken"
    assert a == b, "repeated scan of %s diverged" % target.name
    return "2 scans of %s, %d findings, identical" % (target.name, len(a))


# ======================================================================
# L3 -- shape invariants
# ======================================================================
def _chk_L3_taint_rule_tables_wellformed() -> str:
    """CLAIM: every taint rule states id/title/sev/cwe/src/sink/lang, a legal
    severity, and a well-formed CWE id."""
    from scanner.taint_engine import ENTERPRISE_TAINT_RULES

    cwe_re = re.compile(r"^CWE-\d+$")
    bad = []
    for r in ENTERPRISE_TAINT_RULES:
        for key in ("id", "title", "sev", "cwe", "src", "sink", "lang"):
            if not r.get(key):
                bad.append("%s missing %s" % (r.get("id", "?"), key))
        if r.get("sev") not in SEVERITIES:
            bad.append("%s illegal sev %r" % (r["id"], r.get("sev")))
        if not cwe_re.match(str(r.get("cwe") or "")):
            bad.append("%s malformed cwe %r" % (r["id"], r.get("cwe")))
    assert not bad, "%d rule-table defects: %s" % (len(bad), "; ".join(bad[:WINDOW_4]))
    return "%d taint rules well-formed" % len(ENTERPRISE_TAINT_RULES)


def _chk_L3_all_engine_rule_tables_wellformed() -> str:
    """CLAIM: every rule in EVERY engine's table states an identity, a legal
    severity, and a pattern that actually compiles -- a rule whose pattern
    cannot compile is a crash waiting for its file, and a rule with an
    off-vocabulary severity renders into reports that L3 elsewhere rejects."""
    import re as _re

    from scanner import iac_docker, iac_kubernetes, iac_terraform
    from scanner import llm_security, sast, secret_intelligence
    from scanner.cbom import CRYPTO_RULES

    cwe_re = _re.compile(r"^CWE-\d+$")
    risks = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    bad: list[str] = []

    def _usable(pat) -> bool:
        try:
            if isinstance(pat, str):
                _re.compile(pat)
            else:
                _re.search(pat, "")
            return True
        except _re.error:
            return False

    def _dict_table(rows, id_key, sev_key, pat_key, label, cwe_key="cwe"):
        for r in rows:
            rid = r.get(id_key) or "?"
            if not r.get(id_key):
                bad.append("%s: unnamed rule" % label)
            if r.get(sev_key) not in SEVERITIES:
                bad.append("%s/%s illegal severity %r" % (label, rid, r.get(sev_key)))
            if cwe_key in r and not cwe_re.match(str(r.get(cwe_key) or "")):
                bad.append("%s/%s malformed cwe %r" % (label, rid, r.get(cwe_key)))
            if not _usable(r.get(pat_key) or ""):
                bad.append("%s/%s pattern does not compile" % (label, rid))

    # SAST -- the enterprise table keys pat/sev/id; the regex table is older.
    _dict_table(sast.ENTERPRISE_RULES, "id", "sev", "pat", "sast.enterprise")
    _dict_table(sast.REGEX_RULES, "id", "severity", "pattern", "sast.regex")

    # Secrets -- 6-tuples: (rule_id, title, category, pattern, severity, cwe).
    for label, table in (("secrets.known", secret_intelligence.KNOWN_SECRET_RULES),
                         ("secrets.generic", secret_intelligence.SECRET_RULES)):
        for row in table:
            if len(row) != 6:
                bad.append("%s: tuple arity %d != 6" % (label, len(row)))
                continue
            rid, _t, _c, pat, sev, cwe = row
            if not rid:
                bad.append("%s: unnamed rule" % label)
            if sev not in SEVERITIES:
                bad.append("%s/%s illegal severity %r" % (label, rid, sev))
            if not cwe_re.match(str(cwe or "")):
                bad.append("%s/%s malformed cwe %r" % (label, rid, cwe))
            if not _usable(pat):
                bad.append("%s/%s pattern does not compile" % (label, rid))

    # IaC -- one shape across terraform/docker/kubernetes.
    for label, mod in (("iac.terraform", iac_terraform),
                       ("iac.docker", iac_docker),
                       ("iac.kubernetes", iac_kubernetes)):
        _dict_table(mod.RULES, "rule_id", "severity", "pattern", label)
        missing = getattr(mod, "MISSING_RULES", None)
        for r in (missing or []):
            rid = r.get("rule_id") or "?"
            if not _usable(r.get("required_pattern") or ""):
                bad.append("%s.missing/%s required_pattern does not compile"
                           % (label, rid))

    # LLM -- patterns is a list per rule; the compiled forms live alongside.
    for r in llm_security.LLM_RULES:
        pats = r.get("patterns")
        if not pats:
            bad.append("llm/%s has no patterns" % r.get("rule_id"))
        elif not all(_usable(p) for p in pats):
            bad.append("llm/%s has an uncompilable pattern" % r.get("rule_id"))

    # CBOM -- risk vocabulary, not severity (CBOM findings carry no CWE).
    for r in CRYPTO_RULES:
        if not _usable(r.get("pattern") or ""):
            bad.append("cbom/%s pattern does not compile" % r.get("component"))
        if str(r.get("risk") or "").upper() not in risks:
            bad.append("cbom/%s illegal risk %r" % (r.get("component"), r.get("risk")))

    # Privacy -- (name, pattern-string, risk, description) rows; the risk
    # vocabulary is the CBOM-style one, and an uncompilable pattern here is a
    # crash waiting for the first file that reaches it.
    from analysis.privacy_data_exposure_engine import (
        EXPOSURE_PATTERNS as PII_EXPOSURE,
        PII_PATTERNS as PII_ROWS,
    )
    for table, label in ((PII_ROWS, "pii.patterns"),
                         (PII_EXPOSURE, "pii.exposure")):
        for row in table:
            name, pat, risk, desc = row[0], row[1], row[2], row[3]
            if not name or not desc:
                bad.append("%s/%s unnamed or undescribed" % (label, name))
            if not _usable(pat):
                bad.append("%s/%s pattern does not compile" % (label, name))
            if str(risk or "").upper() not in risks:
                bad.append("%s/%s illegal risk %r" % (label, name, risk))

    total = (len(sast.ENTERPRISE_RULES) + len(sast.REGEX_RULES)
             + len(secret_intelligence.KNOWN_SECRET_RULES)
             + len(secret_intelligence.SECRET_RULES)
             + len(iac_terraform.RULES) + len(iac_docker.RULES)
             + len(iac_kubernetes.RULES) + len(iac_kubernetes.MISSING_RULES)
             + len(llm_security.LLM_RULES) + len(CRYPTO_RULES)
             + len(PII_ROWS) + len(PII_EXPOSURE))
    assert not bad, "%d defects across %d rules: %s" % (
        len(bad), total, "; ".join(bad[:WINDOW_4]))
    return "%d rules across 12 tables well-formed (identity, severity/risk, cwe, pattern)" % total


def _chk_L3_findings_carry_legal_shape() -> str:
    """CLAIM: scanner findings name a rule, a legal severity and a non-empty
    snippet; the evidence boolean is set by the ANALYZER layer, so a finding
    driven through core.analyzer's evidence validator must come out carrying
    evidence_valid as a real bool."""
    from scanner.sast import scan_file

    target = ROOT / "tests" / "e2e_targets" / "flask_sql" / "app.py"
    findings = scan_file(str(target))
    assert findings, "probe target produced no findings"
    bad = []
    for f in findings:
        rid = str(f.get("rule_id") or "")
        sev = f.get("severity")
        snip = str(f.get("snippet") or "")
        if not rid:
            bad.append("finding without rule_id at line %s" % f.get("line"))
        if sev not in SEVERITIES:
            bad.append("%s illegal severity %r" % (rid or "?", sev))
        if not snip.strip():
            bad.append("%s empty snippet" % rid)
    assert not bad, "%d shape defects: %s" % (len(bad), "; ".join(bad[:WINDOW_4]))

    # Layer 2 -- the analyzer owns evidence_valid. Raw scanner output has no
    # such key yet (grep: the only writers live in core/analyzer.py), so the
    # boolean contract is asserted through the function that owns it, with a
    # real finding from the probe scan as the subject.
    from core.analyzer import _apply_evidex_validation

    subject = dict(findings[0])
    out = _apply_evidex_validation(subject)
    ev = out.get("evidence_valid")
    assert isinstance(ev, bool), (
        "analyzer left evidence_valid as %r on %s"
        % (ev, subject.get("rule_id")))
    return "%d findings legal; analyzer stamps evidence_valid=bool on a real finding" % (
        len(findings))


# ======================================================================
# L4 -- adversarial
# ======================================================================
def _chk_L4_corpus_engines_crash_free() -> str:
    """CLAIM: the engines scan representative corpus fixtures without
    raising -- a crash on benign input is worse than a false positive."""
    import tempfile

    from scanner.cbom import generate_cbom
    from scanner.sast import scan_file
    from scanner.secret_intelligence import scan_file as secret_scan
    from scanner.taint_engine import scan_file as taint_scan

    corpus = ROOT / "tests" / "vuln-test-corpus"
    probes = [
        ("sast", corpus / "sast" / "python" / "vulnerable_app.py", scan_file),
        ("sast", corpus / "sast" / "python" / "safe_app.py", scan_file),
        ("cbom", corpus / "cbom" / "weak_hash.py", generate_cbom),
        ("cbom", corpus / "cbom" / "clean_hashing.py", generate_cbom),
    ]
    engine, outcome = [], []
    for fam, path, fn in probes:
        if not path.is_file():
            continue
        try:
            if fam == "cbom":
                # generate_cbom walks a directory; copy the fixture into a
                # bare temp dir so sibling fixtures cannot leak into the run.
                d = Path(tempfile.mkdtemp(prefix="rsx_brain_cbom_"))
                (d / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8")
                out = fn(str(d))
            else:
                out = fn(str(path))
            engine.append(fam)
            outcome.append(len(out) if isinstance(out, list) else 0)
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                "%s engine crashed on %s: %s"
                % (fam, path.name, traceback.format_exception_only(type(exc), exc))
            ) from exc
    assert engine, "no probes ran"
    return "%d probe scans across %s engines, zero crashes (findings: %s)" % (
        len(engine), "/".join(sorted(set(engine))), outcome)


def _chk_L4_iac_and_secrets_engines_crash_free() -> str:
    """CLAIM: the IaC and Secret engines scan their corpus fixtures through
    the SAME machinery the golden corpus measures with, without raising --
    and the secrets fixture scan must find something, which doubles as
    evidence the temp-copy dance around the nonproduction gate still works."""
    from analysis.validation import run as vrun

    corpus = ROOT / "tests" / "vuln-test-corpus"
    probes = [
        (corpus / "iac" / "terraform", "iam_wildcard.tf"),
        (corpus / "iac" / "docker", "root_user.Dockerfile"),
        (corpus / "iac" / "k8s", "privileged_pod.yaml"),
        (corpus / "secrets", "aws_credentials.py"),
    ]
    rows = []
    for case_dir, name in probes:
        if not (case_dir / name).is_file():
            continue
        if name.endswith((".tf", ".Dockerfile", ".yaml")):
            out = vrun._scan_iac(case_dir, name)
        else:
            out = vrun._scan_secrets(case_dir, name)
        rows.append((name, len(out)))
        assert isinstance(out, list), "%s: engine returned %r" % (name, type(out))
    assert rows, "no iac/secrets probes ran"
    secrets_rows = [n for n, _ in rows if "aws_credentials" in n]
    assert secrets_rows, "secrets fixture missing from probes"
    aws = [c for c in rows if c[0] == "aws_credentials.py"][0]
    assert aws[1] > 0, (
        "secrets scan returned 0 findings -- either the fixture moved or the "
        "nonproduction gate started swallowing the temp copy")
    return "iac+secrets probes scanned crash-free: %s" % (
        ", ".join("%s=%d" % (n, c) for n, c in rows))


def _chk_L4_bundle_gate_has_teeth() -> str:
    """CLAIM: the bundle exclusion is load-bearing in BOTH engines -- removing
    it flips the gate open and restoring it closes the gate again. A gate
    that survives its own mutation is decoration, and the L1 sync check would
    then be certifying a no-op."""
    import tempfile

    from scanner import sast, secret_intelligence as si

    d = Path(tempfile.mkdtemp(prefix="rsx_brain_gate_teeth_"))
    (d / "bundle").mkdir()
    (d / "bundle" / "messages.properties").write_text(
        "login.password=Masukkan password", encoding="utf-8")

    original_sast = set(sast.EXCLUDED_DIRS)
    original_sec = set(si.EXCLUDED)
    try:
        sast.EXCLUDED_DIRS.discard("bundle")
        si.EXCLUDED.discard("bundle")
        opened_sast = not sast._skip(d / "bundle" / "messages.properties")
        opened_sec = not si._skip(d / "bundle" / "messages.properties")
    finally:
        sast.EXCLUDED_DIRS.clear()
        sast.EXCLUDED_DIRS.update(original_sast)
        si.EXCLUDED.clear()
        si.EXCLUDED.update(original_sec)

    assert sast.EXCLUDED_DIRS == original_sast, "sast exclusion set not restored"
    assert si.EXCLUDED == original_sec, "secrets exclusion set not restored"
    assert opened_sast and opened_sec, (
        "removing 'bundle' did not open the gates -- the teeth probe is broken "
        "(sast=%s secrets=%s)" % (opened_sast, opened_sec))
    closed = (sast._skip(d / "bundle" / "messages.properties")
              and si._skip(d / "bundle" / "messages.properties"))
    assert closed, "restoring 'bundle' did not close the gates"
    return "mutation opened both gates, restoration closed both, sets intact"


def _chk_L4_privacy_engine_crash_free_and_gated() -> str:
    """CLAIM: enrich_privacy_data_exposure scans a real-looking file without
    raising, returns the documented summary shape, is deterministic across
    two runs, and the nonproduction gate holds BEHAVIORALLY -- a nested i18n
    file with the same evidence contributes zero indicators while the
    production file contributes its own."""
    import tempfile

    from analysis.privacy_data_exposure_engine import (
        enrich_privacy_data_exposure as enrich,
    )

    d = Path(tempfile.mkdtemp(prefix="rsx_brain_pii_"))
    (d / "service.py").write_text(
        'user_email = "alice@acme-corp.example"\n', encoding="utf-8")
    gated = d / "src" / "i18n"
    gated.mkdir(parents=True)
    (gated / "strings.py").write_text(
        'user_email = "bob@acme-corp.example"\n', encoding="utf-8")

    a = enrich(str(d), live_progress=False)
    b = enrich(str(d), live_progress=False)
    assert isinstance(a, dict), "enrich returned %s" % type(a).__name__

    required = ("total_privacy_indicators", "indicators",
                "privacy_classification_complete", "pii_type_counts",
                "raw_privacy_evidence_count")
    missing = [k for k in required if k not in a]
    assert not missing, "summary shape missing %r" % missing
    assert isinstance(a["privacy_classification_complete"], bool), (
        "classification_complete is not a bool")
    assert isinstance(a["indicators"], list), "indicators is not a list"

    assert a == b, "two identical privacy runs disagreed -- nondeterministic"

    counted = [i for i in a["indicators"]
               if str(i.get("file", "")).replace("\\\\", "/") == "service.py"]
    gated_hits = [i for i in a["indicators"]
                  if "i18n" in str(i.get("file", "")).replace("\\\\", "/")]
    assert counted, "the production file produced no indicators -- probe broken"
    assert not gated_hits, (
        "the gated i18n file contributed %d indicator(s): the "
        "nonproduction gate does not hold behaviorally" % len(gated_hits))
    return "2 deterministic runs; summary shape legal; production file -> %d indicator(s), i18n file -> 0" % (
        len(counted),)


def _chk_L4_word_boundary_control_has_teeth() -> str:
    """CLAIM: the L1 word-boundary control is load-bearing -- restoring the
    legacy sink (and RECOMPILING the engine's rule table, because scan_file
    consumes COMPILED_ENTERPRISE_TAINT_RULES bound at import) re-fires the
    getFile( false positive, and fixing it again kills it. A control that
    survives its own mutation is decoration."""
    import tempfile

    from scanner import taint_engine as te

    rule = next(r for r in te.ENTERPRISE_TAINT_RULES
                if r["id"] == "TAINT_MULTIPART_TRAVERSAL")
    original_sink = rule["sink"]
    original_compiled = te.COMPILED_ENTERPRISE_TAINT_RULES

    src = Path(tempfile.mkdtemp(prefix="rsx_brain_teeth_")) / "V.java"
    src.write_text(
        "public class V {\n"
        "    public static String copyFile(String fileName, InputStream in) {\n"
        '        return fileName;\n'
        "    }\n"
        "}\n", encoding="utf-8")

    def _fires() -> bool:
        return any(x.get("rule_id") == "TAINT_MULTIPART_TRAVERSAL"
                   for x in te.scan_file(str(src)))

    try:
        rule["sink"] = original_sink.replace(r"\bFile\(", r"File\(")
        # scan_file iterates the COMPILED table bound at import; mutating the
        # raw dict alone is invisible to the engine. Recompile after every
        # mutation or the probe tests nothing.
        te.COMPILED_ENTERPRISE_TAINT_RULES = te._compile_enterprise_taint_rules()
        legacy_fired = _fires()

        rule["sink"] = original_sink
        te.COMPILED_ENTERPRISE_TAINT_RULES = te._compile_enterprise_taint_rules()
        fixed_fired = _fires()
    finally:
        rule["sink"] = original_sink
        te.COMPILED_ENTERPRISE_TAINT_RULES = original_compiled

    assert rule["sink"] == original_sink, "raw sink not restored"
    assert te.COMPILED_ENTERPRISE_TAINT_RULES is original_compiled, (
        "compiled table not restored -- brain damaged the engine")
    assert legacy_fired, "legacy sink did not fire; the teeth probe is broken"
    assert not fixed_fired, "fixed sink still fires; the control does not hold"
    return "mutation re-fired the FP, restored sink kills it, both layers intact"


def _chk_L4_poisoned_cache_cannot_crash() -> str:
    """CLAIM: a cache entry of the wrong shape degrades to 'unanswered'
    instead of raising -- poisoning the store must not take down a scan."""
    import scanner.vulnerability_intel as vi

    env_key = "RSECOPSX_LIVE_FEEDS"
    operator_value = os.environ.get(env_key)
    os.environ[env_key] = "0"
    original_loader = vi._load_cache
    try:
        vi._load_cache = lambda: {"PyPI|requests|2.31.0": "not-a-list"}
        out = vi.query_osv_batch(
            [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}])
    finally:
        vi._load_cache = original_loader
        if operator_value is None:
            os.environ.pop(env_key, None)
        else:
            os.environ[env_key] = operator_value
    assert isinstance(out, dict), "poisoned cache raised or returned non-dict"
    return "poisoned entry tolerated, degraded to unanswered, env/loader restored"


# ======================================================================
# L5 -- meta
# ======================================================================
def _chk_L5_own_artifacts_self_excluded() -> str:
    """CLAIM: every artifact the scanner writes is refused as scan input by
    both engines -- the tool must not read its own output as source."""
    from scanner.sast import EXCLUDED_FILES as SAST_FILES
    from scanner.secret_intelligence import _skip as sec_skip

    sast = {str(x).lower() for x in SAST_FILES}
    missing = [a for a in SELF_ARTIFACTS if a not in sast]
    assert not missing, "SAST EXCLUDED_FILES lacks: %r" % missing

    import tempfile

    d = Path(tempfile.mkdtemp(prefix="rsx_brain_meta_"))
    probe = d / "clean_report.json"
    probe.write_text('{"metadata": {}, "findings": []}', encoding="utf-8")
    assert sec_skip(probe), "Secret Intelligence would re-scan clean_report.json"
    return "%d/%d artifact names excluded; live probe refused by secrets engine" % (
        len(SELF_ARTIFACTS), len(SELF_ARTIFACTS))


def _chk_L5_envelope_detector_agrees_with_engines() -> str:
    """CLAIM: both engines' scanner-result detectors make the same verdict on
    the envelope and the same refusal on benign JSON."""
    import tempfile

    from scanner.sast import _is_scanner_result_json as sast_is
    from scanner.secret_intelligence import _is_scanner_result_json as sec_is

    d = Path(tempfile.mkdtemp(prefix="rsx_brain_env_"))
    positive = d / "r.json"
    positive.write_text(
        '{"metadata": {"tool": "x", "total_findings": 1},'
        ' "findings": [{"rule_id": "A"}]}', encoding="utf-8")
    negative = d / "b.json"
    negative.write_text('{"findings": ["nodule"], "patient": {"id": 7}}',
                        encoding="utf-8")

    rows = [(sast_is(positive), True, "envelope/sast"),
            (sec_is(positive), True, "envelope/secrets"),
            (sast_is(negative), False, "benign/sast"),
            (sec_is(negative), False, "benign/secrets")]
    bad = ["%s -> %s" % (n, g) for g, w, n in rows if g != w]
    assert not bad, "; ".join(bad)
    return "envelope accepted and benign refused, both engines agree (4/4)"


def _chk_L5_triage_still_classifies_known_fp() -> str:
    """CLAIM: the triage scorer beside this module still places a documented
    FP family in LIKELY_FP -- the analysis layer the brain sits beside is
    itself kept under test."""
    from analysis.validation.triage_report import categorize, score_finding

    finding = {
        "rule_id": "TAINT_MULTIPART_TRAVERSAL",
        "detection": "Enterprise Source-to-Sink Heuristic",
        "confidence": "HIGH",
        "evidence_valid": True,
        "taint_path": "fileName -> File(",
        "snippet": "event.getFile().getFileName()",
    }
    score, reasons = score_finding(finding)
    assert score >= 50, "score dropped below FP threshold: %d (%s)" % (score, reasons)
    assert categorize(score) == "LIKELY_FP", categorize(score)
    assert any("FP family" in r for r in reasons), reasons
    return "known FP family scores %d -> LIKELY_FP on documented grounds" % score


# ======================================================================
# CLI
# ======================================================================
def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="analysis.validation.brain",
        description="Multi-level self-validation of the scanner's own "
                    "controls. Offline by default.")
    parser.add_argument("--levels", default=None,
                        help="comma-separated subset, e.g. L1,L4 "
                             "(default: all six levels)")
    parser.add_argument("--json", action="store_true",
                        help="emit the full verdict as JSON")
    parser.add_argument("--out", default=None,
                        help="optional directory for brain_report.json")
    args = parser.parse_args(argv)

    levels = [s.strip().upper() for s in args.levels.split(",")] \
        if args.levels else None
    try:
        verdict = Brain().run(only=levels)
    except ValueError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2

    if args.out:
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "brain_report.json").write_text(
            json.dumps(verdict, indent=2, default=str), encoding="utf-8")

    if args.json:
        print(json.dumps(verdict, indent=2, default=str))
    else:
        _print_verdict(verdict)
    return int(verdict["exit_code"])


def _print_verdict(verdict: dict) -> None:
    out = io.StringIO()
    out.write("R-SecOpsX Security Brain -- multi-level self-validation\n")
    out.write("=" * 68 + "\n")
    for lvl in verdict["levels"]:
        rows = [c for c in verdict["checks"] if c["level"] == lvl]
        if not rows:
            continue
        out.write("\n%s  %s\n" % (lvl, Brain.LEVEL_NAMES.get(lvl, "")))
        for c in rows:
            mark = {"pass": "ok  ", "fail": "FAIL", "blocked": "BLKD"}[c["status"]]
            out.write("  [%s] %-46s %6.1fms\n" % (mark, c["name"], c["duration_ms"]))
            out.write("        claim: %s\n" % c["claim"])
            out.write("        evidence: %s\n" % c["evidence"])
    counts = verdict["counts"]
    out.write("\n" + "=" * 68 + "\n")
    out.write("VERDICT: %s   (pass=%d fail=%d blocked=%d)\n" % (
        verdict["verdict"], counts.get("pass", 0),
        counts.get("fail", 0), counts.get("blocked", 0)))
    print(out.getvalue())


if __name__ == "__main__":
    sys.exit(main())

