"""Mutation testing for the detection engines (Phase V1.3).

The golden corpus measures recall against hand-built fixtures: does the
scanner find known defects at known lines? This measures a different
property -- SENSITIVITY TO CHANGE. Each case is a pair of sources that
differ by exactly one security-relevant edit (parameterised query -> f-string,
argv subprocess -> os.system concat, sha256 -> md5, escaped response ->
raw response, ...). The scanner must report the mutated source and must NOT
report the baseline; a pair where both fire (baseline noisy) or neither
fires (mutation survived) demonstrates something about the scanner that a
static fixture cannot: it either did not notice the edit, or it was already
complaining before the defect existed.

Ground-truth philosophy carries over from the corpus: misses are reported
as misses, never auto-fixed here, never relabelled. Exit code 1 when any
mutation survives or any baseline is noisy, so CI treats a newly-blind
scanner as a failure rather than a metric drift.

Each case declares the CWE (and/or rule-id substring) that identifies the
defect family; a hit in the mutated scan matching that family kills the
mutation. Matching by family rather than by rule id keeps the table stable
when a rule is renamed or when two layers (SAST regex and AST taint) both
report the same defect.

Usage:
    python -m analysis.validation.mutation [--json] [--case ID]
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_LOG = logging.getLogger("rsx.analysis.validation.mutation")

# NOTE on path context: scans run in a temp dir whose name must not contain
# any token the secrets scanner treats as nonproduction ("test", "fixture",
# ...), or the KNOWN_SECRET_RULES layer is withheld and the secret case
# would silently stop being measurable. "rsx_mut_" is deliberate.


@dataclass(frozen=True)
class MutationCase:
    id: str
    description: str
    filename: str
    safe: str
    mutated: str
    # A mutation is killed when the mutated scan reports a finding whose
    # CWE equals any expected value (case-insensitive) or whose rule_id
    # contains any expected rule substring.
    expect_cwes: tuple[str, ...] = ()
    expect_rules: tuple[str, ...] = ()

    def matches(self, finding: dict) -> bool:
        cwe = str(finding.get("cwe") or "").strip().lower()
        if self.expect_cwes and cwe in {c.lower() for c in self.expect_cwes}:
            return True
        rule = str(finding.get("rule_id") or "")
        return any(s in rule for s in self.expect_rules)


_FLASK_HEAD = """from flask import Flask, request

app = Flask(__name__)

"""


MUTATION_CASES: tuple[MutationCase, ...] = (
    MutationCase(
        id="sql_fstring",
        description="parameterised query -> f-string interpolated into execute()",
        filename="app.py",
        safe=_FLASK_HEAD + '''import sqlite3

@app.route("/user")
def get_user():
    uid = request.args.get("id")
    cur = app_db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cur.fetchone()
''',
        mutated=_FLASK_HEAD + '''import sqlite3

@app.route("/user")
def get_user():
    uid = request.args.get("id")
    cur = app_db.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return cur.fetchone()
''',
        expect_cwes=("CWE-89",),
        expect_rules=("SQL_INJECTION", "SQLI"),
    ),
    MutationCase(
        id="cmd_os_system",
        description="argv subprocess (no shell) -> os.system string concat",
        filename="app.py",
        safe=_FLASK_HEAD + '''import subprocess

@app.route("/ls")
def list_dir():
    path = request.args.get("path")
    subprocess.run(["ls", "-la", path], check=True)
''',
        mutated=_FLASK_HEAD + '''import os

@app.route("/ls")
def list_dir():
    path = request.args.get("path")
    os.system("ls -la " + path)
''',
        expect_cwes=("CWE-78",),
        expect_rules=("COMMAND_INJECTION", "OS_SYSTEM"),
    ),
    MutationCase(
        id="path_traversal",
        description="resolved+prefix-checked path -> raw open(os.path.join(...))",
        filename="app.py",
        safe=_FLASK_HEAD + '''from pathlib import Path

BASE = Path("/srv/data")

@app.route("/file")
def read_cfg():
    name = request.args.get("name")
    p = (BASE / name).resolve()
    if not str(p).startswith(str(BASE.resolve())):
        raise ValueError("traversal")
    return p.read_text()
''',
        mutated=_FLASK_HEAD + '''import os

BASE = "/srv/data"

@app.route("/file")
def read_cfg():
    name = request.args.get("name")
    return open(os.path.join(BASE, name)).read()
''',
        expect_cwes=("CWE-22",),
        expect_rules=("PATH_TRAVERSAL",),
    ),
    MutationCase(
        id="xss_escape_removed",
        description="escaped f-string response -> raw request data in response body",
        filename="app.py",
        safe=_FLASK_HEAD + '''from markupsafe import escape

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<div>{escape(name)}</div>"
''',
        mutated=_FLASK_HEAD + '''@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<div>{name}</div>"
''',
        expect_cwes=("CWE-79",),
        expect_rules=("TAINT_XSS", "XSS"),
    ),
    MutationCase(
        id="secret_hardcoded",
        description="environment lookup -> literal credential in source",
        filename="config.py",
        safe='''import os

API_KEY = os.environ["SERVICE_API_KEY"]
''',
        mutated='''API_KEY = "sk-live-hardcoded-secret-0123456789abcdef"
''',
        expect_cwes=("CWE-798",),
        expect_rules=("API_KEY", "SECRET", "CREDENTIAL"),
    ),
    MutationCase(
        id="hash_md5",
        description="sha256 -> md5 for data integrity",
        filename="digest.py",
        safe='''import hashlib

def digest(data):
    return hashlib.sha256(data).hexdigest()
''',
        mutated='''import hashlib

def digest(data):
    return hashlib.md5(data).hexdigest()
''',
        expect_cwes=("CWE-327", "CWE-328", "CWE-329", "CWE-459"),
        expect_rules=("MD5", "WEAK_HASH"),
    ),
    MutationCase(
        id="eval_injection",
        description="json.loads on untrusted input -> eval()",
        filename="parser.py",
        safe='''import json

def parse(raw):
    return json.loads(raw)
''',
        mutated='''def parse(raw):
    return eval(raw)
''',
        expect_cwes=("CWE-94", "CWE-95"),
        expect_rules=("EVAL", "CODE_INJECTION"),
    ),
    MutationCase(
        id="go_tls_skip_verify",
        description="pinned TLS config -> InsecureSkipVerify: true",
        filename="main.go",
        safe='''package main

import (
	"crypto/tls"
	"crypto/x509"
)

func client(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool}
}
''',
        mutated='''package main

import "crypto/tls"

func client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
''',
        expect_cwes=("CWE-295",),
        expect_rules=("TLS", "INSECURE_SKIP_VERIFY"),
    ),
)


@dataclass
class CaseResult:
    case_id: str
    description: str
    status: str                      # killed | survived | baseline_noisy
    baseline_hits: list[dict] = field(default_factory=list)
    mutant_hits: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "killed"


def _scan(target: Path) -> list[dict]:
    """Run the same detection layers the pipeline runs on a source tree.

    scanner.sast.scan_directory already chains the AST taint engine for
    supported languages (a TAINT_* finding appears in its output), so the
    layers here are the regex+taint pass plus the secrets pass, whose
    known-signature rules live in a separate entry point.

    T-0.2 (task.md): each call is its OWN scan session.  The harness
    rewrites the fixture between the baseline and mutant scans of the same
    root; without begin_scan() the second scan reuses the first scan's
    index and its content cache, serving the pre-mutation bytes, and every
    mutant survives unread.
    """
    from core import file_index
    from scanner.sast import scan_directory
    from scanner.secret_intelligence import scan_secret_intelligence

    file_index.begin_scan()

    findings: list[dict] = list(scan_directory(str(target)))
    findings.extend(
        scan_secret_intelligence(str(target))["secret_intelligence_findings"])
    return findings


def _hits(case: MutationCase, findings: list[dict]) -> list[dict]:
    return [f for f in findings if case.matches(f)]


def run_case(case: MutationCase) -> CaseResult:
    """Scan the safe and mutated sources of one case in isolation."""
    tmp = Path(tempfile.mkdtemp(prefix="rsx_mut_"))
    try:
        src = tmp / case.filename
        src.write_text(case.safe, encoding="utf-8")
        baseline = _hits(case, _scan(tmp))
        src.write_text(case.mutated, encoding="utf-8")
        mutant = _hits(case, _scan(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if baseline:
        # The baseline already matches the defect family, so a mutant hit
        # would prove nothing: the scanner could not tell the two apart.
        status = "baseline_noisy"
    elif mutant:
        status = "killed"
    else:
        status = "survived"
    return CaseResult(case.id, case.description, status, baseline, mutant)


def run_mutations(
    cases: tuple[MutationCase, ...] | list[MutationCase] = MUTATION_CASES,
) -> dict:
    results = [run_case(c) for c in cases]
    killed = sum(1 for r in results if r.status == "killed")
    survived = [r.case_id for r in results if r.status == "survived"]
    noisy = [r.case_id for r in results if r.status == "baseline_noisy"]
    return {
        "total": len(results),
        "killed": killed,
        "survived": survived,
        "baseline_noisy": noisy,
        "results": results,
        "ok": not survived and not noisy,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="analysis.validation.mutation",
        description="Mutation testing: one-edit defect pairs must be detected.")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable results")
    parser.add_argument("--case", action="append", dest="cases",
                        help="run only the given case id (repeatable)")
    args = parser.parse_args(argv)

    cases = MUTATION_CASES
    if args.cases:
        known = {c.id for c in cases}
        unknown = [c for c in args.cases if c not in known]
        if unknown:
            parser.error("unknown case id(s): %s (known: %s)"
                         % (", ".join(unknown), ", ".join(sorted(known))))
        cases = tuple(c for c in cases if c.id in set(args.cases))

    summary = run_mutations(cases)

    if args.json:
        print(json.dumps({
            "total": summary["total"],
            "killed": summary["killed"],
            "survived": summary["survived"],
            "baseline_noisy": summary["baseline_noisy"],
            "ok": summary["ok"],
            "results": [
                {"case": r.case_id, "description": r.description,
                 "status": r.status,
                 "baseline_hits": len(r.baseline_hits),
                 "mutant_hits": len(r.mutant_hits)}
                for r in summary["results"]],
        }, indent=2))
    else:
        print("Mutation testing")
        print("=" * 60)
        for r in summary["results"]:
            mark = {"killed": "KILL", "survived": "SURVIVED",
                    "baseline_noisy": "NOISY"}[r.status]
            detail = ""
            if r.status == "survived":
                detail = "  (no matching finding in mutated source)"
            elif r.status == "baseline_noisy":
                detail = "  (baseline already matches: %s)" % [
                    f.get("rule_id") for f in r.baseline_hits][:3]
            else:
                detail = "  (%d hit(s))" % len(r.mutant_hits)
            print("  [%s] %-20s %s%s" % (mark, r.case_id, r.description, detail))
        print("-" * 60)
        print("killed %d/%d  survived=%s  noisy=%s"
              % (summary["killed"], summary["total"],
                 summary["survived"] or "none",
                 summary["baseline_noisy"] or "none"))
        print("Result: %s" % ("PASS" if summary["ok"] else "FAIL"))

    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
