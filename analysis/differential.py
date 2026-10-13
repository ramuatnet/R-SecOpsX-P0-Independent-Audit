"""Run R-SecOpsX and a peer tool against the same target and diff the results
(Phase V0.3).

    python -m analysis.differential --tool grype --target reports/Security_CycloneDX.json
    python -m analysis.differential --tool trivy --target <sbom.json> --json

WHAT A DISAGREEMENT IS AND IS NOT
---------------------------------
A differential run does not decide who is right. It finds the places where
two tools looked at the same bytes and answered differently, and it hands
those back for triage. "only_in_rsecopsx" may be a real peer blind spot or a
false positive of ours; "only_in_peer" may be a real miss of ours or noise
the peer emits. The runner cannot tell, and pretending otherwise would be
the same category error as deriving a label from a scan: the measurement
would be grading itself.

So disagreements are reported, never resolved, and the exit code only says
whether any remain unexplained -- a caller who has triaged them records that
by passing the triage, not by the runner deciding on their behalf.

AN ABSENT TOOL REPORTS BLOCKED, NEVER PASS
------------------------------------------
semgrep, gitleaks, checkov and kics are not installed here. If a missing
tool produced an empty result set, the run would report "no disagreements"
-- which reads as perfect agreement between two tools, one of which was
never asked. That is the single most misleading output this module could
produce, so absence is a distinct state with its own exit code.

    0   ran, no unexplained disagreements
    1   ran, disagreements remain unexplained
    2   BLOCKED -- the peer tool is missing, or the target is unusable

Exit 2 must never be mistaken for exit 0. Both are non-zero in the sense
that neither is a clean bill of health, but only 0 means "measured and
agreed".

WHY OUR OWN SBOM IS THE TARGET FORMAT
-------------------------------------
The peer tools read CycloneDX. Passing them a directory would make each one
scan differently -- grype would look for a lockfile, trivy would walk the
tree -- so the two would never be looking at the same inputs and every
disagreement would be an artefact of different scopes. One SBOM, fed to both.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_LOG = logging.getLogger("rsx.analysis.differential")

if __package__ in (None, ""):  # allow `python -m analysis.differential`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.validation.normalize import normalize_findings  # noqa: E402
from analysis.validation.compare import identity  # noqa: E402

# Exit codes. BLOCKED is deliberately distinct from both success and failure.
EXIT_OK = 0
EXIT_DISAGREEMENTS = 1
EXIT_BLOCKED = 2

STATUS_RAN = "ran"
STATUS_BLOCKED = "blocked"

# Peer tools this runner knows how to drive, and the binary each needs.
PEER_TOOLS = {
    "grype": "grype",
    "trivy": "trivy",
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "checkov": "checkov",
    "kics": "kics",
}


def peer_available(tool: str) -> tuple[bool, str]:
    """Whether a peer tool is installed, and where from.

    Returns ``(available, detail)``. The detail is carried into the result so
    a BLOCKED report says what was missing rather than just that something
    was, which is the difference between a report someone can act on and one
    they have to reproduce to understand.
    """
    binary = PEER_TOOLS.get(tool)
    if binary is None:
        return False, ("unknown peer tool %r; this runner knows how to drive %s"
                       % (tool, sorted(PEER_TOOLS)))
    found = shutil.which(binary)
    if not found:
        return False, ("%s is not installed -- install it, or the comparison"
                       " cannot be made" % binary)
    return True, found


def run_differential(target: str, peer_tool: str,
                     peer_args: list[str] | None = None,
                     timeout: int = 900) -> dict:
    """Diff R-SecOpsX against a peer tool on one target.

    ``target`` is a CycloneDX SBOM. Both sides are normalized through the
    V0.2 schema before comparison, so the diff rests on the same identity
    rules the golden corpus uses -- CWE and component, never rule ID spelling.

    The result carries ``status``. Read it before anything else: a blocked
    run has no findings to compare, and treating its empty diff as agreement
    would report health that was never established.
    """
    target_path = Path(target)
    peer_args = list(peer_args or [])

    available, detail = peer_available(peer_tool)
    if not available:
        _LOG.error("BLOCKED: %s", detail)
        return _blocked(peer_tool, target_path, [detail])

    if not target_path.is_file():
        return _blocked(peer_tool, target_path,
                        ["target does not exist or is not a file: %s" % target_path])

    ours, ours_error = _run_rsecopsx(target_path)
    if ours_error:
        return _blocked(peer_tool, target_path, [ours_error])

    theirs, peer_error = _run_peer(peer_tool, target_path, peer_args, timeout)
    if peer_error:
        return _blocked(peer_tool, target_path, [peer_error])

    in_both, only_ours, only_peer = _diff(ours, theirs)

    return {
        "status": STATUS_RAN,
        "target": str(target_path),
        "peer_tool": peer_tool,
        "peer_binary": detail,
        "counts": {
            "rsecopsx": len(ours),
            "peer": len(theirs),
            "in_both": len(in_both),
            "only_in_rsecopsx": len(only_ours),
            "only_in_peer": len(only_peer),
        },
        "in_both": in_both,
        "only_in_rsecopsx": only_ours,
        "only_in_peer": only_peer,
        # Anything reported by exactly one side needs a human. This is the
        # figure the exit code is built on, and it is deliberately not
        # auto-resolved: only the caller knows whether an R-only finding was
        # triaged last week.
        "unexplained_disagreements": len(only_ours) + len(only_peer),
        "notes": [],
    }


def _blocked(tool: str, target: Path, reasons: list[str]) -> dict:
    """A run that could not be made.

    Reported as a first-class state rather than as an empty diff. An empty
    diff and a blocked run look identical if both are represented by zero
    findings, and only one of them means the tools agreed.
    """
    for reason in reasons:
        _LOG.error("BLOCKED (%s): %s", tool, reason)
    return {
        "status": STATUS_BLOCKED,
        "target": str(target),
        "peer_tool": tool,
        "reasons": reasons,
        "counts": {},
        "in_both": [],
        "only_in_rsecopsx": [],
        "only_in_peer": [],
        "unexplained_disagreements": None,
        "notes": ["no comparison was made; this is not agreement"],
    }


def _rating_severity(vuln: dict) -> str | None:
    """Severity from the CycloneDX ``ratings`` array, tolerating an empty one.

    ``vuln["ratings"][0]`` raises IndexError when a producer emits
    ``"ratings": []``, and an unhandled IndexError here would abort the whole
    differential run on one finding with no rating. An unrated finding is a
    normal case, not a crash.
    """
    ratings = vuln.get("ratings")
    if not isinstance(ratings, list) or not ratings:
        return None
    first = ratings[0]
    if not isinstance(first, dict):
        return None
    return first.get("severity")


def _run_rsecopsx(sbom_path: Path) -> tuple[list[dict], str | None]:
    """Take R-SecOpsX's view from the SBOM's own vulnerabilities block.

    The peer tools read the same SBOM, so the honest comparison is against
    what that SBOM already asserts -- not against re-scanning the tree, which
    would put two different scopes into one diff.

    Returns ``(findings, error)``. The error is None on success.
    """
    try:
        bom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], "cannot read SBOM %s: %s" % (sbom_path, exc)

    raw: list[dict] = []

    # CycloneDX top-level vulnerabilities, each pointing at a component by ref.
    components_by_ref = {}
    for comp in bom.get("components") or []:
        ref = comp.get("bom-ref") or comp.get("purl")
        if ref:
            components_by_ref[ref] = comp

    for vuln in bom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue

        # The exporter writes both spellings: `id` is the CVE, and the
        # advisory the source actually published is in
        # `rsecopsx:advisory_id` (e.g. GHSA-prr3-c3m5-p7q2). Reading only
        # `id` into a field the normalizer never consults left every record
        # with cve=None, which collapsed all four into one empty location
        # identity -- reported as "in_both: 0" against a peer that had found
        # the very same advisory. That output read as a serious tool
        # disagreement and was entirely the runner's own doing.
        props = {p.get("name"): p.get("value")
                 for p in vuln.get("properties") or []
                 if isinstance(p, dict)}

        advisory_id = vuln.get("id")
        cve = props.get("rsecopsx:cve")
        if not cve and str(advisory_id or "").upper().startswith("CVE-"):
            cve = advisory_id

        # Severity: prefer our own canonical spelling over the raw ratings
        # value. `ratings` carries the CVSS-derived grade in lower case
        # ("medium"), which is not in the canonical vocabulary and would not
        # group or filter alongside a peer's "Medium".
        severity = (props.get("rsecopsx:severity")
                    or _rating_severity(vuln)
                    or vuln.get("severity"))

        record = {
            "rule_id": advisory_id,
            "cve": cve,
            "severity": severity,
            "description": vuln.get("description") or vuln.get("summary"),
        }
        affects = vuln.get("affects") or []
        if affects:
            ref = affects[0].get("ref")
            comp = components_by_ref.get(ref) or {}
            record["package"] = comp.get("name")
            record["version"] = comp.get("version")
            record["path"] = comp.get("name")
        raw.append(record)

        # The exporter cross-links every CVE the advisory carries under
        # `references`. Each alias CVE is a fact a consumer can search for
        # and grype reports them as separate matches (one per CVE), so
        # each gets an identity of its own here. Keying only on the
        # primary CVE read CVE-2026-4800 and CVE-2026-2950 as
        # "only_in_peer" when our own SBOM asserted the very same
        # advisory cluster -- the disagreement was the reader's, not the
        # product's. Non-CVE reference ids (a twin GHSA) stay out: the
        # peer tools keep their GHSA in rule_id and key identity on the
        # CVE, so admitting one here would invent a disagreement.
        for ref_entry in vuln.get("references") or []:
            rid = str(
                ref_entry.get("id") if isinstance(ref_entry, dict)
                else ref_entry or ""
            ).strip()
            if not rid.upper().startswith("CVE-"):
                continue
            if cve and rid.upper() == str(cve).upper():
                continue
            alias_record = dict(record)
            alias_record["cve"] = rid
            raw.append(alias_record)

    # Fallback: some exports put the advisory on the component itself.
    if not raw:
        for comp in bom.get("components") or []:
            for adv in comp.get("vulnerabilities") or []:
                if isinstance(adv, dict):
                    raw.append({"id": adv.get("id"),
                                "package": comp.get("name"),
                                "version": comp.get("version"),
                                "severity": adv.get("severity")})

    return normalize_findings(raw, "rsecopsx"), None


def _run_peer(tool: str, sbom_path: Path, extra_args: list[str],
              timeout: int) -> tuple[list[dict], str | None]:
    """Invoke a peer tool and normalize its JSON.

    Returns ``(findings, error)``. A tool that exits non-zero or emits
    unparseable output is an error, not an empty result set -- an empty set
    would read as "the peer found nothing", which is a finding, not a
    failure to run.
    """
    try:
        findings, parse_error = _PEER_RUNNERS[tool](sbom_path, extra_args, timeout)
    except KeyError:
        return [], ("no runner is implemented for %r; %s are wired up"
                    % (tool, sorted(_PEER_RUNNERS)))
    except subprocess.TimeoutExpired:
        return [], "%s exceeded the %ds timeout" % (tool, timeout)
    except OSError as exc:
        return [], "could not invoke %s: %s" % (tool, exc)

    if parse_error:
        return [], parse_error
    return normalize_findings(findings, tool), None


def _run_grype(sbom_path: Path, extra_args: list[str], timeout: int):
    cmd = ["grype", "sbom:%s" % sbom_path, "--output", "json", *extra_args]
    _LOG.info("running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    stderr = proc.stderr.decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        return None, "grype exited %d: %s" % (proc.returncode, stderr[-400:])
    try:
        data = json.loads(proc.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        return None, "grype output was not JSON (%s): %s" % (exc, stderr[-200:])
    return data.get("matches") or [], None


def _run_trivy(sbom_path: Path, extra_args: list[str], timeout: int):
    # trivy writes to a file rather than stdout, so a temp path is used and
    # read back. Passing "-" for stdout is not reliable across versions.
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False,
                                     mode="w", encoding="utf-8") as handle:
        out_path = Path(handle.name)
    try:
        cmd = ["trivy", "sbom", str(sbom_path), "--format", "json",
               "--output", str(out_path), *extra_args]
        _LOG.info("running: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            return None, "trivy exited %d: %s" % (proc.returncode, stderr[-400:])
        if not out_path.exists():
            return None, "trivy produced no output file"
        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return None, "trivy output was not JSON: %s" % exc
    finally:
        out_path.unlink(missing_ok=True)

    findings: list[dict] = []
    for result in data.get("Results") or []:
        findings += result.get("Vulnerabilities") or []
    return findings, None


# A tool with no runner is reported as such rather than silently producing
# nothing. Four of the six peers are absent from this machine, and the two
# that are present are the two this repo can actually exercise.
_PEER_RUNNERS = {
    "grype": _run_grype,
    "trivy": _run_trivy,
}


def _diff(ours: list[dict], theirs: list[dict]) -> tuple[list, list, list]:
    """Split two normalized finding sets into shared, ours-only, theirs-only.

    Identity comes from the comparator, so a grype GHSA id and our CVE for
    the same advisory compare equal whenever grype carries the CVE among its
    aliases. Keying on the literal id instead would report every shared
    finding as a disagreement simply because the tools prefer different
    naming for one issue.
    """
    our_keys = {identity(f): f for f in ours}
    their_keys = {identity(f): f for f in theirs}

    in_both = []
    for key, finding in our_keys.items():
        if key in their_keys:
            in_both.append({"identity": key, "rsecopsx": finding,
                            "peer": their_keys[key]})

    only_ours = [f for k, f in our_keys.items() if k not in their_keys]
    only_peer = [f for k, f in their_keys.items() if k not in our_keys]

    return in_both, only_ours, only_peer


def format_report(result: dict, max_items: int = 20) -> str:
    """Render a differential result for a human reader."""
    lines: list[str] = []

    if result.get("status") == STATUS_BLOCKED:
        lines.append("BLOCKED -- no comparison was made.")
        lines.append("")
        lines.append("This is NOT agreement between the tools. Nothing was")
        lines.append("compared, because the run could not be made:")
        for reason in result.get("reasons") or []:
            lines.append("  - %s" % reason)
        return "\n".join(lines)

    counts = result.get("counts") or {}
    lines.append("Differential: R-SecOpsX vs %s" % result.get("peer_tool"))
    lines.append("target: %s" % result.get("target"))
    lines.append("")
    lines.append("  rsecopsx findings   %d" % counts.get("rsecopsx", 0))
    lines.append("  peer findings       %d" % counts.get("peer", 0))
    lines.append("  in both             %d" % counts.get("in_both", 0))
    lines.append("  only in rsecopsx    %d" % counts.get("only_in_rsecopsx", 0))
    lines.append("  only in peer        %d" % counts.get("only_in_peer", 0))
    lines.append("")
    lines.append("unexplained disagreements: %d"
                 % result.get("unexplained_disagreements", 0))

    for label, key in (("only in R-SecOpsX", "only_in_rsecopsx"),
                       ("only in peer", "only_in_peer")):
        items = result.get(key) or []
        if not items:
            continue
        lines.append("")
        lines.append("%s (%d):" % (label, len(items)))
        for f in items[:max_items]:
            package = f.get("package")
            cve = f.get("cve") or f.get("rule_id")
            if package:
                lines.append("    %-32s %-10s %s"
                             % (package, f.get("version"), cve))
            else:
                lines.append("    %-32s %s" % (f.get("file") or "(no file)", cve))
        if len(items) > max_items:
            lines.append("    ... and %d more" % (len(items) - max_items))

    lines.append("")
    lines.append("A disagreement is not a verdict. only_in_rsecopsx may be a")
    lines.append("peer blind spot or a false positive of ours; only_in_peer")
    lines.append("may be a real miss or peer noise. The runner does not")
    lines.append("decide -- only the caller knows what has been triaged.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="analysis.differential",
        description="Diff R-SecOpsX against a peer tool on one CycloneDX SBOM.")
    parser.add_argument("--tool", required=True, choices=sorted(PEER_TOOLS),
                        help="peer tool to compare against")
    parser.add_argument("--target", required=True,
                        help="path to a CycloneDX SBOM")
    parser.add_argument("--peer-arg", action="append", default=[],
                        dest="peer_args",
                        help="extra argument for the peer tool; repeatable")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--json", action="store_true",
                        help="emit the result as JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s")

    result = run_differential(args.target, args.tool, args.peer_args,
                              timeout=args.timeout)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_report(result))

    if result.get("status") == STATUS_BLOCKED:
        return EXIT_BLOCKED
    if result.get("unexplained_disagreements"):
        return EXIT_DISAGREEMENTS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
