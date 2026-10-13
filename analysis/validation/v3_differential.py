"""V3 differential: secrets / IaC / license findings vs peer tools.

    python -m analysis.validation.v3_differential --domain secrets --target <dir>
    python -m analysis.validation.v3_differential --domain iac --target <dir> [--peer checkov]
    python -m analysis.validation.v3_differential --domain license --target <dir>
    python -m analysis.validation.v3_differential --domain all --target <root>   # root/<domain>_target

WHAT A DISAGREEMENT IS AND IS NOT
---------------------------------
Same philosophy as analysis/differential.py: the runner finds places where
two tools looked at the same bytes and answered differently, and hands them
back for triage. "only_in_rsecopsx" may be a real peer blind spot or a false
positive of ours; "only_in_peer" may be a real miss of ours or peer noise.
The runner never decides who is right. For the license domain a third
outcome exists: "conflicts" -- both tools named the same package but
disagree on its licence family, which is neither a miss nor a FP but a
disagreement about fact.

AN ABSENT TOOL REPORTS BLOCKED, NEVER PASS
-----------------------------------------
A peer tool that is not installed cannot disagree with us, so its silence
is not agreement. Missing peer / failed run => status "blocked", exit 2.

EXIT CODES
----------
    0  every domain ran and the sides agreed
    1  at least one domain ran and reported disagreements (or conflicts)
    2  no disagreements, but at least one domain was BLOCKED

PEER TOOLS AND WHERE THEY COME FROM
-----------------------------------
Resolution order per domain: explicit --peer, else first available of

    secrets: gitleaks            (binary on PATH, or %RSX_TOOL_DIR%/gitleaks/)
    iac:     checkov, kics, trivy
    license: scancode, trivy

RSX_TOOL_DIR defaults to %TEMP%/rsx_tools with per-tool subdirectories
(gitleaks/gitleaks.exe, kics/kics.exe). Checkov resolves through
RSX_CHECKOV_VENV (a virtualenv whose python can `import checkov`; default
%TEMP%/rsx_checkov_venv) because checkov is driven as
`<venv-python> -m checkov.main`. Trivy resolves on PATH (winget).

Notes recorded from live runs on the development box:
  * gitleaks v8.30: `gitleaks dir <path> --report-format json --report-path
    <file> --no-banner --exit-code 0 --redact`. Run WITH --redact: the
    report then carries no secret material at all, which keeps the whole
    pipeline inside the secret non-republication policy (our side never
    copies snippets/evidence either -- reports here contain only
    file/line/rule-id triples).
  * checkov 3.3.28 on py3.14: JSON summary goes to STDERR as a list of
    per-check-type objects; findings live in results.failed_checks with
    file_abs_path + file_line_range. Exit code is non-zero when findings
    exist, so the runner parses output and ignores the code.
  * kics v2.1.20: the release zip ships ONLY the binary and the binary
    resolves assets/queries relative to ITS OWN directory, not the cwd
    ("unable to find queries: GetFileAttributesEx <exe-dir>/assets/queries").
    On this box the queries were materialised via a blob-less sparse
    checkout of Checkmarx/kics@v2.1.20 (assets/queries, 14k files) at
    %TEMP%/rsx_tools/kics_repo with a directory junction
    %TEMP%/rsx_tools/kics/assets -> kics_repo/assets. Without that
    junction kics reports BLOCKED; the adapter and its parse path are
    covered by tests either way.
  * trivy 0.72: `trivy config` misconfigurations carry no Location; the
    line is CauseMetadata.StartLine and the file is the enclosing
    Results[].Target. `trivy fs --scanners license --license-full`
    reports package-level licences under Results[].Class == "license"
    (Licenses[]: PkgName/FilePath/Name). Without --license-full it reports
    almost nothing for language manifests, so the flag is mandatory here.
  * scancode-toolkit does not install on python 3.14; the adapter is
    written to scancode's documented --json shape but is UNTESTED live.
    On this box it reports BLOCKED (binary absent), which is the honest
    outcome.

COMPARISON IDENTITY (why it differs per domain)
-----------------------------------------------
  secrets / iac: (canonical file, line within tolerance). Rule ids are
    reported on both sides for triage but are NOT part of the identity:
    the same condition carries a different name in every tool
    (TF_PUBLIC_S3_ACL vs CKV_AWS_18 vs AWS-0092). Secrets default
    tolerance is 2 lines, IaC 5 (tools anchor on different lines of the
    same resource block). Matching is greedy 1:1 nearest-line per file so
    one finding cannot absorb two.
  license: (package name, licence family). Family canonicalisation maps
    SPDX ids and long display names onto one token (mit, apache-2.0,
    gpl-3.0, bsd-3-clause, ...) and matches equal-or-contained tokens, so
    "The MIT License (MIT)" == "MIT" and "GPL-3.0-only" == "GPL-3.0".
    A same-package/different-family pair is a CONFLICT, not a miss.

SCOPE BOUNDARIES (documented, not accidental)
---------------------------------------------
  * The IaC comparison covers terraform + Dockerfile + Kubernetes
    misconfigurations our scanners emit; trivy's "root" Target entries
    (file-level checks with no file granularity) are reported as
    "(root)" and can only land in only_in_peer.
  * The license comparison is package-level (trivy Class "license").
    trivy's license-file detections (a LICENSE file at repo root) are a
    different surface ours does not implement and are excluded by the
    Class filter; scancode's file-level licences compare by (file,
    family) instead.
  * Our secrets scanner only reads SECRET_EXT files; gitleaks reads
    everything. Findings in extensions we do not scan legitimately land
    in only_in_peer -- a scope difference the report makes visible.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_TOLERANCE = {"secrets": 2, "iac": 5}
PEER_ORDER = {
    "secrets": ("gitleaks",),
    "iac": ("checkov", "kics", "trivy"),
    "license": ("scancode", "trivy"),
}
# How each license peer reports: package-level or file-level licences.
LICENSE_PEER_MODE = {"trivy": "package", "scancode": "file"}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_ROOT_TOKEN = "(root)"


class ToolError(RuntimeError):
    """A tool could not be run or produced unusable output."""


# ---------------------------------------------------------------------------
# path + label helpers
# ---------------------------------------------------------------------------

def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def _rel_file(raw, root: Path) -> str:
    """Normalise any peer/ours path form to a posix path relative to root."""
    s = str(raw or "").strip().replace("\\", "/")
    if not s or s in (".", "./"):
        return _ROOT_TOKEN
    # os.path.relpath (not Path.relative_to) so drive-less rooted windows
    # paths ("\tmp\root\x") and mixed separators normalise identically; it
    # raises only across drives.
    try:
        rel = os.path.relpath(s, str(root))
    except (ValueError, OSError):
        rel = None
    if rel is not None and not rel.startswith(".."):
        return Path(rel).as_posix()
    s = s.lstrip("/")
    while s.startswith("./"):
        s = s[2:]
    return s


def _strip_root_prefix(rel: str, root: Path) -> str:
    """Our IaC scanners prefix findings with the target directory name."""
    prefix = root.name + "/"
    if rel.startswith(prefix):
        return rel[len(prefix):]
    return rel


def _license_family(raw) -> str:
    """Canonical licence family token from an SPDX id or display name."""
    s = str(raw or "").strip().lower()
    if not s or s in {"unknown", "none", "noassertion", "n/a", "null"}:
        return "unknown"
    s = s.replace("_", "-")
    m = re.search(r"\(([a-z0-9.+-]+)\)", s)  # "GPL v3.0 (gpl-3.0)" -> gpl-3.0
    if m:
        s = m.group(1)
    s = re.sub(r"[^a-z0-9.+-]+", "-", s).strip("-")
    if s == "mit" or s.startswith("mit-"):
        return "mit"
    if "apache" in s:
        return "apache-2.0"
    if s.startswith("agpl") or "affero" in s:
        return "agpl"
    if s.startswith("lgpl") or "lesser general public" in s:
        return "lgpl"
    if s.startswith("gpl-3") or "general-public-license-3" in s or "general public license v3" in s:
        return "gpl-3.0"
    if s.startswith("gpl-2") or "general-public-license-2" in s or "general public license v2" in s:
        return "gpl-2.0"
    if "bsd-3" in s or "3-clause" in s:
        return "bsd-3-clause"
    if "bsd-2" in s or "simplified-bsd" in s or "freebsd" in s:
        return "bsd-2-clause"
    if s.startswith("mpl") or "mozilla public" in s:
        return "mpl-2.0"
    if s.startswith("isc"):
        return "isc"
    if "unlicense" in s or s == "the-unlicense":
        return "unlicense"
    if any(t in s for t in ("proprietary", "commercial", "commercial-use", "busl", "sspl")):
        return "proprietary"
    return s


def _families_match(a: str, b: str) -> bool:
    if a == b:
        return True
    if a == "unknown" or b == "unknown":
        return False
    return a in b or b in a


# ---------------------------------------------------------------------------
# our-side runners (normalised shapes)
# ---------------------------------------------------------------------------

def _ours_secrets(copy_root: Path) -> list[dict]:
    from scanner.secret_intelligence import scan_secret_intelligence

    res = scan_secret_intelligence(str(copy_root))
    return [
        {
            "file": _rel_file(f.get("file"), copy_root),
            "line": int(f.get("line") or 0),
            "label": str(f.get("rule_id") or ""),
        }
        for f in res.get("secret_intelligence_findings", [])
    ]


def _ours_iac(copy_root: Path) -> list[dict]:
    from scanner.iac_docker import scan_docker
    from scanner.iac_kubernetes import scan_kubernetes
    from scanner.iac_terraform import scan_terraform

    findings = (
        scan_terraform(str(copy_root))
        + scan_docker(str(copy_root))
        + scan_kubernetes(str(copy_root))
    )
    out = []
    for f in findings:
        rel = _strip_root_prefix(_rel_file(f.get("file"), copy_root), copy_root)
        out.append({
            "file": rel,
            "line": int(f.get("line") or 0),
            "label": str(f.get("rule_id") or ""),
        })
    return out


def _ours_license(copy_root: Path) -> list[dict]:
    from scanner.sbom import generate_sbom

    out = []
    for pkg in generate_sbom(str(copy_root)):
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        out.append({
            "name": name.casefold().replace("_", "-"),
            "display_name": name,
            "license": str(pkg.get("license") or "unknown"),
        })
    return out


OURS_RUNNERS = {
    "secrets": _ours_secrets,
    "iac": _ours_iac,
    "license": _ours_license,
}


# ---------------------------------------------------------------------------
# peer resolution
# ---------------------------------------------------------------------------

def _tool_dir() -> Path:
    env = os.environ.get("RSX_TOOL_DIR")
    if env:
        return Path(env)
    return Path(tempfile.gettempdir()) / "rsx_tools"


def _find_peer_argv(peer: str) -> list[str] | None:
    """Return the argv prefix for a peer tool, or None when unavailable."""
    if peer == "checkov":
        venv = os.environ.get("RSX_CHECKOV_VENV")
        candidates = []
        if venv:
            candidates.append(Path(venv))
        candidates.append(Path(tempfile.gettempdir()) / "rsx_checkov_venv")
        for v in candidates:
            py = v / "Scripts" / "python.exe"
            if py.exists():
                return [str(py), "-m", "checkov.main"]
        on_path = shutil.which("checkov")
        if on_path:
            return [on_path]
        return None

    exe_names = {
        "gitleaks": ["gitleaks.exe", "gitleaks"],
        "kics": ["kics.exe", "kics"],
        "trivy": ["trivy.exe", "trivy"],
        "scancode": ["scancode.exe", "scancode"],
    }.get(peer, [peer])

    on_path = shutil.which(peer)
    if on_path:
        return [on_path]
    tool_root = _tool_dir() / peer
    for name in exe_names:
        candidate = tool_root / name
        if candidate.exists():
            return [str(candidate)]
    return None


def _run_tool(argv: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError("failed to run %s: %s" % (argv[0], exc)) from exc


# ---------------------------------------------------------------------------
# peer adapters: each returns the normalised entry list
# ---------------------------------------------------------------------------

def _run_gitleaks(argv: list[str], copy_root: Path, work: Path, timeout: int) -> list[dict]:
    report = work / "gitleaks.json"
    proc = _run_tool(
        argv + [
            "dir", str(copy_root),
            "--report-format", "json",
            "--report-path", str(report),
            "--no-banner", "--exit-code", "0",
            # --redact: the report file itself must carry no secret material.
            "--redact",
        ],
        work, timeout,
    )
    if not report.exists():
        raise ToolError("gitleaks produced no report: %s" % (proc.stderr or proc.stdout)[:400])
    try:
        data = json.loads(report.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ToolError("gitleaks report unreadable: %s" % exc) from exc
    return [
        {
            "file": _rel_file(e.get("File"), copy_root),
            "line": int(e.get("StartLine") or 0),
            "label": str(e.get("RuleID") or ""),
        }
        for e in data
    ]


def _parse_checkov_json(text: str, copy_root: Path) -> list[dict]:
    data = json.loads(_strip_ansi(text))
    if isinstance(data, dict):  # single check-type object rather than a list
        data = [data]
    out = []
    for block in data:
        for c in (block.get("results") or {}).get("failed_checks") or []:
            line_range = c.get("file_line_range") or [0]
            out.append({
                "file": _rel_file(c.get("file_abs_path") or c.get("file_path"), copy_root),
                "line": int(line_range[0] or 0),
                "label": str(c.get("check_id") or ""),
            })
    return out


def _run_checkov(argv: list[str], copy_root: Path, work: Path, timeout: int) -> list[dict]:
    proc = _run_tool(
        argv + ["-d", str(copy_root), "--output", "json", "--quiet"],
        work, timeout,
    )
    # checkov's JSON summary goes to stderr; stdout may carry log lines.
    text = _strip_ansi(proc.stderr or proc.stdout or "")
    if not text.strip():
        raise ToolError("checkov produced no output")
    try:
        return _parse_checkov_json(text, copy_root)
    except ValueError as exc:
        raise ToolError("checkov output not JSON: %s" % text[:200]) from exc


def _parse_kics_json(text: str, copy_root: Path, base_dir: Path | None = None) -> list[dict]:
    data = json.loads(_strip_ansi(text))
    out = []
    for q in data.get("queries") or []:
        for f in q.get("files") or []:
            raw = f.get("file_name") or f.get("file")
            # kics relativises file paths to ITS working directory when the
            # scanned tree sits under it (the runner runs kics with cwd=work,
            # and the copy lives inside work). A relative path reaches us
            # ambiguous -- relative to the tool's cwd, not ours -- so resolve
            # it against base_dir before normalising.
            if raw and base_dir is not None and not Path(str(raw)).is_absolute():
                raw = str(Path(base_dir) / str(raw))
            out.append({
                "file": _rel_file(raw, copy_root),
                "line": int(f.get("line") or 0),
                "label": str(q.get("query_id") or q.get("query_name") or ""),
            })
    return out


def _run_kics(argv: list[str], copy_root: Path, work: Path, timeout: int) -> list[dict]:
    report = work / "results.json"
    proc = _run_tool(
        argv + [
            "scan", "--path", str(copy_root),
            "--report-formats", "json",
            "--output-path", str(work),
            "--no-progress",
        ],
        work, timeout,
    )
    if not report.exists():
        tail = (proc.stderr or proc.stdout or "")[-400:]
        raise ToolError("kics produced no results.json (release binary ships "
                        "without assets/queries?): %s" % tail)
    try:
        return _parse_kics_json(report.read_text(encoding="utf-8-sig"), copy_root,
                                base_dir=work)
    except (OSError, ValueError) as exc:
        raise ToolError("kics report unreadable: %s" % exc) from exc


def _parse_trivy_config(text: str, copy_root: Path) -> list[dict]:
    data = json.loads(_strip_ansi(text))
    out = []
    for r in data.get("Results") or []:
        file = _rel_file(r.get("Target"), copy_root)
        for m in r.get("Misconfigurations") or []:
            status = str(m.get("Status") or "FAIL").upper()
            if status != "FAIL":
                continue
            meta = m.get("CauseMetadata") or {}
            out.append({
                "file": file,
                "line": int(meta.get("StartLine") or 0),
                "label": str(m.get("ID") or ""),
            })
    return out


def _run_trivy_config(argv: list[str], copy_root: Path, work: Path, timeout: int) -> list[dict]:
    proc = _run_tool(
        argv + ["config", "--format", "json", "--quiet", "--exit-code", "0", str(copy_root)],
        work, timeout,
    )
    text = _strip_ansi(proc.stdout or "")
    if not text.strip():
        raise ToolError("trivy config produced no output: %s" % (proc.stderr or "")[:300])
    try:
        return _parse_trivy_config(text, copy_root)
    except ValueError as exc:
        raise ToolError("trivy config output not JSON: %s" % text[:200]) from exc


def _parse_trivy_license(text: str, copy_root: Path) -> list[dict]:
    data = json.loads(_strip_ansi(text))
    out = []
    for r in data.get("Results") or []:
        if str(r.get("Class") or "") != "license":
            continue  # package-level licences only; license-file class excluded
        for lg in r.get("Licenses") or []:
            out.append({
                "name": str(lg.get("PkgName") or "").casefold().replace("_", "-"),
                "display_name": str(lg.get("PkgName") or ""),
                "license": str(lg.get("Name") or "unknown"),
                "file": _rel_file(lg.get("FilePath") or r.get("Target"), copy_root),
            })
    return out


def _run_trivy_license(argv: list[str], copy_root: Path, work: Path, timeout: int) -> list[dict]:
    proc = _run_tool(
        argv + [
            "fs", "--scanners", "license", "--license-full",
            "--format", "json", "--quiet", "--exit-code", "0", str(copy_root),
        ],
        work, timeout,
    )
    text = _strip_ansi(proc.stdout or "")
    if not text.strip():
        raise ToolError("trivy license produced no output: %s" % (proc.stderr or "")[:300])
    try:
        return _parse_trivy_license(text, copy_root)
    except ValueError as exc:
        raise ToolError("trivy license output not JSON: %s" % text[:200]) from exc


def _run_scancode(argv: list[str], copy_root: Path, work: Path, timeout: int) -> list[dict]:
    """File-level licences from scancode's documented --json shape.

    NOT tested live on this box (scancode-toolkit does not install on
    python 3.14); only the BLOCKED path has been exercised here.
    """
    out_file = work / "scancode.json"
    proc = _run_tool(
        argv + [str(copy_root), "--json", str(out_file), "--license", "--quiet",
                "--processes", "1"],
        work, timeout,
    )
    if not out_file.exists():
        raise ToolError("scancode produced no report: %s" % (proc.stderr or proc.stdout)[:400])
    try:
        data = json.loads(out_file.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ToolError("scancode report unreadable: %s" % exc) from exc
    out = []
    for f in data.get("files") or []:
        if f.get("type") not in (None, "file"):
            continue
        for lic in f.get("licenses") or []:
            spdx = lic.get("spdx_license_id") or lic.get("key") or ""
            if not spdx:
                continue
            out.append({
                "file": _rel_file(f.get("path"), copy_root),
                "license": str(spdx),
            })
    return out


PEER_ADAPTERS = {
    ("secrets", "gitleaks"): _run_gitleaks,
    ("iac", "checkov"): _run_checkov,
    ("iac", "kics"): _run_kics,
    ("iac", "trivy"): _run_trivy_config,
    ("license", "trivy"): _run_trivy_license,
    ("license", "scancode"): _run_scancode,
}


# ---------------------------------------------------------------------------
# diff engines
# ---------------------------------------------------------------------------

def _diff_location(ours: list[dict], theirs: list[dict], tolerance: int) -> tuple:
    """Greedy 1:1 nearest-line matching per file within tolerance."""
    def group(entries):
        by_file: dict[str, list[dict]] = {}
        for e in entries:
            by_file.setdefault(e["file"], []).append(e)
        for lst in by_file.values():
            lst.sort(key=lambda e: e["line"])
        return by_file

    o_by = group(ours)
    t_by = group(theirs)

    in_both, only_ours, only_peer = [], [], []
    for file in sorted(set(o_by) | set(t_by)):
        o_lst = list(o_by.get(file, []))
        t_lst = list(t_by.get(file, []))
        matched_t: set[int] = set()
        for o in o_lst:
            best_i, best_d = None, None
            for i, t in enumerate(t_lst):
                if i in matched_t:
                    continue
                d = abs(o["line"] - t["line"])
                if d <= tolerance and (best_d is None or d < best_d):
                    best_i, best_d = i, d
            if best_i is None:
                only_ours.append(dict(o))
            else:
                matched_t.add(best_i)
                t = t_lst[best_i]
                in_both.append({
                    "file": file,
                    "line": o["line"],
                    "peer_line": t["line"],
                    "ours_rule": o["label"],
                    "peer_rule": t["label"],
                })
        for i, t in enumerate(t_lst):
            if i not in matched_t:
                only_peer.append(dict(t))
    return in_both, only_ours, only_peer


def _diff_license_packages(ours: list[dict], theirs: list[dict]) -> tuple:
    """Package-level licence comparison: (name, family) identity."""
    o_by = {e["name"]: e for e in ours if e.get("name")}
    t_by = {e["name"]: e for e in theirs if e.get("name")}

    in_both, only_ours, only_peer, conflicts = [], [], [], []
    for name in sorted(set(o_by) | set(t_by)):
        o, t = o_by.get(name), t_by.get(name)
        if o and t:
            o_fam = _license_family(o["license"])
            t_fam = _license_family(t["license"])
            if _families_match(o_fam, t_fam):
                in_both.append({
                    "package": o.get("display_name") or name,
                    "ours_license": o["license"],
                    "peer_license": t["license"],
                    "family": o_fam,
                })
            else:
                conflicts.append({
                    "package": o.get("display_name") or name,
                    "ours_license": o["license"],
                    "peer_license": t["license"],
                    "ours_family": o_fam,
                    "peer_family": t_fam,
                })
        elif o:
            only_ours.append({
                "package": o.get("display_name") or name,
                "ours_license": o["license"],
            })
        else:
            only_peer.append({
                "package": t.get("display_name") or name,
                "peer_license": t["license"],
            })
    return in_both, only_ours, only_peer, conflicts


def _diff_license_files(ours: list[dict], theirs: list[dict]) -> tuple:
    """File-level licence comparison for peers like scancode: (file, family)."""
    def by_file(entries):
        out: dict[str, list[str]] = {}
        for e in entries:
            out.setdefault(e["file"], []).append(e["license"])
        return out

    o_by, t_by = by_file(ours), by_file(theirs)
    in_both, only_ours, only_peer, conflicts = [], [], [], []
    for file in sorted(set(o_by) | set(t_by)):
        o_lics = o_by.get(file, [])
        t_lics = t_by.get(file, [])
        if o_lics and t_lics:
            o_fams = {_license_family(x) for x in o_lics}
            t_fams = {_license_family(x) for x in t_lics}
            if any(_families_match(a, b) for a in o_fams for b in t_fams):
                in_both.append({"file": file, "ours_licenses": o_lics, "peer_licenses": t_lics})
            else:
                conflicts.append({"file": file, "ours_licenses": o_lics, "peer_licenses": t_lics})
        elif o_lics:
            only_ours.append({"file": file, "ours_licenses": o_lics})
        else:
            only_peer.append({"file": file, "peer_licenses": t_lics})
    return in_both, only_ours, only_peer, conflicts


# ---------------------------------------------------------------------------
# domain runner
# ---------------------------------------------------------------------------

def run_domain(domain: str, target: Path, peer: str | None = None,
               tolerance: int | None = None, timeout: int = 600) -> dict:
    """Run ours + one peer over a temp copy of target and diff."""
    if not target.is_dir():
        return {
            "status": "blocked",
            "domain": domain,
            "target": str(target),
            "reasons": ["target does not exist or is not a directory: %s" % target],
        }

    peers = (peer,) if peer else PEER_ORDER[domain]
    chosen, argv = None, None
    for candidate in peers:
        argv = _find_peer_argv(candidate)
        if argv:
            chosen = candidate
            break
    if chosen is None:
        return {
            "status": "blocked",
            "domain": domain,
            "target": str(target),
            "peer_tool": peer or peers[0],
            "reasons": ["peer tool not available: %s (install it or set RSX_TOOL_DIR "
                        "/ RSX_CHECKOV_VENV)" % (peer or "/".join(peers))],
        }

    adapter = PEER_ADAPTERS.get((domain, chosen))
    if adapter is None:
        return {
            "status": "blocked",
            "domain": domain,
            "target": str(target),
            "peer_tool": chosen,
            "reasons": ["no adapter for peer %s in domain %s" % (chosen, domain)],
        }

    # Temp copy: identical bytes for both sides, and outside any path token
    # the secrets scanner treats as nonproduction (see analysis/validation/run.py).
    # The copy is NOT named "target": sbom.EXCLUDED_DIRS excludes any path
    # containing "target" (cargo's build dir), which silently emptied the
    # licence domain to zero packages.
    tmp = Path(tempfile.mkdtemp(prefix="rsx_v3_"))
    try:
        copy_root = tmp / "scanroot"
        shutil.copytree(target, copy_root)

        try:
            ours = OURS_RUNNERS[domain](copy_root)
        except Exception as exc:  # our own scanner blew up: that is a block
            return {
                "status": "blocked",
                "domain": domain,
                "target": str(target),
                "peer_tool": chosen,
                "reasons": ["rsecopsx %s scanner failed: %s" % (domain, exc)],
            }

        try:
            theirs = adapter(argv, copy_root, tmp, timeout)
        except ToolError as exc:
            return {
                "status": "blocked",
                "domain": domain,
                "target": str(target),
                "peer_tool": chosen,
                "peer_binary": argv[0],
                "reasons": [str(exc)],
            }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if domain == "license":
        mode = LICENSE_PEER_MODE.get(chosen, "package")
        if mode == "file":
            in_both, only_ours, only_peer, conflicts = _diff_license_files(ours, theirs)
        else:
            in_both, only_ours, only_peer, conflicts = _diff_license_packages(ours, theirs)
    else:
        tol = tolerance if tolerance is not None else DEFAULT_TOLERANCE[domain]
        in_both, only_ours, only_peer = _diff_location(ours, theirs, tol)
        conflicts = []

    counts = {
        "rsecopsx": len(ours),
        "peer": len(theirs),
        "in_both": len(in_both),
        "only_in_rsecopsx": len(only_ours),
        "only_in_peer": len(only_peer),
    }
    if domain == "license":
        counts["conflicts"] = len(conflicts)

    disagreements = len(only_ours) + len(only_peer) + len(conflicts)
    return {
        "status": "ran",
        "agreement": "agree" if disagreements == 0 else "disagreements",
        "domain": domain,
        "target": str(target),
        "peer_tool": chosen,
        "peer_binary": argv[0],
        "counts": counts,
        "in_both": in_both,
        "only_in_rsecopsx": only_ours,
        "only_in_peer": only_peer,
        "conflicts": conflicts,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_result(result: dict) -> None:
    domain = result.get("domain", "?")
    if result["status"] == "blocked":
        print("[%s] BLOCKED: %s" % (domain, "; ".join(result.get("reasons", []))))
        return
    c = result["counts"]
    line = ("[%s] peer=%s ran=%s in_both=%s only_ours=%s only_peer=%s"
            % (domain, result["peer_tool"], c["rsecopsx"], c["in_both"],
               c["only_in_rsecopsx"], c["only_in_peer"]))
    if "conflicts" in c:
        line += " conflicts=%s" % c["conflicts"]
    print(line + " -> %s" % result["agreement"])
    for section, key in (("  only_in_rsecopsx", "only_in_rsecopsx"),
                         ("  only_in_peer", "only_in_peer"),
                         ("  conflicts", "conflicts")):
        for entry in result.get(key, [])[:20]:
            print("%s: %s" % (section, json.dumps(entry, sort_keys=True)))
        if len(result.get(key, [])) > 20:
            print("%s: ... %d more" % (section, len(result[key]) - 20))


def main(argv_list=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--domain", required=True,
                        choices=["secrets", "iac", "license", "all"])
    parser.add_argument("--target", required=True,
                        help="directory to scan (for --domain all: a root holding "
                             "<domain>_target subdirectories)")
    parser.add_argument("--peer", default=None,
                        help="peer tool override (default: first available per domain)")
    parser.add_argument("--tolerance", type=int, default=None,
                        help="line tolerance for secrets/iac matching")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--json", dest="json_out", default=None,
                        help="write the full report to this JSON file")
    args = parser.parse_args(argv_list)

    root = Path(args.target)
    if args.domain == "all":
        work = [(d, root / ("%s_target" % d)) for d in ("secrets", "iac", "license")]
    else:
        work = [(args.domain, root)]

    results = []
    for domain, target in work:
        result = run_domain(domain, target, peer=args.peer,
                            tolerance=args.tolerance, timeout=args.timeout)
        results.append(result)
        _print_result(result)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
        print("report written: %s" % args.json_out)

    if any(r["agreement"] == "disagreements" for r in results if r["status"] == "ran"):
        return 1
    if any(r["status"] == "blocked" for r in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
