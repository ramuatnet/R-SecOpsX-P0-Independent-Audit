"""Scan the AI Benchmarks corpus one project at a time and measure what it can measure.

What this corpus is, and is not
-------------------------------
`D:\\Data\\Code test\\prodtest\\AI Benchmarks` holds nine PRODUCTION AI frameworks:
AgentGPT, autogen, babyagi, diffusers, llama_index, Open-Assistant, peft,
semantic-kernel, transformers. Roughly 1 GB across ~28,000 files.

These are not deliberately-vulnerable applications. Nothing in them DECLARES
where a vulnerability is, so there is NO ground truth and NO recall or precision
figure can be computed from this corpus. Claiming one would be the same mistake as
scoring juice-shop prose.

What this corpus CAN measure, and does:
  * robustness at scale -- does the scanner stay up on a 728 MB / 9,797-file
    repository, and does it stay fast enough to be usable
  * specificity -- findings per KLOC against real, heavily-reviewed code. A
    scanner that produces a finding on every tenth line of upstream HuggingFace
    is not useful, whatever it claims to find
  * AI-framework coverage -- whether the LLM/AI rules and the SANS / FREE-AI /
    ATLAS mappings engage on genuine AI frameworks rather than only on the small
    red-team labs
  * framework-mapping honesty -- e.g. whether an UNMAPPED finding stays UNMAPPED
    instead of acquiring an invented control

Reports both directions. A project with FEW findings is reported as specific,
not as broken; a project with MANY is reported as noisy, not as thorough.

Lossless merge
--------------
Each project's summary is re-derived from its own clean_report.json on a re-run
rather than rescanned, and merges never drop an existing entry. The earlier
version of the prodtest harness overwrote its own results file and destroyed 15
entries; this one cannot.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
from collections import Counter

ROOT = pathlib.Path(r"D:\Data\Code test\prodtest\AI Benchmarks")
REPO = pathlib.Path(r"D:\Data\Code test\R-SecOpsX_V11")
OUT = pathlib.Path(r"D:\Data\Code test\prodtest\reports\ai_benchmarks")
SWEEP_JSON = OUT / "ai_benchmarks_sweep.json"
SWEEP_MD = OUT / "ai_benchmarks_sweep.md"

SKIP_NAMES = {"reports", "__pycache__", ".git", "node_modules"}


def projects() -> list[pathlib.Path]:
    if not ROOT.exists():
        raise SystemExit(f"corpus root not found: {ROOT}")
    out = []
    for d in sorted(ROOT.iterdir()):
        if d.is_dir() and d.name not in SKIP_NAMES:
            out.append(d)
    return out


def kloc(root: pathlib.Path) -> tuple[int, int]:
    """(source files, kilolines). Counts source text only."""
    exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".cs",
            ".php", ".c", ".h", ".cpp", ".rs", ".sh"}
    files = lines = 0
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        if any(seg in {".git", "node_modules", "__pycache__", "venv", ".venv",
                       "site-packages", "dist", "build"} for seg in p.parts):
            continue
        files += 1
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                lines += sum(1 for _ in fh)
        except OSError:
            continue
    return files, lines // 1000


def summarise(art: pathlib.Path, name: str) -> dict:
    """Re-derive a project's summary from its OWN artifact. Never scans."""
    rep = json.loads(art.read_text(encoding="utf-8", errors="replace"))
    findings = rep.get("findings") or []
    meta = rep.get("metadata") or {}

    sev = Counter(str(f.get("severity") or "?") for f in findings)
    rules = Counter(str(f.get("rule_id") or f.get("vuln_type") or "?")
                    for f in findings)

    # AI-framework mapping engagement, and whether anything stayed UNMAPPED.
    ai = Counter()
    for f in findings:
        for field, tag in (("sans_mapping_mode", "sans"), ("free_ai_mapping_mode", "free_ai"),
                           ("asvs_mapping_mode", "asvs"), ("atlas", "atlas")):
            v = f.get(field)
            if isinstance(v, str) and v:
                ai[f"{tag}:{v}"] += 1
            elif field == "atlas" and v:
                ai["atlas:mapped"] += 1

    paths = set()
    for f in findings:
        for af in (f.get("affected_files") or []):
            paths.add(str(af))

    return {
        "project": name,
        "source": "re-derived from artifact",
        "total_findings": meta.get("total_findings", len(findings)),
        "findings_len": len(findings),
        "severity": dict(sev),
        "unique_rules": len(rules),
        "top_rules": rules.most_common(12),
        "affected_files": len(paths),
        "attack_paths": len(rep.get("attack_paths") or []),
        "ai_mapping": dict(ai),
        "has_mitre": bool(rep.get("mitre")),
        "has_cyclonedx": bool(rep.get("cyclonedx")),
        "compliance_frameworks": sorted(
            (rep.get("compliance_summary") or {}).keys()),
    }


_PHASE_RE = re.compile(
    r"\[PHASE END\]\s*(?P<name>.+?)\s*\|.*?ELAPSED=(?P<dur>[0-9:.]+?)\s*\|")
_PHASE_START_RE = re.compile(r"\[PHASE START\]\s*(?P<name>.+?)\s*\|")


def _duration_seconds(token: str) -> float | None:
    """Parse main.py's `_format_duration` output.

    The format has TWO shapes and both occur in practice:

        MM:SS.ss      under one hour   -> "00:05.40"
        HH:MM:SS.ss   one hour or more -> "01:23:45.67"

    A hardcoded pattern for one shape silently fails on the other. That is not
    hypothetical: the first version of this parser assumed a `\\d+h:\\d+m:\\d+s`
    pattern with literal 'h', 'm' and 's' separators, matched NOTHING against real
    captured output, and returned an empty list -- which reads as "no phase data
    available" rather than "the parser is broken". Every phase-timing field would
    have stayed empty forever and nothing would have said so, which is the worst
    possible failure for a diagnostic: present, plausible, and silent.

    The token is therefore split structurally and both shapes are handled, and the
    empty-result case is asserted against real captured text in
    tests/test_v11_bench_runner.py so a silent no-op cannot come back.
    """
    parts = token.split(":")
    try:
        if len(parts) == 2:
            minutes, seconds = float(parts[0]), float(parts[1])
            return minutes * 60.0 + seconds
        if len(parts) == 3:
            hours, minutes, seconds = (float(p) for p in parts)
            return hours * 3600.0 + minutes * 60.0 + seconds
    except ValueError:
        return None
    return None


def parse_phase_timings(text: str) -> list[dict]:
    """Per-phase elapsed seconds, longest first.

    main.py prints PHASE START/PHASE END pairs with ELAPSED already computed. That
    is the only attribution available for a long run, and it is authoritative
    rather than inferred, so it is read rather than reconstructed.
    """
    out = []
    for m in _PHASE_RE.finditer(text or ""):
        total = _duration_seconds(m.group("dur"))
        if total is None:
            continue
        out.append({"phase": m.group("name").strip(),
                    # Two decimals, matching `_format_duration`'s own %05.2f. One
                    # decimal was enough for large values and misleading for small
                    # ones: a 1.22s phase reported as "1.2s", which is a different
                    # number from the one the scanner printed.
                    "seconds": round(total, 2)})
    return sorted(out, key=lambda d: -d["seconds"])


def parse_last_started_phase(text: str) -> str | None:
    """The phase that had started but never finished -- i.e. where it hung."""
    ends = {m.group("name").strip() for m in _PHASE_RE.finditer(text or "")}
    for m in _PHASE_START_RE.finditer(text or ""):
        name = m.group("name").strip()
        if name not in ends:
            return name
    return None


def _kill_tree(proc) -> None:
    """Kill the child AND everything it spawned.

    The scanner runs a process pool. Killing only the direct child leaves the
    workers holding the pipe, and `communicate()` then blocks waiting for output
    that will never be closed -- which is exactly how a 7200s budget became
    10,519s.
    """
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
            capture_output=True, timeout=120,
        )
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()


def newest_production_source_mtime() -> tuple[float, list[str]]:
    """Newest mtime across the code that decides what a report contains.

    Production source only: tests/, docs/, reports/ and analysis/ are excluded,
    because a benchmark measures the system and a change to the benchmark must not
    make every existing result look stale.
    """
    newest, newest_files = 0.0, []
    for sub in ("scanner", "core", "reporting", "config"):
        d = REPO / sub
        if not d.is_dir():
            continue
        for p in d.rglob("*.py"):
            try:
                m = p.stat().st_mtime
            except OSError:
                continue
            if m > newest:
                newest, newest_files = m, [p.name]
            elif m == newest:
                newest_files.append(p.name)
    main_py = REPO / "main.py"
    if main_py.exists():
        m = main_py.stat().st_mtime
        if m > newest:
            newest, newest_files = m, ["main.py"]
        elif m == newest:
            newest_files.append("main.py")
    return newest, sorted(newest_files)


def artifact_staleness(art: pathlib.Path) -> dict:
    """Whether an artifact still reflects the code that produced it.

    MEASURED, NOT ASSUMED. The corpus sweep reported `transformers-main` as clean
    by re-deriving from an existing artifact, and that artifact turned out to be
    generated at 06:02Z -- missing every layer shipped after it, including
    payload['qbom'], payload['qbom_pq'] and the advisory disclosure. A killed scan
    also leaves a partial artifact behind, which the next run then trusts.

    So an artifact older than the newest production source cannot describe current
    behaviour, and saying so is the difference between a corpus number that means
    something and one that describes code from this morning. This is the same defect
    as G-091, at the harness level: there the artifact predated three shipped
    framework modules, and nothing in the tooling noticed.
    """
    out = {"artifact": str(art), "stale": False, "reason": None,
           "artifact_mtime": None, "newest_source_mtime": None,
           "newer_modules": []}
    if not art.exists():
        out["stale"] = True
        out["reason"] = "no artifact"
        return out

    try:
        art_m = art.stat().st_mtime
    except OSError as exc:
        out["stale"] = True
        out["reason"] = f"artifact unreadable: {exc}"
        return out

    newest, _names = newest_production_source_mtime()
    out["artifact_mtime"] = art_m
    out["newest_source_mtime"] = newest

    if art_m < newest:
        out["stale"] = True
        out["age_seconds"] = round(newest - art_m, 1)
        out["reason"] = (
            f"artifact is {round((newest - art_m) / 3600, 1)}h older than the "
            "newest production source, so it cannot describe current behaviour")
        out["newer_modules"] = _modules_newer_than(art_m)
    return out


def _modules_newer_than(when: float, limit: int = 8) -> list[str]:
    """Which production modules changed after the artifact was written.

    Named, so the staleness is explained rather than merely flagged. A reader who
    is told 'this number is stale' cannot act; a reader who is told 'these six
    modules changed since' can.
    """
    newer = []
    for sub in ("scanner", "core", "reporting"):
        d = REPO / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.py")):
            try:
                if p.stat().st_mtime > when:
                    newer.append(str(p.relative_to(REPO)).replace("\\", "/"))
            except OSError:
                continue
    mp = REPO / "main.py"
    if mp.exists() and mp.stat().st_mtime > when:
        newer.append("main.py")
    return newer[:limit]


def scan_one(root: pathlib.Path, workers: int, timeout: int) -> dict:
    name = root.name
    # These zips each nest their sources one level deeper (AI Benchmarks\\x\\x).
    target = root
    if not any(p.suffix for p in root.iterdir() if p.is_file()):
        subs = [p for p in root.iterdir() if p.is_dir()]
        if len(subs) == 1:
            target = subs[0]
    outdir = OUT / name
    outdir.mkdir(parents=True, exist_ok=True)
    art = outdir / "clean_report.json"

    files, kl = kloc(target)
    t0 = time.time()
    env = dict(os.environ, PYTHONIOENCODING="utf-8")

    proc = subprocess.Popen(
        [sys.executable, str(REPO / "main.py"), str(target),
         "--workers", str(workers), "--output", str(outdir),
         # This harness summarises from clean_report.json and never reads a PDF.
         # Both large corpus projects were timing out in PDF generation -- roughly
         # 2,800s of llama_index-main's 3,600s budget -- for a document nothing here
         # consumes. The flag existed but was not consulted by main.py, so it was
         # doing nothing until G-138. Disclosed in the sweep's `method` text rather
         # than left implicit, because it does change what a corpus run renders.
         "--no-pdf"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        env=env, cwd=str(REPO),
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        # Whatever was captured before the deadline is the only evidence of where
        # the time went. It used to be discarded here.
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        _kill_tree(proc)
        try:
            more_out, more_err = proc.communicate(timeout=120)
            stdout += more_out or ""
            stderr += more_err or ""
        except subprocess.TimeoutExpired:
            stdout += "\n[capture incomplete: pipes still held after kill]"
        rc = -9

    dur = time.time() - t0
    phases = parse_phase_timings(stdout)
    hung_in = parse_last_started_phase(stdout)

    entry = {"project": name, "scanned_path": str(target), "source_files": files,
             "kloc": kl, "returncode": rc, "seconds": round(dur, 1),
             # Stated explicitly so a re-derived row can never be read as a scan.
             # `returncode: 0` alone says an artifact exists and parses; it does not
             # say this build was scanned, and seconds: 0 makes that ambiguity worse
             # by looking instantaneous rather than merely unexamined.
             "scanned_this_run": True}
    if phases:
        entry["phase_seconds"] = phases
        entry["phases_completed"] = len(phases)

    if timed_out:
        # Report the overshoot explicitly. A budget that is routinely exceeded by
        # 50% is not a budget, and naming the gap is the first step to closing it.
        entry["timeout_seconds"] = timeout
        entry["timed_out"] = True
        entry["overshoot_seconds"] = round(dur - timeout, 1)
        if hung_in:
            entry["hung_in_phase"] = hung_in
        entry["error"] = (f"TIMEOUT after {timeout}s (ran {dur:.0f}s, "
                          f"overshoot {dur - timeout:.0f}s)"
                          + (f"; last phase started: {hung_in}" if hung_in
                             else "; no phase had started")
                          )
        entry["stdout_tail"] = (stdout or "")[-1500:]
        entry["stderr_tail"] = (stderr or "")[-600:]
        print(f"    rc={rc} after {dur:.0f}s  {entry['error']}")
        if phases:
            print("      phase breakdown (longest first):")
            for ph in phases[:6]:
                print(f"        {ph['seconds']:9.1f}s  {ph['phase'][:64]}")
        if hung_in:
            print(f"      STALLED IN: {hung_in}")
        return entry

    if rc != 0:
        entry["error"] = (stderr or stdout)[-400:]
        entry["stdout_tail"] = (stdout or "")[-1500:]
        print(f"    rc={rc} after {dur:.0f}s  {entry['error'][:120]}")
        if phases:
            print(f"      completed {len(phases)} phases; longest: "
                  f"{phases[0]['phase']} {phases[0]['seconds']}s")
        return entry
    if not art.exists():
        entry["error"] = "returncode 0 but no clean_report.json was written"
        entry["stdout_tail"] = (stdout or "")[-1500:]
        print(f"    rc=0 but NO ARTIFACT after {dur:.0f}s")
        return entry

    entry.update(summarise(art, name))
    entry["findings_per_kloc"] = round(
        entry["findings_len"] / kl, 2) if kl else None
    print(f"    findings={entry['findings_len']:5d} rules={entry['unique_rules']:4d} "
          f"kloc={kl:6d} per_kloc={entry['findings_per_kloc']} "
          f"paths={entry['attack_paths']:4d} {dur:.0f}s")
    if phases:
        print(f"      slowest phase: {phases[0]['phase'][:56]} "
              f"{phases[0]['seconds']}s")
    return entry


# The evidence a failed attempt produced. A timeout record is only useful if WHERE it
# stalled survives, and that lives entirely in these fields.
_FAILURE_EVIDENCE = (
    "returncode", "error", "stdout_tail", "stderr_tail",
    "phase_seconds", "phases_completed",
    "timeout_seconds", "timed_out", "overshoot_seconds", "hung_in_phase",
    "seconds",
)


def _is_failed_attempt(entry: dict) -> bool:
    """True when this entry records an attempt that did not complete cleanly."""
    if entry.get("timed_out"):
        return True
    rc = entry.get("returncode")
    return isinstance(rc, int) and rc != 0


def _failure_evidence(entry: dict) -> dict:
    return {k: entry[k] for k in _FAILURE_EVIDENCE if k in entry}


def _same_evidence(a: dict, b: dict) -> bool:
    return json.dumps(a, sort_keys=True, default=str) == \
        json.dumps(b, sort_keys=True, default=str)


def merge(results: list[dict]) -> list[dict]:
    """Never drops an entry, and never discards the evidence a failure recorded.

    "LOSSLESS" used to mean only that a project name is never removed from the
    sweep, and the implementation did exactly that and no more. It was lossy in
    substance: a fresh entry replaced a recorded timeout wholesale, so the phase
    breakdown naming the phase the project stalled in, the overshoot against budget,
    and the partial timings were all discarded. That is not a cosmetic loss -- it is
    the only evidence of what blocked the project, and it was being destroyed by the
    run that eventually got past the blocker.

    Concretely: transformers-main timed out at a 2,700s budget after 1,648s in the
    OWASP LLM phase and wrote its artifact before dying in PDF generation. The next
    run found the artifact, re-derived it, and overwrote the timeout record with an
    rc=0 row carrying none of the diagnostic -- leaving no trace that the project had
    ever failed to scan.

    So a recorded failure is now carried forward under `prior_attempts` whenever a
    later run supersedes it. History is deduplicated, because merge() is called once
    per project with the accumulated results, which means a project's own history
    would otherwise be re-appended on every subsequent iteration.
    """
    by = {}
    if SWEEP_JSON.exists():
        for r in json.loads(SWEEP_JSON.read_text(encoding="utf-8")).get("projects", []):
            by[r["project"]] = r
    for r in results:
        prev = by.get(r["project"])
        if prev is not None and _is_failed_attempt(prev) and not _is_failed_attempt(r):
            evidence = _failure_evidence(prev)
            history = list(r.get("prior_attempts") or [])
            if not any(_same_evidence(h, evidence) for h in history):
                history.append(evidence)
            r = dict(r)
            r["prior_attempts"] = history
        by[r["project"]] = r
    return [by[k] for k in sorted(by)]


def write_reports(results: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    doc = {
        "corpus": str(ROOT),
        "method": (
            "Each project scanned once with the real scanner. No accuracy figure is "
            "computed because nothing in this corpus declares where a vulnerability "
            "is; these are production AI frameworks, not deliberately-vulnerable "
            "applications. Findings-per-KLOC is reported as a specificity signal "
            "against real upstream code, and AI mapping engagement is reported to "
            "show whether the AI rules fire on genuine AI frameworks."),
        "not_an_accuracy_claim": True,
        "pdfs_not_rendered": True,
        "rendering_note": (
            "Corpus runs pass --no-pdf. clean_report.json, which is what this "
            "sweep reads, is written before PDF generation, and PDF rendering is "
            "what the two largest projects were timing out in -- roughly 2,800s of "
            "llama_index-main's 3,600s budget. The flag was declared but never "
            "consulted by main.py, so it skipped nothing until G-138. Anything "
            "measured here is unaffected: no finding, mapping, SBOM entry or "
            "finding count comes from the PDF path."
        ),
        "projects": results,
    }
    SWEEP_JSON.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    ok = [r for r in results if r.get("returncode") == 0 and "findings_len" in r]
    bad = [r for r in results if r not in ok]
    # Currency, not just rc. `ok` means the artifact parsed; it says nothing
    # about whether the artifact describes the current build. A stale artifact
    # has rc=0 and so was invisible to the only section that named
    # non-current rows.
    fresh = [r for r in ok if r.get("stale") is False]
    stale_rows = [r for r in ok if r.get("stale") is True]
    unverified = [r for r in ok if r.get("stale") is None]
    lines = [
        "# AI Benchmarks corpus sweep",
        "",
        "Nine production AI frameworks, ~1 GB. **No accuracy figure is computed "
        "here**:",
        "nothing in this corpus declares where a vulnerability is. What is measured "
        "is",
        "robustness at scale, findings-per-KLOC as a specificity signal against "
        "upstream",
        "code, and whether the AI rules and framework mappings engage on genuine AI "
        "frameworks.",
        "",
        "## Per project",
        "",
        "| project | currency | rc | files | kloc | findings | rules | /KLOC | "
        "attack paths | seconds |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(results, key=lambda x: x["project"]):
        _cur = ("current" if r.get("stale") is False
                else "stale" if r.get("stale") is True else "unverified")
        if r.get("returncode") != 0 or "findings_len" not in r:
            lines.append(f"| {r['project']} | **{_cur}** | "
                         f"**{r.get('returncode')}** | "
                         f"{r.get('source_files','?')} | - | - | - | - | - | "
                         f"{r.get('seconds','?')} |")
            continue
        lines.append(
            f"| {r['project']} | **{_cur}** | {r['returncode']} | "
            f"{r['source_files']} | "
            f"{r['kloc']} | {r['findings_len']} | {r['unique_rules']} | "
            f"{r['findings_per_kloc']} | {r['attack_paths']} | {r['seconds']} |")

    lines += ["", "## Severity mix", "",
              f"_Over the {len(fresh)} project(s) whose artifact describes the "
              f"current build. Stale and unverified rows are excluded._", ""]
    agg = Counter()
    for r in fresh:  # currency-scoped: `ok` includes stale rows (G-139)
        for k, v in (r.get("severity") or {}).items():
            agg[k] += v
    if agg:
        lines.append("| severity | count |")
        lines.append("|---|---|")
        for k, v in agg.most_common():
            lines.append(f"| {k} | {v} |")

    lines += ["", "## Top rules across the corpus", "",
              f"_Over the {len(fresh)} current-build project(s) only._", "",
              "| rule | count |", "|---|---|"]
    rules = Counter()
    for r in fresh:  # currency-scoped: `ok` includes stale rows (G-139)
        for rule, n in r.get("top_rules") or []:
            rules[rule] += n
    for k, v in rules.most_common(25):
        lines.append(f"| {k} | {v} |")

    lines += ["", "## AI mapping engagement", "",
              f"_Over the {len(fresh)} current-build project(s) only._", "",
              "| mapping:mode | findings |", "|---|---|"]
    eng = Counter()
    for r in fresh:  # currency-scoped: `ok` includes stale rows (G-139)
        for k, v in (r.get("ai_mapping") or {}).items():
            eng[k] += v
    if eng:
        for k, v in eng.most_common():
            lines.append(f"| {k} | {v} |")
    else:
        lines.append("| (none engaged) | 0 |")

    if stale_rows or unverified:
        lines += ["", "## Rows excluded from the aggregates above", "",
                  "These rows are reported for continuity and are NOT counted "
                  "in any table above. A stale artifact describes the build that "
                  "produced it, not this one.", ""]
        if stale_rows:
            lines += ["### Stale (artifact older than the current build)", ""]
            for r in sorted(stale_rows, key=lambda x: x["project"]):
                _why = str((r.get("staleness") or {}).get("reason", ""))[:180]
                lines.append(f"- **{r['project']}** — {_why}")
            lines.append("")
        if unverified:
            lines += ["### Currency never established", "",
                      "Not known to be current, and not known to be stale "
                      "either. Excluded rather than assumed fresh.", ""]
            for r in sorted(unverified, key=lambda x: x["project"]):
                _why = str((r.get("staleness") or {}).get("reason", ""))[:180]
                lines.append(f"- **{r['project']}** — {_why}")
            lines.append("")

    if bad:
        lines += ["", "## Projects that did not complete cleanly", ""]
        for r in bad:
            lines.append(f"- **{r['project']}** rc={r.get('returncode')}: "
                         f"{str(r.get('error',''))[:200]}")

    lines += ["", "## Reading a LOW finding count",
              "",
              "A framework with few findings is not a broken scan. These are "
              "upstream",
              "projects, so a low count is the specificity signal working: it means "
              "the",
              "scanner did not manufacture findings on real code. A HIGH count "
              "deserves",
              "scrutiny for noise. Both directions are reported; neither is a "
              "thoroughness",
              "claim without ground truth."]
    SWEEP_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def refresh_staleness(rows: list[dict]) -> list[dict]:
    """Recompute the staleness of EVERY row, not just the one just scanned.

    Staleness used to be computed inside the per-target loop, so on a partial run
    (`--only`) the other rows kept whatever flag they had from whenever they last
    ran -- or None, if they never had one computed. Combined with a filter of
    `not r.get("stale")`, a row carrying no staleness information at all was counted
    as fresh.

    That was measured, not hypothesised: transformers-main's artifact was 5.69 hours
    older than main.py, so it was stale by this module's own rule, yet its row
    carried stale=None and was counted in "scanned cleanly" and in the current-build
    findings total.

    So:
      * a scan that just completed sets stale False -- it describes the code as it is
        now by construction, and stating it explicitly is what makes `stale is False`
        mean "known current" rather than "not known to be old";
      * every other row is recomputed from its artifact on disk;
      * a row with no artifact gets stale None, explicitly, so "unknown" is recorded
        as unknown instead of being read as fresh.
    """
    for r in rows:
        # Fresh by construction ONLY IF THE SCAN SUCCEEDED. `scanned_this_run` is set
        # when the scanner is launched, before its outcome is known, so conditioning
        # on it alone marks a timed-out scan as current. That is the same inversion
        # this function exists to remove, reintroduced through the fix: it happened
        # here, labelling transformers-main `stale: False` while it had produced no
        # artifact and no findings at all.
        if (r.get("scanned_this_run")
                and r.get("returncode") == 0
                and "findings_len" in r):
            r["stale"] = False
            continue
        if r.get("scanned_this_run"):
            # A scan that started and did not finish establishes nothing. Not stale
            # either -- there is no artifact to be old.
            r["stale"] = None
            r["staleness"] = {
                "stale": None,
                "reason": (f"scan did not complete cleanly "
                           f"(returncode {r.get('returncode')})"),
            }
            continue
        art = OUT / r["project"] / "clean_report.json"
        if not art.exists():
            r["stale"] = None
            r["staleness"] = {"stale": None,
                              "reason": "no clean_report.json on disk"}
            continue
        s = artifact_staleness(art)
        r["staleness"] = s
        r["stale"] = s["stale"]
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="AI Benchmarks corpus sweep")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=5400,
                    help="per-project seconds before giving up")
    ap.add_argument("--only", default="", help="comma-separated project substrings")
    args = ap.parse_args()

    targets = projects()
    if args.only:
        wanted = [w.strip().lower() for w in args.only.split(",") if w.strip()]
        targets = [t for t in targets
                   if any(w in t.name.lower() for w in wanted)]
    print(f"corpus: {len(targets)} projects from {ROOT}")

    results = []
    for i, t in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {t.name}")
        art = OUT / t.name / "clean_report.json"
        if art.exists():
            stale = artifact_staleness(art)
            if stale["stale"]:
                # Recorded, not silently reused. An artifact older than the code
                # that produced it describes that code, not this one, and folding
                # it into the corpus totals attributes old behaviour to the current
                # build. Re-deriving from it is still allowed -- it is cheaper than
                # a rescan and the numbers may still be the best available -- but it
                # is counted as STALE and never as "scanned cleanly".
                print(f"    existing artifact is STALE: {stale['reason']}")
                for mod in stale.get("newer_modules", [])[:5]:
                    print(f"      changed since: {mod}")
                print("    re-deriving summary from the stale artifact; "
                      "these numbers describe the older build and are "
                      "counted separately, not as a clean scan")
            else:
                print("    re-deriving summary from existing artifact (not rescanning)")
            e = {"project": t.name, "returncode": 0, "scanned_path": str(t),
                 # The artifact exists and parses, which is what returncode 0 means
                 # here. It is NOT a claim that this build was scanned, and nothing
                 # else in this row would say so: seconds is 0, and a reader checking
                 # only the returncode would conclude a fast, clean scan.
                 "scanned_this_run": False}
            if stale["stale"]:
                e["stale"] = True
                e["staleness"] = stale
            sf, kl = kloc(t)
            e["source_files"], e["kloc"] = sf, kl
            e.update(summarise(art, t.name))
            e["seconds"] = 0
            e["findings_per_kloc"] = round(e["findings_len"] / kl, 2) if kl else None
            print(f"    findings={e['findings_len']} rules={e['unique_rules']} "
                  f"kloc={kl}")
            results.append(e)
        else:
            results.append(scan_one(t, args.workers, args.timeout))
        results = merge(results)
        results = refresh_staleness(results)
        write_reports(results)

    results = refresh_staleness(results)
    write_reports(results)

    ok = [r for r in results if r.get("returncode") == 0 and "findings_len" in r]
    # A stale artifact is not a clean scan. Counting it as one is how a corpus
    # starts describing code from earlier in the week while appearing current, and
    # the tally is the line a reader quotes.
    #
    # `stale is False`, not `not stale`: None means the currency was never
    # established, and treating that as fresh is how transformers-main came to be
    # reported inside the current-build totals with an artifact 5.69 hours older
    # than main.py. Unverified rows get their own line rather than being folded
    # into either bucket.
    fresh = [r for r in ok if r.get("stale") is False]
    stale = [r for r in ok if r.get("stale") is True]
    unverified = [r for r in ok if r.get("stale") is None]
    bad = [r for r in results if r not in ok]
    print("\n" + "=" * 70)
    print(f"projects scanned cleanly   : {len(fresh)} / {len(results)}")
    print(f"from a stale artifact      : {len(stale)}  "
          f"({', '.join(r['project'] for r in stale) if stale else 'none'})")
    print(f"currency never established : {len(unverified)}  "
          f"({', '.join(r['project'] for r in unverified) if unverified else 'none'})")
    if unverified:
        print("  NOTE: the unverified rows are EXCLUDED from the current-build "
              "totals. A row whose")
        print("  currency was never established is not evidence that the artifact "
              "is current.")
    print(f"projects with problems     : {len(bad)}")
    if stale:
        print("  NOTE: the stale rows above are reported for continuity but do NOT")
        print("        describe the current build. Rescan them before quoting them.")
    if fresh:
        # Totals are over CURRENT results only. Including stale artifacts would
        # attribute an older build's findings to the current one, which is the
        # specific misreading this whole check exists to prevent.
        tot = sum(r["findings_len"] for r in fresh)
        kl = sum(r["kloc"] for r in fresh)
        print(f"total findings           : {tot}   (current build only)")
        print(f"total kloc               : {kl}   (current build only)")
        print(f"findings per kloc        : {round(tot / kl, 2) if kl else 0}")
    if stale:
        stot = sum(r["findings_len"] for r in stale)
        skl = sum(r["kloc"] for r in stale)
        print(f"[stale] findings         : {stot} over {skl} kloc "
              f"({round(stot / skl, 2) if skl else 0}/kloc) -- EXCLUDED from "
              "the totals above")
    print(f"reports: {SWEEP_JSON}")
    print(f"         {SWEEP_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())