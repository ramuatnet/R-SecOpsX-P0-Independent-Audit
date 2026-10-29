"""T-4.3: fix validation -- apply a candidate patch, re-scan, judge.

task.md contract: apply a candidate patch -> re-scan -> assert the finding
disappears AND the target's own tests still pass -> report
``fix_confirmed: true|false``.

Safety and honesty design:

  * The patch is UNTRUSTED INPUT (ground rule 11): size, hunk-count and
    path caps; headers that escape the target (absolute paths, ``..``)
    are rejected before anything is written; application is exact-context
    (no fuzz) so a wrong-context patch fails loudly instead of landing
    somewhere unintended.  Every hunk is verified against the working
    content BEFORE any write happens, so a rejected patch never leaves a
    half-patched tree.
  * The target tree is NEVER mutated: everything happens in a private
    copy (``rsx_fix_*`` in the system temp -- no secret-scanner-disallowed
    name tokens, no in-source backups), with standard junk dirs
    (``.git``, ``__pycache__``, ``node_modules``, venvs, build outputs)
    skipped and whole-copy caps that fail closed.
  * "still pass" is read strictly: the target's tests are run BEFORE and
    AFTER the patch; a red baseline cannot demonstrate "still", so
    ``fix_confirmed`` requires a green baseline and a green post-patch
    run. No detectable test suite -> ``tests_passed: null`` and
    ``fix_confirmed: false`` with reason ``TESTS_NOT_FOUND``.
  * Finding identity after a patch cannot rely on line numbers (patches
    shift lines): a row counts as "the finding" when rule_id matches and
    the file path matches a suffix signature of the finding's file
    relative to the target root.  Disclosed limit: renaming the file
    hides the finding from the matcher; same-rule rows elsewhere in the
    same file keep it present.
  * Findings the patch introduces elsewhere are reported
    (``new_findings``) but do not flip the spec's two-condition verdict;
    same-rule-in-same-file regressions are already covered by the
    matcher keeping ``finding_cleared`` false.
  * Offline: stdlib only (the re-scan is the local scanner; tests run as
    a local subprocess).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

FIX_REPORT_SCHEMA = "rsecopsx.fix_validation/v1"

# Resource bounds for untrusted input (ground rule 11).
MAX_PATCH_BYTES = 2 * 1024 * 1024
MAX_PATCH_HUNKS = 5000
MAX_PATCH_LINES = 200000
MAX_COPY_FILES = 20000
MAX_COPY_BYTES = 512 * 1024 * 1024
MAX_TEST_OUTPUT = 64 * 1024
DEFAULT_TEST_TIMEOUT_S = 300.0

#: Never copied into the private tree (build junk; disclosed).
_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", "*.pyc", ".pytest_cache", "node_modules",
    ".venv", "venv", ".tox", "dist", "build", "target", "*.egg-info",
)


class FixApplyError(Exception):
    """Patch rejected; ``.reason`` is the machine-readable cause."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded(data: bytes, cap: int = MAX_TEST_OUTPUT) -> str:
    text = data.decode("utf-8", "replace")
    if len(text) > cap:
        return text[:cap] + f"\n...[truncated {len(text) - cap} chars]"
    return text


# ---------------------------------------------------------------------------
# unified-diff application (strict, stdlib)
# ---------------------------------------------------------------------------
def _safe_relpath(header_path: str) -> str:
    """Normalize a diff header path; reject anything that could escape."""
    p = header_path.strip().split("\t")[0].strip()
    if p.startswith(("a/", "b/")):
        p = p[2:]
    if not p or p == "/dev/null":
        return p
    if p.startswith("/") or p.startswith("\\") or ":" in p.split("/")[0]:
        raise FixApplyError("PATH_ESCAPE", header_path)
    parts = [seg for seg in p.replace("\\", "/").split("/")
             if seg not in ("", ".")]
    if any(seg == ".." for seg in parts):
        raise FixApplyError("PATH_ESCAPE", header_path)
    return "/".join(parts)


def _parse_hunk_header(line: str) -> tuple[tuple[int, int], tuple[int, int]]:
    # @@ -old_start,old_len +new_start,new_len @@
    try:
        at = line.index("@@")
        end = line.index("@@", at + 2)
        spec = line[at + 2:end].strip()
        old, new = spec.split(" ")
        o = old[1:].split(",")
        n = new[1:].split(",")
        return ((int(o[0]), int(o[1]) if len(o) > 1 else 1),
                (int(n[0]), int(n[1]) if len(n) > 1 else 1))
    except (ValueError, IndexError) as exc:
        raise FixApplyError("HUNK_HEADER", line) from exc


def parse_unified_diff(diff_text: str) -> list[dict]:
    """Parse a unified diff into per-file hunk structures.

    Hunk bodies are consumed by the line counts in the ``@@`` header, so
    an added line whose text starts with ``++`` is never mistaken for the
    next file's ``+++`` header (headers only appear once the counts are
    satisfied).  Raises FixApplyError on caps and malformed input.
    """
    if len(diff_text.encode("utf-8", "replace")) > MAX_PATCH_BYTES:
        raise FixApplyError("PATCH_TOO_LARGE",
                            f">{MAX_PATCH_BYTES} bytes")
    lines = diff_text.splitlines()
    if len(lines) > MAX_PATCH_LINES:
        raise FixApplyError("PATCH_TOO_LARGE", ">MAX_PATCH_LINES")
    files: list[dict] = []
    cur: Optional[dict] = None
    hunk_count = 0
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        if raw.startswith("--- "):
            old_path = _safe_relpath(raw[4:])
            if i + 1 >= n or not lines[i + 1].startswith("+++ "):
                raise FixApplyError("HEADER_PAIR", raw)
            new_path = _safe_relpath(lines[i + 1][4:])
            i += 2
            if old_path == "/dev/null" and new_path == "/dev/null":
                raise FixApplyError("HEADER_PAIR", raw)
            cur = {"old": None if old_path == "/dev/null" else old_path,
                   "new": None if new_path == "/dev/null" else new_path,
                   "hunks": []}
            files.append(cur)
        elif raw.startswith("@@"):
            if cur is None:
                raise FixApplyError("HUNK_WITHOUT_FILE", raw)
            hunk_count += 1
            if hunk_count > MAX_PATCH_HUNKS:
                raise FixApplyError("TOO_MANY_HUNKS", f">{MAX_PATCH_HUNKS}")
            old_spec, new_spec = _parse_hunk_header(raw)
            i += 1
            body: list[tuple[str, str]] = []
            need_old, need_new = old_spec[1], new_spec[1]
            while need_old or need_new:
                if i >= n:
                    raise FixApplyError("HUNK_TRUNCATED", raw)
                src = lines[i]
                i += 1
                if src.startswith("\\"):
                    continue  # "\ No newline at end of file"
                tag = src[:1] if src else " "
                text = src[1:] if src else ""
                if tag == " ":
                    if need_old == 0 or need_new == 0:
                        raise FixApplyError("HUNK_BODY", raw)
                    need_old -= 1
                    need_new -= 1
                    body.append((" ", text))
                elif tag == "-":
                    if need_old == 0:
                        raise FixApplyError("HUNK_BODY", raw)
                    need_old -= 1
                    body.append(("-", text))
                elif tag == "+":
                    if need_new == 0:
                        raise FixApplyError("HUNK_BODY", raw)
                    need_new -= 1
                    body.append(("+", text))
                elif src == "":
                    # bare empty line == empty context line
                    if need_old == 0 or need_new == 0:
                        raise FixApplyError("HUNK_BODY", raw)
                    need_old -= 1
                    need_new -= 1
                    body.append((" ", ""))
                else:
                    raise FixApplyError("HUNK_BODY", f"unexpected {src!r}")
            cur["hunks"].append({"old": old_spec, "new": new_spec,
                                 "body": body})
        elif raw.startswith(("diff ", "index ", "old mode", "new mode",
                             "new file mode", "deleted file mode",
                             "similarity index", "rename from",
                             "rename to", "Binary ", "GIT binary")):
            i += 1
        elif raw.strip() == "":
            i += 1
        else:
            i += 1  # tolerate stray decoration; hunks decide the content
    if not files:
        raise FixApplyError("NO_HUNKS", "no ---/+++ file headers found")
    return files


def _hunk_old_lines(hunk: dict) -> list[str]:
    return [line + "\n" for tag, line in hunk["body"]
            if tag in (" ", "-")]


def _hunk_new_lines(hunk: dict) -> list[str]:
    return [line + "\n" for tag, line in hunk["body"]
            if tag in (" ", "+")]


def _verify_hunks(old_lines: list[str], entry: dict, path: str) -> None:
    """Every hunk must match EXACTLY at its stated position (no fuzz);
    hunks within one file must ascend without overlap."""
    cursor = 0
    for hunk in entry["hunks"]:
        start = hunk["old"][0] - 1
        expect = _hunk_old_lines(hunk)
        if start < cursor:
            raise FixApplyError("HUNK_OVERLAP", f"{path}: @@ line "
                                f"{hunk['old'][0]}")
        if start < 0 or start + len(expect) > len(old_lines):
            raise FixApplyError(
                "APPLY_FAILED",
                f"{path}: hunk at line {hunk['old'][0]} outside file")
        got = old_lines[start:start + len(expect)]
        if got != expect:
            for j, (g, e) in enumerate(zip(got, expect)):
                if g != e:
                    raise FixApplyError(
                        "APPLY_FAILED",
                        f"{path}:{start + j + 1}: context mismatch "
                        f"(want {e.rstrip()!r}, got {g.rstrip()!r})")
            raise FixApplyError("APPLY_FAILED",
                                f"{path}:{start + 1}: context mismatch")
        cursor = start + len(expect)


def _rebuild_with_hunks(old_lines: list[str], entry: dict) -> list[str]:
    """Hunks are verified; splice new sides in order (original indices)."""
    out: list[str] = []
    cursor = 0  # 0-based index into old_lines
    for hunk in entry["hunks"]:
        start0 = hunk["old"][0] - 1
        out.extend(old_lines[cursor:start0])
        out.extend(_hunk_new_lines(hunk))
        cursor = start0 + len(_hunk_old_lines(hunk))
    out.extend(old_lines[cursor:])
    return out


def apply_unified_diff(root: Path, diff_text: str) -> list[dict]:
    """Apply ``diff_text`` under ``root``.

    Returns [{path, action}] for every file touched, in parse order.
    Raises FixApplyError (PATH_ESCAPE / APPLY_FAILED / ...) without
    partially applying: all hunks are verified against working content
    first, and only then are writes performed.  Multiple entries for the
    same path chain (the second sees the first's output).
    """
    parsed = parse_unified_diff(diff_text)
    root = Path(root).resolve()
    content: dict[str, list[str]] = {}      # working content, path -> lines
    actions: dict[str, str] = {}

    for entry in parsed:
        if entry["old"] is None and entry["new"] is None:
            raise FixApplyError("HEADER_PAIR", "both sides null")
        path = entry["new"] or entry["old"]
        abs_path = (root / path).resolve()
        if abs_path != root and not str(abs_path).startswith(str(root)
                                                             + os.sep):
            raise FixApplyError("PATH_ESCAPE", path)
        if entry["old"] is None:
            # new file: must not exist on disk or in this patch run
            if path in content or abs_path.exists():
                raise FixApplyError("APPLY_FAILED",
                                    f"{path}: exists, header says new file")
            for hunk in entry["hunks"]:
                if any(tag != "+" for tag, _ in hunk["body"]):
                    raise FixApplyError(
                        "APPLY_FAILED",
                        f"{path}: new-file hunk contains context/deletion")
            content[path] = []
            for hunk in entry["hunks"]:
                content[path].extend(_hunk_new_lines(hunk))
            if not content[path]:
                raise FixApplyError("APPLY_FAILED",
                                    f"{path}: empty new file hunk")
            actions[path] = "create"
            continue
        # existing file
        if path not in content:
            try:
                text = abs_path.read_text(encoding="utf-8")
            except FileNotFoundError:
                raise FixApplyError("APPLY_FAILED",
                                    f"{path}: missing") from None
            except UnicodeDecodeError:
                raise FixApplyError("APPLY_FAILED",
                                    f"{path}: not utf-8 text") from None
            content[path] = text.splitlines(keepends=True)
            actions.setdefault(path, "modify")
        _verify_hunks(content[path], entry, path)
        if entry["new"] is None:
            del content[path]
            actions[path] = "delete"
        else:
            content[path] = _rebuild_with_hunks(content[path], entry)

    # Everything verified -- now write.
    changed: list[dict] = []
    for path, action in actions.items():
        abs_path = root / path
        if action == "delete":
            abs_path.unlink(missing_ok=True)
        else:
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            abs_path.write_text("".join(content[path]), encoding="utf-8",
                                newline="")
        changed.append({"path": path, "action": action})
    return changed


# ---------------------------------------------------------------------------
# target copy + finding matcher + test runner
# ---------------------------------------------------------------------------
def copy_target(src: Path) -> Path:
    """Private working copy under the system temp.  Caps fail closed."""
    src = Path(src).resolve()
    if not src.is_dir():
        raise FixApplyError("TARGET_MISSING", str(src))
    n_files = 0
    n_bytes = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames
                       if d not in {".git", "node_modules", "__pycache__",
                                    ".venv", "venv", ".tox"}]
        for fn in filenames:
            n_files += 1
            try:
                n_bytes += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass
            if n_files > MAX_COPY_FILES or n_bytes > MAX_COPY_BYTES:
                raise FixApplyError(
                    "TARGET_TOO_LARGE",
                    f"{n_files} files / {n_bytes} bytes exceeds cap")
    dst = Path(tempfile.mkdtemp(prefix="rsx_fix_"))
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=_COPY_IGNORE)
    return dst


def _finding_file_rel(finding_file: str, target) -> str:
    """Finding file made relative to the target root when it is an
    absolute path under it; otherwise normalized as given."""
    raw = str(finding_file or "").replace("\\", "/").lstrip("./")
    if not raw:
        return ""
    try:
        f = Path(raw)
        if f.is_absolute():
            return f.resolve().relative_to(Path(target).resolve()) \
                .as_posix()
    except (ValueError, OSError):
        pass
    return raw


def _file_signatures(rel_file: str) -> list[str]:
    parts = [p for p in rel_file.split("/") if p]
    if not parts:
        return []
    sigs = ["/".join(parts)]
    if len(parts) > 3:
        sigs.append("/".join(parts[-3:]))
        sigs.append("/".join(parts[-2:]))
    return sigs


def finding_present(scan_rows: list[dict], finding: dict,
                    target=None) -> list[dict]:
    """Rows that ARE this finding.

    ``target`` is the ORIGINAL target root the finding was recorded
    against (rows may live under a private copy but end with the same
    relative path).  Disclosed matcher: rule_id equality AND file-path
    suffix signature; line numbers are reported but never required --
    patches shift lines.
    """
    rule = str(finding.get("rule_id") or "")
    if target is not None:
        rel = _finding_file_rel(str(finding.get("file") or ""), target)
    else:
        rel = str(finding.get("file") or "").replace("\\",
                                                     "/").lstrip("./")
    sigs = _file_signatures(rel)
    hits = []
    for row in scan_rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("rule_id") or "") != rule:
            continue
        row_norm = str(row.get("file") or "").replace("\\", "/")
        if any(row_norm.endswith(sig) for sig in sigs):
            hits.append(row)
    return hits


def _new_findings(before: list[dict], after: list[dict]) -> list[dict]:
    """(rule_id, file) pairs present after but not before."""
    def pairs(rows):
        out = set()
        for r in rows:
            f = str(r.get("file") or "").replace("\\", "/")
            out.add((str(r.get("rule_id") or ""), f))
        return out
    before_pairs = pairs(before)
    seen = set()
    added = []
    for r in after:
        f = str(r.get("file") or "").replace("\\", "/")
        key = (str(r.get("rule_id") or ""), f)
        if key not in before_pairs and key not in seen:
            seen.add(key)
            added.append({"rule_id": key[0], "file": f,
                          "line": r.get("line"),
                          "severity": r.get("severity")})
    return added


def _detect_test_cmd(workdir: Path) -> Optional[list[str]]:
    """Python targets only (auto); other languages need --test-cmd.
    Disclosed: no node/java/go auto-detection in v1."""
    markers = ("pytest.ini", "tox.ini", "conftest.py")
    if any((workdir / m).exists() for m in markers):
        return _pytest_cmd()
    pyproject = workdir / "pyproject.toml"
    if pyproject.exists() and "pytest" in pyproject.read_text(
            encoding="utf-8", errors="replace"):
        return _pytest_cmd()
    for tests_dir in ("tests", "test"):
        d = workdir / tests_dir
        if d.is_dir() and any(d.rglob("test_*.py")):
            return _pytest_cmd()
    if any(workdir.glob("test_*.py")):
        return _pytest_cmd()
    return None


def _pytest_cmd() -> list[str]:
    return [sys.executable, "-m", "pytest", "-q", "--no-header",
            "-p", "no:cacheprovider"]


def run_target_tests(workdir: Path, test_cmd: Optional[list[str]],
                     timeout_s: float) -> dict:
    """Run the target's own tests.  Returns a result dict; never raises
    on subprocess problems -- the failure IS the measurement."""
    cmd = list(test_cmd) if test_cmd else _detect_test_cmd(Path(workdir))
    if not cmd:
        return {"ran": False, "reason": "TESTS_NOT_FOUND",
                "detected_cmd": None}
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, cwd=str(workdir), capture_output=True,
            timeout=timeout_s, stdin=subprocess.DEVNULL,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        rc: Optional[int] = proc.returncode
        out = _bounded(proc.stdout) + _bounded(proc.stderr)
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        rc = None
        timed_out = True
        tail = exc.stdout or b""
        if isinstance(tail, str):
            tail = tail.encode()
        out = _bounded(tail) + f"\n[test timed out after {timeout_s}s]"
    except OSError as exc:
        return {"ran": False, "reason": f"TESTS_UNRUNNABLE: {exc}",
                "detected_cmd": cmd}
    return {
        "ran": True,
        "detected_cmd": cmd,
        "returncode": rc,
        "timed_out": timed_out,
        "passed": bool(rc == 0),
        "duration_s": round(time.monotonic() - t0, 2),
        "output_tail": out[-MAX_TEST_OUTPUT:],
    }


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------
def _code_context(target_path: Path, finding: dict) -> Optional[dict]:
    """Enclosing-symbol context for the finding via the T-1.4 span layer.

    Additive and fully defensive: resolves the finding's source under the
    target root (absolute or relative), then asks the span layer for the
    innermost definition around the finding's line. ``enclosing_symbol`` is
    ``None`` for top-level code or a language with no grammar (honest). Any
    failure -> ``None`` (the fix cycle never breaks on context enrichment).
    """
    try:
        from scanner import span_layer
        raw = str(finding.get("file") or "")
        if not raw:
            return None
        cand = Path(raw)
        src = cand if cand.is_absolute() else target_path / cand
        line = int(finding.get("line") or 0)
        language = finding.get("language") or span_layer.infer_language(src)
        return {
            "file": raw,
            "line": line,
            "language": language,
            "enclosing_symbol": span_layer.enclosing_symbol_for_file(
                src, line, language=finding.get("language") or None),
        }
    except Exception:  # noqa: BLE001 - context enrichment is optional
        return None


def validate_fix(target, patch_text: str, finding: dict,
                 test_cmd: Optional[list[str]] = None,
                 test_timeout_s: float = DEFAULT_TEST_TIMEOUT_S,
                 workers: int = 1) -> dict:
    """Full T-4.3 cycle.  Returns the report (CLI writes it as
    fix_report.json).  Never raises for target-side problems: a failure
    lands in the report with fix_confirmed=false."""
    from core import file_index
    from scanner.sast import scan_directory

    target_path = Path(target)
    patch_sha = _sha256_bytes(patch_text.encode("utf-8"))
    report: dict = {
        "schema": FIX_REPORT_SCHEMA,
        "target_name": target_path.name,
        "patch_sha256": patch_sha,
        "finding_ref": {
            "rule_id": finding.get("rule_id"),
            "vuln_type": finding.get("vuln_type"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "group_key": finding.get("group_key"),
        },
        "fix_confirmed": False,
        "finding_cleared": False,
        "patch_applied": False,
        "tests_passed": None,   # None = not run / not found (disclosed)
        "reasons": [],
        "timestamp": _utc_now(),
    }
    try:
        from core.config import TOOL_VERSION
        report["tool_version"] = TOOL_VERSION
    except Exception:
        report["tool_version"] = ""

    # T-1.4 span layer: the enclosing symbol for the finding's location, as
    # additive, parity-excluded context on the verdict (computed from the
    # ORIGINAL target's source; defensive -- an unreadable file or no
    # grammar degrades to None, never fails the fix cycle).
    report["code_context"] = _code_context(target_path, finding)

    # 1. private copy
    try:
        work = copy_target(target_path)
    except FixApplyError as exc:
        report["reasons"].append(f"{exc.reason}: {exc.detail}".rstrip(": "))
        return report
    except Exception as exc:
        report["reasons"].append(f"COPY_FAILED: {exc}")
        return report

    try:
        # 2. baseline scan + baseline tests (on the copy, pre-patch).
        #    The matcher relativizes finding.file against the ORIGINAL
        #    target root (rows live under the copy but end the same way).
        before_rows = scan_directory(str(work), workers=max(1,
                                                           int(workers)))
        before_hits = finding_present(before_rows, finding,
                                      target=target_path)
        report["before"] = {
            "present": bool(before_hits),
            "matches": [{"line": r.get("line"),
                         "evidence": str(r.get("evidence") or "")[:200]}
                        for r in before_hits[:5]],
            "total_findings": len(before_rows),
        }
        if not before_hits:
            report["reasons"].append(
                "FINDING_ABSENT_BEFORE: the identity matcher found no row "
                "for this rule+file in a baseline scan of the target")
            return report

        baseline_tests = run_target_tests(work, test_cmd, test_timeout_s)
        report["tests_before"] = baseline_tests

        # 3. apply patch (strict; failure stops with APPLY_FAILED)
        try:
            changed = apply_unified_diff(work, patch_text)
            report["patch_applied"] = True
            report["files_changed"] = changed
        except FixApplyError as exc:
            report["reasons"].append(
                f"{exc.reason}: {exc.detail}".rstrip(": "))
            return report

        # 3.5: the scan's index caches file CONTENT in-process
        #     (core.file_index.read_source serves from current()); the
        #     patch just rewrote files under `work`, so drop the current
        #     index or the re-scan would read pre-patch bytes and the
        #     verdict would be stale.  A fresh walk brings a fresh cache.
        #     Deliberately NOT fail-open: a silently stale after-scan is
        #     a wrong verdict, which is worse than an exception.
        file_index.set_current(None)

        # 4. re-scan the patched copy
        after_rows = scan_directory(str(work), workers=max(1,
                                                           int(workers)))
        after_hits = finding_present(after_rows, finding,
                                     target=target_path)
        report["after"] = {
            "present": bool(after_hits),
            "matches": [{"line": r.get("line"),
                         "evidence": str(r.get("evidence") or "")[:200]}
                        for r in after_hits[:5]],
            "total_findings": len(after_rows),
        }
        report["finding_cleared"] = not after_hits
        if after_hits:
            report["reasons"].append(
                "FINDING_STILL_PRESENT: a matching row survives the patch")
        new = _new_findings(before_rows, after_rows)
        report["new_findings"] = {"count": len(new), "samples": new[:5]}
        if new:
            report["reasons"].append(
                f"NEW_FINDINGS: {len(new)} row(s) not in the baseline "
                "(reported for judgement; not part of the two-condition "
                "verdict)")

        # 5. tests after the patch
        after_tests = run_target_tests(work, test_cmd, test_timeout_s)
        report["tests_after"] = after_tests

        # 6. verdict -- task.md's two conditions plus their preconditions.
        #    "still pass" read strictly: green baseline AND green after.
        not_found = (baseline_tests.get("reason") == "TESTS_NOT_FOUND"
                     or after_tests.get("reason") == "TESTS_NOT_FOUND")
        if not_found:
            report["tests_passed"] = None
            report["reasons"].append(
                "TESTS_NOT_FOUND: no detectable target test suite "
                "(auto-detection covers Python/pytest only; pass "
                "--test-cmd for other stacks)")
        elif not baseline_tests.get("ran"):
            report["tests_passed"] = None
            report["reasons"].append(
                f"TESTS_BROKEN_BASELINE: {baseline_tests.get('reason')}")
        elif not baseline_tests.get("passed"):
            report["tests_passed"] = None
            report["reasons"].append(
                "TESTS_BROKEN_BASELINE: tests already failed before the "
                "patch, so 'still pass' cannot be demonstrated")
        elif after_tests.get("timed_out"):
            report["tests_passed"] = None
            report["reasons"].append("TESTS_TIMED_OUT")
        else:
            report["tests_passed"] = bool(after_tests.get("passed"))
            if not report["tests_passed"]:
                report["reasons"].append(
                    "TESTS_FAILED_AFTER: target tests fail on the patched "
                    "tree")

        report["fix_confirmed"] = bool(
            report["patch_applied"]
            and report["finding_cleared"]
            and report["tests_passed"] is True
        )
        return report
    finally:
        # The copy is scratch: remove it on every path (no leftovers),
        # and drop the scan index so no later read_source serves bytes
        # from a tree that no longer exists.
        shutil.rmtree(work, ignore_errors=True)
        file_index.set_current(None)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m analysis.repro.fix_validation",
        description="T-4.3: apply a candidate patch, re-scan, judge "
                    "fix_confirmed")
    ap.add_argument("--target", required=True, help="target tree (untouched)")
    ap.add_argument("--patch", required=True,
                    help="unified diff file, or - for stdin")
    ap.add_argument("--finding", required=True,
                    help="single finding JSON (as produced by a scan)")
    ap.add_argument("--test-cmd", default=None,
                    help="target test command (default: pytest auto-detect)")
    ap.add_argument("--test-timeout", type=float,
                    default=DEFAULT_TEST_TIMEOUT_S)
    ap.add_argument("--out", default="fix_report.json")
    args = ap.parse_args(argv)

    patch_text = (sys.stdin.read() if args.patch == "-"
                  else Path(args.patch).read_text(encoding="utf-8"))
    finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    if isinstance(finding, dict) and isinstance(finding.get("finding"),
                                                dict):
        finding = finding["finding"]  # tolerate a one-bundle manifest

    report = validate_fix(
        args.target, patch_text, finding,
        test_cmd=(args.test_cmd.split() if args.test_cmd else None),
        test_timeout_s=args.test_timeout,
    )
    out = Path(args.out)
    out.write_text(json.dumps(report, sort_keys=True, indent=1),
                   encoding="utf-8", newline="\n")
    print(f"fix_confirmed: {report['fix_confirmed']}  "
          f"patch_applied: {report['patch_applied']}  "
          f"finding_cleared: {report['finding_cleared']}  "
          f"tests_passed: {report['tests_passed']}")
    for reason in report["reasons"]:
        print(f"  reason: {reason}")
    return 0 if report["fix_confirmed"] else 1


if __name__ == "__main__":
    sys.exit(main())
