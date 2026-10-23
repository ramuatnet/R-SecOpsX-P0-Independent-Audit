# -*- coding: utf-8 -*-
r"""G-016 -- secrets that exist only in git history.

A working-tree scan cannot see a credential that was committed and then
removed: by the time the scanner runs, the line is gone from every file on
disk. This engine closes that gap by scanning the *historical revisions* of
each changed file with the exact same detector the working-tree scan uses
(``scanner.secret_intelligence.scan_file``), then reporting a finding ONLY
when the secret is no longer present in the current working tree.

That condition is the whole design:

  * a secret still in HEAD is skipped here -- the working-tree scan already
    reports it, so two engines would otherwise emit two rows for one defect;
  * a secret removed from HEAD is invisible to every other engine and is
    reported here, attributed to the OLDEST commit that carried it (the
    introduction, which is the commit an incident responder needs);
  * a non-git target returns ``available: False`` and costs one failed
    ``git rev-parse``.

Bounds (scan-time mandate): ``--max-commits`` (default 200, newest side of
``HEAD``, merges excluded), ``--max-files`` (default 600 file revisions),
a per-file byte cap, identical-blob caching so a file unchanged across many
commits is scanned once, and a subprocess timeout on every git call. The
result reports every bound that was hit via ``truncated`` so a short scan
can never be mistaken for a complete one.

Scope: only paths the secrets engine itself accepts (``scan_file`` enforces
the extension/config whitelist and the exclusion set), so this cannot widen
the secrets engine's reach -- it only adds the time dimension.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from scanner.secret_intelligence import scan_file

DEFAULT_MAX_COMMITS = 200
DEFAULT_MAX_FILES = 600
MAX_FILE_BYTES = 512_000
_GIT_TIMEOUT = 30


def _git(toplevel: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", toplevel, *args],
        capture_output=True, encoding="utf-8", errors="replace",
        timeout=_GIT_TIMEOUT, check=False)


def _repo_root(target: str) -> str | None:
    """Absolute work-tree root, or None when target is not inside a repo."""
    try:
        probe = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--show-toplevel"],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=_GIT_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if probe.returncode != 0:
        return None
    root = (probe.stdout or "").strip()
    return root or None


def _line_text(content: str, line_no) -> str:
    if not isinstance(line_no, int) or line_no < 1:
        return ""
    lines = content.splitlines()
    return lines[line_no - 1] if line_no <= len(lines) else ""


def scan_git_history(target: str,
                     max_commits: int = DEFAULT_MAX_COMMITS,
                     max_files: int = DEFAULT_MAX_FILES) -> dict:
    """Report secrets present in history but ABSENT from the working tree.

    Returns ``{"available", "commits_scanned", "files_scanned",
    "truncated", "findings"}``. ``available: False`` means the target is not
    a git work tree (or git itself is unavailable) -- not an error.
    """
    out: dict = {"available": False, "commits_scanned": 0,
                 "files_scanned": 0, "truncated": False, "findings": []}
    toplevel = _repo_root(target)
    if toplevel is None:
        return out
    out["available"] = True
    top = Path(toplevel)

    rev = _git(top, "rev-list", "--max-count=%d" % max_commits,
               "--no-merges", "HEAD")
    if rev.returncode != 0:
        return out
    commits = [c for c in (rev.stdout or "").split() if c]
    commits.reverse()  # oldest first: dedup keeps the introduction commit
    if not commits:
        return out
    # The commit bound itself is a truncation: say so rather than let a
    # short history scan read as a complete one.
    cnt = _git(top, "rev-list", "--count", "--no-merges", "HEAD")
    if cnt.returncode == 0:
        try:
            total = int((cnt.stdout or "0").strip())
        except ValueError:
            total = 0
        if total > max_commits:
            out["truncated"] = True

    tmp = Path(tempfile.mkdtemp(prefix="rsx_githist_"))
    seen_rows: set[tuple] = set()
    scanned_blobs: dict[str, bool] = {}
    files_scanned = 0
    try:
        for sha in commits:
            out["commits_scanned"] += 1
            dt = _git(top, "diff-tree", "--root", "--no-commit-id",
                      "--name-only", "-r", sha)
            if dt.returncode != 0:
                continue
            for rel in (dt.stdout or "").splitlines():
                rel = rel.strip()
                if not rel or files_scanned >= max_files:
                    if files_scanned >= max_files:
                        out["truncated"] = True
                        break
                    continue
                show = _git(top, "show", "%s:%s" % (sha, rel))
                if show.returncode != 0:
                    continue  # deleted at this commit, or a submodule/binary
                content = show.stdout or ""
                if len(content.encode("utf-8", "replace")) > MAX_FILE_BYTES:
                    out["truncated"] = True
                    continue
                blob = hashlib.sha256(
                    content.encode("utf-8", "replace")).hexdigest()
                if blob in scanned_blobs:
                    continue
                scanned_blobs[blob] = True
                files_scanned += 1
                out["files_scanned"] = files_scanned

                # Recreate the repo-relative path under a temp root so the
                # detector sees the same basename and extension whitelist it
                # would see on a real scan of that file.
                stage = tmp / rel
                try:
                    stage.parent.mkdir(parents=True, exist_ok=True)
                    stage.write_text(content, encoding="utf-8",
                                     errors="replace")
                except OSError:
                    continue
                try:
                    staged = scan_file(str(stage))
                except Exception:
                    continue
                if not staged:
                    continue

                current = top / rel
                current_text = None
                if current.is_file():
                    try:
                        current_text = current.read_text(
                            encoding="utf-8", errors="replace")
                    except OSError:
                        current_text = None

                for f in staged:
                    # The engine redacts known-signature snippets (policy:
                    # "[KNOWN SECRET REDACTED]"), so the snippet is what gets
                    # EMITTED, never the fingerprint. The fingerprint is the
                    # historical line itself, used only internally to decide
                    # whether the working tree still carries the secret.
                    emit = str(f.get("snippet") or "").strip()
                    secret = _line_text(content, f.get("line"))
                    if len(secret) < 6:
                        continue
                    # HEAD still carries it -> the working-tree scan owns it.
                    if current_text is not None and secret in current_text:
                        continue
                    key = (str(f.get("rule_id")), rel, secret)
                    if key in seen_rows:
                        continue
                    seen_rows.add(key)

                    real = current if current.exists() else None
                    shown = str(real) if real else (top / rel).as_posix()
                    row = dict(f)
                    row.update({
                        "file": shown,
                        "line": f.get("line"),
                        "evidence": "%s@%s:%s: %s" % (rel, sha[:12],
                                                      f.get("line"),
                                                      emit or "(redacted)"),
                        "group_key": "%s|%s|%s" % (f.get("rule_id"), rel, sha),
                        "commit": sha,
                        "commit_ref": sha[:12],
                        "in_git_history": True,
                        "description": (
                            "Secret committed in git history and no longer "
                            "present in the working tree; rotate the "
                            "credential and purge it from history."),
                        "engine": "scanner.git_history_secrets",
                    })
                    out["findings"].append(row)
            if files_scanned >= max_files:
                out["truncated"] = True
                break
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out
