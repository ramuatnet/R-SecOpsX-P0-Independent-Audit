# -*- coding: utf-8 -*-
r"""G-016 git-history secrets (2026-10-23).

Red-first evidence: the module under test did not exist when these tests
were written -- running them before scanner/git_history_secrets.py was
added fails on import (ModuleNotFoundError), which is the red state for a
new engine. The behavioural contract proven here:

  * a credential committed and then removed from the working tree is
    reported, attributed to the OLDEST commit carrying it;
  * a credential still present in the working tree is NOT reported here
    (the working-tree scan owns it -- two engines, one row);
  * a clean history stays dark, a non-git target degrades to
    ``available: False`` (never an error), and repeated appearances of one
    secret dedupe to the introduction commit.

Secret used: AKIA + 16 alnum (the engine's own AWS_ACCESS_KEY shape), with
no decoy word so confidence stays High.
"""
import subprocess
from pathlib import Path

import pytest

from scanner.git_history_secrets import scan_git_history

AWS_KEY = "AKIA7XK4P9QW2MNB8VTR"


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, encoding="utf-8", errors="replace",
        timeout=60, check=False)
    if res.returncode != 0:
        raise AssertionError("git %s failed: %s" % (" ".join(args),
                                                    res.stderr))
    return (res.stdout or "").strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "gate@rsecopsx.test")
    _git(repo, "config", "user.name", "Gate")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def _commit(repo: Path, name: str, text: str, message: str) -> str:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def test_removed_secret_reported_at_introduction_commit(tmp_path):
    repo = _repo(tmp_path)
    first = _commit(
        repo, "app.py",
        "AWS_ACCESS_KEY_ID = \"%s\"\n" % AWS_KEY,
        "add credential")
    _commit(repo, "app.py",
            "AWS_ACCESS_KEY_ID = None  # moved to the vault\n",
            "remove credential")

    result = scan_git_history(str(repo))
    assert result["available"] is True
    rows = [f for f in result["findings"]
            if f.get("rule_id") == "AWS_ACCESS_KEY"
            and str(f.get("file", "")).endswith("app.py")]
    assert rows, result["findings"]
    assert rows[0]["commit"] == first
    assert rows[0]["in_git_history"] is True
    # Evidence keeps the engine's own redaction policy: a report must not
    # re-print the raw credential just because history is the source.
    assert "[KNOWN SECRET REDACTED]" in str(rows[0].get("evidence"))


def test_secret_still_in_working_tree_is_not_reported_here(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "app.py",
            "AWS_ACCESS_KEY_ID = \"%s\"\n" % AWS_KEY,
            "add credential")

    result = scan_git_history(str(repo))
    assert result["available"] is True
    assert not [f for f in result["findings"]
                if f.get("rule_id") == "AWS_ACCESS_KEY"], \
        result["findings"]


def test_clean_history_stays_dark(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "app.py", "def handler():\n    return 42\n", "init")

    result = scan_git_history(str(repo))
    assert result["available"] is True
    assert result["findings"] == []
    assert result["truncated"] is False


def test_non_git_target_degrades_without_error(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text("x = 1\n", encoding="utf-8")

    result = scan_git_history(str(plain))
    assert result["available"] is False
    assert result["findings"] == []


def test_reintroduced_secret_dedupes_to_oldest_commit(tmp_path):
    repo = _repo(tmp_path)
    first = _commit(
        repo, "app.py",
        "AWS_ACCESS_KEY_ID = \"%s\"\n" % AWS_KEY,
        "add credential")
    _commit(repo, "app.py", "AWS_ACCESS_KEY_ID = None\n", "remove")
    _commit(repo, "app.py",
            "AWS_ACCESS_KEY_ID = \"%s\"\n" % AWS_KEY,
            "re-add")
    _commit(repo, "app.py", "AWS_ACCESS_KEY_ID = None\n", "remove again")

    result = scan_git_history(str(repo))
    rows = [f for f in result["findings"]
            if f.get("rule_id") == "AWS_ACCESS_KEY"]
    assert len(rows) == 1, [f.get("commit") for f in rows]
    assert rows[0]["commit"] == first


def test_commit_bound_reports_truncation(tmp_path):
    repo = _repo(tmp_path)
    for i in range(5):
        _commit(repo, "app.py", "value = %d\n" % i, "c%d" % i)

    result = scan_git_history(str(repo), max_commits=2)
    assert result["commits_scanned"] == 2
    assert result["truncated"] is True
