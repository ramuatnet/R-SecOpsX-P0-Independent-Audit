"""Regression guard for G-060: nothing unreachable may sit in the live tree.

The integrity gate's backup policy (dump/...CLEAN.ps1:226) tests only whether a
*filename* contains `.bak` or `backup`, so it cannot see a directory of stale
`.py` copies outside `backup/` - which is exactly how
`R-SecOpsX_V11_Remaining_Intelligence_v1/` survived there carrying a
pre-G-041 `core/owasp_mappings.py` (1492 bytes against 12295 live). This test
enforces reachability instead of a filename pattern, so a reintroduced dead
tree fails on every run rather than whenever someone happens to notice.

It also pins that quarantine is one-way: a quarantined module must not be
imported by live code, otherwise the two copies would drift apart.
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from analysis.audit_dead_code import audit  # noqa: E402


def test_no_unreachable_module_in_the_live_tree():
    res = audit(REPO)
    assert res["dead"] == [], (
        "these files are unreachable from main.py/tests/dump/tooling roots - "
        "either import them, or move them to quarantine/:\n  "
        + "\n  ".join(res["dead"])
    )


def test_reachability_audit_actually_runs_on_this_tree():
    # Guards the guard: a bug that made the audit find nothing would make the
    # test above vacuously green, so assert it sees a real tree.
    res = audit(REPO)
    assert res["files"] > 200, res
    assert res["roots"] > 50, res
    assert res["reachable"] > 200, res


def test_quarantine_is_never_imported_by_live_code():
    """A quarantined module must not be imported, or the two copies drift.

    Matches import statements and file paths only - not the bare word, since
    analysis/audit_dead_code.py legitimately names the directory it skips.
    """
    import re
    ref = re.compile(r"(?:^|\s)(?:from|import)\s+quarantine\b"
                     r"|quarantine[/\\][\w .]+\.py")
    offenders = []
    for p in REPO.rglob("*.py"):
        if any(seg in p.parts for seg in
               ("backup", "dump", "Working folder",
                "R-SecOpsX_V11_Evidence_Error_Cleanup_v1",
                "quarantine", "__pycache__")):
            continue
        if p.name == "test_v11_dead_code_guard.py":
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if ref.search(text):
            offenders.append(str(p.relative_to(REPO)).replace("\\", "/"))
    assert not offenders, (
        "live code imports or paths into quarantine/ - move the file back "
        f"instead of importing across the boundary: {offenders}"
    )
    # Sanity: the guard must scan a real tree, or it passes vacuously.
    assert len(list(REPO.rglob("*.py"))) > 200


def test_quarantine_manifest_records_every_move():
    manifest = REPO / "quarantine" / "MANIFEST.txt"
    assert manifest.exists(), "quarantine/MANIFEST.txt must document every move"
    text = manifest.read_text(encoding="utf-8")
    # The two highest-risk moves must be traceable to their original path.
    assert "core/idoranalyzer.py" in text
    assert "R-SecOpsX_V11_Remaining_Intelligence_v1" in text
    assert "scanner/business_logic_patterns.py" in text
    assert "Nothing here was deleted." in text


def test_the_modules_that_nearly_got_quarantined_are_still_live():
    """Regression pin for the three audit bugs.

    `from pkg import submodule` resolving only to pkg/__init__.py made
    scanner/abom_v3.py look dead despite test_abom_v3_canonical_acceptance
    importing it; relative imports made core/rule_contract.py look dead
    despite core/analyzer.py:22 -> core/rule_contract_adapter.py:5.
    """
    res = audit(REPO)
    assert "scanner/abom_v3.py" not in res["dead"]
    assert "core/rule_contract.py" not in res["dead"]
    assert (REPO / "scanner" / "abom_v3.py").exists()
    assert (REPO / "core" / "rule_contract.py").exists()
    assert (REPO / "core" / "__init__.py").exists()
    assert (REPO / "reporting" / "__init__.py").exists()
