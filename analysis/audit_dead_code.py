"""Dead-code audit: which live modules are never loaded by anything?

Why this exists
---------------
G-060. The integrity gate's "Backup location policy" tests only whether a
*filename* contains ``.bak`` or ``backup`` (dump/...CLEAN.ps1:226), so a stale
tree of ``.py`` copies sitting outside ``backup/`` is invisible to it - and a
module that nothing imports looks identical to live code when you read the
tree. This audit answers the question the gate cannot: *reachability*.

A file is dead when no root can reach it. Roots are the things actually
executed: ``main.py``, every test under ``tests/``, ``dump/`` helpers, and the
explicitly runnable analysis tooling (``benchmark_``, ``render_``, ``audit_``,
``inspect_``, ``compare_``, ``profile_``, ``instrument_``).

Imports followed
    static ``import a.b`` / ``from a.b import c``
    ``from pkg import submodule``       (resolves to pkg.submodule, not just pkg)
    relative ``from .sibling import x`` (resolved against the importing package)
    literal ``importlib.import_module`` / ``__import__`` / ``spec_from_file_location``
    runtime sibling loads ``Path(__file__).with_name("x.py")`` -- subprocess
    entry scripts (e.g. analysis/validation/aibom_generator_driver.py, run
    under an external interpreter) have no import edge and would otherwise
    look dead

Three traps this deliberately avoids, each of which previously made a LIVE
module look dead and would have caused it to be quarantined:
    * ``from pkg import submodule`` resolving only to ``pkg/__init__.py``
      (would have killed scanner/abom_v3.py, imported by the v3 acceptance test)
    * package ``__init__.py`` files being counted as unreachable
    * relative imports not resolving (would have killed core/rule_contract.py,
      reachable via core/analyzer.py:22 -> core/rule_contract_adapter.py:5)

Usage:
    python analysis/audit_dead_code.py            # report, exit 1 if any dead
    python analysis/audit_dead_code.py --json     # machine-readable
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
from collections import defaultdict, deque
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

SKIP_DIRS = {"backup", "dump", "Working folder", "__pycache__",
             ".git", ".venv",
             "node_modules", "reports", "quarantine"}

# Never a quarantine candidate regardless of reachability.  tools/ holds
# the operator-run diagnostics (T-0.7 moved them out of tests/); like
# tests/, they import the product but nothing imports them.
PROTECTED_PREFIX = ("backup", "dump", "Working folder", "integration_fixture_llm01",
                    "tests", "tools")

ROOT_NAME_RE = re.compile(
    r"^(benchmark_|render_|audit_|inspect_|compare_|profile_|instrument_)")

IMPORT_RE = re.compile(
    r"^\s*from\s+(?P<frm>[\w.]+)\s+import\s+(?P<names>[^\n#]*)"
    r"|^\s*import\s+(?P<mods>[\w., ]+)", re.M)
DYN_RE = re.compile(
    r"(?:importlib\.import_module|__import__|spec_from_file_location)"
    r"\s*\(\s*['\"]([^'\"]+)['\"]")
PATH_RE = re.compile(
    r"spec_from_file_location\([^,]+,\s*['\"]([^'\"]+\.py)['\"]")
WITH_NAME_RE = re.compile(r"with_name\(\s*['\"]([^'\"]+\.py)['\"]")


def _norm(p: Path) -> str:
    return str(p).replace("\\", "/")


def collect(root: Path) -> list[str]:
    out = []
    for p in sorted(root.rglob("*.py")):
        rel = _norm(p.relative_to(root))
        parts = rel.split("/")
        if any(s in SKIP_DIRS for s in parts[:-1]):
            continue
        if parts[0] in SKIP_DIRS:
            continue
        out.append(rel)
    return out


def audit(root: Path | None = None) -> dict:
    root = root or REPO
    files = collect(root)

    mod_of: dict[str, str] = {}
    for rel in files:
        if rel.endswith("/__init__.py"):
            mod = rel[: -len("/__init__.py")].replace("/", ".")
        else:
            mod = rel[:-3].replace("/", ".")
        mod_of[mod] = rel

    roots: set[str] = set()
    for rel in files:
        base = os.path.basename(rel)
        if rel == "main.py" or rel.startswith(("tests/", "tools/")):
            roots.add(rel)
        elif rel.split("/")[0] in (
            "backup", "dump", "Working folder", "integration_fixture_llm01"):
            roots.add(rel)
        elif ROOT_NAME_RE.match(base):
            roots.add(rel)

    edges: dict[str, set[str]] = defaultdict(set)
    for rel in files:
        try:
            t = io.open(root / rel, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        this_mod = rel[:-3].replace("/", ".")
        targets: set[str] = set()
        for m in IMPORT_RE.finditer(t):
            frm = m.group("frm")
            if frm:
                if frm.startswith("."):
                    dots = len(frm) - len(frm.lstrip("."))
                    rest = frm.lstrip(".")
                    pkg = this_mod.split(".")[:-1] if "." in this_mod else []
                    up = dots - 1
                    if up:
                        pkg = pkg[:-up] if up <= len(pkg) else []
                    base_pkg = ".".join(pkg)
                    frm = (f"{base_pkg}.{rest}" if base_pkg and rest
                           else (base_pkg or rest))
                targets.add(frm)
                for piece in re.split(r"[,(]", m.group("names") or ""):
                    piece = piece.strip().split(" as ")[0].strip()
                    if piece and piece != "*":
                        targets.add(f"{frm}.{piece}")
            else:
                for part in (m.group("mods") or "").split(","):
                    part = part.strip().split(" as ")[0].strip()
                    if part:
                        targets.add(part)
        for m in DYN_RE.finditer(t):
            targets.add(m.group(1))
        for m in PATH_RE.finditer(t):
            targets.add(m.group(1).replace("/", ".").removesuffix(".py"))
        for m in WITH_NAME_RE.finditer(t):
            # Path(__file__).with_name("x.py") loads a sibling file at
            # runtime -- subprocess entry scripts run under an external
            # interpreter have no import edge and would look dead.
            # pathlib resolves it against this file's own directory.
            sib = (rel.rsplit("/", 1)[0] + "/" + m.group(1)
                   if "/" in rel else m.group(1))
            edges[rel].add(sib)

        for name in targets:
            parts = name.split(".")
            for i in range(len(parts), 0, -1):
                cand = ".".join(parts[:i])
                if cand in mod_of:
                    edges[rel].add(mod_of[cand])
                    break

    # mod_of is keyed by MODULE NAME; nxt is a PATH. Testing `nxt in mod_of`
    # is therefore never true and the traversal silently stops at the roots.
    path_set = set(files)
    seen = set(roots)
    q = deque(roots)
    while q:
        cur = q.popleft()
        for nxt in edges.get(cur, ()):
            if nxt not in seen and nxt in path_set:
                seen.add(nxt)
                q.append(nxt)

    def is_init(rel: str) -> bool:
        return os.path.basename(rel) == "__init__.py"

    dead = sorted(
        rel for rel in files
        if rel not in seen
        and not is_init(rel)
        and not rel.startswith(PROTECTED_PREFIX)
    )
    return {
        "files": len(files),
        "roots": len(roots),
        "reachable": len(seen & set(files)),
        "unreachable_protected": sorted(
            rel for rel in files if rel not in seen and is_init(rel)),
        "dead": dead,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Dead-code reachability audit (G-060)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--root", default=None)
    args = ap.parse_args()

    res = audit(Path(args.root) if args.root else None)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"live .py files : {res['files']}")
        print(f"roots          : {res['roots']}")
        print(f"reachable      : {res['reachable']}")
        print(f"package inits excluded : {len(res['unreachable_protected'])}")
        print(f"DEAD (unreachable, not protected): {len(res['dead'])}")
        for rel in res["dead"]:
            print(f"   {rel}")
    return 1 if res["dead"] else 0


if __name__ == "__main__":
    sys.exit(main())
