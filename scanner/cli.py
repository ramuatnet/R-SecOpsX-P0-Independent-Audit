"""R-SecOpsX scan CLI — the ftasks test-policy entry point (ftasks.md §1).

    python -m scanner.cli --target juice-shop-git --formats pdf,json,xlsx --out /tmp/r

Thin wrapper around main.py's pipeline so the three-command policy (scan,
parity, audit) has one stable interface:

  * ``--target`` accepts a real directory path or a bare target name; a
    name is resolved against the working directory, the repo root and the
    sibling ``prodtest/`` checkout (where the canonical validation targets
    live).  No absolute path literals — the sibling is derived from this
    file's location.
  * ``--formats`` maps onto main's switches: omitting ``pdf`` adds
    ``--no-pdf``, omitting ``xlsx`` adds ``--no-excel``.  ``json`` has no
    off switch (clean_report.json is the canonical artifact every other
    format is derived from), so requesting a json-less run is an error
    rather than a silent extra file.
  * ``--out`` becomes ``--output-dir``.

The scan itself is main()'s, byte for byte — this module only resolves
arguments and forwards the exit code.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_SUPPORTED = ("pdf", "json", "xlsx")


def resolve_target(name: str) -> Path:
    """Resolve ``--target``: an existing path first, then known layouts.

    Tried in order: the value as given (absolute or cwd-relative), a
    directory beside the working directory, one beside the repo root, and
    ``<repo-parent>/prodtest/<name>`` — the sibling checkout that holds
    the canonical validation targets (juice-shop-git, ...).
    """
    given = Path(name)
    if given.is_dir():
        return given.resolve()
    tried = [given]
    for candidate in (Path.cwd() / name,
                      REPO_ROOT / name,
                      REPO_ROOT.parent / "prodtest" / name):
        tried.append(candidate)
        if candidate.is_dir():
            return candidate.resolve()
    raise SystemExit(
        "scanner.cli: target not found as a path or name: %r (tried: %s)"
        % (name, ", ".join(str(p) for p in tried))
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scanner.cli",
        description="R-SecOpsX scan entry point (ftasks test policy).",
    )
    parser.add_argument(
        "--target", required=True,
        help="directory to scan, or a target name resolved against "
             "cwd / repo root / the sibling prodtest checkout",
    )
    parser.add_argument(
        "--formats", default=",".join(_SUPPORTED),
        help="comma-separated list from {%s} (default: all)"
             % ",".join(_SUPPORTED),
    )
    parser.add_argument(
        "--out", required=True,
        help="output directory for the artifacts (main --output-dir)",
    )
    args = parser.parse_args(argv)

    formats = {f.strip().lower() for f in args.formats.split(",") if f.strip()}
    unknown = formats - set(_SUPPORTED)
    if unknown:
        raise SystemExit(
            "scanner.cli: unknown formats: %s (supported: %s)"
            % (", ".join(sorted(unknown)), ", ".join(_SUPPORTED))
        )
    if "json" not in formats:
        raise SystemExit(
            "scanner.cli: json is mandatory — clean_report.json has no "
            "off switch; request pdf,xlsx or all three"
        )

    target = resolve_target(args.target)
    out = Path(args.out)

    cmd = [sys.executable, str(REPO_ROOT / "main.py"), str(target),
           "--output-dir", str(out)]
    if "pdf" not in formats:
        cmd.append("--no-pdf")
    if "xlsx" not in formats:
        cmd.append("--no-excel")
    return subprocess.call(cmd, cwd=str(REPO_ROOT))


if __name__ == "__main__":
    sys.exit(main())
