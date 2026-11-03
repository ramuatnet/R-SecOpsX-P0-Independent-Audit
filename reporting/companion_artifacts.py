# -*- coding: utf-8 -*-
"""Companion files that must ship beside the report artifacts.

reporting/companion_artifacts.py

The NIST AML prose in Security_Report.pdf and the Excel AML sheet both cite
``gap_register.json (G-088)``. The register lives in the repo's gitignored
``reports/`` directory, so the citation pointed at a file the report reader
never received. ``ship_gap_register`` copies it next to the generated
artifacts; the renderers cite the shipped copy by bare filename.
"""
from __future__ import annotations

import shutil
from pathlib import Path

# Repo-root reports/gap_register.json: reporting/ is one level below root.
_DEFAULT_SOURCE = Path(__file__).resolve().parents[1] / "reports" / "gap_register.json"

_DEST_NAME = "gap_register.json"


def ship_gap_register(output_dir, source=None) -> bool:
    """Copy the gap register into ``output_dir``; True when a copy was written.

    A missing source is not an error: airgap checkouts and shallow clones may
    not carry the gitignored register, and the reports must still generate.
    The renderers' wording ("copied alongside this report") stays true
    either way -- the citation names the file, and when it exists it is
    beside the report; when it does not, no repo-internal path is quoted
    that the reader could not open anyway.
    """
    src = Path(source) if source is not None else _DEFAULT_SOURCE
    if not src.is_file():
        return False
    dest_dir = Path(output_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / _DEST_NAME
    # Same-file guard: shutil.copy2 raises SameFileError if a caller points
    # output_dir at the register's own directory.
    try:
        if dest.resolve() == src.resolve():
            return True
    except OSError:
        pass
    shutil.copy2(src, dest)
    return True
