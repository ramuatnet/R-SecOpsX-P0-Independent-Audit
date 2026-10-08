from __future__ import annotations

import os
from pathlib import Path


def to_report_path(file_path: str, target_root: str) -> str:
    try:
        root = Path(target_root).resolve()
        path = Path(file_path).resolve()
        rel = path.relative_to(root)
        return rel.as_posix()
    except (ValueError, OSError, RuntimeError):
        return str(file_path)
def file_name(file_path: str) -> str:
    return Path(file_path).name
