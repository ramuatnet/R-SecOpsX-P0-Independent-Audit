"""FND-02: the one raw file walk for scanner/ and analysis/.

    walk(root, exts, ignore, max_bytes, follow_symlinks=False)
        -> Iterator[(path, size, mtime)]

Every former ``rglob`` / ``_iter_files`` raw walk in scanner/ and
analysis/ goes through this generator, so extension allow-lists, skip
sets, size caps and symlink policy are declared once per call instead of
being re-derived from ``Path.rglob``'s implicit behaviour (which has no
skip set, no size cap, no stat contract, and OS-dependent order).

Contract
  * yields FILES only, as ``(Path, size, mtime)`` -- one stat per file
    via ``os.DirEntry``;
  * deterministic depth-first order (siblings sorted by name), so
    downstream artifacts stay byte-stable (ground rule 10);
  * ``exts`` -- ``None`` means every file, otherwise a suffix allow-list
    (case-insensitive, leading dot: ``{".py", ".ts"}``);
  * ``ignore`` -- directory NAMES to skip at any depth (no path
    fragments); the caller declares policy, this module has no hidden
    default;
  * ``max_bytes`` -- skip files larger than this (``None`` = no cap);
  * ``follow_symlinks=False`` by default; when True, visited directory
    identities (device, inode) are tracked so a symlink loop cannot
    spin forever.

Not to be confused with ``core/file_index.py`` (T-0.2): that is the
scan-time index main() builds ONCE and every scan engine queries -- do
not walk a second time inside an indexed scan.  walk.py is the raw
generator for standalone scripts, fallback paths with no active index,
and any caller that only needs a traversal.  This module is stdlib-only
and imports nothing from the project, so core/, scanner/ and analysis/
can share it without cycle risk.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator, Optional

#: What walk() yields: file path, byte size, mtime (epoch seconds).
WalkItem = tuple[Path, int, float]


def walk(
    root: "Path | str",
    exts: Optional[Iterable[str]] = None,
    ignore: Iterable[str] = frozenset(),
    max_bytes: Optional[int] = None,
    follow_symlinks: bool = False,
) -> Iterator[WalkItem]:
    """Yield ``(path, size, mtime)`` for every matching file under ``root``.

    ``root`` may itself be a file: it is yielded alone when it matches
    the same filters (the single-file target case every engine used to
    special-case before calling rglob).
    """
    root_path = Path(root)
    ignore_set = frozenset(ignore)
    exts_set: Optional[set[str]] = (
        {e.lower() for e in exts} if exts is not None else None
    )

    if not root_path.is_dir():
        # Single file (or nonexistent -> stat raises -> empty).
        try:
            st = root_path.stat()
        except OSError:
            return
        if exts_set is not None and root_path.suffix.lower() not in exts_set:
            return
        if max_bytes is not None and st.st_size > max_bytes:
            return
        yield root_path, st.st_size, st.st_mtime
        return

    # Identity set only matters when symlinks are followed (a loop would
    # otherwise never terminate); plain walks prune nothing extra.
    seen_dirs: set[tuple[int, int]] = set()
    stack: list[Path] = [root_path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        subdirs: list[Path] = []
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=follow_symlinks):
                    if entry.name in ignore_set:
                        continue
                    if follow_symlinks:
                        est = entry.stat(follow_symlinks=True)
                        ident = (est.st_dev, est.st_ino)
                        if ident in seen_dirs:
                            continue  # symlink loop -- already visited
                        seen_dirs.add(ident)
                    subdirs.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=follow_symlinks):
                    continue
                if exts_set is not None:
                    suffix = Path(entry.name).suffix.lower()
                    if suffix not in exts_set:
                        continue
                st = entry.stat(follow_symlinks=follow_symlinks)
            except OSError:
                continue
            if max_bytes is not None and st.st_size > max_bytes:
                continue
            yield Path(entry.path), st.st_size, st.st_mtime
        # Push reversed so the sorted first sibling is walked first:
        # pre-order DFS with lexicographic siblings (deterministic).
        stack.extend(reversed(subdirs))
