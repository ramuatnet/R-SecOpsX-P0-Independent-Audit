"""T-8.1 watch mode -- incremental re-scan of changed files only.

The never-a-full-tree-re-walk invariant (task.md section 11):

  * ``prime()`` consumes the ONE tree walk (``core.file_index.index_for``
    -- called exactly once through the module attribute so the acceptance
    spy sees it) and scans every indexed file once to establish the
    baseline.  Same T-0.2 precedent as ``scan_directory``: "consume the
    one walk's index; no re-walk of the tree here."
  * ``apply(events)`` re-scans ONLY the paths named in the event set,
    straight from the event dicts -- it never touches the tree index,
    never enumerates a directory.  A deleted event does not scan at all:
    its baseline rows are released as removals.
  * diffs are per-key ``(rule_id, file, line)`` -- the same identity the
    T-7.2 feedback store uses -- producing added / removed / changed
    (``{before, after}``) lists with a human explanation per row, and
    the baseline is updated after every apply so a re-flush of unchanged
    content reports zero deltas (no duplicate adds).

``default_scan_fn`` mirrors ``scanner.sast.scan_directory``'s per-file
composition exactly (regex ``scan_file`` + taint ``analyze_file`` +
G-037 shell-sink gate when taint ran + AST validation, each best-effort
the same way), so a watch-mode file produces the same rows a full scan
would.  Injected ``scan_fn`` in tests records the exact paths asked for.

All skips are annotated, never silently dropped (ground rule 3): invalid
events carry ``event_*`` reasons, a scan that raises carries
``scan_failed_<ExcClass>`` and leaves the baseline untouched (fail-open,
consistent with the engine's own error posture).

No I/O happens at import; ``prime()`` is the only walker and it is
called explicitly.
"""
from __future__ import annotations

from typing import Any, Callable

from core import file_index  # module-attribute binding: the spy must see
# index_for looked up ON the module at call time (a `from ... import
# index_for` would bind the original and hide the monkeypatch).

from analysis.watch.model import EVENT_KINDS, SCHEMA

# Diff identity: (rule_id, file, line) -- identical to the T-7.2
# feedback store's key so watch deltas and feedback state agree.
_FindingKey = tuple


def _key(row: dict) -> _FindingKey:
    return (row.get("rule_id"), row.get("file"), row.get("line"))


def default_scan_fn(filepath: str) -> "list[dict]":
    """The scan_directory per-file composition, for one file.

    scan_file + taint analyze_file + G-037 gate (only when taint ran) +
    AST validation (best effort) -- probe-verified to match the full
    scan's rows for the same path.
    """
    from scanner.sast import scan_file

    results = scan_file(filepath)
    taint_ok = False
    try:
        from scanner.taint_engine import analyze_file as taint_analyze
        results = results + taint_analyze(filepath)
        taint_ok = True
    except Exception:
        pass
    if taint_ok:
        from scanner.sast import _gate_shell_sink_findings
        results = _gate_shell_sink_findings(results)
    try:
        from scanner.ast_validators import apply_ast_validation
        results = apply_ast_validation(results, filepath)
    except Exception:
        pass
    return results


def _explain(kind: str, path: str, added: "list", removed: "list",
             changed: "list", scanned: bool) -> str:
    base = (f"{kind} event on {path}: "
            f"{len(added)} added, {len(removed)} removed, "
            f"{len(changed)} changed vs baseline")
    if not scanned:
        return base + " (deleted path -- baseline released, not re-scanned)"
    if not (added or removed or changed):
        return base + "; file re-scanned, findings unchanged"
    return base + " (per-key diff on rule_id+file+line)"


class IncrementalScanner:
    """Prime once, then re-scan only what the events say changed.

    ``target`` is the scan root (str or Path).  ``scan_fn`` maps an
    absolute path string -> engine rows; defaults to
    :func:`default_scan_fn` (the full-engine composition).
    """

    def __init__(self, target, scan_fn: "Callable[[str], list[dict]] | None"
                 = None) -> None:
        self.target = str(target)
        self.scan_fn = scan_fn if scan_fn is not None else default_scan_fn
        # path -> {finding key: row}   (the per-file baseline)
        self._baseline: "dict[str, dict[_FindingKey, dict]]" = {}
        self._primed = False
        self._files: "list[str]" = []        # the one walk's scannable set
        # cumulative across applies, surfaced by document()
        self._deltas: "list[dict]" = []
        self._all_skips: "list[dict]" = []
        self._changed: "set[str]" = set()
        self._cumulative = {"flushes": 0, "scans": 0, "added": 0,
                            "removed": 0, "changed_findings": 0,
                            "files_scanned_in": 0}

    # -- prime: THE one walk -------------------------------------------
    def prime(self) -> "list[str]":
        """Walk the tree exactly once and baseline every indexed file.

        Returns the indexed file list.  Idempotent: a second prime()
        never walks again (the walk budget is one per scanner).
        """
        if self._primed:
            return list(self._files)
        from scanner.sast import _should_scan
        # Module-attribute call: exactly what the spy counts.  Looked up
        # on `file_index` at call time so monkeypatching is observable.
        idx = file_index.index_for(self.target)
        files = [str(p) for p in idx.files(pred=_should_scan)]
        for fp in files:
            try:
                rows = self.scan_fn(fp)
            except Exception as exc:  # annotated, never silent
                self._all_skips.append({
                    "reason": f"scan_failed_{type(exc).__name__}",
                    "path": fp,
                    "phase": "prime",
                    "detail": str(exc)[:300],
                })
                continue
            self._baseline[fp] = {_key(r): r for r in rows or []}
        self._files = files
        self._primed = True
        return list(files)

    # -- apply: changed files only --------------------------------------
    def apply(self, events: "list[Any]") -> dict:
        """Re-scan exactly the paths the events name; never the tree.

        Returns the delta document::

            {schema, files: [{path, kind, added, removed, changed,
                              explanation}], skips: [...],
             stats: {flushes, scans, added, removed, changed_findings,
                     files_scanned_in}}

        ``stats`` here is per-apply; :meth:`document` reports cumulative
        numbers.  Invalid events become annotated skips; a deleted path
        releases its baseline rows without any scan; the baseline is
        updated so the next flush of unchanged content diffs to zero.
        """
        if not self._primed:
            # Honest ordering: a scanner that never primed has no
            # baseline and would mis-report every finding as new.
            raise RuntimeError(
                "prime() must run before apply() -- apply never walks, "
                "it can only diff against the primed baseline")
        skips: "list[dict]" = []
        valid: "dict[str, str]" = {}   # path -> latest kind (coalesced)
        for ev in events:
            if not isinstance(ev, dict):
                skips.append({"reason": "event_not_object",
                              "event": repr(ev)[:200]})
                continue
            path = ev.get("path")
            if not isinstance(path, str) or not path:
                skips.append({"reason": "event_missing_path",
                              "event": repr(ev)[:200]})
                continue
            kind = ev.get("kind")
            if kind not in EVENT_KINDS:
                skips.append({"reason": "event_kind_unknown", "path": path,
                              "kind": repr(kind)[:80]})
                continue
            valid[path] = kind  # latest event for this path wins
        rows: "list[dict]" = []
        stats = {"flushes": 1, "scans": 0, "added": 0, "removed": 0,
                 "changed_findings": 0, "files_scanned_in": 0}
        for path in sorted(valid):
            kind = valid[path]
            if kind == "deleted":
                old = self._baseline.pop(path, {})
                removed = list(old.values())
                row = {"path": path, "kind": kind, "added": [],
                       "removed": removed, "changed": [],
                       "explanation": _explain(kind, path, [], removed,
                                               [], scanned=False)}
                stats["removed"] += len(removed)
                rows.append(row)
                self._changed.add(path)
                continue
            try:
                new_rows = self.scan_fn(path)
            except Exception as exc:  # annotated; baseline untouched
                skips.append({
                    "reason": f"scan_failed_{type(exc).__name__}",
                    "path": path,
                    "detail": str(exc)[:300],
                })
                continue
            stats["scans"] += 1
            stats["files_scanned_in"] += 1
            new_map = {_key(r): r for r in new_rows or []}
            old_map = self._baseline.get(path, {})
            added = [r for k, r in new_map.items() if k not in old_map]
            removed = [r for k, r in old_map.items() if k not in new_map]
            changed = [{"before": old_map[k], "after": new_map[k]}
                       for k in sorted(set(old_map) & set(new_map),
                                       key=repr)
                       if old_map[k] != new_map[k]]
            # baseline updated here -- the anti-duplicate-add contract
            self._baseline[path] = new_map
            stats["added"] += len(added)
            stats["removed"] += len(removed)
            stats["changed_findings"] += len(changed)
            rows.append({"path": path, "kind": kind, "added": added,
                         "removed": removed, "changed": changed,
                         "explanation": _explain(kind, path, added,
                                                 removed, changed,
                                                 scanned=True)})
            self._changed.add(path)
        delta = {"schema": SCHEMA, "files": rows, "skips": skips,
                 "stats": stats}
        self._deltas.append(delta)
        self._all_skips.extend(skips)
        for k in self._cumulative:
            self._cumulative[k] += stats.get(k, 0)
        return delta

    # -- document ---------------------------------------------------------
    def note_skip(self, row: dict) -> None:
        """Record a caller-side skip (CLI-level: absent events file,
        watcher disclosure) so it rides the document like every other
        skip -- annotating, never silently dropping."""
        self._all_skips.append(row)

    def document(self, as_of: "str | None" = None) -> dict:
        """The artifact: every per-file delta row + cumulative stats.

        ``deltas`` is FLAT -- one row per (event, file) across all
        applies, each carrying its own ``explanation`` (the CLI asserts
        it).  ``changed_files`` is the union of paths that ever
        appeared in a delta row (what changed over this watch session).
        """
        return {
            "schema": SCHEMA,
            "as_of": as_of,
            "deltas": [row for d in self._deltas for row in d["files"]],
            "stats": dict(self._cumulative),
            "skips": list(self._all_skips),
            "changed_files": sorted(self._changed),
        }

    # -- introspection ----------------------------------------------------
    @property
    def files(self) -> "list[str]":
        """The one walk's file list (after prime)."""
        return list(self._files)

    @property
    def primed(self) -> bool:
        return self._primed
