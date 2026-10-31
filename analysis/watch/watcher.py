"""T-8.1 watch mode -- OS-native file watching + a disclosed poll fallback.

Native paths (stdlib/ctypes only -- no required runtime deps, offline by
construction):

  * Windows: ``ReadDirectoryChangesW`` via ctypes on a background thread
    (blocking call + ``CancelIoEx`` on close), buffers drained by
    ``poll()`` and decoded by :func:`parse_read_directory_changes`.
  * Linux/other POSIX: ``inotify`` via ctypes, decoded by
    :func:`parse_inotify_events`.  Any init failure falls through to the
    poll fallback (never an exception to the caller).
  * macOS: no FSEvents wiring -- falls back to poll, disclosed.

Fallback: :class:`PollWatcher` stats ONLY the initial file list.  It
never re-enumerates a directory (the walk budget stays one -- the same
invariant as prime()), so creations outside the initial list are
invisible until the next prime; that blind spot and the other three are
listed in :data:`POLL_LIMITATIONS` and returned by ``disclosure()``
(ground rule: disclose, never be silently wrong).

The two buffer decoders are pure functions pinned by tests off-platform:
``parse_read_directory_changes(data, root, collect_skips=False)`` returns
a bare event list by default and an ``(events, skips)`` tuple when
``collect_skips=True``; same shape for ``parse_inotify_events``.  Unknown
action codes / masks / watch descriptors become annotated skips -- never
raised, never silently dropped.
"""
from __future__ import annotations

import os
import queue
import struct
import sys
import threading
import time

POLL_LIMITATIONS = (
    "poll fallback only stats the initial file list: creation of files "
    "outside that list is invisible until the next prime (no directory "
    "re-enumeration -- the walk budget stays one)",
    "event latency floor = interval_ms (the stat cadence)",
    "signature is (mtime_ns, size): a same-size write inside one mtime "
    "tick can be missed",
    "renames are not paired; a rename of a listed file surfaces as a "
    "delete (plus a create if the new name is later listed)",
    "no FSEvents wiring on macOS, and inotify is only attempted on "
    "POSIX hosts where the ctypes init succeeds -- every other host "
    "runs this disclosed poll path",
)

# FILE_ACTION_* codes from FILE_NOTIFY_INFORMATION.
_RDCW_ACTIONS = {
    1: "created",    # FILE_ACTION_ADDED
    2: "deleted",    # FILE_ACTION_REMOVED
    3: "modified",   # FILE_ACTION_MODIFIED
    4: "deleted",    # FILE_ACTION_RENAMED_OLD_NAME: the old path no
    # longer exists; mapping it to deleted releases that path's baseline.
    # The new name arrives as action 5 -> created, so a rename becomes
    # delete+create -- correct for scanning without pairing state.
    5: "created",    # FILE_ACTION_RENAMED_NEW_NAME
}

# inotify masks -> kind (checked in this order; a mask may combine bits).
_IN_OVERFLOW = 0x4000   # IN_Q_OVERFLOW
_IN_CREATED = 0x100 | 0x80      # IN_CREATE | IN_MOVED_TO
_IN_DELETED = 0x200 | 0x400 | 0x40   # IN_DELETE | IN_DELETE_SELF |
# IN_MOVED_FROM (unpaired move-away: the path is gone from the tree)
_IN_MODIFIED = 0x2 | 0x4 | 0x8  # IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE
_IN_MOVED_SELF = 0x800          # IN_MOVE_SELF
_IN_WATCH_MASK = (0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x200 |
                  0x400 | 0x800 | _IN_OVERFLOW)


def parse_read_directory_changes(data: bytes, root: str,
                                 collect_skips: bool = False):
    """Decode a FILE_NOTIFY_INFORMATION buffer into watch events.

    Each entry: ``<III`` (NextEntryOffset, Action, FileNameLength) then
    the utf-16-le name; entries advance by NextEntryOffset (0 = last).
    Unknown actions are annotated ``rdcw_action_<n>_unsupported`` when
    ``collect_skips`` is set; with the default they are omitted (the
    caller opted out of skips) -- the native watcher always collects.
    """
    events: "list[dict]" = []
    skips: "list[dict]" = []
    off, size = 0, len(data)
    while off + 12 <= size:
        next_off, action, name_len = struct.unpack_from("<III", data, off)
        end = off + 12 + name_len
        if end > size:
            skips.append({"reason": "rdcw_truncated_entry", "offset": off})
            break
        raw = data[off + 12:end]
        name = raw.decode("utf-16-le", "replace").split("\x00", 1)[0]
        path = os.path.join(root, name) if name else root
        kind = _RDCW_ACTIONS.get(action)
        if kind is None:
            skips.append({"reason": f"rdcw_action_{action}_unsupported",
                          "path": path})
        else:
            events.append({"path": path, "kind": kind})
        if next_off == 0:
            break
        if next_off < 12:
            skips.append({"reason": "rdcw_bad_next_offset",
                          "offset": off, "next_off": next_off})
            break
        off += next_off
    if not (collect_skips):
        return events
    return events, skips


def parse_inotify_events(data: bytes, wd_to_path: "dict[int, str]",
                         collect_skips: bool = False):
    """Decode raw inotify frames into watch events.

    Each frame: native ``iIII`` (wd, mask, cookie, len) then the utf-8
    name padded into ``len`` bytes.  ``IN_Q_OVERFLOW`` becomes an
    ``inotify_overflow`` skip (the kernel dropped events -- that must be
    visible, ground rule 3); unknown masks and unknown watch descriptors
    are annotated the same way.  Same return-shape contract as
    :func:`parse_read_directory_changes`.
    """
    events: "list[dict]" = []
    skips: "list[dict]" = []
    off, size = 0, len(data)
    while off + 16 <= size:
        wd, mask, _cookie, name_len = struct.unpack_from("iIII", data, off)
        end = off + 16 + name_len
        if end > size:
            skips.append({"reason": "inotify_truncated_entry", "offset": off})
            break
        name = data[off + 16:end].split(b"\x00", 1)[0].decode(
            "utf-8", "replace")
        off = end
        if mask & _IN_OVERFLOW:
            skips.append({"reason": "inotify_overflow",
                          "detail": "kernel event queue overflowed; "
                                    "events were dropped upstream"})
            continue
        base = wd_to_path.get(wd)
        if base is None:
            skips.append({"reason": f"inotify_wd_unknown_{wd}",
                          "mask": hex(mask)})
            continue
        if mask & _IN_CREATED:
            kind = "created"
        elif mask & _IN_DELETED:
            kind = "deleted"
        elif mask & _IN_MODIFIED:
            kind = "modified"
        elif mask & _IN_MOVED_SELF:
            kind = "renamed"
        else:
            skips.append({"reason": f"inotify_mask_{mask:#x}_unsupported",
                          "path": os.path.join(base, name) if name
                          else base})
            continue
        path = os.path.join(base, name) if name else base
        events.append({"path": path, "kind": kind})
    if not (collect_skips):
        return events
    return events, skips


class PollWatcher:
    """Stat-only fallback over a FIXED file list.  Never walks.

    First ``poll()`` records baseline signatures and returns no events;
    later polls diff ``(mtime_ns, size)`` per listed path.  ``interval_ms``
    gates the stat cadence; an explicit ``now`` wins over ``now_fn``.
    """

    source_name = "poll_fallback"

    def __init__(self, files, interval_ms: int = 250,
                 now_fn=time.time) -> None:
        self._files = [str(f) for f in (files or [])]
        self.interval_ms = max(0, int(interval_ms))
        self.now_fn = now_fn
        self._sig: "dict[str, tuple | None]" = {}
        self._primed = False
        self._last: "float | None" = None
        self._closed = False

    def _stat(self, path: str):
        try:
            st = os.stat(path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def poll(self, now: "float | None" = None) -> "list[dict]":
        if self._closed:
            return []
        now = self.now_fn() if now is None else float(now)
        if (self._last is not None
                and (now - self._last) * 1000.0 < self.interval_ms):
            return []
        self._last = now
        events: "list[dict]" = []
        if not self._primed:
            for p in self._files:
                self._sig[p] = self._stat(p)
            self._primed = True
            return events
        for p in self._files:
            sig = self._stat(p)
            old = self._sig.get(p)
            if sig is None and old is not None:
                events.append({"path": p, "kind": "deleted"})
            elif sig is not None and old is None:
                events.append({"path": p, "kind": "created"})
            elif sig is not None and old is not None and sig != old:
                events.append({"path": p, "kind": "modified"})
            self._sig[p] = sig
        return events

    def disclosure(self) -> "list[dict]":
        return [{"source": self.source_name, "reason": r}
                for r in POLL_LIMITATIONS]

    def close(self) -> None:
        self._closed = True


class _ReadDirectoryChangesWatcher:
    """Windows native watcher: ReadDirectoryChangesW on a worker thread.

    The thread blocks in the (synchronous) native call; ``close()`` sets
    the stop flag and issues ``CancelIoEx`` so the pending read returns,
    then closes the handle.  Construction raises on any failure --
    :func:`open_watcher` catches it and falls back to poll (disclosed).
    """

    source_name = "read_directory_changes_w"

    def __init__(self, target: str) -> None:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                    wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD,
                                    wintypes.HANDLE]
        k32.ReadDirectoryChangesW.restype = wintypes.BOOL
        # Real signature is EIGHT parameters: the fifth is dwNotifyFilter
        # (omitting it made ctypes see 7 and reject the 8-arg call).
        k32.ReadDirectoryChangesW.argtypes = [
            wintypes.HANDLE,    # hDirectory
            wintypes.LPVOID,    # lpBuffer
            wintypes.DWORD,     # nBufferLength
            wintypes.BOOL,      # bWatchSubtree
            wintypes.DWORD,     # dwNotifyFilter
            wintypes.LPDWORD,   # lpBytesReturned
            wintypes.LPVOID,    # lpOverlapped
            wintypes.LPVOID]    # lpCompletionRoutine
        k32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.CancelIoEx.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL

        invalid = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
        handle = k32.CreateFileW(
            target,
            0x0001,                 # FILE_LIST_DIRECTORY
            0x00000007,             # FILE_SHARE_READ|WRITE|DELETE
            None,
            3,                      # OPEN_EXISTING
            0x02000000,             # FILE_FLAG_BACKUP_SEMANTICS
            None)
        if handle in (None, 0, invalid):
            raise OSError(f"CreateFileW failed for {target!r}")
        self._k32 = k32
        self._handle = handle
        self._root = target
        self._q: "queue.Queue[bytes]" = queue.Queue()
        self._stop = threading.Event()
        self._closed = False
        self._skips: "list[dict]" = []   # per-instance, never shared
        # 0x5F = FILE_NAME|DIR_NAME|ATTRIBUTES|SIZE|LAST_WRITE|CREATION
        self._filter = 0x5F
        self._thread = threading.Thread(target=self._loop,
                                        name="rsx-watch-rdcw",
                                        daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        import ctypes
        from ctypes import wintypes
        buf = ctypes.create_string_buffer(1 << 16)
        ret = wintypes.DWORD()
        while not self._stop.is_set():
            ret.value = 0
            ok = self._k32.ReadDirectoryChangesW(
                self._handle, buf, ctypes.sizeof(buf), True,
                self._filter, ctypes.byref(ret), None, None)
            if not ok or self._stop.is_set():
                return
            if ret.value == 0:
                # TRUE with zero bytes = overflow (kernel dropped some):
                # annotated, not silently ignored (ground rule 3).
                self._q.put(b"")
                continue
            self._q.put(bytes(buf.raw[:ret.value]))

    def poll(self, now: "float | None" = None) -> "list[dict]":
        events: "list[dict]" = []
        while True:
            try:
                raw = self._q.get_nowait()
            except queue.Empty:
                return events
            if not raw:
                # An overflow marker (TRUE with zero bytes): expose as
                # an annotated skip via disclosure() -- ground rule 3.
                self._skips.append({"reason": "rdcw_buffer_overflow",
                                    "detail": "native buffer overflowed; "
                                              "some events were dropped"})
                continue
            try:
                evs, skips = parse_read_directory_changes(
                    raw, root=self._root, collect_skips=True)
            except Exception as exc:  # never kill the drain loop
                self._skips.append({
                    "reason": f"rdcw_parse_{type(exc).__name__}",
                    "detail": str(exc)[:300]})
                continue
            events.extend(evs)
            self._skips.extend(skips)

    def disclosure(self) -> "list[dict]":
        return list(self._skips)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        import ctypes
        try:
            self._k32.CancelIoEx(self._handle, None)
        except Exception:
            pass
        try:
            self._k32.CloseHandle(self._handle)
        except Exception:
            pass
        self._thread.join(timeout=2.0)


class _InotifyWatcher:
    """POSIX native watcher: inotify fd drained non-blocking by poll().

    Any ctypes/init failure raises; :func:`open_watcher` converts that
    into the disclosed poll fallback.
    """

    source_name = "inotify"

    def __init__(self, target: str) -> None:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        init1 = getattr(libc, "inotify_init1", None)
        add_watch = getattr(libc, "inotify_add_watch", None)
        if init1 is None or add_watch is None:
            raise OSError("inotify symbols unavailable on this host")
        init1.restype = ctypes.c_int
        init1.argtypes = [ctypes.c_int]
        add_watch.restype = ctypes.c_int
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p,
                              ctypes.c_uint32]
        IN_NONBLOCK = 0x800
        fd = init1(IN_NONBLOCK)
        if fd < 0:
            raise OSError("inotify_init1 failed")
        wd = add_watch(fd, os.fsencode(target), _IN_WATCH_MASK)
        if wd < 0:
            os.close(fd)
            raise OSError("inotify_add_watch failed")
        self._fd = fd
        self._wdmap = {wd: target}
        self._skips: "list[dict]" = []
        self._closed = False

    def poll(self, now: "float | None" = None) -> "list[dict]":
        if self._closed:
            return []
        events: "list[dict]" = []
        while True:
            try:
                data = os.read(self._fd, 1 << 16)
            except (BlockingIOError, OSError):
                break
            if not data:
                break
            try:
                evs, skips = parse_inotify_events(
                    data, self._wdmap, collect_skips=True)
            except Exception as exc:
                self._skips.append({
                    "reason": f"inotify_parse_{type(exc).__name__}",
                    "detail": str(exc)[:300]})
                continue
            events.extend(evs)
            self._skips.extend(skips)
        return events

    def disclosure(self) -> "list[dict]":
        return list(self._skips)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self._fd)
        except OSError:
            pass


def open_watcher(target, files=None):
    """Best native watcher for this host, else the disclosed poll path.

    Always returns an object with ``source_name``, ``poll(now=...)``,
    ``close()`` and ``disclosure()``.  Never raises for an unavailable
    native backend -- that is exactly when the fallback engages.
    """
    target = str(target)
    if sys.platform == "win32":
        try:
            return _ReadDirectoryChangesWatcher(target)
        except Exception:
            pass
    elif os.name == "posix":
        try:
            return _InotifyWatcher(target)
        except Exception:
            pass
    return PollWatcher(files or [], interval_ms=250)
