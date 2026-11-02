"""T-9.16: memory + CPU limits (task.md section 13 "memory + CPU
limits").

Per ground rule 12 (resource bounds are mandatory for anything parsing
untrusted input: depth cap, size cap, time cap) -- depth and per-regex
time caps already exist (core/depth_guard, core/regex_budget); this
module bounds the SCAN PROCESS ITSELF:

  * portable in-process WATCHDOG (daemon thread) samples process CPU
    seconds (time.process_time) and memory (stdlib ctypes working-set
    read on Windows, getrusage peak RSS on POSIX).  On breach it stores
    a machine-readable LAST_BREACH row and injects the
    ResourceLimitExceeded class into the main thread via
    ctypes.pythonapi.PyThreadState_SetAsyncExc -- the exception fires
    between bytecodes (grounded on this host: delivery confirmed;
    long-running C calls delay it, and core/regex_budget's subprocess
    hard-guard covers the runaway-regex case);
  * main.py additionally checks cooperatively at EVERY stage boundary
    (_timing_start_stage, fed by the 85 _step calls), so even if
    injection never lands the next stage refuses to start;
  * on POSIX, SOFT kernel caps (resource.setrlimit RLIMIT_AS / a
    +10%-margin RLIMIT_CPU) are applied best-effort and restored on
    deactivate -- the kernel is the backstop behind the watchdog
    (RLIMIT_CPU soft would raise SIGXCPU, hence the margin: the
    watchdog is expected to deliver the message first);
  * breach -> the guard decorator prints one machine-readable
    ``[ERROR] RESOURCE LIMIT EXCEEDED kind=... limit=... observed=...``
    row and exits with LIMIT_EXCEEDED_EXIT_CODE (2) -- same exit
    contract as the other scan errors.  A breach aborts the scan, so
    report artifacts may be incomplete; exit 2 is the signal.

Defaults are generous (DEFAULT_MAX_MEMORY_MB / DEFAULT_MAX_CPU_SECONDS)
so a normal scan never trips them; ``0`` disables a dimension.  main.py
exposes --max-memory-mb / --max-cpu-seconds to tighten per run.

NOT ADOPTED: psutil -- memory sampling is stdlib ctypes
(GetProcessMemoryInfo) / resource.getrusage instead, because the scan
mode must run with zero required third-party runtime dependencies.
Windows Job Objects are NOT adopted either (nested-job and restricted
host failure modes, plus per-process time limits that hard-kill without
our message): the in-process watchdog enforces the portable contract
and POSIX carries the kernel backstop.  Known coverage limits, disclosed:
worker/child processes are NOT watched on Windows (they inherit the
POSIX rlimit caps where those exist), memory is the working set on
Windows and peak RSS on POSIX (conservative), and sampling granularity
is SAMPLE_INTERVAL_S so observed overshoot is bounded by one interval
plus one stage.
"""
from __future__ import annotations

import ctypes
import functools
import sys
import threading
import time

DEFAULT_MAX_MEMORY_MB = 8192
DEFAULT_MAX_CPU_SECONDS = 7200
SAMPLE_INTERVAL_S = 0.5
LIMIT_EXCEEDED_EXIT_CODE = 2

#: Filled by check()/watchdog before raising, so the bare-class async
#: injection (which instantiates ResourceLimitExceeded with no args)
#: still describes the breach that caused it.
LAST_BREACH: dict = {}

_state = {
    "active": False,
    "max_memory_mb": 0.0,
    "max_cpu_seconds": 0.0,
    "enforcement": "disabled",
    "peak_memory_mb": 0.0,
    "peak_cpu_seconds": 0.0,
}
_lock = threading.Lock()
_watchdog: "_Watchdog | None" = None
_main_tid: "int | None" = None
_posix_saved: dict | None = None
_ws_init: dict | None = None


class ResourceLimitExceeded(RuntimeError):
    """Raised when a memory or CPU budget is exceeded (check/watchdog)."""

    def __init__(self, kind=None, limit=None, observed=None, source=None):
        breach = LAST_BREACH or {}
        self.kind = kind or breach.get("kind") or "unknown"
        self.limit = limit if limit is not None else breach.get("limit")
        self.observed = (
            observed if observed is not None else breach.get("observed"))
        self.source = source or breach.get("source") or "watchdog"
        super().__init__(self.describe())

    def describe(self) -> str:
        unit = "s" if self.kind == "cpu" else "MB"
        return (
            "RESOURCE LIMIT EXCEEDED kind=%s limit=%s observed=%s "
            "enforcement=%s"
            % (self.kind,
               _fmt_amount(self.limit, unit),
               _fmt_amount(self.observed, unit),
               _state.get("enforcement") or "watchdog"))


def _fmt_amount(value, unit: str) -> str:
    if value is None:
        return "-"
    if unit == "s":
        return "%.2fs" % float(value)
    return "%.1fMB" % float(value)


# --------------------------------------------------------------- primitives


def process_cpu_seconds() -> float:
    """CPU seconds consumed by this process (portable, monotonic)."""
    return time.process_time()


def _windows_working_set_mb() -> float | None:
    global _ws_init
    if _ws_init is None:
        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32),
                ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]
        _ws_init = {"PMC": PMC, "ok": False}
        try:
            k32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            # restype matters: the default c_int truncates the HANDLE.
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            psapi.GetProcessMemoryInfo.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_uint32]
            psapi.GetProcessMemoryInfo.restype = ctypes.c_int
            _ws_init.update(k32=k32, psapi=psapi, ok=True)
        except Exception:  # pragma: no cover - defensive
            _ws_init["ok"] = False
    if not _ws_init.get("ok"):
        return None
    try:
        pmc = _ws_init["PMC"]()
        pmc.cb = ctypes.sizeof(pmc)
        ok = _ws_init["psapi"].GetProcessMemoryInfo(
            _ws_init["k32"].GetCurrentProcess(), ctypes.byref(pmc), pmc.cb)
        if not ok:
            return None
        return pmc.WorkingSetSize / (1024.0 * 1024.0)
    except Exception:  # pragma: no cover - defensive
        return None


def current_memory_mb() -> float | None:
    """Current (Windows) or peak (POSIX) resident memory in MB."""
    if sys.platform == "win32":
        return _windows_working_set_mb()
    try:
        import resource as _resource
        raw = _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss
        # ru_maxrss: bytes on macOS, kilobytes elsewhere on POSIX.
        if sys.platform == "darwin":
            return raw / (1024.0 * 1024.0)
        return raw / 1024.0
    except Exception:  # pragma: no cover - defensive
        return None


# ------------------------------------------------------------ posix backstop


def _posix_apply(max_memory_mb: float, max_cpu_seconds: float) -> bool:
    """Best-effort SOFT rlimits (POSIX only); restorable on deactivate."""
    global _posix_saved
    try:
        import resource as _resource
    except ImportError:
        return False
    saved: dict = {}
    try:
        if max_memory_mb > 0 and hasattr(_resource, "RLIMIT_AS"):
            soft, hard = _resource.getrlimit(_resource.RLIMIT_AS)
            new = int(max_memory_mb * 1024 * 1024)
            if soft == _resource.RLIM_INFINITY or new < soft:
                _resource.setrlimit(_resource.RLIMIT_AS, (new, hard))
                saved["as"] = soft
        if max_cpu_seconds > 0 and hasattr(_resource, "RLIMIT_CPU"):
            soft, hard = _resource.getrlimit(_resource.RLIMIT_CPU)
            # +10% margin: the watchdog delivers the machine-readable
            # message first; SIGXCPU remains the silent backstop.
            new = int(max_cpu_seconds * 1.1) + 1
            if soft == _resource.RLIM_INFINITY or new < soft:
                _resource.setrlimit(_resource.RLIMIT_CPU, (new, hard))
                saved["cpu"] = soft
    except (ValueError, OSError):  # pragma: no cover - platform dependent
        _posix_saved = saved or None
        return bool(saved)
    _posix_saved = saved or None
    return bool(saved)


def _posix_restore() -> None:
    global _posix_saved
    if not _posix_saved:
        return
    try:
        import resource as _resource
        if "as" in _posix_saved and hasattr(_resource, "RLIMIT_AS"):
            soft, hard = _resource.getrlimit(_resource.RLIMIT_AS)
            _resource.setrlimit(_resource.RLIMIT_AS, (_posix_saved["as"], hard))
        if "cpu" in _posix_saved and hasattr(_resource, "RLIMIT_CPU"):
            soft, hard = _resource.getrlimit(_resource.RLIMIT_CPU)
            _resource.setrlimit(
                _resource.RLIMIT_CPU, (_posix_saved["cpu"], hard))
    except (ValueError, OSError):  # pragma: no cover - platform dependent
        pass
    _posix_saved = None


# ---------------------------------------------------------------- watchdog


def _set_async_argtypes_inject():
    f = ctypes.pythonapi.PyThreadState_SetAsyncExc
    f.argtypes = (ctypes.c_ulong, ctypes.py_object)
    f.restype = ctypes.c_ulong
    return f


def _set_async_argtypes_clear():
    # NULL only passes through a c_void_p argtype: bare None under a
    # py_object argtype marshals a None OBJECT (SystemError: "exception
    # None is not a BaseException subclass") -- grounded probe.
    f = ctypes.pythonapi.PyThreadState_SetAsyncExc
    f.argtypes = (ctypes.c_ulong, ctypes.c_void_p)
    f.restype = ctypes.c_ulong
    return f


def _clear_pending_injection() -> None:
    if _main_tid is None:
        return
    try:
        f = _set_async_argtypes_clear()
        f(ctypes.c_ulong(_main_tid), None)
    except Exception:  # pragma: no cover - defensive
        pass


class _Watchdog(threading.Thread):
    """Samples CPU/memory; on breach stores LAST_BREACH and injects."""

    def __init__(self, max_memory_mb: float, max_cpu_seconds: float,
                 enforcement: str):
        super().__init__(name="rsx-resource-watchdog", daemon=True)
        self.max_memory_mb = max_memory_mb
        self.max_cpu_seconds = max_cpu_seconds
        self.enforcement = enforcement
        self._stop_evt = threading.Event()
        self.injected = False

    def run(self) -> None:
        while not self._stop_evt.wait(SAMPLE_INTERVAL_S):
            if self._evaluate():
                return

    def _evaluate(self) -> bool:
        cpu = process_cpu_seconds()
        if cpu > _state["peak_cpu_seconds"]:
            _state["peak_cpu_seconds"] = cpu
        mem = current_memory_mb()
        if mem and mem > _state["peak_memory_mb"]:
            _state["peak_memory_mb"] = mem

        kind = None
        limit = None
        observed = None
        if self.max_cpu_seconds > 0 and cpu > self.max_cpu_seconds:
            kind, limit, observed = "cpu", self.max_cpu_seconds, cpu
        elif (self.max_memory_mb > 0 and mem
                and mem > self.max_memory_mb):
            kind, limit, observed = "memory", self.max_memory_mb, mem
        if kind is None:
            return False

        LAST_BREACH.clear()
        LAST_BREACH.update(kind=kind, limit=limit, observed=observed,
                           source="watchdog", enforcement=self.enforcement)
        self._inject()
        return True

    def _inject(self) -> None:
        if _main_tid is None or self.injected:
            return
        try:
            f = _set_async_argtypes_inject()
            n = f(ctypes.c_ulong(_main_tid),
                  ctypes.py_object(ResourceLimitExceeded))
            self.injected = bool(n)
        except Exception:  # pragma: no cover - injection is best-effort
            # Cooperative check() still raises from LAST_BREACH.
            self.injected = False

    def stop(self) -> None:
        self._stop_evt.set()
        self.join(timeout=SAMPLE_INTERVAL_S * 4 + 1.0)


# ------------------------------------------------------------------ control


def enforcement_for(max_memory_mb: float, max_cpu_seconds: float) -> str:
    if max_memory_mb <= 0 and max_cpu_seconds <= 0:
        return "disabled"
    try:
        import resource  # noqa: F401
        return "watchdog+rlimit-soft"
    except ImportError:
        return "watchdog"


def activate(max_memory_mb=None, max_cpu_seconds=None, *,
             quiet: bool = False) -> dict:
    """Arm the limits for this scan (idempotent; stops any prior run).

    Prints one deterministic ``[LIMITS]`` startup line unless ``quiet``
    (core stays presentation-free when callers opt out; main.py lets the
    line print so every scan documents its budget in stdout/scan.log).
    Returns the armed snapshot.
    """
    global _main_tid
    deactivate()
    mm = float(DEFAULT_MAX_MEMORY_MB if max_memory_mb is None
               else max_memory_mb)
    cpu = float(DEFAULT_MAX_CPU_SECONDS if max_cpu_seconds is None
                else max_cpu_seconds)
    if mm < 0:
        mm = 0.0
    if cpu < 0:
        cpu = 0.0
    LAST_BREACH.clear()

    with _lock:
        _state["active"] = True
        _state["max_memory_mb"] = mm
        _state["max_cpu_seconds"] = cpu
        _state["peak_memory_mb"] = 0.0
        _state["peak_cpu_seconds"] = 0.0
        _state["enforcement"] = enforcement_for(mm, cpu)
        _main_tid = threading.get_ident()

    if mm > 0 or cpu > 0:
        if _state["enforcement"] == "watchdog+rlimit-soft":
            _posix_apply(mm, cpu)
        watchdog = _Watchdog(mm, cpu, _state["enforcement"])
        global _watchdog
        _watchdog = watchdog
        watchdog.start()
    if not quiet:
        if _state["enforcement"] == "disabled":
            print("       [LIMITS] disabled "
                  "(max-memory-mb=0 max-cpu-seconds=0)")
        else:
            print("       [LIMITS] memory<=%dMB cpu<=%ds enforcement=%s"
                  % (int(mm), int(cpu), _state["enforcement"]))
    return snapshot()


def deactivate() -> None:
    """Stop the watchdog, restore POSIX soft caps, clear pending exc."""
    global _watchdog, _main_tid
    watchdog = _watchdog
    _watchdog = None
    if watchdog is not None:
        watchdog.stop()
        if watchdog.injected:
            _clear_pending_injection()
    _posix_restore()
    with _lock:
        _state["active"] = False


def snapshot() -> dict:
    return dict(_state)


def check() -> None:
    """Cooperative stage-boundary check: raise if a budget is exceeded."""
    if LAST_BREACH:
        raise ResourceLimitExceeded()
    state = _state
    if not state["active"]:
        return
    if state["max_cpu_seconds"] > 0:
        cpu = process_cpu_seconds()
        if cpu > _state["peak_cpu_seconds"]:
            _state["peak_cpu_seconds"] = cpu
        if cpu > state["max_cpu_seconds"]:
            _raise_breach("cpu", state["max_cpu_seconds"], cpu)
    if state["max_memory_mb"] > 0:
        mem = current_memory_mb()
        if mem and mem > _state["peak_memory_mb"]:
            _state["peak_memory_mb"] = mem
        if mem and mem > state["max_memory_mb"]:
            _raise_breach("memory", state["max_memory_mb"], mem)


def _raise_breach(kind: str, limit: float, observed: float) -> None:
    LAST_BREACH.clear()
    LAST_BREACH.update(kind=kind, limit=limit, observed=observed,
                       source="check", enforcement=_state["enforcement"])
    raise ResourceLimitExceeded(kind=kind, limit=limit, observed=observed,
                                source="check")


def guard(func):
    """Wrap main(): catch ResourceLimitExceeded -> message + exit 2."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ResourceLimitExceeded as exc:
            deactivate()  # stop watchdog first; clear undelivered inject
            sys.stderr.write("  [ERROR] %s\n" % exc.describe())
            sys.stderr.flush()
            raise SystemExit(LIMIT_EXCEEDED_EXIT_CODE) from None
        finally:
            deactivate()

    return wrapper
