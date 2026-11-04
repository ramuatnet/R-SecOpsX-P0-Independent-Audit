"""T-4.1: repro sandbox -- bring up a target, apply a payload, capture.

Ground rule 11 (resource bounds for untrusted input) and the offline
invariant both apply here: every subprocess, HTTP read and wait is capped,
payload and capture bodies are size-truncated, and the module uses only
the standard library.

Runtime resolution, in order:

  1. ``docker`` / ``podman`` when the *daemon* answers (CLI presence alone
     is not enough -- Docker Desktop installed but not running yields
     BLOCKED later, never a silent hang).
  2. local fallback: the target's own launch command as a subprocess on
     loopback.  The fallback is recorded in the capture, never hidden.
  3. neither available and no launch command: BLOCKED with a reason.

Nothing here decides REPRODUCED/REFUTED: a capture is raw observation.
The bundler (analysis.repro.bundler) judges it against the finding's
stated expectation.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_12, WINDOW_300
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_12, WINDOW_300

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Bounds (ground rule 11).  Every one is a hard cap, not a hint.
RUNTIME_PROBE_TIMEOUT_S = 10
READY_TIMEOUT_DEFAULT_S = 30.0
PAYLOAD_TIMEOUT_S = 15.0
TERMINATE_GRACE_S = 5.0
MAX_CAPTURE_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024

_CONTAINER_MODES = ("docker", "podman")


@dataclass(frozen=True)
class RuntimeInfo:
    kind: str            # "docker" | "podman" | "local" | "none"
    version: str = ""
    error: str = ""

    @property
    def container(self) -> bool:
        return self.kind in _CONTAINER_MODES

    def to_dict(self) -> dict:
        return {"kind": self.kind, "version": self.version,
                "error": self.error}


def detect_runtime() -> RuntimeInfo:
    """Probe container runtimes.  Never raises; a hang is a failure, not a
    wait -- the probe itself is timed."""
    for kind in _CONTAINER_MODES:
        exe = shutil.which(kind)
        if not exe:
            continue
        try:
            proc = subprocess.run(
                [exe, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True,
                timeout=RUNTIME_PROBE_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return RuntimeInfo(kind, "", f"{kind} info timed out")
        except OSError as exc:
            return RuntimeInfo(kind, "", f"{kind} not runnable: {exc}")
        out = (proc.stdout or "").strip()
        if proc.returncode == 0 and out:
            return RuntimeInfo(kind, out)
        # CLI present, daemon down (Docker Desktop not started): say so.
        err = (proc.stderr or out or "").strip().splitlines()
        return RuntimeInfo(kind, "", err[0] if err
                           else f"{kind} daemon not reachable")
    return RuntimeInfo("none", "", "no container runtime on PATH")


@dataclass(frozen=True)
class ReproTarget:
    """How to bring one target up.

    ``launch`` is the local-fallback command (argv, never a shell string);
    ``container_image`` is the container-mode identity.  At least one must
    be present or the capture is BLOCKED.  ``ready_url`` is polled until
    it answers (any HTTP status counts as "up"); without it a short fixed
    warm-up is used and disclosed in the timing.
    """
    name: str
    launch: tuple[str, ...] = ()
    workdir: str = ""
    env: tuple[tuple[str, str], ...] = ()
    # Origin payloads are sent to (``http://127.0.0.1:8086``).  When empty
    # it is derived from an absolute ready_url; with neither, payload
    # application is skipped and the reason lands in capture.errors.
    base_url: str = ""
    ready_url: str = ""
    ready_timeout_s: float = READY_TIMEOUT_DEFAULT_S
    warmup_s: float = 1.0
    container_image: str = ""
    container_publish: tuple[tuple[str, str], ...] = ()  # (host, container)


@dataclass(frozen=True)
class HttpPayload:
    method: str = "GET"
    path: str = "/"
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "headers": dict(self.headers),
            "body_sha256": _sha256(self.body),
            "body_len": len(self.body),
            "body_text": _bounded(self.body),
        }


@dataclass
class ReproCapture:
    """One bring-up + payload application, with everything the spec names."""
    target: str
    runtime_used: str = ""          # docker | podman | local | "" (blocked)
    blocked_reason: str = ""
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    payload_applied: bool = False
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timing_ms: dict = field(default_factory=dict)
    env_fingerprint: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_reason)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "runtime_used": self.runtime_used,
            "blocked_reason": self.blocked_reason,
            "request": self.request,
            "response": self.response,
            "payload_applied": self.payload_applied,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timing_ms": self.timing_ms,
            "env_fingerprint": self.env_fingerprint,
            "errors": list(self.errors),
        }


def _sha256(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _bounded(data: bytes, cap: int = MAX_CAPTURE_BYTES) -> str:
    if len(data) > cap:
        return data[:cap].decode("utf-8", "replace") + (
            f"\n...[truncated {len(data) - cap} bytes]")
    return data.decode("utf-8", "replace")


def _fingerprint(runtime: RuntimeInfo, image_digest: str = "") -> dict:
    # Tool version comes from the one place that owns it; a missing config
    # module must not break a capture.
    try:
        from core.config import TOOL_VERSION
        tool_version = TOOL_VERSION
    except Exception:
        tool_version = ""
    return {
        "os": platform.platform(),
        "python": platform.python_version(),
        "runtime": runtime.kind,
        "runtime_version": runtime.version,
        "image_digest": image_digest or None,
        "tool_version": tool_version,
        "hostname": socket.gethostname(),
    }


def _local_env(target: ReproTarget) -> dict[str, str]:
    env = dict(os.environ)
    for key, value in target.env:
        env[key] = value
    return env


def _wait_ready(url: str, deadline_s: float) -> Optional[float]:
    """Poll until any HTTP response or deadline.  None = never answered."""
    if not url:
        return None
    t0 = time.monotonic()
    while time.monotonic() - t0 < deadline_s:
        try:
            with urllib.request.urlopen(url, timeout=2.0):
                return time.monotonic() - t0
        except urllib.error.HTTPError:
            return time.monotonic() - t0   # server answered: it is up
        except Exception:
            time.sleep(0.15)
    return None


def _apply_payload(base_url: str, payload: HttpPayload) -> dict:
    """Send the payload.  Returns the raw-observation envelope; transport
    failure is an error entry, HTTP 4xx/5xx is still a captured response."""
    if len(payload.body) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"payload body {len(payload.body)}B exceeds cap "
            f"{MAX_PAYLOAD_BYTES}B")
    url = base_url.rstrip("/") + payload.path
    headers = dict(payload.headers)
    req = urllib.request.Request(url, data=payload.body or None,
                                 method=payload.method.upper(),
                                 headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=PAYLOAD_TIMEOUT_S) as resp:
            body = resp.read(MAX_CAPTURE_BYTES + 1)
            elapsed = time.monotonic() - started
            return {
                "url": url,
                "status": resp.status,
                "headers": dict(resp.headers.items()),
                "body": _bounded(body),
                "body_sha256": _sha256(body[:MAX_CAPTURE_BYTES]),
                "elapsed_ms": round(elapsed * 1000, 1),
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_CAPTURE_BYTES + 1)
        elapsed = time.monotonic() - started
        return {
            "url": url,
            "status": exc.code,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body": _bounded(body),
            "body_sha256": _sha256(body[:MAX_CAPTURE_BYTES]),
            "elapsed_ms": round(elapsed * 1000, 1),
        }


def run_repro(target: ReproTarget, payload: HttpPayload,
              runtime: str = "auto") -> ReproCapture:
    """Bring ``target`` up, apply ``payload``, capture, tear down.

    ``runtime``: "auto" (container if the daemon answers, else local),
    "docker"/"podman" (force container; daemon down => BLOCKED, no silent
    fallback), "local" (force local; no launch => BLOCKED).
    Always tears down -- the finally block runs on every path.
    """
    capture = ReproCapture(target=target.name)
    t_start = time.monotonic()
    probe = detect_runtime()
    base_url, proc, container_name = "", None, ""
    image_digest = ""

    # -- runtime selection -------------------------------------------------
    use_container = False
    if runtime in _CONTAINER_MODES:
        if not probe.container or probe.kind != runtime or probe.error:
            capture.blocked_reason = (
                f"forced {runtime} but daemon unavailable: "
                f"{probe.error or probe.kind}")
        elif not target.container_image:
            capture.blocked_reason = f"forced {runtime} but target declares no image"
        else:
            use_container = True
    elif runtime == "local":
        if not target.launch:
            capture.blocked_reason = "forced local but target declares no launch command"
    else:  # auto
        if probe.container and not probe.error and target.container_image:
            use_container = True
        elif not target.launch:
            capture.blocked_reason = (
                "no usable runtime: "
                + (probe.error or "container image not declared")
                + " and no local launch command")

    if capture.blocked_reason:
        capture.runtime_used = ""
        capture.env_fingerprint = _fingerprint(probe)
        capture.timing_ms["total"] = round(
            (time.monotonic() - t_start) * 1000, 1)
        return capture

    try:
        if use_container:
            capture.runtime_used = probe.kind
            base_url, container_name, image_digest = _start_container(
                probe, target, capture)
        else:
            capture.runtime_used = "local"
            base_url, proc = _start_local(target, capture)
            if proc is None:
                capture.blocked_reason = (
                    capture.blocked_reason or "local launch failed")
                capture.runtime_used = "local"
                capture.env_fingerprint = _fingerprint(probe)
                capture.timing_ms["total"] = round(
                    (time.monotonic() - t_start) * 1000, 1)
                return capture

        # -- ready check ---------------------------------------------------
        t_ready = time.monotonic()
        if base_url and target.ready_url:
            ready_in = _wait_ready(_ready_absolute(target, base_url),
                                   target.ready_timeout_s)
            if ready_in is None:
                capture.blocked_reason = (
                    f"target never became ready within "
                    f"{target.ready_timeout_s}s")
            else:
                capture.timing_ms["ready_ms"] = round(ready_in * 1000, 1)
        else:
            time.sleep(min(target.warmup_s, 5.0))
            capture.timing_ms["warmup_ms"] = round(
                (time.monotonic() - t_ready) * 1000, 1)

        # -- apply payload -------------------------------------------------
        if not capture.blocked_reason:
            origin = base_url or _origin_from(target)
            if not origin:
                capture.errors.append(
                    "payload not applied: target declares no base_url and "
                    "no absolute ready_url to derive one from")
            else:
                capture.request = payload.to_dict()
                try:
                    capture.response = _apply_payload(origin, payload)
                    capture.payload_applied = True
                except Exception as exc:
                    capture.errors.append(
                        f"payload application failed: {exc}")
    finally:
        # -- teardown (always) --------------------------------------------
        if container_name:
            _stop_container(probe, container_name, capture)
        elif proc is not None:
            _stop_local(proc, capture)
        capture.env_fingerprint = _fingerprint(probe, image_digest)
        capture.timing_ms["total"] = round(
            (time.monotonic() - t_start) * 1000, 1)
    return capture


def _origin_from(target: ReproTarget) -> str:
    import urllib.parse
    for candidate in (target.base_url, target.ready_url):
        if candidate.startswith(("http://", "https://")):
            parts = urllib.parse.urlsplit(candidate)
            return f"{parts.scheme}://{parts.netloc}"
    return ""


def _ready_absolute(target: ReproTarget, base_url: str) -> str:
    """target.ready_url may be a path (``/healthz``) or an absolute URL."""
    if target.ready_url.startswith(("http://", "https://")):
        return target.ready_url
    return base_url.rstrip("/") + "/" + target.ready_url.lstrip("/")


# ---------------------------------------------------------------------------
# local fallback
# ---------------------------------------------------------------------------
def _start_local(target: ReproTarget,
                 capture: ReproCapture) -> tuple[str, Optional[subprocess.Popen]]:
    workdir = target.workdir or None
    if workdir and not Path(workdir).is_dir():
        capture.errors.append(f"workdir not found: {workdir}")
        return "", None
    # Spooled temp files, not pipes: a chatty target must not fill a pipe
    # buffer and deadlock the sandbox while we wait for readiness.
    out_f = tempfile.TemporaryFile()
    err_f = tempfile.TemporaryFile()
    try:
        proc = subprocess.Popen(
            list(target.launch),
            cwd=workdir,
            env=_local_env(target),
            stdin=subprocess.DEVNULL,
            stdout=out_f,
            stderr=err_f,
            shell=False,
        )
    except OSError as exc:
        capture.errors.append(f"launch failed: {exc}")
        out_f.close()
        err_f.close()
        return "", None
    capture.timing_ms["launch_ms"] = 0.0
    # Stash the spools on the process object so _stop_local can drain them.
    proc._rsx_out_f = out_f  # type: ignore[attr-defined]
    proc._rsx_err_f = err_f  # type: ignore[attr-defined]
    # Ready polling and payload origin: absolute ready_url wins, then
    # base_url, then derived origin -- never a bare "port 80" guess.
    if target.ready_url.startswith(("http://", "https://")):
        base_url = target.ready_url
    elif target.base_url:
        base_url = target.base_url
    else:
        base_url = _origin_from(target)
    return base_url, proc


def _stop_local(proc: subprocess.Popen, capture: ReproCapture) -> None:
    try:
        proc.terminate()
        try:
            proc.wait(timeout=TERMINATE_GRACE_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=TERMINATE_GRACE_S)
    except Exception as exc:
        capture.errors.append(f"teardown failed: {exc}")
    capture.exit_code = proc.returncode
    for attr, slot in (("_rsx_out_f", "stdout"), ("_rsx_err_f", "stderr")):
        fh = getattr(proc, attr, None)
        if fh is None:
            continue
        try:
            fh.seek(0)
            capture.__dict__[slot] = _bounded(fh.read())
        finally:
            fh.close()


# ---------------------------------------------------------------------------
# container mode
# ---------------------------------------------------------------------------
def _start_container(runtime: RuntimeInfo, target: ReproTarget,
                     capture: ReproCapture
                     ) -> tuple[str, str, str]:
    """docker/podman run; returns (base_url, container_name, image_digest)."""
    exe = runtime.kind
    name = f"rsx_repro_{uuid.uuid4().hex[:WINDOW_12]}"
    cmd = [exe, "run", "-d", "--name", name]
    for host, cont in target.container_publish:
        cmd += ["-p", f"127.0.0.1:{host}:{cont}"]
    for key, value in target.env:
        cmd += ["-e", f"{key}={value}"]
    cmd.append(target.container_image)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=RUNTIME_PROBE_TIMEOUT_S * 3)
    except Exception as exc:
        capture.errors.append(f"container run failed: {exc}")
        capture.blocked_reason = f"container run failed: {exc}"
        return "", "", ""
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:WINDOW_300]
        capture.errors.append(f"container run failed: {detail}")
        capture.blocked_reason = f"container run failed: {detail}"
        return "", "", ""
    digest = ""
    try:
        insp = subprocess.run(
            [exe, "image", "inspect", "--format",
             "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}",
             target.container_image],
            capture_output=True, text=True, timeout=RUNTIME_PROBE_TIMEOUT_S)
        if insp.returncode == 0:
            digest = (insp.stdout or "").strip()
    except Exception:
        pass  # digest absence is disclosed as null, never faked
    host_port = target.container_publish[0][0] if target.container_publish \
        else "80"
    return f"http://127.0.0.1:{host_port}", name, digest


def _stop_container(runtime: RuntimeInfo, name: str,
                    capture: ReproCapture) -> None:
    try:
        logs = subprocess.run([runtime.kind, "logs", name],
                              capture_output=True, text=True,
                              timeout=RUNTIME_PROBE_TIMEOUT_S)
        if logs.stdout:
            capture.stdout = _bounded(logs.stdout.encode())
        if logs.stderr:
            capture.stderr = _bounded(logs.stderr.encode())
    except Exception as exc:
        capture.errors.append(f"container logs failed: {exc}")
    try:
        rm = subprocess.run([runtime.kind, "rm", "-f", name],
                            capture_output=True, text=True,
                            timeout=RUNTIME_PROBE_TIMEOUT_S)
        capture.exit_code = rm.returncode
    except Exception as exc:
        capture.errors.append(f"container teardown failed: {exc}")


def capture_from_dict(data: dict) -> dict:
    """Validate/normalize a serialized capture for the bundler.  Returns a
    dict; raises ValueError on a structurally unusable capture."""
    if not isinstance(data, dict):
        raise ValueError("capture must be a mapping")
    if "target" not in data:
        raise ValueError("capture missing 'target'")
    return data


def write_capture_json(capture: ReproCapture, path: Path) -> str:
    """Deterministic capture artifact; returns its sha256."""
    blob = json.dumps(capture.to_dict(), sort_keys=True,
                      indent=1).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return _sha256(blob)
