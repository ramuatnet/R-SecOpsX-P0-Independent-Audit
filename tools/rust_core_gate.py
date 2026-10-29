"""T-1.1/T-1.2 CI gate: build the native core, run its crate unit tests,
then the bridge tests with the extension REQUIRED.

A missing toolchain, a failed build, or an unbuildable extension is a RED
gate -- never a skip. The gate is self-sufficient: it runs the cargo
steps itself so `ci_matrix` stays a single command.

Usage: python tools/rust_core_gate.py
Exit codes: 0 = build + both test layers green, 1 = first failure.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _step(label: str, cmd: list[str], *, cwd: Path, env: dict | None = None) -> int:
    print(f"--- {label}: {' '.join(cmd)}", flush=True)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except OSError as e:
        print(f"FAILED to launch: {e}", flush=True)
        return 1
    tail = (proc.stdout or "")[-3000:]
    if proc.returncode != 0:
        tail += "\n[stderr]\n" + (proc.stderr or "")[-3000:]
    print(tail, flush=True)
    if proc.returncode != 0:
        print(f"--- {label}: FAIL (exit {proc.returncode})", flush=True)
    else:
        print(f"--- {label}: ok", flush=True)
    return proc.returncode


def main() -> int:
    cargo = shutil.which("cargo")
    if not cargo:
        print(
            "cargo not found on PATH. The rust_core gate needs a Rust "
            "toolchain (rustc + cargo) and a C linker for the host "
            "target -- install rustup, or export the PATH entries for a "
            "local install. This gate fails RED rather than skipping: a "
            "missing toolchain must not silently drop native-engine "
            "validation.",
            flush=True,
        )
        return 1

    env = dict(os.environ)
    env["RSX_RUST_REQUIRED"] = "1"
    # Cargo's own output is deterministic given the same lockfile; keep
    # it quiet in the gate log and let failures print.
    env.setdefault("CARGO_TERM_COLOR", "never")

    steps = [
        ("cargo build --release",
         [cargo, "build", "--release"], ROOT / "rust"),
        ("cargo test",
         [cargo, "test"], ROOT / "rust"),
        ("bridge tests (RSX_RUST_REQUIRED=1)",
         [sys.executable, "-m", "pytest",
          str(ROOT / "tests" / "test_rust_core.py"), "-q", "--tb=short"],
         ROOT),
    ]
    for label, cmd, cwd in steps:
        if _step(label, cmd, cwd=cwd, env=env) != 0:
            return 1
    print("rust_core gate: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
