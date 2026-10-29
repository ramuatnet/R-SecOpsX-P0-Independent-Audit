"""T-4.1+T-4.2: repro sandbox and evidence/PoC bundler.

``sandbox``   brings a target up (container runtime, or the documented
              local fallback), applies one payload, and captures request,
              response, exit code, stdout/stderr, timing and an
              environment fingerprint.

``bundler``   writes a per-finding bundle: a runnable PoC, the capture,
              SHA-256 of every input and output, timestamp, tool version
              and image digest, with
              ``verification_status in {UNTESTED, REPRODUCED, REFUTED,
              INCONCLUSIVE, BLOCKED}`` carried on the existing
              ``core.evidence_schema.Evidence`` (extended, not replaced).
"""
from .sandbox import (  # noqa: F401
    HttpPayload,
    ReproCapture,
    ReproTarget,
    RuntimeInfo,
    detect_runtime,
    run_repro,
)
