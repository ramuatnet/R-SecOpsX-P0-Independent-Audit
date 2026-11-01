"""Static analysis of machine-learning model artifacts (native, stdlib-only).

TECHNIQUE provenance -- logic reimplemented, no third-party tool is invoked,
downloaded, or required:

* Pickle opcode analysis after picklescan/fickling: the artifact is
  DISASSEMBLED with ``pickletools.genops`` and never UNPICKLED -- calling
  ``pickle.load`` would execute the payload, which is exactly the defect
  being detected. Every ``GLOBAL`` / ``INST`` / ``STACK_GLOBAL`` target is
  resolved through the memo (``MEMOIZE`` / ``PUT`` / ``BINPUT`` ->
  ``GET`` / ``BINGET``); a target that cannot be resolved (missing memo
  entry, non-string operand) is classified ``unknown`` and treated as
  dangerous, because that shape is an evasion attempt. Streams are parsed
  to EOF: torch checkpoints store several pickles concatenated (probe:
  ``pickletools.genops`` stops after each ``STOP``), and a stream that
  fails mid-parse still yields every opcode seen before the failure -- a
  partial pickle unpickles its prefix, so those globals are salvaged.

* safetensors structural validation: 8-byte little-endian header length,
  JSON header, per-tensor ``data_offsets`` bounded by the real payload.
  A header length that runs past EOF, negative/overlapping/overflowing
  offsets, or payload bytes no tensor references are integrity failures.

Classification mirrors the technique's data model: an UNSAFE set (module ->
names, or ``*`` for the whole module, propagated to submodules), a SAFE set
(promoted to innocuous), everything else SUSPICIOUS -- and suspicious is
reported only under ``RSX_ARTIFACT_STRICT=1``. Only dangerous findings are
emitted by default, which is what keeps a legitimate model file silent.

Escape hatches (default ON; env can only turn features OFF):
  RSX_MODEL_ARTIFACT_SCAN=0   skip the whole artifact pass
  RSX_ARTIFACT_STRICT=1       also report unproven (suspicious) globals

Known limits (documented, never silently widened): .npy/.npz and 7z archives
are not parsed (they would need numpy/py7zr); files larger than
_MAX_PREFIX_BYTES are parsed from their prefix only, which covers torch
metadata streams but would miss a payload appended after the cap.
"""

from __future__ import annotations

import io
import json
import os
import pickletools
import re
import struct
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Candidate files
# ---------------------------------------------------------------------------

# Extensions scanned unconditionally (they are model-artifact formats).
_PICKLE_EXTS_ALWAYS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt"}
# Extensions scanned only when the content proves it: pickle PROTO magic or
# a zip container (torch >= 1.6 stores checkpoints as zip). A bare .bin is a
# generic name -- magic gating is what keeps random binaries silent.
_PICKLE_EXTS_MAGIC = {".bin", ".dat", ".data"}
_SAFETENSORS_EXT = ".safetensors"

_PICKLE_PROTO_MAGIC = re.compile(rb"\x80[\x00-\x06]")  # PROTO + protocol 0..6
_MAX_PREFIX_BYTES = 64 * 1024 * 1024
_MAX_STREAMS = 64
_MAX_SAFETENSORS_HEADER = 100 * 1024 * 1024  # spec limit
_MODEL_CONFIG_KEYS = {
    "model_type", "architectures", "transformers_version",
    "pipeline_type", "auto_map",
}
_WEIGHTS_EXTS = (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dat", ".data")

# ---------------------------------------------------------------------------
# Classification data (technique: safe / unsafe / suspicious)
# ---------------------------------------------------------------------------

_UNSAFE_GLOBALS: dict[str, set[str] | str] = {
    "__builtin__": {  # pickle protocols 0-2
        "eval", "compile", "getattr", "apply", "exec", "open", "breakpoint",
    },
    "builtins": {  # pickle protocols 3+
        "eval", "compile", "getattr", "apply", "exec", "open", "breakpoint",
    },
    "cloudpickle.cloudpickle": {
        "_builtin_type", "_make_function", "_function_setstate",
        "_make_cell", "_make_empty_cell", "subimport",
    },
    "types": {"CodeType"},
    "aiohttp": "*",
    "asyncio": "*",
    "bdb": "*",
    "commands": "*",
    "ctypes": "*",
    "functools": {"partial"},
    "httplib": "*",
    "logging": {"FileHandler"},
    "_io": {"FileIO"},
    "numpy.f2py": "*",
    "numpy.testing._private.utils": "*",
    "nt": "*",
    "posix": "*",
    "_operator": {"attrgetter", "itemgetter", "methodcaller"},
    "operator": {"attrgetter", "itemgetter", "methodcaller"},
    "os": "*",
    "requests.api": "*",
    "runpy": "*",
    "shutil": "*",
    "socket": "*",
    "ssl": "*",
    "subprocess": "*",
    "sys": "*",
    "code": {"InteractiveInterpreter.runcode"},
    "cProfile": "*",
    "distutils.file_util": "*",
    "doctest": {"debug_script"},
    "ensurepip": {"_run_pip"},
    "imaplib": {"IMAP4_stream"},
    "lib2to3.pgen2.grammar": {"Grammar.loads"},
    "lib2to3.pgen2.pgen": {"ParserGenerator.make_label"},
    "pdb": "*",
    "pickle": "*",
    "_pickle": "*",
    "pip": "*",
    "pkgutil": {"resolve_name"},
    "pty": "*",
    "profile": "*",
    "pydoc": "*",
    "test": "*",
    "timeit": "*",
    "torch._dynamo.guards": {"GuardBuilder.get"},
    "torch._inductor.codecache": {"compile_file"},
    "torch.fx.experimental.symbolic_shapes": {"ShapeEnv.evaluate_guards_expression"},
    "torch.jit.unsupported_tensor_ops": {"execWrapper"},
    "torch.serialization": {"load"},
    "torch.utils._config_module": {"ConfigModule.load_config"},
    "torch.utils.bottleneck.__main__": {"run_cprofile", "run_autograd_prof"},
    "torch.utils.collect_env": {"run"},
    "torch.utils.data.datapipes.utils.decoder": {"basichandlers"},
    "trace": {"Trace.run", "Trace.runctx"},
    "urllib.request": "*",
    "uuid": "*",
    "venv": "*",
    "webbrowser": "*",
    "_osx_support": "*",
    "_aix_support": "*",
    "_pyrepl": "*",
}

_SAFE_GLOBALS: dict[str, set[str] | str] = {
    "collections": {"OrderedDict"},
    "torch": {
        "LongStorage", "FloatStorage", "HalfStorage", "QUInt2x4Storage",
        "QUInt4x2Storage", "QInt32Storage", "QInt8Storage", "QUInt8Storage",
        "ComplexFloatStorage", "ComplexDoubleStorage", "DoubleStorage",
        "BFloat16Storage", "BoolStorage", "CharStorage", "ShortStorage",
        "IntStorage", "ByteStorage",
    },
    "numpy": {"dtype", "ndarray"},
    "numpy._core.multiarray": {"_reconstruct"},
    "numpy.core.multiarray": {"_reconstruct"},
    "torch._utils": {"_rebuild_tensor_v2"},
}

_STRING_OPCODES = frozenset({
    "SHORT_BINUNICODE", "UNICODE", "BINUNICODE", "BINUNICODE8",
    "STRING", "BINSTRING", "SHORT_BINSTRING",
})
_MEMO_WRITES = frozenset({"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"})
_MEMO_READS = frozenset({"GET", "BINGET", "LONG_BINGET"})


# ---------------------------------------------------------------------------
# Technique core: extract (module, name) globals from pickle bytecode
# ---------------------------------------------------------------------------

def _collect_globals(ops: list, out: set[tuple[str, str]]) -> None:
    """Resolve GLOBAL/INST/STACK_GLOBAL targets from one stream's opcodes.

    Memo writes record the PREVIOUS opcode's value (the string being stored);
    STACK_GLOBAL walks backwards over the opcode list collecting exactly the
    two strings on top of the stack, resolving memo reads, and substituting
    ``unknown`` for anything unresolvable -- including a memo key that was
    never written (evasion) or a non-string operand.
    """
    memo: dict = {}
    for n, (op, arg, _pos) in enumerate(ops):
        name = op.name
        if name == "MEMOIZE" and n > 0:
            memo[len(memo)] = ops[n - 1][1]
        elif name in ("PUT", "BINPUT", "LONG_BINPUT") and n > 0:
            memo[arg] = ops[n - 1][1]
        elif name in ("GLOBAL", "INST"):
            parts = str(arg).split(" ", 1)
            if len(parts) == 2:
                out.add((parts[0], parts[1]))
        elif name == "STACK_GLOBAL":
            values: list[str] = []
            for offset in range(1, n + 1):
                prev_op, prev_arg, _p = ops[n - offset]
                pn = prev_op.name
                if pn in _MEMO_WRITES:
                    continue
                if pn in _MEMO_READS:
                    try:
                        key = int(prev_arg)
                    except (TypeError, ValueError):
                        values.append("unknown")
                        continue
                    if key not in memo:
                        values.append("unknown")
                    else:
                        memo_value = memo[key]
                        values.append(
                            memo_value if isinstance(memo_value, str)
                            else str(memo_value))
                elif pn not in _STRING_OPCODES:
                    values.append("unknown")
                else:
                    values.append(str(prev_arg))
                if len(values) == 2:
                    break
            while len(values) < 2:  # unreachable in valid streams; fail loud
                values.append("unknown")
            out.add((values[1], values[0]))


def _extract_globals(data: bytes) -> tuple[set[tuple[str, str]], str | None]:
    """All globals from every pickle stream in ``data``.

    Returns ``(globals, parse_note)``. Streams are parsed until EOF; when a
    stream fails mid-parse, every opcode already yielded is still collected
    (salvage) and the note records the failure. Never raises.
    """
    found: set[tuple[str, str]] = set()
    fh = io.BytesIO(data)
    note: str | None = None
    streams = 0
    try:
        while True:  # sast-ignore LLM04_MODEL_DENIAL_OF_SERVICE bounded stream loop (exits at EOF)
            start = fh.tell()
            ops: list = []
            try:
                for op in pickletools.genops(fh):
                    ops.append(op)
            except Exception as exc:  # noqa: BLE001 -- salvage, never raise
                note = f"partial pickle stream: {exc}"
                try:
                    _collect_globals(ops, found)
                except Exception:
                    pass
                break
            try:
                _collect_globals(ops, found)
            except Exception:
                pass
            streams += 1
            if fh.tell() == start or streams >= _MAX_STREAMS:
                break
            if not fh.read(1):  # EOF
                break
            fh.seek(-1, 1)
    except Exception as exc:  # noqa: BLE001
        note = f"pickle scan aborted: {exc}"
    return found, note


def _classify(module: str, name: str) -> str:
    """dangerous | innocuous | suspicious, with parent-module wildcarding."""
    if "unknown" in module or "unknown" in name:
        return "dangerous"
    unsafe = _UNSAFE_GLOBALS.get(module)
    if unsafe is None and "." in module:
        parts = module.split(".")
        for i in range(1, len(parts)):
            if _UNSAFE_GLOBALS.get(".".join(parts[:i])) == "*":
                unsafe = "*"
                break
    if unsafe is not None and (unsafe == "*" or name in unsafe):
        return "dangerous"
    safe = _SAFE_GLOBALS.get(module)
    if safe is not None and (safe == "*" or name in safe):
        return "innocuous"
    return "suspicious"


def _globals_report(data: bytes, strict: bool) -> tuple[str | None, str | None]:
    """(snippet_detail, parse_note) -- snippet_detail None means silent."""
    globals_found, note = _extract_globals(data)
    dangerous: list[str] = []
    suspicious: list[str] = []
    for module, name in sorted(globals_found):
        level = _classify(module, name)
        if level == "dangerous":
            dangerous.append(f"{module}.{name}")
        elif level == "suspicious":
            suspicious.append(f"{module}.{name}")
    if dangerous:
        shown = ", ".join(dangerous[:3])
        if len(dangerous) > 3:
            shown += f" (+{len(dangerous) - 3} more)"
        return f"pickle dangerous global: {shown}", note
    if strict and suspicious:
        shown = ", ".join(suspicious[:3])
        if len(suspicious) > 3:
            shown += f" (+{len(suspicious) - 3} more)"
        return f"pickle unproven global (strict): {shown}", note
    return None, note


def _scan_pickle_bytes(data: bytes, strict: bool) -> tuple[str | None, str | None]:
    """Pickle or zip container -> (detail, note); never raises."""
    if not data:
        return None, None
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > _MAX_PREFIX_BYTES:
                        continue
                    member_ext = Path(info.filename).suffix.lower()
                    try:
                        with zf.open(info) as member:
                            head = member.read(2)
                    except Exception:
                        continue
                    qualifies = (
                        member_ext in _PICKLE_EXTS_ALWAYS
                        or member_ext in _PICKLE_EXTS_MAGIC
                        or bool(_PICKLE_PROTO_MAGIC.match(head))
                    )
                    if not qualifies:
                        continue
                    try:
                        payload = zf.read(info.filename)
                    except Exception as exc:
                        return None, f"zip member unreadable: {exc}"
                    detail, note = _globals_report(payload[:_MAX_PREFIX_BYTES], strict)
                    if detail:
                        return (f"{info.filename}: {detail}", note)
            return None, None
        detail, note = _globals_report(data[:_MAX_PREFIX_BYTES], strict)
        return detail, note
    except Exception as exc:  # noqa: BLE001
        return None, f"artifact unreadable: {exc}"


# ---------------------------------------------------------------------------
# safetensors structural validation
# ---------------------------------------------------------------------------

def _check_safetensors(path: Path) -> str | None:
    """Structural verdict for one .safetensors file; None = sound. Never raises."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(8)
            if len(head) < 8:
                return "truncated before the 8-byte header length"
            header_len = struct.unpack("<Q", head)[0]
            if header_len == 0:
                return "header length is zero"
            if header_len > _MAX_SAFETENSORS_HEADER:
                return f"header length {header_len} exceeds the 100 MB spec limit"
            if 8 + header_len > size:
                return (f"header length {header_len} runs past EOF "
                        f"(file is {size} bytes)")
            header_raw = fh.read(header_len)
        try:
            header = json.loads(header_raw.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            return f"header is not valid JSON: {exc}"
        if not isinstance(header, dict):
            return "header JSON is not an object"
        payload_len = size - 8 - header_len
        ranges: list[tuple[int, int, str]] = []
        for key, spec in header.items():
            if key == "__metadata__":
                continue
            if not isinstance(spec, dict):
                return f"tensor {key!r} spec is not an object"
            offsets = spec.get("data_offsets")
            if (not isinstance(offsets, (list, tuple)) or len(offsets) != 2
                    or not all(isinstance(v, int) for v in offsets)):
                return f"tensor {key!r} has no [begin, end] integer offsets"
            begin, end = offsets
            if begin < 0 or end < begin:
                return f"tensor {key!r} has negative or inverted offsets"
            if end > payload_len:
                return (f"tensor {key!r} offset end {end} exceeds the payload "
                        f"({payload_len} bytes)")
            ranges.append((begin, end, key))
        ranges.sort()
        for i in range(1, len(ranges)):
            if ranges[i][0] < ranges[i - 1][1]:
                return (f"tensor {ranges[i][2]!r} overlaps "
                        f"{ranges[i - 1][2]!r}")
        covered = max((end for _b, end, _k in ranges), default=0)
        if payload_len > covered:
            return (f"{payload_len - covered} payload bytes are not "
                    f"referenced by any tensor")
        return None
    except Exception as exc:  # noqa: BLE001
        return f"unreadable: {exc}"


# ---------------------------------------------------------------------------
# Directory-level advisory: pickle weights without a safetensors alternative
# ---------------------------------------------------------------------------

def _looks_like_model_config(config_path: Path) -> bool:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return False
    return isinstance(data, dict) and bool(_MODEL_CONFIG_KEYS & set(data))


def _dir_has_safetensors(model_dir: Path) -> bool:
    try:
        return any(p.suffix.lower() == _SAFETENSORS_EXT for p in model_dir.iterdir()
                   if p.is_file())
    except OSError:
        return False


def _dir_pickle_weights(model_dir: Path) -> Path | None:
    """First (sorted) file in the directory that is genuinely a pickle artifact."""
    try:
        candidates = sorted(
            (p for p in model_dir.iterdir()
             if p.is_file() and p.suffix.lower() in _WEIGHTS_EXTS),
            key=lambda p: p.name.lower())
    except OSError:
        return None
    for candidate in candidates:
        try:
            with open(candidate, "rb") as fh:
                head = fh.read(2)
            if _PICKLE_PROTO_MAGIC.match(head) or zipfile.is_zipfile(candidate):
                return candidate
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Rule dicts + findings
# ---------------------------------------------------------------------------

_PICKLE_RULE = {
    "id": "AI_PICKLE_DANGEROUS_GLOBAL",
    "name": "Model Artifact Pickle Executes Arbitrary Code",
    "vuln_type": "insecure_deserialization",
    "severity": "Critical",
    "cwe": "CWE-502",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "note": ("The artifact is pickle bytecode carrying a global that executes "
             "arbitrary code when the model is loaded; loading it compromises "
             "the host."),
    "detection": "Static Pickle Opcode Analysis (pickletools, never unpickled)",
    "remediation": [
        "Load model weights from the safetensors format, which cannot execute code, or rebuild the model from trusted source.",
        "Obtain model files only from trusted publishers and verify their checksum/signature before loading.",
        "If pickle is unavoidable, load with an allow-listing unpickler or equivalent guard and never load files from untrusted paths.",
        "Quarantine the artifact and re-acquire the model from its authoritative repository.",
    ],
}

_SAFETENSORS_RULE = {
    "id": "AI_SAFETENSORS_INVALID_HEADER",
    "name": "Malformed safetensors Header (Integrity Failure)",
    "vuln_type": "unsafe_model_artifact",
    "severity": "High",
    "cwe": "CWE-130",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "note": ("The safetensors header is structurally inconsistent with the "
             "file (length past EOF, offsets out of bounds or overlapping, "
             "unreferenced payload bytes) -- the artifact is corrupt or "
             "tampered with."),
    "detection": "safetensors Structure Validation (8-byte length + JSON offsets)",
    "remediation": [
        "Re-acquire the model file from its authoritative source and verify the published checksum.",
        "Treat a malformed weights file as a supply-chain integrity incident; do not load it.",
        "Validate safetensors headers at ingestion time before any consumer reads the payload.",
    ],
}

_ADVISORY_RULE = {
    "id": "AI_PICKLE_WEIGHTS_NO_SAFETENSORS",
    "name": "Model Directory Ships Pickle Weights Without safetensors",
    "vuln_type": "unsafe_model_artifact",
    "severity": "Low",
    "cwe": "CWE-502",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "note": ("This model directory carries pickle-based weights and no "
             ".safetensors alternative, so every consumer executes pickle "
             "bytecode to load the model."),
    "detection": "Model Directory Layout Check (config.json + pickle weights)",
    "remediation": [
        "Prefer a safetensors release of the same model when the publisher provides one.",
        "Pin the model revision and verify file hashes before loading pickle weights.",
        "Convert the checkpoint to safetensors with an offline conversion tool and publish that artifact.",
    ],
}


def _enabled() -> bool:
    return os.environ.get("RSX_MODEL_ARTIFACT_SCAN", "1").strip().lower() not in {
        "0", "false", "off", "no"}


def _strict() -> bool:
    return os.environ.get("RSX_ARTIFACT_STRICT", "0").strip().lower() in {
        "1", "true", "on", "yes"}


def scan_model_artifacts(target) -> list[dict]:
    """Scan model artifacts under ``target``; returns finding dicts.

    Wired from ``scanner.sast.scan_directory`` behind a try/except: any
    failure degrades to zero artifact findings and never breaks the
    baseline scanner. Every finding is built with ``_make_finding`` so the
    shape is identical to engine-produced findings.
    """
    if not _enabled():
        return []
    from scanner.sast import _make_finding  # call-time: no import cycle
    # T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
    from core import file_index

    root = Path(target)
    if not root.exists():
        return []
    strict = _strict()
    findings: list[dict] = []
    pickle_paths: list[Path] = []

    # Walk policy (skip dirs/files, scanner-result exports, .sastignore
    # paths) already applied by the one walk; _skip is subsumed.
    for fp in file_index.index_for(root).files():
        ext = fp.suffix.lower()
        try:
            if ext == _SAFETENSORS_EXT:
                reason = _check_safetensors(fp)
                if reason:
                    finding = _make_finding(
                        _SAFETENSORS_RULE, str(fp), 1,
                        f"safetensors: {reason}", "safetensors")
                    finding["description"] = f"{_SAFETENSORS_RULE['note']} ({reason})"
                    findings.append(finding)
                continue
            if ext in _PICKLE_EXTS_ALWAYS:
                pickle_paths.append(fp)
            elif ext in _PICKLE_EXTS_MAGIC:
                with open(fp, "rb") as fh:
                    head = fh.read(2)
                if _PICKLE_PROTO_MAGIC.match(head) or zipfile.is_zipfile(fp):
                    pickle_paths.append(fp)
        except OSError:
            continue

    for fp in pickle_paths:
        try:
            with open(fp, "rb") as fh:
                data = fh.read(_MAX_PREFIX_BYTES)
        except OSError:
            continue
        detail, note = _scan_pickle_bytes(data, strict)
        if not detail:
            continue
        severity_rule = dict(_PICKLE_RULE)
        if "strict" in detail:  # unproven globals only -- never Critical
            severity_rule["severity"] = "Low"
            severity_rule["confidence"] = "Low"
        finding = _make_finding(severity_rule, str(fp), 1, detail, "python")
        suffix = f" ({note})" if note and "strict" not in detail else ""
        finding["description"] = f"{_PICKLE_RULE['note']} [{detail}]{suffix}"
        findings.append(finding)

    # One advisory per model directory that has pickle weights and no
    # safetensors sibling. Anchored on the first pickle-weight file.
    try:
        configs = file_index.index_for(root).files(names={"config.json"})
    except OSError:
        configs = []
    for config in configs:
        model_dir = config.parent
        if _dir_has_safetensors(model_dir):
            continue
        if not _looks_like_model_config(config):
            continue
        weights = _dir_pickle_weights(model_dir)
        if weights is None:
            continue
        finding = _make_finding(
            _ADVISORY_RULE, str(weights), 1,
            "pickle weights present, no .safetensors sibling", "python")
        finding["description"] = _ADVISORY_RULE["note"]
        findings.append(finding)

    return findings
