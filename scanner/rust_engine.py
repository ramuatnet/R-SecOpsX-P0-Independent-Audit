"""T-1.1: Python side of the Rust engine bridge (`--engine rust`).

The Rust crate never holds rule logic or policy lists: this module builds
one config JSON from the SAME Python sources the Python engine uses
(scanner.sast rule tables, core.file_index skip policy, the shared
.sastignore loader), so there is exactly one source of truth for what a
finding is and what gets scanned.

The extension is an optional accelerator. It is never imported unless the
caller asked for it (`--engine rust`), the default stays `py` until T-1.5
parity, and a missing build fails LOUDLY with build instructions -- no
silent fallback to a different engine than the user chose.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

CONFIG_SCHEMA = "rsecopsx.rust_scan_config/v1"
ENVELOPE_SCHEMA = "rsecopsx.rust_findings/v1"

# Fields `_make_finding` derives from the match; the Rust engine fills
# them per match from its own walk.
_PER_MATCH_KEYS = ("file", "line", "snippet", "evidence", "group_key", "language")

_CORE: Any = None
_LAST_STATUS: dict | None = None
_LOAD_ERROR: str | None = None

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _build_candidates() -> list[Path]:
    """Ordered search for the built extension (env override first)."""
    out: list[Path] = []
    env = os.environ.get("RSX_RUST_EXT")
    if env:
        out.append(Path(env))
    target = _REPO_ROOT / "rust" / "target"
    # Release before debug; host-dir layouts (direct or triple-nested).
    for name in ("rsecopsx_core.pyd", "rsecopsx_core.dll"):
        out.append(target / "release" / name)
        out.append(target / "x86_64-pc-windows-gnu" / "release" / name)
        out.append(target / "x86_64-pc-windows-msvc" / "release" / name)
        out.append(target / "debug" / name)
    return out


def _build_help() -> str:
    return (
        "Rust engine extension not built. Build it with:\n"
        "    cd rust && cargo build --release\n"
        "then re-run with --engine rust. (Toolchain: rustc/cargo plus a C "
        "linker; set RSX_RUST_EXT=/path/to/rsecopsx_core.pyd to point at an "
        "existing build. --engine py, the default, does not need it.)"
    )


def load_extension() -> Any:
    """Import rsecopsx_core, materialising a .pyd from a fresh .dll build."""
    global _CORE, _LOAD_ERROR
    if _CORE is not None:
        return _CORE
    # Already importable (installed or previously loaded)?
    try:
        import rsecopsx_core as core  # type: ignore

        _CORE = core
        return _CORE
    except ImportError:
        pass

    for cand in _build_candidates():
        if not cand.is_file():
            continue
        if cand.suffix == ".dll":
            # Windows only loads extensions named .pyd; mirror the build
            # beside it (refreshed whenever the dll is newer).
            pyd = cand.with_suffix(".pyd")
            if (not pyd.exists()) or cand.stat().st_mtime > pyd.stat().st_mtime:
                pyd.write_bytes(cand.read_bytes())
            mod_path = pyd
        else:
            # Candidates list the .pyd before its sibling .dll, so a stale
            # .pyd would be imported as-is and the refresh above never
            # runs. Compare against the sibling .dll here too, or an old
            # copy silently wins and the engine reports pre-fix behaviour.
            dll = cand.with_suffix(".dll")
            if dll.is_file() and dll.stat().st_mtime > cand.stat().st_mtime:
                cand.write_bytes(dll.read_bytes())
            mod_path = cand
        sys.path.insert(0, str(mod_path.parent))
        try:
            import rsecopsx_core as core  # type: ignore

            _CORE = core
            return _CORE
        except ImportError as e:
            _LOAD_ERROR = f"{mod_path}: {e}"
            sys.path.pop(0)
            continue

    detail = f" (last import error: {_LOAD_ERROR})" if _LOAD_ERROR else ""
    raise RuntimeError(_build_help() + detail)


def _flags_of(pattern: re.Pattern) -> str:
    letters = "".join(
        ch for bit, ch in ((re.I, "i"), (re.M, "m"), (re.S, "s"))
        if pattern.flags & bit
    )
    return letters


def _remediation_by_lang(rule: dict, base_remediation: Any) -> dict[str, list]:
    """The language-dependent `_remediation` edge (js-yaml deserialisation).

    Only languages whose remediation DIFFERS from the language-neutral
    static are shipped, so the config stays small and the rule stays
    declarative.
    """
    from scanner import sast

    langs = sorted(set(sast.LANG_BY_EXT.values()) | {"javascript", "typescript"})
    out: dict[str, list] = {}
    for lang in langs:
        alt = sast._make_finding(rule, "", 0, "", lang)
        if alt.get("remediation") != base_remediation:
            out[lang] = list(alt.get("remediation") or [])
    return out


def _static_of(rule: dict) -> dict:
    from scanner import sast

    static = sast._make_finding(rule, "", 0, "", "")
    for key in _PER_MATCH_KEYS:
        static.pop(key, None)
    return static


def _langs_of(rule: dict, *keys: str) -> list[str] | None:
    """Language gate as a JSON list (the tables store list OR set)."""
    val = None
    for key in keys:
        val = rule.get(key)
        if val:
            break
    if not val:
        return None
    return sorted(str(v) for v in val)


def build_config(target: str | os.PathLike) -> dict:
    """One config JSON: rule program + every policy list, sourced from the
    same Python objects the `--engine py` path uses."""
    from core import file_index
    from scanner import sast

    target_path = Path(target)
    sastignore_target = target_path if target_path.is_dir() else target_path.parent

    rules: list[dict] = []
    for rule in sast.REGEX_RULES:
        pattern = rule["pattern"]  # compiled re.Pattern
        static = _static_of(rule)
        rules.append(
            {
                "id": rule.get("id") or "?",
                "pattern": pattern.pattern,
                "flags": _flags_of(pattern),
                "langs": _langs_of(rule, "languages", "lang"),
                "kind": "regex",
                "vuln_type": rule.get("vuln_type"),
                "static_finding": static,
                "remediation_by_lang": _remediation_by_lang(
                    rule, static.get("remediation")
                ),
            }
        )
    for rule in sast.COMPILED_ENTERPRISE_RULES:
        pattern = rule["pattern"]  # compiled re.Pattern
        static = _static_of(rule)
        rules.append(
            {
                "id": rule.get("id") or "?",
                "pattern": rule["pat"],
                "flags": _flags_of(pattern),
                "langs": _langs_of(rule, "langs"),
                "kind": "enterprise",
                "vuln_type": rule.get("vuln_type") or rule.get("vuln"),
                "static_finding": static,
                "remediation_by_lang": _remediation_by_lang(
                    rule, static.get("remediation")
                ),
            }
        )

    scannable = sast.SCANNABLE_EXT
    return {
        "schema": CONFIG_SCHEMA,
        "excluded_files": sorted({str(x).lower() for x in sast.EXCLUDED_FILES}),
        "excluded_dirs": sorted({str(x).lower() for x in sast.EXCLUDED_DIRS}),
        "lang_by_ext": {str(k).lower(): v for k, v in sast.LANG_BY_EXT.items()},
        # Python checks suffix.lower() against the LOWERED set and the
        # exact name against the EXACT set; ship both views.
        "scannable_ext": sorted({str(x).lower() for x in scannable}),
        "scannable_names": sorted(str(x) for x in scannable),
        "max_depth": file_index.MAX_DEPTH,
        "sastignore_rules": list(
            file_index._load_sastignore_rules(sastignore_target)
        ),
        "line_comment_prefixes": {
            str(k).lower(): list(v) for k, v in sast._LINE_COMMENT_PREFIXES.items()
        },
        "block_comment_langs": sorted(sast._BLOCK_COMMENT_DELIMS),
        "non_executable_data_langs": sorted(sast.NON_EXECUTABLE_DATA_LANGUAGES),
        "rules": rules,
    }


def scan_directory(target: str | os.PathLike, workers: int = 2) -> list[dict]:
    """Drop-in for scanner.sast.scan_directory: same finding schema.

    `workers` is accepted for signature parity; the v1 Rust engine is
    single-process (the prefilter makes per-line cost the bound) and the
    envelope status discloses that.
    """
    del workers  # signature parity only
    core = load_extension()
    config_json = json.dumps(build_config(target), ensure_ascii=True)
    raw = core.scan(str(target), config_json)
    envelope = json.loads(raw)
    schema = envelope.get("schema")
    if schema != ENVELOPE_SCHEMA:
        raise RuntimeError(
            f"rust engine returned schema {schema!r}, want {ENVELOPE_SCHEMA!r}"
        )
    status = envelope.get("status") or {}
    _remember_status(status)
    findings = envelope.get("findings") or []
    if not isinstance(findings, list):
        raise RuntimeError("rust engine findings is not a list")
    return findings


def _remember_status(status: dict) -> None:
    global _LAST_STATUS
    _LAST_STATUS = status


def disclosure_lines(status: dict | None = None) -> list[str]:
    """Human-readable disclosure of everything the Rust engine degraded,
    skipped or does not do yet -- printed on `--engine rust` (no silent
    drops: unsupported rules and limits are always surfaced)."""
    st = status if status is not None else _LAST_STATUS
    if st is None:
        return ["rust engine: no scan has run yet (status unknown)"]
    lines = [f"engine: {st.get('engine', '?')}"]
    walk = st.get("walk") or {}
    lines.append(
        "walk: files={files} excluded_dirs={excluded_dirs} "
        "excluded_files={excluded_files} scanner_result_skipped={scanner_result_skipped} "
        "sastignore_skipped={sastignore_skipped} symlink_outside_root={symlink_files_outside_root}".format(
            files=walk.get("files", 0),
            excluded_dirs=walk.get("excluded_dirs", 0),
            excluded_files=walk.get("excluded_files", 0),
            scanner_result_skipped=walk.get("scanner_result_skipped", 0),
            sastignore_skipped=walk.get("sastignore_skipped", 0),
            symlink_files_outside_root=walk.get("symlink_files_outside_root", 0),
        )
    )
    lines.append(
        "files: scanned={} skipped_not_scannable_or_vetoed={}".format(
            st.get("files_scanned", 0), st.get("files_skipped", 0)
        )
    )
    unsupported = st.get("rules_unsupported") or []
    if unsupported:
        shown = ", ".join(
            f"{u.get('id', '?')}" for u in unsupported[:6]
        )
        more = "" if len(unsupported) <= 6 else f" (+{len(unsupported) - 6} more)"
        lines.append(
            f"UNSUPPORTED rules skipped by the regex engine "
            f"({len(unsupported)}): {shown}{more}"
        )
    unpref = st.get("rules_unprefilterable") or []
    if unpref:
        lines.append(
            f"unprefilterable rules run on every line ({len(unpref)}): "
            + ", ".join(unpref[:6])
            + ("" if len(unpref) <= 6 else f" (+{len(unpref) - 6} more)")
        )
    for lim in st.get("limits") or []:
        lines.append(f"limit: {lim}")
    return lines
