"""NuGet manifest and lock parsers (NuGet ecosystem).

Covers the three files a .NET solution actually declares dependencies in:

* ``*.csproj`` / ``*.fsproj`` -- ``<PackageReference Include="X" Version="Y">``
  (version attribute or nested ``<Version>`` element; absent version means the
  repo uses central package management and the pin lives in the props file).
* ``Directory.Packages.props`` -- central package management
  ``<PackageVersion Include="X" Version="Y" />`` catalog (stamped
  direct=False; the csproj rows carry the direct flag via the shared merge).
* ``packages.lock.json`` -- NuGet's own lockfile
  (``dependencies.<tfm>.<pkg>.resolved`` with a ``type`` of Direct/Transitive).

Version policy mirrors _resolve_pinned_version: an exact version (or the
bracket-exact ``[13.0.3]`` form) pins; ranges ``[13.0,14.0)``, ``13.*`` and
wildcards become ``unknown`` so the advisory query skips them rather than
guessing. semantic-kernel ships 155 csproj files that previously contributed
ZERO sbom rows because only requirements/package.json/pom were read.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.nuget_packages")

_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.\-+]+)?$")


def _pinned_version(spec: str):
    """Exact version -> itself; ranges/wildcards -> ``unknown``."""
    raw = str(spec or "").strip()
    if not raw or raw.lower() == "unknown":
        return "unknown"
    if raw.startswith("[") and raw.endswith("]") and "," not in raw:
        raw = raw[1:-1].strip()  # bracket-exact [13.0.3]
        if not raw:
            return "unknown"
    return raw if _EXACT_VERSION.fullmatch(raw) else "unknown"


def _localname(tag: str) -> str:
    """Element local name (strips any MSBuild XML namespace)."""
    return str(tag).rsplit("}", 1)[-1]


def _find_line(text: str, needle: str) -> int:
    m = re.search(re.escape(needle), text)
    return text[: m.start()].count("\n") + 1 if m else 1


def parse_nuget_csproj(filepath: str) -> list[dict]:
    """Parse ``PackageReference`` entries from a csproj/fsproj manifest."""
    import xml.etree.ElementTree as ET

    path = Path(filepath)
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        root = ET.fromstring(text)
    except Exception as exc:  # malformed manifest must not abort the scan
        _LOG.debug("csproj parse failed for %s: %s", filepath, exc)
        return []

    pkgs = []
    for el in root.iter():
        if _localname(el.tag) != "PackageReference":
            continue
        name = str(el.get("Include") or el.get("Update") or "").strip()
        if not name:
            continue
        version = str(el.get("Version") or "").strip()
        if not version:
            for child in el:
                if _localname(child.tag) == "Version":
                    version = str(child.text or "").strip()
                    break
        pkgs.append({
            "name": name,
            "version": _pinned_version(version),
            "ecosystem": "NuGet",
            "license": "unknown",
            "direct": True,
            "manifest_file": path.name,
            "manifest_line": _find_line(text, name),
        })
    return pkgs


def parse_nuget_packages_props(filepath: str) -> list[dict]:
    """Parse a central package management ``Directory.Packages.props``."""
    import xml.etree.ElementTree as ET

    path = Path(filepath)
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        root = ET.fromstring(text)
    except Exception as exc:
        _LOG.debug("props parse failed for %s: %s", filepath, exc)
        return []

    pkgs = []
    for el in root.iter():
        if _localname(el.tag) != "PackageVersion":
            continue
        name = str(el.get("Include") or "").strip()
        if not name:
            continue
        pkgs.append({
            "name": name,
            "version": _pinned_version(el.get("Version")),
            "ecosystem": "NuGet",
            "license": "unknown",
            "direct": False,
            "manifest_file": path.name,
            "manifest_line": _find_line(text, name),
        })
    return pkgs


def parse_nuget_lock(filepath: str) -> list[dict]:
    """Parse packages.lock.json (per-TFM resolved versions + directness)."""
    path = Path(filepath)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except Exception as exc:
        _LOG.debug("packages.lock.json parse failed for %s: %s", filepath, exc)
        return []
    if not isinstance(data, dict):
        return []

    pkgs = []
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        return []
    for tfm_pkgs in dependencies.values():
        if not isinstance(tfm_pkgs, dict):
            continue
        for name, meta in tfm_pkgs.items():
            if not isinstance(meta, dict):
                continue
            resolved = str(meta.get("resolved") or "").strip()
            pkgs.append({
                "name": str(name),
                "version": _pinned_version(resolved) if resolved else "unknown",
                "ecosystem": "NuGet",
                "license": "unknown",
                "direct": str(meta.get("type") or "").strip().lower() == "direct",
                "manifest_file": path.name,
                "manifest_line": 1,
            })
    return pkgs
