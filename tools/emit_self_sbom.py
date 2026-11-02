"""SBOM of the scanner itself (task.md section 13 "SBOM of the scanner itself").

Emits a CycloneDX 1.5 JSON inventory of THIS repository's declared
supply chain and writes it to supplychain/rsecopsx_sbom.json.  Fully
offline: only committed repo files are read (pyproject.toml,
rust/Cargo.toml, rust/Cargo.lock, Dockerfile), no network I/O, no
third-party SBOM library -- stdlib tomllib + json only.

Determinism by construction:
* NO metadata.timestamp (nor any wall-clock/ageing key) anywhere in
  the document;
* serialNumber = uuid5 over the canonical sorted-components payload --
  content-bound: stable across runs, changes iff the inventory does;
* sort_keys serialization + components sorted by (name, purl).

Sources and scope:
* build-system.requires -> required components (the build chain);
* project.optional-dependencies -> optional components (scan mode has
  ZERO required runtime deps -- these are declared CONSTRAINTS, not a
  resolved lock: nothing is locked because nothing is required);
* rust/Cargo.lock -> every locked crate (direct AND transitive) at its
  RESOLVED version with its sha256 checksum; Cargo.toml [dependencies]
  marks the direct table via rsx:cargo_scope;
* Dockerfile FROM lines -> base image component(s).

CLI exit codes rc 0/1/2:
* default: regenerate and write the artifact (rc 0);
* --check: byte-compare a fresh generation against the committed
  artifact -- rc 0 when identical, rc 1 on drift or a missing file;
* rc 2 on could-not-run (missing/unreadable sources).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib
import uuid

_REPO = pathlib.Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from core.config import TOOL_VERSION  # noqa: E402  single-source (t114)

#: Default artifact location, relative to the repo root.
DEFAULT_REL = pathlib.Path("supplychain") / "rsecopsx_sbom.json"

# FROM [--platform=...] image[:tag|@digest] [AS name]
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$",
    re.IGNORECASE | re.MULTILINE)
# RUN ... pip install ... pkg==version   (image-pinned extras)
_PIP_PIN_RE = re.compile(
    r"pip install[^\n]*?\b([A-Za-z0-9._-]+)==([0-9][0-9A-Za-z._-]*)")
# PEP 508 style requirement -> (name, constraint)
_REQ_RE = re.compile(r"^([A-Za-z0-9._-]+)\s*(.*)$")


def _props(mapping: dict) -> list:
    """CycloneDX properties, keys sorted so list order is deterministic."""
    return [{"name": key, "value": str(val)}
            for key, val in sorted(mapping.items())]


def _split_req(req: str) -> tuple:
    match = _REQ_RE.match(str(req).strip())
    if not match:
        raise ValueError("unparsable requirement %r" % (req,))
    name, constraint = match.group(1), match.group(2).strip()
    return name, constraint


def _declared_str(value) -> str:
    """Cargo requirement -> string (int/float literal or version key)."""
    if isinstance(value, dict):
        return str(value.get("version", ""))
    return str(value)


def _python_components(pyproject: dict) -> list:
    components = []

    # build-system.requires -- required, the build chain.
    for req in pyproject.get("build-system", {}).get("requires", []):
        name, constraint = _split_req(req)
        components.append({
            "type": "library",
            "name": name,
            "version": constraint or "*",
            "purl": "pkg:pypi/%s" % name,
            "scope": "required",
            "properties": _props({"rsx:role": "build-system"}),
        })

    # project.optional-dependencies -- optional enrichers.  Deduped
    # across extras: one component per (name, constraint) carrying the
    # sorted list of extras that declare it.
    extras = pyproject.get("project", {}).get("optional-dependencies", {})
    seen: dict = {}
    for extra in sorted(extras):
        for req in extras[extra]:
            name, constraint = _split_req(req)
            key = (name, constraint)
            seen.setdefault(key, set()).add(extra)
    for (name, constraint), extra_names in seen.items():
        components.append({
            "type": "library",
            "name": name,
            "version": constraint or "*",
            "purl": "pkg:pypi/%s" % name,
            "scope": "optional",
            "properties": _props({"rsx:extras": ",".join(sorted(extra_names))}),
        })

    return components


def _cargo_components(cargo_toml: dict, lock: dict) -> list:
    direct = {}
    for table in ("dependencies", "build-dependencies", "dev-dependencies"):
        for name, spec in cargo_toml.get(table, {}).items():
            direct.setdefault(name, spec)

    components = []
    for pkg in lock.get("package", []):
        name = pkg.get("name", "")
        if name == "rsecopsx_core":
            continue  # the subject's native lib, covered by metadata
        checksum = pkg.get("checksum")
        comp = {
            "type": "library",
            "name": name,
            "version": pkg.get("version", ""),
            "purl": "pkg:cargo/%s" % name,
            "scope": "required",
            "properties": _props({
                "rsx:cargo_scope":
                    "direct" if name in direct else "transitive",
            }),
        }
        if checksum:
            comp["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        if name in direct:
            comp["properties"].append({
                "name": "rsx:declared_req",
                "value": _declared_str(direct[name]),
            })
        components.append(comp)

    # Direct table entries missing from the lock still belong in the
    # inventory (declared version, no resolved checksum).
    locked = {p.get("name") for p in lock.get("package", [])}
    for name in sorted(set(direct) - locked):
        spec = direct[name]
        components.append({
            "type": "library",
            "name": name,
            "version": _declared_str(spec) or "*",
            "purl": "pkg:cargo/%s" % name,
            "scope": "required",
            "properties": _props({
                "rsx:cargo_scope": "direct",
                "rsx:declared_req": _declared_str(spec),
                "rsx:unlocked": "true",
            }),
        })

    return components


def _dockerfile_components(dockerfile: str) -> list:
    components = []
    for match in _FROM_RE.finditer(dockerfile):
        ref = match.group(1)
        if "@" in ref:
            image, version = ref.split("@", 1)
        elif ":" in ref.rsplit("/", 1)[-1]:
            image, version = ref.rsplit(":", 1)
        else:
            image, version = ref, "latest"
        components.append({
            "type": "container",
            "name": image,
            "version": version,
            "purl": "pkg:docker/%s@%s" % (image, version),
            "scope": "required",
        })
    return components


def _apply_image_pins(components: list, dockerfile: str) -> None:
    """Annotate inventory entries the Dockerfile pins to an exact build."""
    pins = {name: version
            for name, version in _PIP_PIN_RE.findall(dockerfile)}
    if not pins:
        return
    for comp in components:
        pinned = pins.get(comp.get("name"))
        if pinned and str(comp.get("purl", "")).startswith("pkg:pypi/"):
            comp.setdefault("properties", []).append(
                {"name": "rsx:image_pin", "value": pinned})
            comp["properties"].sort(key=lambda p: p["name"])


def build_document(root) -> dict:
    """Build the CycloneDX dict purely from committed repo files."""
    root = pathlib.Path(root)
    pyproject = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8"))
    cargo_toml = tomllib.loads(
        (root / "rust" / "Cargo.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads(
        (root / "rust" / "Cargo.lock").read_text(encoding="utf-8"))
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")

    components = []
    components.extend(_python_components(pyproject))
    components.extend(_cargo_components(cargo_toml, lock))
    components.extend(_dockerfile_components(dockerfile))
    _apply_image_pins(components, dockerfile)
    components.sort(key=lambda c: (c.get("name", ""), c.get("purl", "")))

    # Content-derived serial: stable across runs, changes iff the
    # inventory does.  MUST match tests/test_t118_self_sbom.py.
    payload = json.dumps(components, sort_keys=True)
    serial = "urn:uuid:" + str(uuid.uuid5(
        uuid.NAMESPACE_URL, "rsecopsx/self-sbom/" + payload))

    requires_python = pyproject.get("project", {}).get(
        "requires-python", "")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": serial,
        "metadata": {
            "tools": [{"name": "emit_self_sbom"}],
            "component": {
                "type": "application",
                "name": pyproject.get("project", {}).get(
                    "name", "rsecopsx"),
                "version": TOOL_VERSION,
                "purl": "pkg:pypi/rsecopsx",
                "properties": _props(
                    {"rsx:requires-python": requires_python}),
            },
        },
        "components": components,
    }


def render_document(doc: dict) -> str:
    """Canonical bytes: sort_keys, 2-space indent, trailing newline."""
    return json.dumps(doc, indent=2, sort_keys=True,
                      ensure_ascii=True) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit or verify the repo's CycloneDX self-SBOM.")
    parser.add_argument("--check", action="store_true",
                        help="verify the committed artifact instead of "
                             "writing it (rc 0/1/2)")
    parser.add_argument("--path", default=None,
                        help="artifact path (default: %s under root)"
                             % DEFAULT_REL.as_posix())
    parser.add_argument("--root", default=None,
                        help="repo root to read sources from "
                             "(default: the tools/ parent)")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root) if args.root else _REPO
    out = (pathlib.Path(args.path) if args.path
           else root / DEFAULT_REL)

    try:
        fresh = render_document(build_document(root))
    except (OSError, KeyError, ValueError, tomllib.TOMLDecodeError) as exc:
        sys.stderr.write("self-sbom could-not-run: %s\n" % exc)
        return 2

    if args.check:
        try:
            on_disk = out.read_bytes()
        except FileNotFoundError:
            sys.stderr.write(
                "self-sbom drift: %s is missing -- run "
                "tools/emit_self_sbom.py\n" % out)
            return 1
        if on_disk != fresh.encode("utf-8"):
            sys.stderr.write(
                "self-sbom drift: %s differs from a fresh generation -- "
                "run tools/emit_self_sbom.py\n" % out)
            return 1
        count = len(json.loads(fresh)["components"])
        print("self-sbom ok: %s matches (%d components)" % (out, count))
        return 0

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(fresh.encode("utf-8"))
    count = len(json.loads(fresh)["components"])
    print("wrote %s (%d components)" % (out, count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
