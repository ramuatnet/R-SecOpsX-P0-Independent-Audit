"""T-9.14 reproducible builds (task.md section 13).

Builds the rsecopsx wheel TWICE in two independent child processes
with a pinned environment (SOURCE_DATE_EPOCH / PYTHONHASHSEED=0 /
TZ=UTC / PYTHONDONTWRITEBYTECODE=1) and requires the two artifacts to
be byte-identical (sha256 equal) AND self-consistent (RECORD digests,
zip layout, metadata == pyproject) before the gate passes.

setuptools / the wheel package / ``python -m build`` (the PEP 517
path pyproject.toml declares) are NOT adopted by this gate: none of
the three is installed on this offline build host (pip 26.1.2 only),
and fetching them would break the offline/airgap invariant -- the
same named-tool precedent as petgraph/sigstore/cargo-fuzz.  This
module is the in-house offline equivalent: a PEP 427 wheel writer
whose determinism is structural -- sorted archive entries, fixed
SOURCE_DATE_EPOCH timestamps (values before the 1980 zip epoch are
clamped; zip cannot represent earlier), fixed compression level,
canonical METADATA/WHEEL/entry_points/RECORD generated from
pyproject.toml via stdlib tomllib, version single-sourced from
core.config.TOOL_VERSION.  pyproject keeps setuptools.build_meta for
environments that DO have setuptools; measured on this box: two
independent builds of the current tree are byte-identical and
``pip install --no-deps --no-index`` accepts the wheel.

Docker image reproducibility is NOT claimed: no image build runs on
this host (network base-image pull; t-9.9 already disclosed "image
build not executed"), and FROM-tag posture is pinned elsewhere by
tests/test_t99_deploy.py.  The wheel is a release artifact but is not
yet in release_attestation.DEFAULT_GLOBS -- disclosed, follow-up when
packaging is cut for distribution.

EXIT CODES:
    0  reproducible (both builds byte-identical and verified)
    1  not reproducible (sha mismatch or verification failed)
    2  could-not-run (missing pyproject/README/source, child failed)
"""
from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
import zipfile
from pathlib import Path

SCHEMA = "rsecopsx.reproducible_build/v1"
# Deterministic archive timestamp: 1980-01-01T00:00:00Z, the zip
# epoch (zipfile cannot encode anything earlier).
ZIP_MIN_EPOCH = 315532800
ZIP_MAX_EPOCH = 4354819199  # 2107-12-31T23:59:59Z (zip 2-byte limit)
DEFAULT_EPOCH = str(ZIP_MIN_EPOCH)
GENERATOR = "rsecopsx reproducible-build"
# The procedure's pinned environment; children inherit it verbatim.
REPRO_ENV = {
    "PYTHONHASHSEED": "0",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def _epoch_from_env(env: "dict | None" = None) -> int:
    env = os.environ if env is None else env
    raw = env.get("SOURCE_DATE_EPOCH") or DEFAULT_EPOCH
    try:
        epoch = int(raw)
    except (TypeError, ValueError):
        raise ValueError("SOURCE_DATE_EPOCH is not an integer")
    if epoch < ZIP_MIN_EPOCH:
        epoch = ZIP_MIN_EPOCH  # clamp to the zip epoch, documented
    if epoch > ZIP_MAX_EPOCH:
        raise ValueError("SOURCE_DATE_EPOCH beyond the zip 2107 limit")
    return epoch


def _epoch_date_time(epoch: int) -> "tuple[int, int, int, int, int, int]":
    return time.gmtime(epoch)[:6]


def wheel_filename(name: str, version: str) -> str:
    return "%s-%s-py3-none-any.whl" % (name, version)


def dist_info_dir(name: str, version: str) -> str:
    return "%s-%s.dist-info" % (name, version)


def _project_metadata(source_root: Path) -> "tuple[dict, dict]":
    """Read pyproject + README + TOOL_VERSION (no drift from declared
    packaging config)."""
    pyproject = source_root / "pyproject.toml"
    if not pyproject.is_file():
        raise ValueError("missing pyproject.toml under %s" % source_root)
    with open(pyproject, "rb") as fh:
        data = tomllib.load(fh)
    project = data.get("project") or {}
    for key in ("name", "description", "requires-python"):
        if not project.get(key):
            raise ValueError("pyproject missing project.%s" % key)
    readme_path = source_root / str(project.get("readme") or "README.md")
    if not readme_path.is_file():
        raise ValueError("missing readme %s" % readme_path.name)
    package_dirs = _package_dirs(source_root, data)
    from core.config import TOOL_VERSION
    return project, {
        "version": TOOL_VERSION,
        "readme": readme_path.read_bytes(),
        "package_dirs": package_dirs,
    }


def _package_dirs(source_root: Path, data: dict) -> "list[str]":
    """Top-level package dirs derived from pyproject's own
    ``[tool.setuptools.packages.find].include`` patterns -- no
    hardcoded layout.  Every include pattern MUST match an existing
    directory (a vanished package is a broken build, not a thin wheel).
    """
    includes = (((data.get("tool") or {}).get("setuptools") or {})
                .get("packages") or {}).get("find") or {}
    patterns = includes.get("include")
    if not patterns:
        raise ValueError(
            "pyproject missing [tool.setuptools.packages.find].include")
    top_dirs = sorted(c.name for c in source_root.iterdir()
                      if c.is_dir() and not c.name.startswith((".", "__")))
    dirs = []
    for pattern in patterns:
        hits = [d for d in top_dirs if fnmatch.fnmatch(d, pattern)]
        if not hits:
            raise ValueError(
                "package include pattern %r matched no directory"
                % pattern)
        dirs.extend(h for h in hits if h not in dirs)
    return dirs


def collect_entries(source_root: Path, project: dict, resolved: dict
                    ) -> "dict[str, bytes]":
    """All wheel members: package .py trees + main.py + dist-info.

    Sorted by construction; __pycache__ and non-.py files excluded
    (setuptools package discovery without package-data would include
    no data files either).
    """
    version = resolved["version"]
    entries: "dict[str, bytes]" = {}
    for pkg in resolved["package_dirs"]:
        pkg_root = source_root / pkg
        for f in sorted(pkg_root.rglob("*.py")):
            if "__pycache__" in f.parts:
                continue
            rel = f.relative_to(source_root).as_posix()
            entries[rel] = f.read_bytes()
    main_py = source_root / "main.py"
    if not main_py.is_file():
        raise ValueError("missing main.py")
    entries["main.py"] = main_py.read_bytes()

    dist = dist_info_dir(project["name"], version)
    entries[dist + "/METADATA"] = _metadata_bytes(project, resolved)
    entries[dist + "/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Generator: %s\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n" % GENERATOR
    ).encode("utf-8")
    scripts = project.get("scripts") or {}
    if scripts:
        lines = ["[console_scripts]"]
        for entry, target in sorted(scripts.items()):
            lines.append("%s = %s" % (entry, target))
        entries[dist + "/entry_points.txt"] = (
            "\n".join(lines) + "\n").encode("utf-8")
    entries[dist + "/RECORD"] = _record_bytes(entries, dist)
    return entries


def _metadata_bytes(project: dict, resolved: dict) -> bytes:
    lines = [
        "Metadata-Version: 2.1",
        "Name: %s" % project["name"],
        "Version: %s" % resolved["version"],
        "Summary: %s" % project["description"],
        "Requires-Python: %s" % project["requires-python"],
    ]
    license_obj = project.get("license")
    if isinstance(license_obj, dict) and license_obj.get("text"):
        lines.append("License: %s" % license_obj["text"])
    for author in project.get("authors") or []:
        if isinstance(author, dict) and author.get("name"):
            lines.append("Author: %s" % author["name"])
    for classifier in project.get("classifiers") or []:
        lines.append("Classifier: %s" % classifier)
    extras = project.get("optional-dependencies") or {}
    for extra in sorted(extras):
        lines.append("Provides-Extra: %s" % extra)
        for req in extras[extra]:
            lines.append('Requires-Dist: %s; extra == "%s"' % (req, extra))
    lines.append("Description-Content-Type: text/markdown")
    return ("\n".join(lines) + "\n\n").encode("utf-8") + resolved["readme"]


def _sha256_b64(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _record_bytes(entries: "dict[str, bytes]", dist: str) -> bytes:
    rows = []
    for arcname in sorted(entries):
        data = entries[arcname]
        rows.append("%s,sha256=%s,%d"
                    % (arcname, _sha256_b64(data), len(data)))
    rows.append("%s/RECORD,," % dist)
    return ("\n".join(rows) + "\n").encode("utf-8")


def build_wheel(source_root: "str | os.PathLike", out_path: "str | os.PathLike",
                *, epoch: "int | None" = None) -> str:
    """Write one wheel to out_path; return its sha256 hex.

    Deterministic: fixed timestamps, sorted entries, fixed compression
    level -- same inputs always produce identical bytes.
    """
    source_root = Path(source_root)
    if epoch is None:
        epoch = _epoch_from_env()
    project, resolved = _project_metadata(source_root)
    entries = collect_entries(source_root, project, resolved)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    date_time = _epoch_date_time(epoch)
    with zipfile.ZipFile(out_path, "w",
                         compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as zf:
        for arcname in sorted(entries):
            info = zipfile.ZipInfo(arcname, date_time=date_time)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, entries[arcname])
    return hashlib.sha256(out_path.read_bytes()).hexdigest()


def verify_wheel(path: "str | os.PathLike",
                 *, expect_version: "str | None" = None
                 ) -> "tuple[bool, str]":
    """Self-consistency: zip integrity, RECORD digests, layout rules."""
    path = Path(path)
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            if bad is not None:
                return False, "corrupt member %s" % bad
            names = zf.namelist()
            if names != sorted(names):
                return False, "archive entries not sorted"
            for name in names:
                if name.startswith("/") or "\\" in name or ":" in name \
                        or ".." in name.split("/"):
                    return False, "non-portable member path %s" % name
            dists = {n.split("/")[0] for n in names
                     if n.endswith("/RECORD")}
            if len(dists) != 1:
                return False, "expected exactly one RECORD, got %d" % len(dists)
            dist = dists.pop()
            record = zf.read(dist + "/RECORD").decode("utf-8")
            seen = set()
            for row in record.splitlines():
                if not row:
                    continue
                parts = row.split(",")
                if len(parts) != 3:
                    return False, "bad RECORD row %r" % row
                arcname, spec, size = parts
                seen.add(arcname)
                data = zf.read(arcname)  # KeyError -> invalid
                # Empty fields are legal (RECORD's own row uses ",,").
                if size and str(len(data)) != size:
                    return False, "size mismatch for %s" % arcname
                if spec.startswith("sha256="):
                    if _sha256_b64(data) != spec[len("sha256="):]:
                        return False, "digest mismatch for %s" % arcname
                elif spec:
                    return False, "unsupported digest spec for %s" % arcname
            if seen != set(names):
                return False, "RECORD does not cover the archive"
            if "pyproject.toml" in names or any(
                    n.startswith(("data/", "tests/", "dump/"))
                    for n in names):
                return False, "non-package content leaked into the wheel"
            metadata = zf.read(dist + "/METADATA").decode("utf-8")
            version = next(
                (ln.split(":", 1)[1].strip()
                 for ln in metadata.splitlines()
                 if ln.startswith("Version: ")), None)
            if expect_version is not None and version != expect_version:
                return False, "METADATA version %r != %r" % (
                    version, expect_version)
            times = {info.date_time for info in zf.infolist()}
            if len(times) != 1:
                return False, "mixed entry timestamps: %s" % sorted(times)
            if times.pop()[0] < 1980:
                return False, "entry timestamp before the zip epoch"
            return True, "ok (%d members)" % len(names)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        return False, "unreadable wheel: %s" % exc


def _child_env(epoch: int) -> "dict[str, str]":
    env = dict(os.environ)
    env.update(REPRO_ENV)
    env["SOURCE_DATE_EPOCH"] = str(epoch)
    return env


def _build_child(source_root: Path, out_path: Path, epoch: int) -> str:
    # cwd = the directory CONTAINING the analysis package (repo root in
    # dev, site-packages when installed) so `-m` resolves even when
    # --source points at a synthetic tree under test.
    package_root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, "-m",
         "analysis.validation.reproducible_build", "_one",
         "--source", str(source_root), "--out", str(out_path),
         "--epoch", str(epoch)],
        cwd=str(package_root), env=_child_env(epoch),
        capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError("build child failed rc=%d: %s"
                           % (proc.returncode,
                              (proc.stderr or proc.stdout).strip()[-400:]))
    return hashlib.sha256(out_path.read_bytes()).hexdigest()


def run_reproducible(source_root: "str | os.PathLike" = ".",
                     out_dir: "str | os.PathLike | None" = None
                     ) -> "tuple[bool, dict]":
    """Two independent child builds -> (identical_and_verified, info)."""
    source_root = Path(source_root).resolve()
    epoch = _epoch_from_env()
    project, resolved = _project_metadata(source_root)
    name = project["name"]
    version = resolved["version"]
    fname = wheel_filename(name, version)
    tmp_owned = out_dir is None
    base = Path(tempfile.mkdtemp(prefix="rsx_t114_build_")) \
        if out_dir is None else Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    try:
        sha1 = _build_child(source_root, base / "a" / fname, epoch)
        sha2 = _build_child(source_root, base / "b" / fname, epoch)
        wheel1 = base / "a" / fname
        wheel2 = base / "b" / fname
        ok1, why1 = verify_wheel(wheel1, expect_version=version)
        ok2, why2 = verify_wheel(wheel2, expect_version=version)
        identical = sha1 == sha2
        verified = ok1 and ok2
        info = {
            "schema": SCHEMA,
            "source": str(source_root),
            "wheel": fname,
            "version": version,
            "epoch": epoch,
            "sha256_build1": sha1,
            "sha256_build2": sha2,
            "identical": identical,
            "verified": verified,
            "verify1": why1,
            "verify2": why2,
            "kept_dir": None if tmp_owned else str(base),
        }
        return bool(identical and verified), info
    finally:
        if tmp_owned:
            import shutil
            shutil.rmtree(base, ignore_errors=True)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.validation.reproducible_build",
        description="T-9.14 reproducible builds: double-build the wheel "
                    "and require byte-identical output (setuptools NOT "
                    "adopted; offline in-house builder).")
    sub = parser.add_subparsers(dest="cmd")
    p_build = sub.add_parser("build", help="double-build and compare")
    p_build.add_argument("--source", default=".")
    p_build.add_argument("--out-dir", default=None,
                         help="keep both wheels here (default: temp, "
                              "removed after comparison)")
    p_build.add_argument("--json", action="store_true")
    p_one = sub.add_parser("_one", help=argparse.SUPPRESS)
    p_one.add_argument("--source", required=True)
    p_one.add_argument("--out", required=True)
    p_one.add_argument("--epoch", type=int, default=None)
    args = parser.parse_args(argv)

    if not args.cmd:
        parser.print_help()
        return 2

    if args.cmd == "_one":
        try:
            sha = build_wheel(args.source, args.out, epoch=args.epoch)
        except (OSError, ValueError) as exc:
            print("[REPRO] could-not-run: %s" % exc)
            return 2
        print(sha)
        return 0

    try:
        ok, info = run_reproducible(args.source, args.out_dir)
    except (OSError, ValueError, RuntimeError) as exc:
        print("[REPRO] could-not-run: %s" % exc)
        return 2
    if args.json:
        original = sys.stdout
        try:
            import io as _io
            wrapper = _io.TextIOWrapper(original.buffer, encoding="utf-8",
                                        errors="replace")
            sys.stdout = wrapper
            print(json.dumps(info, sort_keys=True))
            wrapper.flush()
        finally:
            sys.stdout = original
            try:
                wrapper.detach()
            except Exception:
                pass
    else:
        if not info["identical"]:
            verdict = "NOT REPRODUCIBLE"
        elif not info["verified"]:
            verdict = "REPRODUCIBLE BUT INVALID WHEEL"
        else:
            verdict = "REPRODUCIBLE"
        print("[REPRO] %s %s sha1=%s sha2=%s (verified=%s, epoch=%d, "
              "setuptools NOT adopted)"
              % (verdict, info["wheel"], info["sha256_build1"][:16],
                 info["sha256_build2"][:16], info["verified"],
                 info["epoch"]))
        if not info["identical"]:
            print("[REPRO] builds differ: %s vs %s"
                  % (info["sha256_build1"], info["sha256_build2"]))
        if not info["verified"]:
            print("[REPRO] verification failed: %s / %s"
                  % (info["verify1"], info["verify2"]))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
