"""FND-08: capture the three phase-gate artifacts with a SHA manifest.

    python tools/baseline.py [--out /tmp/r] [--dest tests/fixtures/baseline]

Copies the three artifacts ``python -m scanner.cli ... --formats
pdf,json,xlsx`` produces -- ``Security_Report.pdf``, ``clean_report.json``
and ``Security_Report.xlsx`` -- from a scan output directory into the
baseline fixture directory and writes ``manifest.json`` next to them::

    {
      "schema": "rsecopsx.baseline/v1",
      "artifacts": ["Security_Report.pdf", "clean_report.json",
                    "Security_Report.xlsx"],
      "files": {
        "Security_Report.pdf": {"sha256": "<hex>", "bytes": <int>},
        ...
      }
    }

``tools/report_audit.py <out_dir> --baseline`` then diffs any later scan
against this manifest (AUD-B01): identical bytes pass, a changed
artifact is reported by name with both digest prefixes.  Capture is
deliberately re-runnable -- an intentional report change moves the
reference by re-capturing from the policy scan output.

stdlib only; exits non-zero when any of the three artifacts is missing
or under the same 1 KiB floor the audit applies (a truncated capture
must never become the committed reference).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = Path("/tmp/r")
DEFAULT_DEST = REPO_ROOT / "tests" / "fixtures" / "baseline"

#: The three artifacts the phase-gate scan command produces.
ARTIFACTS = ("Security_Report.pdf", "clean_report.json",
             "Security_Report.xlsx")
#: Same non-trivial floor as report_audit.AUD-005/006.
MIN_ARTIFACT_BYTES = 1024
MANIFEST_SCHEMA = "rsecopsx.baseline/v1"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def capture(out_dir: Path, dest: Path) -> int:
    """Copy the three artifacts into ``dest`` and write the manifest.

    Returns 0 on success; 1 when any artifact is missing/truncated (the
    manifest is not written in that case -- a partial capture must never
    replace a good reference).
    """
    problems: list[str] = []
    for name in ARTIFACTS:
        src = out_dir / name
        if not src.is_file():
            problems.append(f"missing {name} in {out_dir}")
            continue
        size = src.stat().st_size
        if size < MIN_ARTIFACT_BYTES:
            problems.append(
                f"{name} is only {size} bytes "
                f"(expected >= {MIN_ARTIFACT_BYTES})")
    if problems:
        for msg in problems:
            print(f"baseline: {msg}", file=sys.stderr)
        print("baseline: capture aborted, manifest not written",
              file=sys.stderr)
        return 1

    dest.mkdir(parents=True, exist_ok=True)
    files: dict[str, dict] = {}
    for name in ARTIFACTS:
        src = out_dir / name
        shutil.copyfile(src, dest / name)
        files[name] = {
            "sha256": _sha256(dest / name),
            "bytes": (dest / name).stat().st_size,
        }
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "artifacts": list(ARTIFACTS),
        "files": files,
    }
    manifest_path = dest / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    for name in ARTIFACTS:
        print(f"captured {name}: {files[name]['sha256'][:12]}… "
              f"({files[name]['bytes']} bytes)")
    print(f"wrote {manifest_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/baseline.py",
        description="Capture the three phase-gate artifacts and write "
                    "tests/fixtures/baseline/manifest.json (FND-08).",
    )
    parser.add_argument(
        "--out", type=Path, default=DEFAULT_OUT,
        help="scan output directory to capture from (default: /tmp/r)")
    parser.add_argument(
        "--dest", type=Path, default=DEFAULT_DEST,
        help="baseline fixture directory to write (default: "
             "tests/fixtures/baseline)")
    args = parser.parse_args(argv)
    return capture(args.out, args.dest)


if __name__ == "__main__":
    sys.exit(main())
