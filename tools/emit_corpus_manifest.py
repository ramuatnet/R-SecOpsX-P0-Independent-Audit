#!/usr/bin/env python3
"""Emit the T-3.1 corpus manifest and its pinned SCA advisory store.

    python tools/emit_corpus_manifest.py            # write artifacts
    python tools/emit_corpus_manifest.py --check    # verify freshness

Reads the labels in tests/vuln-test-corpus/ (read-only -- this tool never
writes into the corpus) plus tests/replay/known_misses.json, and writes:

    tests/replay/manifest.json           content-addressed entries
    tests/replay/vuln_cache_pinned.json  offline SCA advisory subset

``--check`` rebuilds both in memory and byte-compares against the
committed files, exiting 1 on drift. That is what the test gate and ci
run; the write mode exists so a corpus change can refresh the artifacts
in the same commit (ground rule: baselines update together).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="verify committed artifacts instead of writing")
    parser.add_argument("--corpus", default=None,
                        help="corpus root (default: tests/vuln-test-corpus)")
    args = parser.parse_args(argv)

    from analysis.validation import manifest as manifest_mod

    if args.check:
        problems = manifest_mod.check_committed(
            corpus_root=Path(args.corpus) if args.corpus else None)
        for problem in problems:
            print("STALE: %s" % problem, file=sys.stderr)
        if problems:
            return 1
        print("manifest fresh: committed artifacts match a fresh build")
        return 0

    kwargs = {}
    if args.corpus:
        kwargs["corpus_root"] = Path(args.corpus)
    doc = manifest_mod.write_manifest(**kwargs)
    print("wrote tests/replay/manifest.json (%d entries)"
          % doc["entry_count"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
