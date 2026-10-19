"""Run the OWASP aibom-generator's REAL validator and completeness scorer.

Invoked by analysis.validation.sbom_conformance's real-tool layer with
an external Python interpreter that has
``cyclonedx-python-lib[json-validation]`` installed (the extra the
upstream validator requires). ``RSX_AIBOM_GENERATOR`` must point at an
aibom-generator checkout (https://github.com/
GenAI-Security-Project/aibom-generator).

The upstream package's ``src/__init__.py`` imports fastapi/torch, which
validation never needs, so the two modules under test are loaded
standalone through a synthetic package shell. Prints one JSON object:
``cyclonedx_16_valid`` + ``errors`` from the upstream
``validate_aibom()``, and ``completeness_score`` from the upstream
``calculate_completeness_score()``.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import types
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(json.dumps({"error": "usage: aibom_generator_driver.py <aibom.json>"}))
        return 2
    aibom_path = Path(argv[0])
    root = Path(os.environ.get("RSX_AIBOM_GENERATOR", ""))
    if not root.is_dir():
        print(json.dumps({"error": "RSX_AIBOM_GENERATOR is not a directory: %s" % root}))
        return 2

    pkg = types.ModuleType("rsx_aibom_gen")
    pkg.__path__ = [str(root / "src")]
    sys.modules["rsx_aibom_gen"] = pkg
    for sub in ("utils", "models"):
        m = types.ModuleType("rsx_aibom_gen." + sub)
        m.__path__ = [str(root / "src" / sub)]
        sys.modules["rsx_aibom_gen." + sub] = m
    try:
        validation = importlib.import_module("rsx_aibom_gen.utils.validation")
        scoring = importlib.import_module("rsx_aibom_gen.models.scoring")
    except Exception as e:  # noqa: BLE001 -- evidence capture
        print(json.dumps({"error": "cannot import aibom-generator modules: %r" % e}))
        return 2

    try:
        aibom = json.loads(aibom_path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": "cannot read AIBOM: %r" % e}))
        return 2

    ok, errors = validation.validate_aibom(aibom)
    result = {"cyclonedx_16_valid": ok, "errors": errors}
    try:
        result["completeness_score"] = scoring.calculate_completeness_score(aibom)
    except Exception as e:  # noqa: BLE001 -- evidence capture
        result["completeness_score_error"] = repr(e)
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
