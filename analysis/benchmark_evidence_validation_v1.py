from __future__ import annotations

"""
R-SecOpsX EVIDEX / Evidence-Sink Validation Benchmark v1

Loads the production validator directly from core.analyzer.
It does not depend on analyzer_evidence_hardened_v1.py.

Supports both:
- current rich EVIDEX dict results
- older tuple/list results with at least 3 values
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import core.analyzer as mod


CASES = [
    ("FP_IMPORT_MASS_ASSIGNMENT", {
        "vuln_type": "mass_assignment",
        "detection": "Regex Pattern",
        "snippet": 'import {TicketModel} from "./model";',
        "taint_path": "",
    }, False),

    ("TP_TAINT_MASS_ASSIGNMENT", {
        "vuln_type": "mass_assignment",
        "detection": "TAINT-VALIDATED",
        "snippet": "const ticket = TicketModel.create(req.body);",
        "taint_path": "req.body -> TicketModel.create",
    }, True),

    ("FP_COMMENT_SSRF", {
        "vuln_type": "ssrf",
        "detection": "Regex Pattern",
        "snippet": "// requests.get(user_url) would be vulnerable",
        "taint_path": "",
    }, False),

    ("TP_SSRF_DYNAMIC_URL", {
        "vuln_type": "ssrf",
        "detection": "Regex Pattern",
        "snippet": "requests.get(user_url)",
        "taint_path": "user_url -> requests.get",
    }, True),

    ("FP_IMPORT_NOSQL", {
        "vuln_type": "nosql_injection",
        "detection": "Regex Pattern",
        "snippet": 'import {UserModel} from "./model";',
        "taint_path": "",
    }, False),

    ("TP_NOSQL_DYNAMIC_QUERY", {
        "vuln_type": "nosql_injection",
        "detection": "TAINT-VALIDATED",
        "snippet": "UserModel.findOne({username: req.body.username})",
        "taint_path": "req.body.username -> UserModel.findOne",
    }, True),

    ("SAFE_UNRELATED_FINDING", {
        "vuln_type": "debug_exposure",
        "detection": "Regex Pattern",
        "snippet": "app.run(debug=True)",
        "taint_path": "",
    }, True),
]


def _normalise_validation_result(result):
    if isinstance(result, dict):
        valid = bool(result.get("valid", False))
        reason = str(result.get("reason", ""))

        quality = result.get(
            "evidence_score",
            result.get("quality", result.get("evidence_quality", "")),
        )
        return valid, reason, quality

    if isinstance(result, (tuple, list)):
        if len(result) < 3:
            raise ValueError(
                f"Unsupported EVIDEX tuple result: expected >=3 values, "
                f"got {len(result)}"
            )
        return bool(result[0]), str(result[1]), result[2]

    raise TypeError(
        f"Unsupported EVIDEX result type: {type(result).__name__}"
    )


def main() -> int:
    print("=" * 80)
    print("R-SecOpsX EVIDEX / EVIDENCE-SINK VALIDATION BENCHMARK v1")
    print("=" * 80)

    validator = getattr(mod, "_validate_security_evidence", None)

    if validator is None:
        print()
        print("ERROR: _validate_security_evidence() is not present in")
        print("      core\\analyzer.py")
        return 1

    passed = 0

    for name, finding, expected in CASES:
        try:
            result = validator(finding)
            valid, reason, quality = _normalise_validation_result(result)
            ok = valid is expected
        except Exception as exc:
            valid = False
            reason = f"VALIDATOR ERROR: {type(exc).__name__}: {exc}"
            quality = ""
            ok = False

        passed += int(ok)

        print(
            f"{'PASS' if ok else 'FAIL'}  {name:<32} "
            f"expected={expected} actual={valid} quality={quality}"
        )
        print(f"      {reason}")

    print("-" * 80)
    print(f"Passed: {passed}/{len(CASES)}")
    print(f"Failed: {len(CASES) - passed}")

    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
