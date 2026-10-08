from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE = Path(__file__).with_name("analyzer_evidence_hardened_v1.py")

spec = importlib.util.spec_from_file_location("analyzer_evidence_hardened_v1", MODULE)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

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

def main() -> int:
    print("=" * 80)
    print("R-SecOpsX EVIDENCE / SINK VALIDATION BENCHMARK v1")
    print("=" * 80)
    passed = 0
    for name, finding, expected in CASES:
        valid, reason, quality = mod._validate_security_evidence(finding)
        ok = valid is expected
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
