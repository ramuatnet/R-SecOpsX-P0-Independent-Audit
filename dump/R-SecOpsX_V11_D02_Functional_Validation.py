from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(r"D:\data\Code test\R-SecOpsX_V11")
ENGINE_PATH = ROOT / "analysis" / "privacy_data_exposure_engine.py"


def load_engine():
    spec = importlib.util.spec_from_file_location("rsecopsx_privacy_d02_validation", ENGINE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load engine: {ENGINE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def get_pii_types(engine, text, path, target):
    helper = getattr(engine, "_privacy_pii_hits_fast", None)
    if helper is None:
        helper = getattr(engine, "_semantic_pii_hits", None)
    if helper is None:
        raise RuntimeError("No privacy PII helper found")
    hits = helper(text, path, target)
    return sorted({h[0] for h in hits}), hits


def run_case(engine, root, name, source, expected_types, expected_state=None):
    path = root / f"{name}.py"
    path.write_text(source, encoding="utf-8")

    result = engine.enrich_privacy_data_exposure(str(root))
    indicators = [
        x for x in result.get("indicators", [])
        if str(x.get("file", "")).endswith(path.name)
    ]

    detected = sorted({
        pii for item in indicators for pii in (item.get("pii_types") or [])
    })

    states = sorted({
        str(item.get("privacy_evidence_state"))
        for item in indicators
    })

    if expected_types:
        ok_detect = all(t in detected for t in expected_types)
    else:
        ok_detect = not detected

    ok_state = True if expected_state is None else expected_state in states

    return {
        "case": name,
        "expected_types": expected_types,
        "detected_types": detected,
        "expected_state": expected_state,
        "states": states,
        "indicators": len(indicators),
        "PASS": bool(ok_detect and ok_state),
    }


def main():
    print("=" * 72)
    print("R-SecOpsX V11 - D-02 FUNCTIONAL VALIDATION")
    print("READ-ONLY ENGINE VALIDATION / NO PRODUCTION SOURCE MODIFICATION")
    print("=" * 72)

    if not ENGINE_PATH.exists():
        raise SystemExit(f"[FAIL] Engine not found: {ENGINE_PATH}")

    engine = load_engine()
    print(f"[PASS] Loaded: {ENGINE_PATH}")

    # Keep test target outside tests/fixtures/docs/localization naming so the
    # production-context filter does not intentionally suppress these cases.
    with tempfile.TemporaryDirectory(prefix="RSECOPSX_D02_") as td:
        root = Path(td)
        print(f"[INFO] Ephemeral validation target: {root}")

        # Direct helper-level checks first.
        helper_cases = [
            ("email", "user_email = 'alice@example.com'", ["EMAIL"]),
            ("phone", "phone_number = '+14155552671'", ["PHONE"]),
            ("ssn", "ssn = '123-45-6789'", ["SSN"]),
            ("card", "card_number = '4111 1111 1111 1111'", ["PAYMENT_CARD"]),
            ("ipv4", "client_ip = '192.168.10.25'", []),
            ("ipv6", "client_ip = '2001:db8::25'", []),
        ]

        helper_rows = []
        probe = root / "helper_probe.py"
        for name, source, expected in helper_cases:
            detected, raw = get_pii_types(
                engine, source, probe, root
            )
            ok = all(x in detected for x in expected) and (
                bool(expected) or "IP_ADDRESS" not in detected
            )
            helper_rows.append({
                "case": name,
                "expected": expected,
                "detected": detected,
                "raw_hits": raw,
                "PASS": ok,
            })

        print("\n[HELPER TESTS]")
        for row in helper_rows:
            print(
                f"{'PASS' if row['PASS'] else 'FAIL':4} "
                f"{row['case']:8} expected={row['expected']} detected={row['detected']}"
            )

        # Whole-engine functional cases.
        cases = [
            (
                "positive_pii_observation",
                "user = {'email': 'alice@example.com', 'phone': '+14155552671', 'ssn': '123-45-6789'}\n",
                ["EMAIL", "PHONE", "SSN"],
                "OBSERVED_ONLY",
            ),
            (
                "payment_card",
                "payment = {'card_number': '4111 1111 1111 1111', 'cvv': '123'}\n",
                ["PAYMENT_CARD"],
                "OBSERVED_ONLY",
            ),
            (
                "benign_email_metadata",
                "contact_email = 'maintainers@example.org'\n# project maintainers contact\n",
                [],
                None,
            ),
            (
                "production_log_exposure",
                "def handler(user):\n    logger.info('customer email=%s', user.email)\n",
                ["EMAIL"],
                "EXPOSED",
            ),
            (
                "request_side_only",
                "def handler(request):\n    email = request.body.email\n    return email\n",
                ["EMAIL"],
                "OBSERVED_ONLY",
            ),
            (
                "third_party_transfer",
                "requests.post('https://example.invalid', json={'email': user.email})\n",
                ["EMAIL"],
                "EXPOSED",
            ),
        ]

        rows = []
        for name, source, expected, state in cases:
            rows.append(run_case(engine, root, name, source, expected, state))

        print("\n[ENGINE TESTS]")
        for row in rows:
            print(
                f"{'PASS' if row['PASS'] else 'FAIL':4} "
                f"{row['case']:26} expected={row['expected_types']} "
                f"detected={row['detected_types']} states={row['states']}"
            )

        # Explicit source inspection for redaction and NER implementation.
        source_text = ENGINE_PATH.read_text(encoding="utf-8", errors="replace")

        redaction_def = any(
            token in source_text
            for token in (
                "def redact(",
                "def redact_",
                "def mask(",
                "def mask_",
                "def sanitize_pii(",
                "def anonymize_pii(",
            )
        )

        ner_import = any(
            token in source_text.lower()
            for token in (
                "import spacy",
                "from spacy",
                "transformers",
                "namedentityrecognizer",
                "ner_model",
            )
        )

        ip_family = any(
            token in source_text
            for token in (
                '"IP_ADDRESS"',
                "'IP_ADDRESS'",
                '"IPV4"',
                "'IPV4'",
                '"IPV6"',
                "'IPV6'",
            )
        )

        print("\n[SOURCE CAPABILITY CHECK]")
        print(f"{'PASS' if redaction_def else 'GAP '} actual redaction callable: {redaction_def}")
        print(f"{'PASS' if ner_import else 'REVIEW'} NER implementation evidence: {ner_import}")
        print(f"{'PASS' if ip_family else 'GAP '} explicit IP PII family: {ip_family}")

        all_functional = all(x["PASS"] for x in helper_rows) and all(
            x["PASS"] for x in rows
        )

        report = {
            "schema_version": "D02_FUNCTIONAL_VALIDATION_V1",
            "engine": str(ENGINE_PATH),
            "production_source_modified": False,
            "helper_tests": helper_rows,
            "engine_tests": rows,
            "source_capability": {
                "actual_redaction_callable": redaction_def,
                "ner_implementation_evidence": ner_import,
                "explicit_ip_pii_family": ip_family,
            },
            "functional_gate": "PASS" if all_functional else "FAIL",
        }

        out = ROOT / "Working folder" / "D02_PII_Functional_Validation"
        out.mkdir(parents=True, exist_ok=True)
        report_path = out / "V11_D02_Functional_Validation.json"
        report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

        print("\n" + "=" * 72)
        print(f"FUNCTIONAL GATE: {report['functional_gate']}")
        print(f"EVIDENCE: {report_path}")
        print("Production source modified: FALSE")
        print("=" * 72)


if __name__ == "__main__":
    main()
