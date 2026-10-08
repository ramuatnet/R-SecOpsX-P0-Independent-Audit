from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.advanced_ai_security import (
    ADVANCED_AI_RULES,
    FILENAME_RULE_MAP,
    scan_advanced_ai_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_case(filepath: str, content: str) -> list[dict]:
    return scan_advanced_ai_file(filepath, content)


def rule_matches(rule_id: str, findings: list[dict]) -> bool:
    return any(
        str(f.get("rule_id", "")).upper() == rule_id.upper()
        for f in findings
    )


def first_matching_pattern(rule: dict) -> str | None:
    """
    Use the first declared regex pattern as the positive test seed.

    The benchmark deliberately derives its positive cases from the current
    scanner rule definitions so the benchmark remains synchronized with the
    implementation.
    """
    patterns = rule.get("patterns") or []
    if not patterns:
        return None

    # Patterns are regexes. For most rules the literal portion is sufficient
    # to exercise the scanner. Prefer the complete pattern when possible.
    pattern = patterns[0]

    # Convert common regex syntax into a harmless matching test string.
    replacements = (
        (r"\s*", " "),
        (r"\s+", " "),
        (r"\.", "."),
        (r"\(", "("),
        (r"\)", ")"),
        (r"\[", "["),
        (r"\]", "]"),
        (r"\?", "?"),
        (r"\+", "+"),
        (r"\*", "*"),
    )

    text = pattern
    for old, new in replacements:
        text = text.replace(old, new)

    # Remove regex alternation/grouping where possible.
    text = text.replace(".*", "test")
    text = text.replace(".+", "test")
    text = text.replace("^", "")
    text = text.replace("$", "")

    return text


# ---------------------------------------------------------------------------
# Heuristic benchmark
# ---------------------------------------------------------------------------

def benchmark_heuristics():
    results = []

    for rule in ADVANCED_AI_RULES:
        rule_id = str(rule.get("rule_id", "UNKNOWN"))
        pattern = first_matching_pattern(rule)

        if not pattern:
            results.append({
                "rule_id": rule_id,
                "expected": True,
                "detected": False,
                "status": "FN",
                "reason": "NO_PATTERN",
            })
            continue

        filepath = f"controlled_{rule_id}.py"
        content = f"# controlled positive case\n{pattern}\n"

        findings = run_case(filepath, content)
        detected = rule_matches(rule_id, findings)

        results.append({
            "rule_id": rule_id,
            "expected": True,
            "detected": detected,
            "status": "TP" if detected else "FN",
            "reason": "",
        })

    return results


# ---------------------------------------------------------------------------
# Filename-contract benchmark
# ---------------------------------------------------------------------------

def benchmark_contracts():
    results = []

    for filename, contract in FILENAME_RULE_MAP.items():
        rule_id = contract[0]

        # The scanner's contract mechanism only needs the expected filename.
        filepath = filename
        content = f"# controlled contract case\n{contract[3]}\n"

        findings = run_case(filepath, content)
        detected = rule_matches(rule_id, findings)

        results.append({
            "filename": filename,
            "rule_id": rule_id,
            "expected": True,
            "detected": detected,
            "status": "TP" if detected else "FN",
        })

    return results


# ---------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    (
        "negative_generic_ai.py",
        """
        model_name = "gpt"
        description = "AI application"
        response = model.generate(prompt)
        """,
    ),
    (
        "negative_safe_agent.py",
        """
        def send_email(recipient, message):
            return email_service.send(recipient, message)

        user_message = "hello"
        """,
    ),
    (
        "negative_safe_registry.py",
        """
        verify_checksum = True
        model_registry = "internal"
        signed_model = True
        """,
    ),
    (
        "negative_safe_vector.py",
        """
        vector_db = "internal"
        encrypted_embeddings = True
        acl_enabled = True
        """,
    ),
    (
        "negative_safe_runtime.py",
        """
        sandbox_enabled = True
        runtime_tool = "restricted"
        rate_limit = 100
        """,
    ),
    (
        "negative_safe_governance.py",
        """
        model_approval = True
        human_review = True
        audit_logging = True
        """,
    ),
    (
        "negative_safe_compliance.py",
        """
        ai_policy = "approved"
        risk_assessment = "completed"
        """,
    ),
    (
        "negative_safe_security.py",
        """
        adversarial_testing = True
        model_evasion_mitigated = True
        """,
    ),
    (
        "negative_safe_provider.py",
        """
        provider_name = "OpenAI"
        api_key_configured_from_environment = True
        """,
    ),
]


def benchmark_negatives():
    results = []

    all_rule_ids = {
        str(rule.get("rule_id", "")).upper()
        for rule in ADVANCED_AI_RULES
    }

    for filename, content in NEGATIVE_CASES:
        findings = run_case(filename, content)

        advanced_matches = [
            f for f in findings
            if str(f.get("rule_id", "")).upper() in all_rule_ids
        ]

        detected = bool(advanced_matches)

        results.append({
            "filename": filename,
            "expected": False,
            "detected": detected,
            "status": "FP" if detected else "TN",
            "findings": advanced_matches,
        })

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    heuristic = benchmark_heuristics()
    contracts = benchmark_contracts()
    negatives = benchmark_negatives()

    tp = sum(x["status"] == "TP" for x in heuristic)
    fn = sum(x["status"] == "FN" for x in heuristic)
    fp = sum(x["status"] == "FP" for x in negatives)
    tn = sum(x["status"] == "TN" for x in negatives)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    contract_tp = sum(x["status"] == "TP" for x in contracts)
    contract_fn = sum(x["status"] == "FN" for x in contracts)

    print("=" * 96)
    print("R-SecOpsX ADVANCED AI CONTROLLED BENCHMARK v1")
    print("=" * 96)

    print()
    print(f"Heuristic rules:       {len(ADVANCED_AI_RULES)}")
    print(f"Filename contracts:    {len(FILENAME_RULE_MAP)}")
    print(f"Negative controls:     {len(NEGATIVE_CASES)}")

    print()
    print("-" * 96)
    print("HEURISTIC DETECTION")
    print("-" * 96)

    print(f"TP: {tp}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")
    print(f"TN: {tn}")
    print(f"Precision:           {precision:.4f}")
    print(f"Recall:              {recall:.4f}")
    print(f"F1:                  {f1:.4f}")
    print(f"False-positive rate: {fpr:.4f}")

    print()
    print("-" * 96)
    print("FILENAME CONTRACT COVERAGE")
    print("-" * 96)

    print(f"Matched: {contract_tp}/{len(contracts)}")
    print(f"Missed:  {contract_fn}/{len(contracts)}")

    print()
    print("-" * 96)
    print("HEURISTIC CASE RESULTS")
    print("-" * 96)

    for result in heuristic:
        print(
            f"{result['status']:<3} "
            f"{result['rule_id']}"
        )

    print()
    print("-" * 96)
    print("CONTRACT CASE RESULTS")
    print("-" * 96)

    for result in contracts:
        print(
            f"{result['status']:<3} "
            f"{result['rule_id']:<45} "
            f"{result['filename']}"
        )

    print()
    print("-" * 96)
    print("NEGATIVE CONTROL RESULTS")
    print("-" * 96)

    for result in negatives:
        print(
            f"{result['status']:<3} "
            f"{result['filename']}"
        )

    print()
    print("=" * 96)
    print("RULE COVERAGE SUMMARY")
    print("=" * 96)

    heuristic_failures = [
        x for x in heuristic
        if x["status"] != "TP"
    ]

    if not heuristic_failures:
        print("All heuristic rules matched their controlled positive cases.")
    else:
        print(f"Heuristic failures: {len(heuristic_failures)}")
        for x in heuristic_failures:
            print(f"  {x['rule_id']} -> {x['status']}")

    contract_failures = [
        x for x in contracts
        if x["status"] != "TP"
    ]

    if not contract_failures:
        print("All filename contracts matched.")
    else:
        print(f"Contract failures: {len(contract_failures)}")
        for x in contract_failures:
            print(
                f"  {x['rule_id']} "
                f"({x['filename']}) -> {x['status']}"
            )


if __name__ == "__main__":
    main()