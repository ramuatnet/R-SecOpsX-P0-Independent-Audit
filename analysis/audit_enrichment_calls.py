from pathlib import Path
import re

main = Path("main.py").read_text(encoding="utf-8")

patterns = [
    "enrich_kev_intelligence",
    "enrich_vulnerability_age",
    "enrich_legacy_protocol_intelligence",
    "enrich_exposure_surface_intelligence",
    "enrich_epss_intelligence",
    "enrich_exploitability_decision",
    "enrich_license_policy",
    "enrich_supply_chain_trust",
    "enrich_data_flow_sensitivity",
    "enrich_identity_access_risk",
    "enrich_business_logic_risk",
    "enrich_auth_hardening_risk",
    "enrich_auth_hardening_correlation",
    "enrich_data_flow_correlation",
    "enrich_identity_access_correlation",
    "enrich_business_logic_correlation",
    "enrich_framework_mappings",
    "enrich_runtime_artifact_integrity",
    "enrich_dependency_intelligence",
    "analyze_reachability",
]

print("=" * 70)
print("R-SecOpsX ENRICHMENT CALL-SITE AUDIT")
print("=" * 70)

for pattern in patterns:
    print("\n###", pattern)

    found = False

    for i, line in enumerate(main.splitlines(), start=1):
        if pattern in line:
            print(f"{i}: {line.strip()}")
            found = True

    if not found:
        print("NOT FOUND")

