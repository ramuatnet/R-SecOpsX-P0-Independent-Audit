import sys
from pathlib import Path

# Make project root importable when this script is executed as:
# py .\analysis\profile_real_pipeline.py
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import runpy
import time


TARGET = r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64"
MAIN = ROOT / "main.py"

PROFILE = []


def wrap(module, name):
    original = getattr(module, name)

    def timed(*args, **kwargs):
        start = time.perf_counter()

        result = original(*args, **kwargs)

        elapsed = time.perf_counter() - start
        PROFILE.append((name, elapsed))

        try:
            count = len(result) if isinstance(result, (list, dict, tuple, set)) else "-"
        except Exception:
            count = "-"

        print(
            f"       [PROFILE] {name:<42} "
            f"{elapsed:8.2f}s  result={count}"
        )

        return result

    setattr(module, name, timed)


# Import the actual modules used by main.py.
import analysis.framework_enrichment_engine as framework_mod
import scanner.dependency_intelligence as dependency_mod
import scanner.reachability as reachability_mod

import analysis.kev_intelligence_engine as kev_mod
import analysis.vulnerability_age_engine as age_mod
import analysis.legacy_protocol_engine as legacy_mod
import analysis.exposure_surface_engine as exposure_mod
import analysis.epss_intelligence_engine as epss_mod
import analysis.exploitability_decision_engine as exploit_mod
import analysis.license_policy_engine as license_mod
import analysis.copyright_ip_compliance_engine as copyright_mod
import analysis.supply_chain_trust_engine as trust_mod
import analysis.runtime_artifact_integrity_engine as runtime_mod

import analysis.data_flow_sensitivity_engine as dfs_mod
import analysis.data_flow_correlation_engine as dfc_mod

import analysis.privacy_data_exposure_engine as privacy_mod
import analysis.ioc_malware_intelligence_engine as ioc_mod

import analysis.identity_access_risk_engine as iar_mod
import analysis.identity_access_correlation_engine as iac_mod
import analysis.auth_hardening_risk_engine as ahr_mod
import analysis.auth_hardening_correlation_engine as ahc_mod

import analysis.ai_model_risk_engine as ai_mod
import analysis.business_logic_risk_engine as blr_mod
import analysis.api_abuse_risk_engine as api_mod
import analysis.business_logic_correlation_engine as blc_mod
import analysis.security_control_coverage_engine as coverage_mod
import analysis.crypto_misuse_engine as crypto_mod


FUNCTIONS = [
    (framework_mod, "enrich_framework_mappings"),
    (dependency_mod, "enrich_dependency_intelligence"),
    (reachability_mod, "analyze_reachability"),
    (kev_mod, "enrich_kev_intelligence"),
    (age_mod, "enrich_vulnerability_age"),
    (legacy_mod, "enrich_legacy_protocol_intelligence"),
    (exposure_mod, "enrich_exposure_surface_intelligence"),
    (epss_mod, "enrich_epss_intelligence"),
    (exploit_mod, "enrich_exploitability_decision"),
    (license_mod, "enrich_license_policy"),
    (copyright_mod, "analyze_copyright_ip_compliance"),
    (trust_mod, "enrich_supply_chain_trust"),
    (runtime_mod, "enrich_runtime_artifact_integrity"),
    (dfs_mod, "enrich_data_flow_sensitivity"),
    (dfc_mod, "enrich_data_flow_correlation"),
    (privacy_mod, "enrich_privacy_data_exposure"),
    (ioc_mod, "enrich_ioc_malware_intelligence"),
    (iar_mod, "enrich_identity_access_risk"),
    (iac_mod, "enrich_identity_access_correlation"),
    (ahr_mod, "enrich_auth_hardening_risk"),
    (ahc_mod, "enrich_auth_hardening_correlation"),
    (ai_mod, "enrich_ai_model_risk"),
    (blr_mod, "enrich_business_logic_risk"),
    (api_mod, "enrich_api_abuse_risk"),
    (blc_mod, "enrich_business_logic_correlation"),
    (coverage_mod, "enrich_security_control_coverage"),
    (crypto_mod, "enrich_crypto_misuse"),
]


for module, name in FUNCTIONS:
    if hasattr(module, name):
        wrap(module, name)
    else:
        print(
            f"[PROFILE] WARNING: "
            f"{module.__name__}.{name} not found"
        )


print("=" * 70)
print("R-SecOpsX TARGETED POST-PROCESSING PROFILER")
print("=" * 70)
print("Target:", TARGET)
print("Main  :", MAIN)
print("=" * 70)

sys.argv = ["main.py", TARGET]

try:
    runpy.run_path(str(MAIN), run_name="__main__")
finally:
    print("\n" + "=" * 70)
    print("POST-PROCESSING PROFILE SUMMARY")
    print("=" * 70)

    total = sum(t for _, t in PROFILE)

    for name, elapsed in sorted(
        PROFILE,
        key=lambda x: x[1],
        reverse=True
    ):
        print(f"{name:<42} {elapsed:8.2f}s")

    print("-" * 70)
    print(f"{'PROFILED TOTAL':<42} {total:8.2f}s")
