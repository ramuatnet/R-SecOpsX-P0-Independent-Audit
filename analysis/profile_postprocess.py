import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

TARGET = r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64"

print("=" * 70)
print("R-SecOpsX POST-PROCESSING PROFILER")
print("=" * 70)
print("Target:", TARGET)
print()

from analysis.privacy_data_exposure_engine import (
    enrich_privacy_data_exposure,
)

from analysis.ioc_malware_intelligence_engine import (
    enrich_ioc_malware_intelligence,
)

from analysis.copyright_ip_compliance_engine import (
    analyze_copyright_ip_compliance,
)


def run_test(name, function):
    print(f"\n>> {name}")
    print("-" * 70)

    start = time.perf_counter()

    try:
        result = function()

        elapsed = time.perf_counter() - start

        print(f"Time   : {elapsed:.2f}s")
        print(f"Result : {type(result).__name__}")

        if isinstance(result, dict):
            interesting = (
                "total_privacy_indicators",
                "critical_privacy_indicators",
                "high_privacy_indicators",
                "third_party_transfer_indicators",
                "total_ioc_indicators",
                "critical_ioc_indicators",
                "high_ioc_indicators",
                "malware_behavior_indicators",
            )

            for key in interesting:
                if key in result:
                    print(f"{key}: {result[key]}")

        return result

    except Exception as exc:
        elapsed = time.perf_counter() - start

        print(f"FAILED after {elapsed:.2f}s")
        print(f"{type(exc).__name__}: {exc}")

        return None


# ------------------------------------------------------------------
# 1. Privacy Data Exposure
# ------------------------------------------------------------------

privacy_result = run_test(
    "Privacy Data Exposure",
    lambda: enrich_privacy_data_exposure(
        TARGET,
        findings=[],
        api_bom=[],
        data_flow_summary={},
    ),
)


# ------------------------------------------------------------------
# 2. IOC / Backdoor Intelligence
# ------------------------------------------------------------------

ioc_result = run_test(
    "IOC / Backdoor Intelligence",
    lambda: enrich_ioc_malware_intelligence(
        TARGET,
        findings=[],
        sbom=[],
    ),
)


# ------------------------------------------------------------------
# 3. Copyright / IP Compliance
# ------------------------------------------------------------------

copyright_result = run_test(
    "Copyright / IP Compliance",
    lambda: analyze_copyright_ip_compliance(
        TARGET,
    ),
)


print()
print("=" * 70)
print("PROFILING COMPLETE")
print("=" * 70)