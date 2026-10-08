from pathlib import Path

p = Path("main.py")
s = p.read_text(encoding="utf-8")

# Backup
Path("main.py.before_profiling").write_text(s, encoding="utf-8")

# Add timing import
if "import time as _profile_time" not in s:
    marker = "import time\n"
    if marker in s:
        s = s.replace(marker, marker + "import time as _profile_time\n", 1)
    else:
        s = "import time as _profile_time\n" + s

# Add helper immediately before the main post-processing section.
helper = r'''

# ---------------------------------------------------------------------------
# R-SecOpsX PROFILING
# ---------------------------------------------------------------------------
_PROFILE_ENABLED = True

def _profile_call(name, fn, *args, **kwargs):
    if not _PROFILE_ENABLED:
        return fn(*args, **kwargs)

    t0 = _profile_time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = _profile_time.perf_counter() - t0

    try:
        if isinstance(result, list):
            count = len(result)
        elif isinstance(result, dict):
            count = len(result)
        elif isinstance(result, tuple):
            count = len(result)
        else:
            count = "-"
    except Exception:
        count = "-"

    print(f"       [PROFILE] {name:<38} {elapsed:8.2f}s  result={count}")
    return result

'''

# Insert before the first major post-processing call.
needle = 'payload["findings"] = enrich_framework_mappings(payload.get("findings", []))'

if helper not in s:
    if needle in s:
        s = s.replace(needle, helper + "\n" + needle, 1)
    else:
        raise SystemExit("Could not find post-processing insertion point.")

# Replace exact calls with profiling wrappers.
replacements = {
    'payload["findings"] = enrich_framework_mappings(payload.get("findings", []))':
        'payload["findings"] = _profile_call("Framework Enrichment", enrich_framework_mappings, payload.get("findings", []))',

    'payload["sbom"] = enrich_dependency_intelligence(payload.get("sbom", []))':
        'payload["sbom"] = _profile_call("Dependency Intelligence", enrich_dependency_intelligence, payload.get("sbom", []))',

    'payload["sbom"] = enrich_kev_intelligence(payload.get("sbom", []))':
        'payload["sbom"] = _profile_call("KEV Intelligence", enrich_kev_intelligence, payload.get("sbom", []))',

    'payload["sbom"] = enrich_vulnerability_age(payload.get("sbom", []))':
        'payload["sbom"] = _profile_call("Vulnerability Age", enrich_vulnerability_age, payload.get("sbom", []))',

    'payload["sbom"] = enrich_epss_intelligence(payload.get("sbom", []))':
        'payload["sbom"] = _profile_call("EPSS Intelligence", enrich_epss_intelligence, payload.get("sbom", []))',

    'payload["sbom"] = enrich_exploitability_decision(payload.get("sbom", []))':
        'payload["sbom"] = _profile_call("Exploitability Decision", enrich_exploitability_decision, payload.get("sbom", []))',

    'payload["sbom"] = enrich_license_policy(payload.get("sbom", []))':
        'payload["sbom"] = _profile_call("License Policy", enrich_license_policy, payload.get("sbom", []))',

    'payload["sbom"], payload["legacy_protocol_summary"] = enrich_legacy_protocol_intelligence(':
        'payload["sbom"], payload["legacy_protocol_summary"] = _profile_call("Legacy Protocol Intelligence", enrich_legacy_protocol_intelligence, ',

    'payload["sbom"], payload["exposure_surface_summary"] = enrich_exposure_surface_intelligence(':
        'payload["sbom"], payload["exposure_surface_summary"] = _profile_call("Exposure Surface Intelligence", enrich_exposure_surface_intelligence, ',

    'payload["sbom"], payload["supply_chain_trust_summary"] = enrich_supply_chain_trust(':
        'payload["sbom"], payload["supply_chain_trust_summary"] = _profile_call("Supply Chain Trust", enrich_supply_chain_trust, ',

    'payload["sbom"], payload["runtime_artifact_integrity_summary"] = enrich_runtime_artifact_integrity(':
        'payload["sbom"], payload["runtime_artifact_integrity_summary"] = _profile_call("Runtime Artifact Integrity", enrich_runtime_artifact_integrity, ',

    'payload["data_flow_sensitivity_summary"] = enrich_data_flow_sensitivity(':
        'payload["data_flow_sensitivity_summary"] = _profile_call("Data Flow Sensitivity", enrich_data_flow_sensitivity, ',

    'payload["data_flow_correlation_summary"] = enrich_data_flow_correlation(':
        'payload["data_flow_correlation_summary"] = _profile_call("Data Flow Correlation", enrich_data_flow_correlation, ',

    'payload["identity_access_risk_summary"] = enrich_identity_access_risk(':
        'payload["identity_access_risk_summary"] = _profile_call("Identity Access Risk", enrich_identity_access_risk, ',

    'payload["identity_access_correlation_summary"] = enrich_identity_access_correlation(':
        'payload["identity_access_correlation_summary"] = _profile_call("Identity Access Correlation", enrich_identity_access_correlation, ',

    'payload["auth_hardening_risk_summary"] = enrich_auth_hardening_risk(':
        'payload["auth_hardening_risk_summary"] = _profile_call("Auth Hardening Risk", enrich_auth_hardening_risk, ',

    'payload["auth_hardening_correlation_summary"] = enrich_auth_hardening_correlation(':
        'payload["auth_hardening_correlation_summary"] = _profile_call("Auth Hardening Correlation", enrich_auth_hardening_correlation, ',

    'payload["business_logic_risk_summary"] = enrich_business_logic_risk(':
        'payload["business_logic_risk_summary"] = _profile_call("Business Logic Risk", enrich_business_logic_risk, ',

    'payload["business_logic_correlation_summary"] = enrich_business_logic_correlation(':
        'payload["business_logic_correlation_summary"] = _profile_call("Business Logic Correlation", enrich_business_logic_correlation, ',
}

for old, new in replacements.items():
    if old in s:
        s = s.replace(old, new, 1)

p.write_text(s, encoding="utf-8")

print("Profiling instrumentation added.")
print("Backup: main.py.before_profiling")
