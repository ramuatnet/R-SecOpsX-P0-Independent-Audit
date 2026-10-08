# Mandatory P0 conformance baseline

**Baseline:** `p0-mandatory-baseline` v2026-10-01  
**Verified:** 11/12 (91.7%)  
**Artifact supplied:** yes

| Standard | Version | Status | Failed probes |
|---|---|---|---|
| `CWE` | CWE 4.20 | **VERIFIED** | - |
| `OWASP` | LLM Top 10 2025 (published) + 2026 (published 2026-08-04) | **VERIFIED** | - |
| `MITRE_ATLAS` | ATLAS release 2026.09 (format-version 6.0.0) | **VERIFIED** | - |
| `MITRE_ATTACK` | ATT&CK Enterprise 19.2 (pinned in core/attack_mappings.py, bundle SHA-256 recorded there) | **VERIFIED** | - |
| `NIST_AML` | AI 100-2e2025 (2025-03-24) | **VERIFIED** | - |
| `ASVS` | 4.0.3 (pinned in core/asvs_mappings.py, enumeration SHA-256 recorded there) | **VERIFIED** | - |
| `WSTG` | v4.2, catalogue pinned by digest in core/wstg_mappings.py | **VERIFIED** | - |
| `CERT_IN` | v2.0 (9 July 2025) | **NOT_VERIFIED** | `aibom_minimum_elements`, `hbom_emitted`, `csaf_emitted` |
| `RBI_FREE_AI` | Committee report, 13 August 2025 (7 Sutras / 6 pillars / 26 recommendations) | **VERIFIED** | - |
| `NIST_SSDF` | SP 800-218 v1.1 (2022-02-03) | **VERIFIED** | - |
| `SANS_AI` | v1.4 (March 2026), pinned by PDF SHA-256 in core/sans_mappings.py | **VERIFIED** | - |
| `SUPPLY_CHAIN` | CycloneDX + VEX + SPDX implemented; CSAF / SLSA absent | **VERIFIED** | - |

## Not verified

- **`CERT_IN`** — aibom_minimum_elements, hbom_emitted, csaf_emitted

> A passing baseline requires all eleven standards to verify. The gap is
> recorded rather than closed; no probe may be relaxed to make it green.
