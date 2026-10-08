# ATLAS mapping reconciliation

**Benchmark:** `atlas-mapping-2026-10`  
**Dataset:** MITRE ATLAS 2026.09 (format-version 6.0.0)  
**Coverage floor:** 40% (regression guard, not a target)

## Properties

| Property | Status | Detail |
|---|---|---|
| `P1_every_live_rule_has_a_disposition` | **PASS** | 80 rule ids + 40 vuln types; undisposed=none |
| `P2_every_mapping_resolves_with_a_rationale` | **PASS** | catalogue=208 techniques; unresolved=none; bad_mode=none; no_rationale=none |
| `P3_llm_family_attributed_and_prompt_injection_resolves` | **PASS** | catalogue llm_prompt_injection -> AML.T0051 (DIRECT); scanner emitted a llm_prompt_injection finding=True |
| `P4_coverage_meets_declared_floor` | **PASS** | floor=0.40  advanced_ai=38/80 (0.475)  owasp_llm=16/40 (0.400)  combined=54/120 (0.450) |
| `P5_dataset_pin_present_and_fails_closed` | **PASS** | fail_closed=True  governance_gets_no_technique=True  every_emitted_finding_pinned=True  dataset=MITRE ATLAS 2026.09 (format-version 6.0.0) |

## Coverage

| Family | Mapped | Total | Ratio | Modes |
|---|---:|---:|---:|---|
| advanced AI (rule ids) | 38 | 80 | 0.475 | `{'DIRECT': 5, 'RELATED': 33, 'UNMAPPED': 42}` |
| OWASP LLM (vuln types) | 16 | 40 | 0.400 | `{'RELATED': 13, 'UNMAPPED': 24, 'DIRECT': 3}` |
| **combined** | **54** | **120** | **0.450** | |

## Open gaps (recorded, not suppressed)

- 42 advanced-AI rules and 24 OWASP LLM vuln types have **no** ATLAS technique. Each carries an explicit reason in `core/atlas_mappings.py`.
- The majority are governance, compliance and lifecycle obligations (bias assessment, fairness testing, model card, audit logging, kill switch). ATLAS models *adversary behaviour* and has no technique for a control gap. Assigning one would manufacture an adversary claim no evidence supports.
- Several are agentic (memory, multi-agent escalation, runtime tools). ATLAS 2026 explicitly defers agentic amplifications to the OWASP Top 10 for Agentic Applications.
- A small number are genuine near-misses: resource-exhaustion, citation suppression and grounding rules have plausible ATLAS techniques whose definitions were **not read** from the pinned content, so no attribution was claimed. Reading them would raise coverage; guessing them would be fabrication.
