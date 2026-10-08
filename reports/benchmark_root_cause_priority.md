# Root-Cause Priority — severity-weighted ranking of OPEN gaps

Generated 2026-10-07 11:24:24Z · register 132 rows · **78 open**

> This ranks documented gaps by impact-per-effort using the register's own fields. It does not estimate the probability that a gap causes harm, and two rows with identical fields may still deserve a different order. It narrows the field; it does not decide.

## The 20 rows that set the programme order

Priority band is a hard constraint; density orders WITHIN a band. Ranking by
density alone was measured and rejected: it put a P3 hygiene item first and
sank the accuracy-baseline row to 49 and CERT-In to 71 of 75.

| # | ID | P | impact | days | density | class | what |
|---:|---|---|---:|---:|---:|---|---|
| 1 | `G-079` | P0 | 103 | 5 | 20.6 | `ARCH_GAP` | Mandatory P0 baseline: 12 standards declared, 10 verify |
| 2 | `G-098` | P0 | 111 | 13 | 8.538 | `COVERAGE_GAP` | First measured accuracy baseline: BenchmarkJava recall ... |
| 3 | `G-073` | P1 | 93 | 2 | 46.5 | `SCHEMA_ALIGNMENT_GAP` | risk_category and severity disagree with no documented ... |
| 4 | `G-070` | P1 | 88 | 2 | 44.0 | `ARTIFACT` | 163 absolute scanner-host paths are disclosed in the ar... |
| 5 | `G-076` | P1 | 88 | 2 | 44.0 | `EVIDENCE_GAP` | Evidence validation benchmark fails TP_NOSQL_DYNAMIC_QU... |
| 6 | `G-088` | P1 | 88 | 2 | 44.0 | `MODEL_GAP` | NIST AI 100-2e2025 AML taxonomy added as a 12th mandato... |
| 7 | `G-091` | P1 | 88 | 2 | 44.0 | `ARTIFACT` | The shipped 19:14 artifact predates three shipped frame... |
| 8 | `G-130` | P1 | 95 | 5 | 19.0 | `COVERAGE_GAP` | ATLAS technique catalogue covers 42 of the 208 techniqu... |
| 9 | `G-054` | P1 | 92 | 5 | 18.4 | `MODEL_GAP` | ATT&CK techniques present without tactics, version pinn... |
| 10 | `G-095` | P1 | 92 | 5 | 18.4 | `COVERAGE_GAP` | juice-shop recall is 0.1121 against the declared challe... |
| 11 | `G-064` | P1 | 89 | 5 | 17.8 | `SCHEMA_ALIGNMENT_GAP` | compliance 'Observed Mappings' mixes two units and stat... |
| 12 | `G-094` | P1 | 88 | 5 | 17.6 | `EVIDENCE_GAP` | Corpus validation harness did not exist, and its first ... |
| 13 | `G-006` | P1 | 87 | 5 | 17.4 | `DISCOVERY_GAP` | Discovery precision 61.1% — 7 synthesised transitive de... |
| 14 | `G-062` | P1 | 85 | 5 | 17.0 | `WIRING_GAP` | 14 business-logic pattern rules are built but never imp... |
| 15 | `G-072` | P1 | 84 | 5 | 16.8 | `ARCH_GAP` | No dependency manifest and no HTTP surface, despite fou... |
| 16 | `G-011` | P1 | 75 | 5 | 15.0 | `RESOLUTION_GAP` | CBOM does not resolve mode, key size, or curve |
| 17 | `G-014` | P1 | 75 | 5 | 15.0 | `DATA_GAP` | No exploit / PoC availability intelligence |
| 18 | `G-016` | P1 | 75 | 5 | 15.0 | `SCOPE_GAP` | Git-history secret scanning absent |
| 19 | `G-039` | P1 | 56 | 5 | 11.2 | `SCHEMA_ALIGNMENT_GAP` | `correlate()` selects models and providers by identity ... |
| 20 | `G-059` | P1 | 96 | 13 | 7.385 | `PARSER_GAP` | Regex is the detection technique for every language exc... |

## Quick wins — highest density regardless of band

What can be closed cheaply, not what should lead. Useful for a spare
afternoon; not a programme order, for the reason measured above.

| # | ID | P | days | density | what |
|---:|---|---|---:|---:|---|
| 1 | `G-045` | P3 | 1 | **64.0** | EVIDEX sink catalogue is a second, hand-maintained sink list |
| 2 | `G-073` | P1 | 2 | **46.5** | risk_category and severity disagree with no documented relation... |
| 3 | `G-070` | P1 | 2 | **44.0** | 163 absolute scanner-host paths are disclosed in the artifact |
| 4 | `G-076` | P1 | 2 | **44.0** | Evidence validation benchmark fails TP_NOSQL_DYNAMIC_QUERY (6/7... |
| 5 | `G-088` | P1 | 2 | **44.0** | NIST AI 100-2e2025 AML taxonomy added as a 12th mandatory P0 st... |
| 6 | `G-091` | P1 | 2 | **44.0** | The shipped 19:14 artifact predates three shipped framework mod... |
| 7 | `G-074` | P2 | 2 | **40.0** | grouped[] is a full second 102-element copy of the finding sche... |
| 8 | `G-087` | P2 | 2 | **40.0** | The report pipeline prunes empty containers, so schema keys are... |
| 9 | `G-038` | P2 | 2 | **39.5** | 13 of 29 credential sites undetected - os.environ[...] bindings... |
| 10 | `G-058` | P2 | 2 | **38.0** | Two field names per framework: three declared twins never popul... |
| 11 | `G-068` | P2 | 2 | **37.5** | attack_paths and bom_correlation are empty while their status l... |
| 12 | `G-092` | P2 | 2 | **37.5** | ASVS is CC BY-SA 4.0; the requirement text was deliberately not... |

## Attack order, batched by root-cause class

Fixing a class once often closes several rows, and this is the actionable
sequence. `best density` is the strongest single row standing behind the batch.

| # | root-cause class | rows | days | best density | lead row | domains |
|---:|---|---:|---:|---:|---|---|
| 1 | `ARCH_GAP` | 5 | 33 | **20.6** | `G-079` | Conformance baseline, Repository hygiene, SAST / architecture |
| 2 | `COVERAGE_GAP` | 9 | 65 | **19.0** | `G-130` | Benchmark / measurement, Benchmark coverage, Compliance mapping |
| 3 | `SCHEMA_ALIGNMENT_GAP` | 6 | 32 | **46.5** | `G-073` | BOM correlation, Compliance mapping, MITRE ATLAS |
| 4 | `ARTIFACT` | 4 | 8 | **44.0** | `G-070` | Benchmark hygiene, Evidence / report integrity, Reporting integrity |
| 5 | `EVIDENCE_GAP` | 4 | 11 | **44.0** | `G-076` | Benchmark hygiene, Graph / reporting, Reporting integrity |
| 6 | `MODEL_GAP` | 13 | 146 | **44.0** | `G-088` | AI detection provenance, Attack graph, MITRE ATLAS |
| 7 | `DISCOVERY_GAP` | 1 | 5 | **17.4** | `G-006` | SBOM / SCA |
| 8 | `WIRING_GAP` | 4 | 22 | **33.5** | `G-060` | Detection wiring, Graph / reporting, Repository hygiene |
| 9 | `RESOLUTION_GAP` | 1 | 5 | **15.0** | `G-011` | Crypto (CBOM) |
| 10 | `DATA_GAP` | 3 | 15 | **15.0** | `G-014` | Threat intelligence, Vulnerability intelligence |
| 11 | `SCOPE_GAP` | 4 | 22 | **37.5** | `G-110` | Compliance mapping, Framework coverage, Secrets |
| 12 | `PARSER_GAP` | 2 | 43 | **7.385** | `G-059` | Detection engine, SAST / parsing |
| 13 | `RULE_GAP` | 2 | 18 | **7.385** | `G-101` | Detection accuracy, SAST / architecture |
| 14 | `STUB_GAP` | 1 | 13 | **7.0** | `G-009` | RCMSP |
| 15 | `ECOSYSTEM_GAP` | 1 | 13 | **6.308** | `G-007` | SBOM / SCA |

## Where the open work sits

| dimension | distribution |
|---|---|
| evidence tier | STRUCTURAL 38, MEASURED_OPEN 36, UNMEASURED 4 |
| priority | P2 39, P1 31, P3 6, P0 2 |
| root-cause class | MODEL_GAP 13, COVERAGE_GAP 9, SCHEMA_ALIGNMENT_GAP 6, ARCH_GAP 5, ARTIFACT 4, EVIDENCE_GAP 4, SCOPE_GAP 4, WIRING_GAP 4, FORMAT_GAP 3, DATA_GAP 3, TAINT_GAP 3, SOURCE_GAP 2, ENUM_GAP 2, PARSER_GAP 2, RULE_GAP 2, ALIAS_GAP 2, SINK_GAP 1, ASSIGNMENT_SHAPE_GAP 1, SEED_TABLE_INVENTION 1, DISCOVERY_GAP 1, RESOLUTION_GAP 1, STUB_GAP 1, ECOSYSTEM_GAP 1, SANITIZER_GAP 1, IDENTIFIER_GAP 1, GRANULARITY_GAP 1 |
| domain | Reporting integrity 5, MITRE ATLAS 4, SBOM / SCA 4, Repository hygiene 3, Compliance mapping 3, SAST / taint 3, Evidence / report integrity 2, Verification 2, Benchmark hygiene 2, Graph / reporting 2, Software supply chain 2, OWASP GenAI conformance 2, Vulnerability intelligence 2, Secrets 2, SAST / evidence 2, OWASP / framework conformance 2, Reachability 2, Detection accuracy 2, Risk modelling 2, SAST / architecture 2, Rule calibration 2, AI detection provenance 1, Secrets / SCA 1, Licensing / redistribution 1, Framework coverage 1, Coverage taxonomy 1, VEX 1, Conformance baseline 1, MITRE ATT&CK 1, Detection coverage 1, Detection wiring 1, Benchmark / measurement 1, Crypto (CBOM) 1, SBOM / CycloneDX export 1, SAST / false positives 1, Threat intelligence 1, BOM correlation 1, Detection engine 1, RCMSP 1, Attack graph 1, Validation coverage 1, Benchmark coverage 1, SAST / sanitizers 1, Supply-chain transparency 1, SAST / data flow 1, SAST / parsing 1, Research differentiator 1 |

Total estimated effort across all open rows: **588 engineer-days** across 78 rows. That is the sum of the register's own coarse
size labels, so treat it as an order of magnitude rather than a schedule.

