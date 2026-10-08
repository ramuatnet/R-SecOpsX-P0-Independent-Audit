# ATT&CK coverage benchmark

Root cause: G-054

Ground truth: MITRE ATT&CK for Enterprise, tactic list (15 tactics) (15 tactics), authored before inspection.

| property | value |
|---|---|
| distinct technique IDs in source | 27 |
| sub-technique IDs | 5 |
| ATT&CK tactic IDs (TA####) | 0 / 15 |
| ATT&CK version pinned | False |
| bundled ATT&CK dataset | False |
| sigma rule files | 0 |
| log_source tokens | 0 |
| findings carrying a technique | 21 / 102 |
| techniques reported | 7 |
| techniques on no finding (stale) | 0 |
| defaulted technique descriptions | 1 |

Technique IDs found: T1005, T1027, T1053, T1059, T1059.001, T1059.004, T1059.006, T1068, T1071, T1078, T1082, T1083, T1102, T1105, T1110, T1129, T1189, T1190, T1195, T1203, T1543.002, T1547.001, T1552, T1557, T1566, T1595, T1600

## Verdict

- v1_tactics_modelled: FAIL
- v2_version_pinned: FAIL
- v3_detection_mapping: FAIL
- v4_no_stale_technique: PASS
- v5_coverage_measurable: FAIL

## Honest limitation

This benchmark measures structure, not correctness. It can say whether a tactic model, a pinned version and a detection mapping exist; it cannot say whether the hardcoded technique IDs are correct ATT&CK assignments, because that requires the dataset.

Tactics never modelled as data: 15 of 15 absent.
