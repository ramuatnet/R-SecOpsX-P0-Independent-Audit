# Report-consistency benchmark

Corpus: OWASP Juice Shop (data/static/challenges.yml, 116 declared challenges)

Root causes: G-047, G-048, G-049, G-053

| property | before | after |
|---|---|---|
| findings | 1290 | 102 |
| owasp total | 1436 | 102 |
| owasp - findings delta | 146 | 0 |
| cross-aggregate delta | 146 | 0 |
| insight parity | False | True |
| severity insight parity (P5) | False | True |
| stale MITRE techniques | 0 | 0 |
| findings in withheld paths | 1165 | 0 |
| CONFIG_CONTEXTUAL_CREDENTIAL | 1225 | 37 |
| challenges covered | 13 | 13 |
| declared-intentional findings | 15 | 15 |
| challenge recall | 0.1121 | 0.1121 |

## Insight parity (claimed vs actual)

| insight | claimed before | claimed after | actual |
|---|---|---|---|
| ssrf | 9 | 6 | 6 |
| deserialization | 4 | 1 | 1 |
| secret | 141 | 3 | 3 |
| injection | 3 | 3 | 3 |

## Severity insight vs severity table (P5)

The severity table and `metadata.severity_distribution` both count SAST findings plus unique vulnerable dependency packages; the insight sentences were produced from the SAST-only population and, for the console and clean_report.json, were never normalised.

| sentence | claimed before | expected before | claimed after | expected after |
|---|---|---|---|---|
| high_risk | 2 | 4 | 4 | 4 |
| compliance_risk | 2 | 5 | 5 | 5 |

## Verdict

- p1: PASS
- p2: PASS
- p3: PASS
- p4: PASS
- p5: PASS

Preservation gate (P3): PASS - no ground-truth match lost
