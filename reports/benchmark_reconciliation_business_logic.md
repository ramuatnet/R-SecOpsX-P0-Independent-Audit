# Business-logic rules — dry run

Root cause: G-062

**Mode:** DRY RUN - the product pipeline was not modified and no finding was added to any report

Rule table: `D:\Data\Code test\R-SecOpsX_V11\quarantine\scanner\business_logic_patterns.py`  
Corpora: 2 · source files scanned: 746

Rules: **0/14 exercised** · total matches: **0**

| rule | severity | confidence | matches | files |
|---|---|---|---:|---:|
| BL_APPROVAL_BYPASS | High | MEDIUM | 0 | 0 |
| BL_CLIENT_CONTROLLED_AMOUNT | High | HIGH | 0 | 0 |
| BL_COUPON_MANIPULATION | High | MEDIUM | 0 | 0 |
| BL_DOUBLE_SPEND_RISK | Critical | MEDIUM | 0 | 0 |
| BL_IDEMPOTENCY_MISSING | High | MEDIUM | 0 | 0 |
| BL_INVENTORY_RACE_CONDITION | High | MEDIUM | 0 | 0 |
| BL_LIMIT_BYPASS | High | MEDIUM | 0 | 0 |
| BL_MISSING_BALANCE_CHECK | Critical | MEDIUM | 0 | 0 |
| BL_NEGATIVE_BALANCE_ALLOWED | High | HIGH | 0 | 0 |
| BL_NEGATIVE_QUANTITY_ALLOWED | High | HIGH | 0 | 0 |
| BL_REFUND_APPROVAL_BYPASS | High | MEDIUM | 0 | 0 |
| BL_ROLE_FROM_CLIENT | Critical | HIGH | 0 | 0 |
| BL_SKIP_PAYMENT | Critical | HIGH | 0 | 0 |
| BL_TRUSTED_CLIENT_STATUS | High | HIGH | 0 | 0 |

## Samples

## Verdict

- v1_rule_module_locatable: PASS
- v2_every_rule_exercised: FAIL

## Problems

- 14 of 14 rules matched nothing on these corpora, so their behaviour is unmeasured: ['BL_APPROVAL_BYPASS', 'BL_CLIENT_CONTROLLED_AMOUNT', 'BL_COUPON_MANIPULATION', 'BL_DOUBLE_SPEND_RISK', 'BL_IDEMPOTENCY_MISSING', 'BL_INVENTORY_RACE_CONDITION', 'BL_LIMIT_BYPASS', 'BL_MISSING_BALANCE_CHECK', 'BL_NEGATIVE_BALANCE_ALLOWED', 'BL_NEGATIVE_QUANTITY_ALLOWED', 'BL_REFUND_APPROVAL_BYPASS', 'BL_ROLE_FROM_CLIENT', 'BL_SKIP_PAYMENT', 'BL_TRUSTED_CLIENT_STATUS']

## Decision input

Match volume is a noise estimate, not a quality score. A high count here means wiring these rules would add findings that no ground truth currently validates -- which argues for measuring against a labelled corpus first, not for enabling them silently.
