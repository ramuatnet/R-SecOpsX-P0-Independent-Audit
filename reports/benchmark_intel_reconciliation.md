# Benchmark reconciliation — threat-intelligence feeds

**Benchmark ID:** `intel-feeds-2026-10`  
**Generated:** 2026-10-06T09:02:14.505737+00:00  
**Corpus:** 80 CVE identifiers  
**Ground truth:** FIRST.org EPSS (79 rows) + CISA KEV catalog `2026.10.04` (1734 records), snapshot taken `2026-10-06T09:02:11.607224+00:00` **before** the product ran.

## What this measures

Wiring fidelity: R-SecOpsX reproduces both feeds exactly, labels every value with the provenance of its actual source, and never converts a miss into a number. It does not evaluate whether EPSS or KEV predict exploitation - the feeds are the reference by construction.

## EPSS — resolution coverage

| Mode | TP | FP | FN | Precision | Recall | F1 | Coverage |
|---|---:|---:|---:|---:|---:|---:|---:|
| offline | 8 | 0 | 71 | 1.0000 | 0.1013 | 0.1839 | 10.0% |
| live | 79 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 98.75% |

## EPSS — value fidelity against the reference

| Mode | Compared | Exact | Exact % | Mean abs error | Max abs error |
|---|---:|---:|---:|---:|---:|
| offline | 8 | 0 | 0.0 | 0.075839 | 0.19233 |
| live | 79 | 79 | 100.0 | 0.0 | 0.0 |

> Live-side fidelity is 1.0 **by construction** (the feed is the reference) and is a wiring check, not a forecasting claim. The substantive number is the offline row: that is how wrong the compiled-in seed table was against the same reference.

## CISA KEV — determination

| Mode | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| offline | 8 | 0 | 0 | 72 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| live | 8 | 0 | 0 | 72 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## Miss reconciliation (offline, by root cause)

| Root cause | Count |
|---|---:|
| `COVERAGE_GAP` | 71 |

**Total reconciled misses:** 71

## Decisions that move when the feed goes live

| Field | Changes |
|---|---:|
| `epss_bucket` | 73 |
| `epss_priority` | 11 |
| `kev_priority` | 0 |
| `kev_status` | 0 |

## Provenance correctness

- Offline run claimed `LIVE_FEED`: **no**
- Live-run provenance errors: **0**

## Sentinel — a never-issued identifier

`CVE-2099-999999` is not issued by any authority. Expected: no EPSS score, not in KEV.

| Mode | EPSS score | EPSS provenance | KEV |
|---|---|---|---|
| offline | `None` | `NOT_AVAILABLE` | `False` |
| live | `None` | `NOT_AVAILABLE` | `False` |

## Offline safety (`RSECOPSX_LIVE_FEEDS=0`)

- Pass: **True**
- Packages produced: 80
- `LIVE_FEED` claims: 0
- Reason reported: RSECOPSX_LIVE_FEEDS is disabled by the operator
