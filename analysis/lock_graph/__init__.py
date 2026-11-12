"""Multi-ecosystem verified lockfile graph extraction (R2).

Common contract: `contract.py`. Dispatch: `registry.py`. The npm engine is
wrapped (never modified) by `npm_adapter.py`. Per-ecosystem extractors emit
the approved edge schema with VERIFIED/AMBIGUOUS/UNRESOLVED/UNSUPPORTED/
INVALID confidence; only VERIFIED edges ever join.
"""
