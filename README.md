# R-SecOpsX

## Overview

R-SecOpsX is an offline, verification-driven multi-surface security
scanner: SAST (regex + taint + AST), SCA and SBOM/BOM generation, IaC
(Terraform / Kubernetes), secrets, container images, plus opt-in DAST,
external ASM, cloud posture, IAM and asset-graph analysis surfaces.

Every reported finding carries a UFIB verdict (disposition +
release eligibility with gate results and rationale), so a consumer can
always ask *why* a finding was reported and *whether* it is releasable.
The CLI banner prints the exact tool version, single-sourced from
`core/config.py::TOOL_VERSION`.

The build plan this repository implements lives in `task.md`; release
notes live in `RELEASE_NOTES.md`.

## Requirements

- Python >= 3.12 (see `pyproject.toml`).
- Scan mode needs **no third-party packages**: the product is
  stdlib-only at import time. Optional enrichers are extras and
  degrade gracefully when absent:
  - `yaml` extra -> PyYAML (rule/policy files; a built-in subset
    parser covers the offline default),
  - `pdf` extra -> reportlab,
  - `excel` extra -> openpyxl.
- Optional native engine (`--engine rust`) builds from `rust/` with a
  normal Rust toolchain; the default engine is pure Python and needs
  nothing extra.
- Optional Docker / kubectl CLIs only for the container-image flags.

## Quick start

```bash
# from a checkout, no install required
python main.py path/to/project

# or install the console script
pip install -e .
rsecopsx path/to/project
```

Reports land in `--output-dir` when given, otherwise in
`<target-parent>/reports/<project-name>/`.

## Usage

```bash
python main.py path/to/project --output-dir out/ --quiet --no-pdf --no-excel
python main.py path/to/project --fail-on high            # exit 1 above the bar
python main.py path/to/project --policy policy.yaml      # policy gate, same exit
python main.py path/to/project --explain-drops           # drops.json ledger
python main.py path/to/project --explain-verdict         # verdicts.json audit
python main.py path/to/project --telemetry               # telemetry.json
```

Key flags (see `python main.py --help` for the full list):

| Flag | Purpose |
| --- | --- |
| `--output-dir` / `-o` | where reports are written |
| `--workers` / `-w` | parallel scan workers |
| `--engine {py,rust}` | findings engine (default `py`) |
| `--fail-on {critical,high,medium}` | security-gate exit code |
| `--policy FILE` | policy-as-code gate (exclusions, SLA, evidence) |
| `--sbom FILE` / `--baseline FILE` | SBOM ingest / baseline diff |
| `--explain-drops` / `--explain-verdict` / `--telemetry` | structured side artifacts |
| `--html-embedded` | triage SPA beside the report |
| `--no-pdf` / `--no-excel` | skip the heavy renderers |
| `--quiet` / `--verbose` / `--debug` | log verbosity |
| `--max-memory-mb` / `--max-cpu-seconds` | resource budget (0 disables) |
| `--image-ref` / `--image-tar` | scan a local container image (opt-in) |
| `--dast-base-url` etc. | live DAST probing (opt-in, network) |

Exit codes: `0` scan completed and gates passed, `1` a gate failed
(security or policy), `2` usage error (bad flag, bad policy file,
unreadable credentials config).

## Output artifacts

- `clean_report.json` -- the canonical machine-readable report
  (findings, metadata, gates, release manifest).
- `Scan_Performance.json` -- stage timings for the run.
- `Security_*.json` / workbooks / PDFs -- SBOM, QBOM, CycloneDX,
  SPDX, VEX, SARIF, Excel and (unless skipped) PDF renderings.
- `drops.json` with `--explain-drops` -- every finding the filter
  pipeline removed, each with a machine-readable reason.
- `verdicts.json` with `--explain-verdict` -- per-finding UFIB
  verdict, gates and release eligibility.
- `telemetry.json` with `--telemetry` -- structured scan telemetry:
  stage timings, drop counts and regex timeouts in one artifact.
- `triage.html` with `--html-embedded` -- self-contained triage SPA.

Score explanations are a separate CLI surface:

```bash
python -m analysis.scoring.connect --finding findings.json --explain-score
```

`--explain-drops`, `--explain-score` and `--explain-verdict` are all
functional (task.md Definition of Done).

## Offline and airgap invariant

Heavy network stages are opt-in behind explicit flags (`--dast-*`,
`--asm-*`, `--cloud-*`, `--live-secrets`, image pulls) and injectable
for tests. Advisory/intel feeds are a separate class with per-stage
switches: EPSS/KEV/OSV enrichment and the Maven Central POM lookup
honour `RSECOPSX_LIVE_FEEDS` (default ON per the G-001 design),
HuggingFace hub metadata honours `RSX_HF_ENRICH` (default ON), and NVD
secondary enrichment honours `RSX_NVD_ENRICH` (default OFF). For a
zero-I/O run — the airgap mode — set:

```bash
export RSECOPSX_LIVE_FEEDS=0   # EPSS/KEV/OSV + Maven POM fetch
export RSX_HF_ENRICH=0         # HuggingFace hub metadata
unset RSX_NVD_ENRICH           # NVD secondary (already off by default)
```

With those set, a default scan performs **zero network I/O**: no
telemetry, no package installs, no lookups — the invariant is pinned
behaviourally by `tests/test_t15_dod.py`. Credentials are read in
exactly one place (`analysis/cloud/connect.py::resolve_credentials`);
DSNs and secrets are never echoed in errors. The same invariant makes
the tool usable in an airgapped environment straight from a checkout.

## Validation

The repository ships its own oracles; run them from the repo root:

```bash
# golden corpus (no flags -- the pinned expectation lives in the harness)
python -m analysis.validation.run

# deterministic replay: double-run byte-identical + manifest assertions
python -m analysis.validation.replay

# committed manifest freshness
python tools/emit_corpus_manifest.py --check

# full CI validation matrix (unit, corpus, parity, stability, ReDoS,
# self-SBOM, dead-code audit, native engine -- needs a Rust toolchain
# for the native gates)
python -m analysis.validation.ci_matrix

# external recall measurement against a BenchmarkJava checkout
python -m analysis.validation.owasp_benchmark --benchmark-dir path/to/BenchmarkJava

# the unit suite itself
python -m pytest tests/ -q
```

CI runs the same gates through `.github/workflows/validation.yml`.

## Project layout

| Path | Contents |
| --- | --- |
| `main.py` | CLI entry point and scan pipeline |
| `core/` | shared primitives: file walk, findings model, filters, budgets |
| `scanner/` | detection engines (regex, taint, AST, secrets, IaC, BOM) |
| `analysis/` | verdicts, validation harnesses, DAST/ASM/cloud/IAM/graph, serve |
| `reporting/` | renderers (PDF, Excel, HTML, export formats) |
| `scanner/rules/` | rule tables + schema + loader (`enterprise_v1.yaml`, `regex_v1.yaml`, `schema_v1.json`) |
| `tests/` | unit, gate, mutation and oracle tests |
| `tools/` | offline maintenance tools (manifest, SBOM, rule emitters) |
| `rust/` | optional native engine (walk + prefilter + regex crate) |
| `docs/` | design and analysis documents (linked below) |

## Documentation

- `task.md` -- the build plan this repository is implemented against.
- `RELEASE_NOTES.md` -- release history.
- `docs/accuracy_layer.md` -- accuracy / FP-CI layer design.
- `docs/ufib_acceptance_matrix.md` -- UFIB gate acceptance matrix.
- `docs/ufib_baseline_audit.md` -- baseline audit of verdict states.
- `docs/gap_analysis.md` -- capability gap analysis.
- `docs/rule_gap_analysis.md` -- rule coverage gaps.
- `docs/fp_root_causes.md` -- false-positive root causes.
- `docs/php_webshell_rules.md` -- PHP webshell rule notes.
- `docs/cross_tool_reference.md` -- comparison notes vs other tools.
- `docs/enterprise_capability_matrix.md` -- enterprise features.
- `docs/known_contract_conflicts.md` -- known contract conflicts.
- `docs/enterprise_web_ui_architecture.md` -- web UI architecture.

## License

Proprietary (see `license` in `pyproject.toml`). No LICENSE file is
published; redistribution terms come from the project owner.
