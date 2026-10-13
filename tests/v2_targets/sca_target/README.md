# V2.2 SCA differential target

Synthetic manifest fixture for the live Grype/Trivy differential
(`analysis/differential.py`, technique plan V2.2).

Four packages, all pinned to exact versions carrying well-documented
advisories in OSV **and** in both peers' vulnerability databases, so all
three sides have something to compare:

| ecosystem | package | pinned | notable advisories |
|-----------|---------|--------|--------------------|
| PyPI | requests | 2.19.1 | CVE-2018-18074 (leaks Authorization header over HTTP) |
| PyPI | urllib3  | 1.24.1 | CVE-2019-11236 (CRLF injection), CVE-2019-11324 (cert validation) |
| npm  | lodash   | 4.17.15 | CVE-2019-10744 (critical prototype pollution), CVE-2020-8203, CVE-2021-23337 |
| npm  | minimist | 1.2.0 | CVE-2020-7598, CVE-2021-44906 (prototype pollution) |

`package-lock.json` is lockfileVersion 3 and carries the npm entries (the
lockfile pass supplies the exact version; a bare `package.json` range would
resolve to `unknown` and be skipped by the advisory query — see
`_resolve_npm_version`). No `node_modules` is needed or wanted.

The versions are intentionally **not** the latest-known-vulnerable: the
point is agreement across three independent matchers on identical inputs,
not maximum finding count.

## Run the differential

```bash
python main.py tests\v2_targets\sca_target -o <out> --no-pdf --no-excel
python -m analysis.differential --tool grype --target <out>\Security_CycloneDX.json --json
python -m analysis.differential --tool trivy --target <out>\Security_CycloneDX.json --json
```

Exit codes: 0 = no disagreements, 1 = disagreements remain unexplained
(needs triage; the runner never resolves them), 2 = BLOCKED (peer not
installed / target unreadable — never reported as agreement).

This directory is a scan target only. It is never a golden-corpus label;
nothing here feeds recall/FP numbers.
