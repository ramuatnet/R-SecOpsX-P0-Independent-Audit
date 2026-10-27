# Rule Gap Analysis: codeshield vs R-SecOpsX

Reference: https://github.com/ne0psych/codeshield — **License: MIT** (permissive;
import permitted with attribution). Matched by CWE + language + sink semantics,
not by name or regex text. Full CSV: `accuracy/rule_gap_analysis.csv`.

## Verdict legend

- **(a) equivalent** — our rules already cover it at equal or better precision.
- **(b) theirs more precise / better idea** — imported as a validator or
  confirm/deny check inside the accuracy layer (never as an edit to a legacy rule).
- **(c) missing here** — added to `accuracy/rules_pack_cs.py` with a `CS_` id,
  **disabled by default**, positive+negative tests included.
- **(d) rejected** — low precision / not applicable; listed with the reason.

## SAST rules (16)

| Their rule | Ours | Verdict | Action |
|---|---|---|---|
| SAST-001 SQLi (python f-string/SELECT) | TAINT_SQL_INJECTION (+JS variant) | (a) | ours is taint-backed |
| SAST-002 Command injection | TAINT_CMDI | (a) | — |
| SAST-003 Hardcoded credentials (broad `password=` no entropy) | CONFIG_CONTEXTUAL_CREDENTIAL + GENERIC_* + secret engine value validation | **(d) reject** | broad keyword; ours validates the VALUE (formats/entropy/placeholder). Their *idea* (entropy gate) already ported into the accuracy layer |
| SAST-004 Path traversal (open+request) | TAINT_MULTIPART_TRAVERSAL, JAVA_J3_PATH_TRAVERSAL | (a) | — |
| SAST-005 XSS (innerHTML=/\.html\() | SAST-XSS | (a) | — |
| SAST-006 Weak crypto | CBOM, JAVA_J2_WEAK_RANDOM, CRYPTO_* | (a) | — |
| SAST-007 Insecure deserialization (pickle/yaml.load w/o Loader) | SAST-DESER, PYTHON_PICKLE_* | (a) | — |
| **SAST-008 Debug code (pdb/breakpoint/debugger)** CWE-489 | missing (we only flag Flask debug=True) | **(c) imported** | `CS_DEBUG_IN_PRODUCTION` (narrowed: pdb/breakpoint/debugger; console.log excluded as high-FP), **disabled** |
| SAST-009 SSRF (requests.get(...request.)) | TAINT_SSRF_EXPANDED | (a) | ours is taint-backed (more precise) |
| SAST-010 Open redirect | DOTNET/GO/EXPRESS/PHP_OPEN_REDIRECT | (a) | — |
| SAST-011 eval() with user input | EVAL_CALL | **(b) idea imported** | user-input coupling → the accuracy layer's taint/source-boundary confirm (eval near a request boundary = stronger) |
| SAST-012 random.* (python) | JAVA_J2_WEAK_RANDOM/CBOM | (a) | — |
| SAST-013 SQLi JS template literals | NODE_SQL_TEMPLATE_INTERPOLATION | (a) | — |
| SAST-014 Prototype pollution (`Object.assign` broad) | TAINT_PROTOTYPE_POLLUTION, NODE_PROTOTYPE_POLLUTION_MERGE | (a)/(d) | theirs matches any Object.assign — low precision; ours is taint-backed. Reject import |
| SAST-015 TLS verify=False/CERT_NONE | PY_TLS_CERT_VALIDATION_DISABLED, DOTNET_CERT_*, GO_TLS_INSECURE_SKIP_VERIFY | (a) | — |
| **SAST-016 Hardcoded internal IP** CWE-547 | missing | **(d) reject** | private IPs in configs are normal; high-FP, low value |

## Secrets patterns (14)

| Their pattern | Ours | Verdict | Action |
|---|---|---|---|
| SEC-001 AWS Access Key | AWS_ACCESS_KEY (AKIA/ASIA) | (a) | — |
| SEC-002 AWS Secret Key (+entropy 3.5) | AWS_SECRET_KEY | (a) | — |
| SEC-003 GitHub token ghp_ | GITHUB_TOKEN | (a) | — |
| SEC-004 Google API key AIza | GOOGLE_API_KEY | (a) | — |
| SEC-005/006/014 PEM RSA/EC/DSA/OPENSSH | Hardcoded Private Key / PRIVATE_KEY_HEADER | (a) | — |
| SEC-007 JWT | JWT_SIGNING_SECRET | (a) | — |
| SEC-008 Slack xox | SLACK_TOKEN | (a) | — |
| SEC-009 Stripe sk_live | STRIPE_SECRET_KEY | (a) | — |
| SEC-010 Generic secret | SPRING_DATASOURCE_PASSWORD + generic engine (value-validated) | (a) | — |
| SEC-011 DB connection string with creds | STRUCTURED_CONNECTION_CREDENTIAL / DATABASE_URL_CREDENTIALS / JDBC_URL_CREDENTIALS | (a) | — |
| **SEC-012 Bearer token** | missing | **(c) imported** | `CS_BEARER_TOKEN`, **disabled** |
| SEC-013 Generic API key | GENERIC_API_KEY_PASSWORD | (a) | — |

## Non-rule ideas

| Their idea | Ours | Verdict | Action |
|---|---|---|---|
| **Shannon entropy gate** for generic secrets | validated_live only | **(b) ported** | accuracy layer secret validator (`_shannon_entropy`, attribution in code + here) |
| `is_minified` / `is_test` file scoping | nonproduction gates + partial minified guard | **(b) ported** | accuracy layer minified heuristics (name/longest-line/whitespace-ratio) |
| Aho-Corasick pre-filter | n/a (engine-coupled) | (d) reject | performance idea; touching the engine is forbidden by this mission's constraints |
| Eval-with-user-input coupling | n/a | **(b) ported** | source-boundary confirm in the accuracy layer |
| API-security plugin (broad keyword) | api_abuse engine + authz/rate-limit rules | (d) reject | broad keyword patterns below our precision bar |

## Summary

- Imported as **(c) new CS_ rules (disabled)**: `CS_BEARER_TOKEN`, `CS_PRIVATE_KEY_BLOCK`, `CS_DEBUG_IN_PRODUCTION`.
- Ported as **(b) validators**: entropy gate, minified/test scoping, eval-coupling confirm.
- **Rejected (d)** with reasons: SAST-003, SAST-014 (broad shape), SAST-016, API-security keyword plugin, Aho-Corasick (engine coupling).
- Everything else: **(a) equivalent** — no action.
