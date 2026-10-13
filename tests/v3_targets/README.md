# V3 differential targets

Synthetic fixtures for `analysis/validation/v3_differential.py` (secrets /
IaC / licence differentials vs gitleaks, kics, checkov, trivy, scancode).

Every credential here is FAKE and pattern-valid on purpose - the same
convention as `tests/vuln-test-corpus` (aws_credentials.py, github_token.py,
stripe_key.py). The harness compares detections; nothing here is a real
secret and none of it may ever be treated as one.

- `secrets_target/`  AWS key pair, GitHub PAT, Stripe key, URL credentials,
  PEM private-key block, plus a clean settings.ini as a negative.
- `iac_target/`      four classic Terraform misconfigurations (public S3,
  SSH open to 0.0.0.0/0, unencrypted EBS, wildcard IAM) + a Dockerfile
  with `:latest` and `USER root`.
- `license_target/`  composer.lock with DECLARED SPDX licences (the path
  that regressed once), requirements.txt and package.json where only
  our offline catalogue can resolve licences.
