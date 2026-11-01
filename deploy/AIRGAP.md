# Airgap install runbook (task.md section 12 "airgap install verified")

Verified live on 2026-11-01 with Docker 29.9.2 (docker compose v2):
build -> save -> rmi (images absent) -> load -> compose up -> healthy
-> profile postgres up -> healthy -> down -v, zero registry access on
the offline side.  Every command below is the one that was run.

## Leg 1 -- build station (network allowed, done ONCE)

```sh
docker build -t rsecopsx/api:0.1.0 .
docker pull postgres:16.4-alpine     # only for the "postgres" profile
docker save rsecopsx/api:0.1.0 postgres:16.4-alpine -o airgap_images.tar
```

The tarball was ~501 MiB.  Transfer it (and this repository checkout)
to the offline host by any physical route.

## Leg 2 -- offline host (NO registry, NO pulls, NO rebuilds)

```sh
docker load -i airgap_images.tar
docker compose up -d                 # api only; uses the loaded image
```

Compose does not build or pull when the pinned image already exists
locally (verified: `up` started the loaded image with no build step).

Verify:

```sh
docker compose ps                     # rsecopsx-api-1 ... (healthy)
curl http://127.0.0.1:8080/v1/health
# -> {"schema": "rsecopsx.serve/v1", "status": "ok"}
```

/v1/health is deliberately OPEN (liveness must never depend on
credentials); every other route requires the Bearer token from the
mounted auth file.

## PostgreSQL profile (optional)

The db component is opt-in and FAIL-CLOSED: with `RSX_DB_PASSWORD`
unset the postgres entrypoint refuses to initialise with an empty
password and the container restart-loops without ever accepting a
connection (verified live).  Provide the password only via the
environment / `.env` (copy `deploy/env.example`):

```sh
RSX_DB_PASSWORD=CHOOSE_A_STRONG_PASSWORD docker compose --profile postgres up -d
# both containers report (healthy); tear down with:
docker compose --profile postgres down -v
```

The password never lives in docker-compose.yml -- a `${VAR:default}`
form at that key would be reported by the secrets engine as a hardcoded
configuration fallback, which is why the file interpolates the plain
`${RSX_DB_PASSWORD}`.

## Helm / Kubernetes

The chart (`deploy/helm/rsecopsx`) pins `pullPolicy: IfNotPresent`, so a
pre-loaded image is never re-fetched; `templates/NOTES.txt` documents the
same save/load step plus the external auth Secret.  The helm BINARY was
not available on the verification host, so `helm template` /
`helm install` were not executed -- the chart is validated statically
(YAML parse + our IaC/secrets engines + test contracts in
tests/test_t99_deploy.py).  Create the `<name>-auth` Secret
out-of-band as described in NOTES.txt before installing: the pod cannot
start without it (no `optional:` on the mount), and serve itself exits
rc2 without a readable auth file on a non-loopback bind.

## Rules this runbook keeps

* no registry sign-in, no image upload, no registry anywhere on the
  offline leg -- the offline invariant is the product's core property;
* image tags are pinned (`0.1.0`, `postgres:16.4-alpine`) -- never the
  `latest` tag;
* credentials are placeholders in-tree (`deploy/auth.example.json`,
  `deploy/env.example`) and replaced out-of-band, never committed.
