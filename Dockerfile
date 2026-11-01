# syntax=docker/dockerfile:1
# R-SecOpsX scanner/API image -- task.md section 12 PHASE 9
# "docker-compose + helm".
#
# Offline contract: the Python package has ZERO required runtime deps;
# PyYAML is the one optional extra installed here because
# scanner/iac_compose.py imports it unguarded at module load
# (PRE-EXISTING, disclosed -- the image ships the optional extra so
# `python main.py` and compose/k8s scanning work inside the container).
#
# Security posture (pinned by tests/test_t99_deploy.py and enforced by
# our own IaC engines in that test): tagged base image (never :latest),
# non-root runtime uid, HEALTHCHECK on the open /v1/health route, EXPOSE
# 8080 only, no secrets in ENV/ARG, no remote ADD / shell pipes.
#
# Fail-closed default: serve refuses a non-loopback bind without an auth
# file (auth_required_for_non_loopback), so this CMD hardcodes
# --serve-host 0.0.0.0 together with --auth-file -- the container exits
# rc 2 (auth_file_unreadable) until the deployment mounts a real auth
# file at /etc/rsecopsx/auth.json.
FROM python:3.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .

# Optional extra imported unguarded by scanner/iac_compose.py (see above).
RUN python -m pip install --no-cache-dir PyYAML==6.0.3

# Runtime state root + auth mount point, owned by the non-root user.
RUN useradd --uid 10001 --no-create-home --user-group rsecopsx \
    && mkdir -p /var/lib/rsecopsx/out /etc/rsecopsx \
    && chown -R rsecopsx:rsecopsx /var/lib/rsecopsx /etc/rsecopsx

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/v1/health', timeout=5)"]

CMD ["python", "-m", "analysis.serve.connect", \
     "--serve", "--serve-host", "0.0.0.0", "--serve-port", "8080", \
     "--auth-file", "/etc/rsecopsx/auth.json", \
     "--db", "/var/lib/rsecopsx/rsecopsx.db", \
     "--out", "/var/lib/rsecopsx/out/clean_report.json"]
