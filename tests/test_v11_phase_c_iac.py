"""Phase C — Docker/IaC posture rules that closed gaps versus CodeSec.

  C1  DOCKER_MISSING_HEALTHCHECK — CodeSec's CKV_DOCKER_2 parity; V11 had no
      container-healthcheck control.
  C2  DOCKER_MAINTAINER_DEPRECATED — CKV_DOCKER_6 parity; MAINTAINER is a
      deprecated legacy instruction.
  C3  DOCKER_ADD_VS_COPY — CKV_DOCKER_4 parity; ADD of a LOCAL, non-archive
      file should be COPY (ADD only earns its keep for URLs and archives).
  C4  docker-compose scanning — compose files were never assessed (hardcoded
      creds, docker.sock mounts, privileged, unpinned images, missing user).
"""

from __future__ import annotations

from pathlib import Path

from scanner.iac_docker import scan_docker


def _ids(findings):
    return [f.get("rule_id") for f in findings]


# ---------------------------------------------------------------------------
# C1 — missing HEALTHCHECK
# ---------------------------------------------------------------------------

def test_docker_missing_healthcheck_flagged(tmp_path):
    d = tmp_path / "Dockerfile"
    d.write_text(
        "FROM python:3.12-slim\n"
        "RUN useradd -m app\n"
        "USER app\n"
        "CMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    assert "DOCKER_MISSING_HEALTHCHECK" in _ids(scan_docker(str(tmp_path)))


def test_docker_with_healthcheck_not_flagged(tmp_path):
    d = tmp_path / "Dockerfile"
    d.write_text(
        "FROM python:3.12-slim\n"
        "USER app\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1\n"
        "CMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    assert "DOCKER_MISSING_HEALTHCHECK" not in _ids(scan_docker(str(tmp_path)))


# ---------------------------------------------------------------------------
# C2 — deprecated MAINTAINER
# ---------------------------------------------------------------------------

def test_docker_maintainer_flagged(tmp_path):
    d = tmp_path / "Dockerfile"
    d.write_text(
        "FROM python:3.12-slim\n"
        "MAINTAINER Dev Team <dev@example.com>\n"
        "USER app\n",
        encoding="utf-8",
    )
    assert "DOCKER_MAINTAINER_DEPRECATED" in _ids(scan_docker(str(tmp_path)))


def test_docker_label_not_maintainer(tmp_path):
    d = tmp_path / "Dockerfile"
    d.write_text(
        "FROM python:3.12-slim\n"
        'LABEL maintainer="Dev Team <dev@example.com>"\n'
        "USER app\n",
        encoding="utf-8",
    )
    assert "DOCKER_MAINTAINER_DEPRECATED" not in _ids(scan_docker(str(tmp_path)))


# ---------------------------------------------------------------------------
# C3 — ADD of a local file should be COPY
# ---------------------------------------------------------------------------

def test_docker_add_local_file_flagged(tmp_path):
    d = tmp_path / "Dockerfile"
    d.write_text(
        "FROM python:3.12-slim\n"
        "USER app\n"
        "ADD requirements.txt /app/requirements.txt\n",
        encoding="utf-8",
    )
    assert "DOCKER_ADD_VS_COPY" in _ids(scan_docker(str(tmp_path)))


def test_docker_add_archive_or_url_not_flagged(tmp_path):
    # ADD is justified for auto-extracted archives and remote URLs.
    d = tmp_path / "Dockerfile"
    d.write_text(
        "FROM python:3.12-slim\n"
        "USER app\n"
        "ADD data.tar.gz /app/data/\n"
        "ADD https://example.com/artifact /app/artifact\n",
        encoding="utf-8",
    )
    assert "DOCKER_ADD_VS_COPY" not in _ids(scan_docker(str(tmp_path)))


def test_docker_copy_not_flagged(tmp_path):
    d = tmp_path / "Dockerfile"
    d.write_text(
        "FROM python:3.12-slim\n"
        "USER app\n"
        "COPY requirements.txt /app/requirements.txt\n",
        encoding="utf-8",
    )
    assert "DOCKER_ADD_VS_COPY" not in _ids(scan_docker(str(tmp_path)))


# ---------------------------------------------------------------------------
# C4 — docker-compose scanning
# ---------------------------------------------------------------------------

def test_compose_hardcoded_secret_and_socket(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  api:\n"
        "    image: myapp:latest\n"
        "    privileged: true\n"
        "    environment:\n"
        "      DB_PASSWORD: hunter2hunter2\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    from scanner.iac_compose import scan_compose
    ids = _ids(scan_compose(str(tmp_path)))
    assert "COMPOSE_HARDCODED_SECRET" in ids
    assert "COMPOSE_DOCKER_SOCKET_MOUNT" in ids
    assert "COMPOSE_PRIVILEGED" in ids
    assert "COMPOSE_UNPINNED_IMAGE" in ids


def test_compose_clean_not_flagged(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  api:\n"
        "    image: myapp:v1.2.3\n"
        "    user: \"1000:1000\"\n"
        "    environment:\n"
        "      DB_PASSWORD: ${DB_PASSWORD}\n"
        "    read_only: true\n",
        encoding="utf-8",
    )
    from scanner.iac_compose import scan_compose
    ids = _ids(scan_compose(str(tmp_path)))
    assert "COMPOSE_HARDCODED_SECRET" not in ids
    assert "COMPOSE_UNPINNED_IMAGE" not in ids
    assert "COMPOSE_PRIVILEGED" not in ids
