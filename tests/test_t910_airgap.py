"""T-9.10 airgap install verified (task.md section 12 last line).

task.md §12 ends with "airgap install verified".  The verification was
run LIVE (2026-11-01, Docker 29.9.2): build -> docker save (~501 MiB
tar) -> docker rmi (images absent) -> docker load (restored) ->
docker compose up -> api container healthy + GET /v1/health -> 200;
profile postgres restart-loops with RSX_DB_PASSWORD unset (fail-closed,
postgres refuses an empty password) and goes healthy once the password
is provided; down -v leaves no containers/volumes/network.

The runbook (deploy/AIRGAP.md) is the committed product of that run --
these tests pin it against product drift: image tags, the health
endpoint, and the fail-closed db rule must stay in sync with
docker-compose.yml / Dockerfile, the offline invariants (no login/push/
:latest) must hold, and the secrets engine must stay clean over the
runbook.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
RUNBOOK = REPO / "deploy" / "AIRGAP.md"
COMPOSE = REPO / "docker-compose.yml"
DOCKERFILE = REPO / "Dockerfile"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """Collapse whitespace so prose needles survive line wrapping."""
    return " ".join(text.split())


def test_runbook_exists_with_verified_choreography():
    text = _read(RUNBOOK)
    for needle in (
        "docker build -t rsecopsx/api:0.1.0",
        "docker pull postgres:16.4-alpine",
        "docker save rsecopsx/api:0.1.0 postgres:16.4-alpine",
        "docker load -i airgap_images.tar",
        "docker compose up -d",
        "docker compose ps",
        "docker compose --profile postgres down -v",
        "127.0.0.1:8080/v1/health",
    ):
        assert needle in text, needle


def test_runbook_image_refs_match_compose_exactly():
    import yaml

    text = _read(RUNBOOK)
    doc = yaml.safe_load(_read(COMPOSE))
    api_image = doc["services"]["api"]["image"]
    db_image = doc["services"]["db"]["image"]
    assert api_image in text, api_image
    assert db_image in text, db_image
    # the save line must carry BOTH pinned images for a complete transfer
    save_line = [ln for ln in text.splitlines() if "docker save " in ln]
    assert save_line, "no docker save line"
    assert api_image in save_line[0] and db_image in save_line[0]


def test_runbook_health_endpoint_matches_dockerfile():
    text = _read(RUNBOOK)
    assert "/v1/health" in text
    assert "/v1/health" in _read(DOCKERFILE)


def test_runbook_pins_fail_closed_db_password_rule():
    text = _flat(_read(RUNBOOK))
    assert "RSX_DB_PASSWORD" in text
    assert "FAIL-CLOSED" in text
    # postgres refuses to initialise with an empty password -- the
    # restart-loop behaviour verified live
    assert "empty password" in text


def test_runbook_offline_invariants():
    text = _read(RUNBOOK).lower()
    assert "docker login" not in text
    assert "docker push" not in text
    assert ":latest" not in text
    for registry in ("docker.io", "ghcr.io", "quay.io", "registry-"):
        assert registry not in text, registry


def test_runbook_references_out_of_band_placeholders():
    text = _read(RUNBOOK)
    assert "deploy/auth.example.json" in text
    assert "deploy/env.example" in text


def test_runbook_documents_helm_static_validation():
    text = _flat(_read(RUNBOOK))
    assert "IfNotPresent" in text  # airgap never re-fetches a loaded image
    assert "helm BINARY was not available" in text
    assert "NOTES.txt" in text  # external Secret instructions stay canonical


def test_runbook_has_no_host_absolute_paths():
    bad_literals = ("/home/", "/Users/", "/c/Users", "/d/Users")
    drive = re.compile(r"(?<![A-Za-z])[A-Za-z]:[/\\]")
    text = _read(RUNBOOK)
    for lit in bad_literals:
        assert lit not in text, lit
    assert drive.search(text) is None


def test_secrets_engine_zero_over_runbook():
    from scanner.secret_intelligence import scan_secret_intelligence

    rows = scan_secret_intelligence(
        str(RUNBOOK))["secret_intelligence_findings"]
    assert rows == [], rows[:3]
