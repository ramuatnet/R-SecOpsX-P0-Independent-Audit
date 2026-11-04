# RSECOPSX_DOCKERFILE_NAME_COVERAGE_20261020
#
# The Lacework-vs-V11 comparison on Open-Assistant-main surfaced a file-coverage
# defect: Lacework/checkov assessed 12 Dockerfiles and returned 20 failed
# findings, while V11's Dockerfile engine produced a single finding from the one
# file literally named "Dockerfile". Open-Assistant (like most real repos)
# uses the Docker Hub convention ``Dockerfile.<role>``:
# Dockerfile.backend, Dockerfile.worker, Dockerfile.server, Dockerfile.safety,
# Dockerfile.website, Dockerfile.discord-bot, Dockerfile.model-training, ...
#
# The original enumeration helper only accepted the exact names dockerfile /
# dockerfile.dev / dockerfile.prod / dockerfile.production / dockerfile.test
# and the ``*.dockerfile`` suffix, so every ``Dockerfile.<role>`` file was
# never even opened -- a coverage hole, not a rule-precision trade-off.
# FND-02 inlined the enumeration into ``scan_docker`` (single-file targets
# yielded unconditionally, directory targets one index query with the
# ``_docker_candidate`` pred); these tests pin that contract end-to-end so
# the naming convention stays covered.
from pathlib import Path

from scanner.iac_docker import (
    DOCKER_SPECIAL_NAMES,
    _is_dockerfile,
    scan_docker,
)

REPO_DOCKERFILE = """
FROM python:3.10
ENV APP_PORT=8080
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
"""


def _mk(tmp_path: Path, name: str) -> Path:
    p = tmp_path / "docker" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(REPO_DOCKERFILE, encoding="utf-8")
    return p


def test_scan_docker_enumerates_role_named_variants(tmp_path):
    """End-to-end enumeration pin: every ``Dockerfile.<role>`` must be
    opened by ``scan_docker`` and reported (REPO_DOCKERFILE content fires
    missing-user + missing-healthcheck for each one)."""
    names = (
        "Dockerfile.backend",
        "Dockerfile.worker",
        "Dockerfile.server",
        "Dockerfile.safety",
        "Dockerfile.website",
        "Dockerfile.discord-bot",
        "Dockerfile.model-training",
        "Dockerfile.worker-full",
    )
    for name in names:
        _mk(tmp_path, name)

    findings = scan_docker(tmp_path)
    paths = {f.get("file") for f in findings}
    expected = {f"docker/{name}" for name in names}
    assert paths == expected, paths


def test_scan_docker_ignores_unrelated_files(tmp_path):
    """Unrelated names are not enumerated. FROM bodies on the decoys: if
    the enumeration leaked them, the content fallback would report them."""
    _mk(tmp_path, "Dockerfile.backend")
    (tmp_path / "notes.backend").write_text("FROM alpine\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# hi\nFROM alpine\n", encoding="utf-8")

    findings = scan_docker(tmp_path)
    paths = {f.get("file") for f in findings}
    assert paths == {"docker/Dockerfile.backend"}, paths


def test_special_names_keep_legacy_members():
    # The historical set must not regress while the prefix rule is added.
    assert {"dockerfile", "dockerfile.dev", "dockerfile.prod"} <= DOCKER_SPECIAL_NAMES


def test_is_dockerfile_accepts_role_name_and_from_fallback(tmp_path):
    p = _mk(tmp_path, "Dockerfile.backend")
    assert _is_dockerfile(REPO_DOCKERFILE, p)

    other = tmp_path / "build.script"
    other.write_text("FROM nothing\n", encoding="utf-8")
    # content fallback: a plain file whose body is a Dockerfile
    assert _is_dockerfile("FROM alpine\n", other)


def test_scan_docker_reports_findings_for_role_named_dockerfile(tmp_path):
    _mk(tmp_path, "Dockerfile.backend")
    findings = scan_docker(tmp_path)
    rules = {f.get("rule_id") for f in findings}
    # no USER + has CMD => missing-user and missing-healthcheck both fire
    assert "DOCKER_MISSING_USER" in rules, rules
    assert "DOCKER_MISSING_HEALTHCHECK" in rules, rules
    paths = {f.get("file") for f in findings}
    assert paths == {"docker/Dockerfile.backend"}, paths
