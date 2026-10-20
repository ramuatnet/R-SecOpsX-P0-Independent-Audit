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
# ``_iter_files`` only accepted the exact names dockerfile / dockerfile.dev /
# dockerfile.prod / dockerfile.production / dockerfile.test and the
# ``*.dockerfile`` suffix, so every ``Dockerfile.<role>`` file was never even
# opened -- a coverage hole, not a rule-precision trade-off. These tests pin
# the enumeration contract so the naming convention stays covered.
from pathlib import Path

from scanner.iac_docker import (
    DOCKER_SPECIAL_NAMES,
    _is_dockerfile,
    _iter_files,
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


def test_iter_files_yields_dockerfile_role_variants(tmp_path):
    for name in (
        "Dockerfile.backend",
        "Dockerfile.worker",
        "Dockerfile.server",
        "Dockerfile.safety",
        "Dockerfile.website",
        "Dockerfile.discord-bot",
        "Dockerfile.model-training",
        "Dockerfile.worker-full",
    ):
        _mk(tmp_path, name)

    found = sorted(p.name for p in _iter_files(tmp_path))
    assert found == sorted(
        [
            "Dockerfile.backend",
            "Dockerfile.discord-bot",
            "Dockerfile.model-training",
            "Dockerfile.safety",
            "Dockerfile.server",
            "Dockerfile.website",
            "Dockerfile.worker",
            "Dockerfile.worker-full",
        ]
    ), found


def test_iter_files_still_ignores_unrelated_files(tmp_path):
    _mk(tmp_path, "Dockerfile.backend")
    (tmp_path / "notes.backend").write_text("not a dockerfile", encoding="utf-8")
    (tmp_path / "README.md").write_text("# hi", encoding="utf-8")

    found = sorted(p.name for p in _iter_files(tmp_path))
    assert found == ["Dockerfile.backend"], found


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
