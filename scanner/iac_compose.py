"""docker-compose / Compose file IaC scanning.

Compose files were previously never assessed: the AI-benchmark comparison
found AgentGPT's docker-compose.yml carried a hardcoded ``REWORKD_PLATFORM_DB_PASS``
and autogen mounted ``/var/run/docker.sock``, and CodeSec's own export confirmed
compose was skipped entirely. This module closes that gap with five posture
controls, reusing the docker finding schema and the target-relative report-path
contract (scanner/iac_docker.py::_report_path).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from scanner.iac_docker import _priority, _report_path
# T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
from core import file_index

# Compose file name patterns: docker-compose.yml, docker-compose.override.yml,
# docker-compose.prod.yml, compose.yml, compose.yaml, compose.override.yaml, ...
_COMPOSE_NAME_RE = re.compile(
    r"^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$", re.IGNORECASE
)

_SECRET_NAME_RE = re.compile(
    r"PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|CREDENTIAL",
    re.IGNORECASE,
)

_ARCHIVE_SKIP = None  # reserved

COMPOSE_RULES: dict[str, dict[str, Any]] = {
    "COMPOSE_HARDCODED_SECRET": {
        "title": "Hardcoded Credential In docker-compose Environment",
        "severity": "High",
        "description": "A service environment variable carries a literal secret value instead of a runtime reference.",
        "remediation": "Use an environment reference like ${VAR} or an orchestrator secrets mechanism instead of a literal value.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    "COMPOSE_DOCKER_SOCKET_MOUNT": {
        "title": "Docker Socket Mounted Into Container",
        "severity": "High",
        "description": "The service mounts the host Docker socket (/var/run/docker.sock), which yields root-equivalent control of the host.",
        "remediation": "Remove the docker.sock mount. Use a scoped API proxy or a dedicated sidecar if Docker control is required.",
        "cwe": "CWE-250",
        "framework": "CIS Docker Benchmark",
        "control": "Container Escape Reduction",
    },
    "COMPOSE_PRIVILEGED": {
        "title": "Service Runs In Privileged Mode",
        "severity": "High",
        "description": "privileged: true disables container isolation and grants near-root host capabilities.",
        "remediation": "Remove privileged: true and grant only the specific capabilities the service needs via cap_add.",
        "cwe": "CWE-250",
        "framework": "CIS Docker Benchmark",
        "control": "Least Privilege",
    },
    "COMPOSE_UNPINNED_IMAGE": {
        "title": "Service Image Not Pinned To A Version",
        "severity": "Low",
        "description": "The service image uses the mutable latest tag or no tag/digest, so builds are not reproducible.",
        "remediation": "Pin the image to an immutable version tag or digest (image: repo:v1.2.3 or repo@sha256:<digest>).",
        "cwe": "CWE-1104",
        "framework": "CIS Docker Benchmark",
        "control": "Image Version Pinning",
    },
    "COMPOSE_MISSING_USER": {
        "title": "Service Does Not Run As A Non-Root User",
        "severity": "Medium",
        "description": "The service defines no user: directive, so the container process may run as root.",
        "remediation": "Add a user: \"<uid>:<gid>\" directive so the service runs as a non-root user.",
        "cwe": "CWE-250",
        "framework": "CIS Docker Benchmark",
        "control": "Least Privilege Container User",
    },
}


def _is_compose_file(path: Path) -> bool:
    return bool(_COMPOSE_NAME_RE.match(path.name))


def _iter_compose_files(target: Path):
    if target.is_file():
        if _is_compose_file(target):
            yield target
        return
    # T-0.2: index query replaces target.rglob. This engine used to apply
    # NO directory skip at all; the shared union policy now covers it.
    yield from file_index.index_for(target).files(pred=_is_compose_file)


def _find_line(lines: list[str], start: int, end: int, pattern: re.Pattern) -> int | None:
    """Return the 1-based line of the first match of pattern within [start, end)."""
    for i in range(start, min(end, len(lines))):
        if pattern.search(lines[i]):
            return i + 1
    return None


def _service_block_bounds(lines: list[str], service: str) -> tuple[int, int]:
    """Find the [start, end) line range of a top-level service block by indent."""
    header = re.compile(rf"^\s{{2,}}{re.escape(service)}:\s*(?:#.*)?$")
    start = None
    base_indent = None
    for i, line in enumerate(lines):
        if start is None:
            if header.match(line):
                start = i
                base_indent = len(line) - len(line.lstrip())
        else:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent:
                return (start, i)
    return (start, len(lines)) if start is not None else (0, len(lines))


def _env_pairs(env: Any) -> list[tuple[str, str]]:
    """Normalize a compose environment value (map or list) to (key, value) pairs."""
    pairs: list[tuple[str, str]] = []
    if isinstance(env, dict):
        for k, v in env.items():
            pairs.append((str(k), "" if v is None else str(v)))
    elif isinstance(env, list):
        for item in env:
            s = str(item)
            if "=" in s:
                k, _sep, v = s.partition("=")
                pairs.append((k.strip(), v.strip()))
    return pairs


def _is_literal_secret_value(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    # Runtime references / interpolation / file / secret providers are not literals.
    if v.startswith(("${", "$", "*/", "file:", "secrets:", "vault:", "/run/secrets")):
        return False
    if re.fullmatch(r"\$\{[^}]*\}", v):
        return False
    # Obvious placeholders are not secrets.
    if v.lower() in {"changeme", "password", "secret", "xxx", "todo", "placeholder", "none", "null"}:
        return False
    return len(v) >= 4


def _image_unpinned(image: str) -> bool:
    img = image.strip()
    if not img:
        return False
    if "@sha256:" in img or "@sha512:" in img:
        return False  # digest-pinned
    # A tag is the part after the last ':' that is not part of a registry port.
    last_colon = img.rfind(":")
    if last_colon == -1:
        return True  # no tag at all
    after = img[last_colon + 1:]
    if "/" in after:
        return True  # the ':' was a registry port, no tag
    return after.lower() == "latest"


def _finding(rule_id: str, file_path: Path, line: int, snippet: str,
             target_root: Path, service: str) -> dict[str, Any]:
    rule = COMPOSE_RULES[rule_id]
    rel_path = _report_path(file_path, target_root)
    absolute_path = str(file_path.resolve())
    return {
        "title": rule["title"],
        "rule_id": rule_id,
        "vuln_type": rule_id.lower(),
        "category": "Cloud Infrastructure Security",
        "issue_group": "Infrastructure / IaC",
        "issue_type": rule["title"],
        "severity": rule["severity"],
        "priority": _priority(rule["severity"]),
        "confidence": "HIGH",
        "language": "docker-compose",
        "file": rel_path,
        "file_name": file_path.name,
        "file_path": rel_path,
        "full_path": absolute_path,
        "line": line,
        "snippet": snippet.strip(),
        "evidence": snippet.strip(),
        "description": rule["description"],
        "remediation": [rule["remediation"]],
        "recommendation": rule["remediation"],
        "cwe": rule["cwe"],
        "framework": rule["framework"],
        "control": rule["control"],
        "detection": "docker-compose IaC Static Analysis",
        "resource_path": f"service.{service}",
        "occurrences": [
            {
                "file": rel_path,
                "file_name": file_path.name,
                "file_path": rel_path,
                "full_path": absolute_path,
                "line": line,
                "snippet": snippet.strip(),
            }
        ],
        "affected_files": [rel_path],
        "instances": 1,
    }


def _scan_compose_file(file_path: Path, target_root: Path) -> list[dict[str, Any]]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    services = data.get("services")
    if not isinstance(services, dict):
        return []

    lines = text.splitlines()
    findings: list[dict[str, Any]] = []

    for service, cfg in services.items():
        if not isinstance(cfg, dict):
            continue
        svc_start, svc_end = _service_block_bounds(lines, str(service))

        # COMPOSE_UNPINNED_IMAGE
        image = cfg.get("image")
        if isinstance(image, str) and _image_unpinned(image):
            ln = _find_line(lines, svc_start, svc_end, re.compile(r"^\s*image:")) or (svc_start + 1)
            findings.append(_finding("COMPOSE_UNPINNED_IMAGE", file_path, ln,
                                     f"image: {image}", target_root, str(service)))

        # COMPOSE_PRIVILEGED
        if cfg.get("privileged") is True:
            ln = _find_line(lines, svc_start, svc_end, re.compile(r"^\s*privileged:")) or (svc_start + 1)
            findings.append(_finding("COMPOSE_PRIVILEGED", file_path, ln,
                                     "privileged: true", target_root, str(service)))

        # COMPOSE_DOCKER_SOCKET_MOUNT
        vols = cfg.get("volumes")
        if isinstance(vols, list):
            for vol in vols:
                src = vol.split(":")[0] if isinstance(vol, str) else ""
                if "docker.sock" in src:
                    ln = _find_line(lines, svc_start, svc_end,
                                    re.compile(r"docker\.sock")) or (svc_start + 1)
                    findings.append(_finding("COMPOSE_DOCKER_SOCKET_MOUNT", file_path, ln,
                                             str(vol), target_root, str(service)))
                    break

        # COMPOSE_HARDCODED_SECRET
        for key, value in _env_pairs(cfg.get("environment")):
            if _SECRET_NAME_RE.search(key) and _is_literal_secret_value(value):
                ln = _find_line(lines, svc_start, svc_end,
                                re.compile(rf"^\s*{re.escape(key)}:")) or (svc_start + 1)
                findings.append(_finding("COMPOSE_HARDCODED_SECRET", file_path, ln,
                                         f"{key}: {value}", target_root, str(service)))

        # COMPOSE_MISSING_USER
        if "user" not in cfg:
            ln = _find_line(lines, svc_start, svc_end,
                            re.compile(rf"^\s{{2,}}{re.escape(str(service))}:")) or (svc_start + 1)
            findings.append(_finding("COMPOSE_MISSING_USER", file_path, ln,
                                     f"service {service} defines no user:", target_root, str(service)))

    return findings


def scan_compose(target_path: str) -> list[dict[str, Any]]:
    target = Path(target_path)
    target_root = target if target.is_dir() else target.parent
    findings: list[dict[str, Any]] = []
    for file_path in _iter_compose_files(target):
        findings.extend(_scan_compose_file(file_path, target_root))
    return findings


def main() -> None:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="R-SecOpsX docker-compose IaC Scanner")
    parser.add_argument("target", help="Target compose file or directory")
    args = parser.parse_args()
    print(json.dumps(scan_compose(args.target), indent=2))


if __name__ == "__main__":
    main()
