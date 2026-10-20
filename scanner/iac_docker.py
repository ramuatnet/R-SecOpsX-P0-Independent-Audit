from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from scanner.iac_models import evaluate_docker_rules, parse_dockerfile


DOCKER_EXTENSIONS = {".dockerfile"}
DOCKER_SPECIAL_NAMES = {
    "dockerfile",
    "dockerfile.dev",
    "dockerfile.prod",
    "dockerfile.production",
    "dockerfile.test",
}


RULES = [
    {
        "rule_id": "DOCKER_RUNS_AS_ROOT",
        "title": "Container Runs As Root",
        "severity": "High",
        "pattern": re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE),
        "description": "Dockerfile explicitly configures the container to run as root.",
        "remediation": "Create and use a non-root user with USER <non-root-user>.",
        "cwe": "CWE-250",
        "framework": "CIS Docker Benchmark",
        "control": "Least Privilege Container User",
    },
    {
        "rule_id": "DOCKER_MISSING_USER",
        "title": "Dockerfile Missing Non-Root USER",
        "severity": "Medium",
        "pattern": re.compile(r"^\s*FROM\s+", re.IGNORECASE),
        "description": "Dockerfile does not appear to define a non-root USER instruction.",
        "remediation": "Add a non-root USER instruction after creating a dedicated application user.",
        "cwe": "CWE-250",
        "framework": "CIS Docker Benchmark",
        "control": "Least Privilege Container User",
        "requires_absence_regex": re.compile(r"^\s*USER\s+(?!root\b).+", re.IGNORECASE | re.MULTILINE),
        "once_per_file": True,
    },
    {
        "rule_id": "DOCKER_LATEST_TAG",
        "title": "Base Image Uses latest Tag",
        "severity": "Medium",
        "pattern": re.compile(r"^\s*FROM\s+[^:\s]+:latest\b", re.IGNORECASE),
        "description": "Base image uses the mutable latest tag.",
        "remediation": "Pin base images to immutable version tags or digests.",
        "cwe": "CWE-1104",
        "framework": "CIS Docker Benchmark",
        "control": "Image Version Pinning",
    },
    {
        "rule_id": "DOCKER_UNPINNED_BASE_IMAGE",
        "title": "Base Image Version Not Pinned",
        "severity": "Low",
        "pattern": re.compile(r"^\s*FROM\s+([^\s:@]+)\s*$", re.IGNORECASE),
        "description": "Base image does not specify a version tag or digest.",
        "remediation": "Use a specific image tag or digest, for example python:3.12-slim@sha256:<digest>.",
        "cwe": "CWE-1104",
        "framework": "CIS Docker Benchmark",
        "control": "Image Version Pinning",
    },
    {
        "rule_id": "DOCKER_ADD_REMOTE_URL",
        "title": "ADD Uses Remote URL",
        "severity": "Medium",
        "pattern": re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE),
        "description": "ADD downloads remote content during image build, which can introduce supply-chain risk.",
        "remediation": "Use COPY for local files. Download remote artifacts using verified checksums and pinned versions.",
        "cwe": "CWE-494",
        "framework": "CIS Docker Benchmark",
        "control": "Image Build Integrity",
    },
    {
        "rule_id": "DOCKER_CURL_PIPE_SHELL",
        "title": "curl/wget Piped to Shell",
        "severity": "High",
        "pattern": re.compile(r"(curl|wget).*(\|\s*(sh|bash|python|perl))", re.IGNORECASE),
        "description": "Remote script is executed directly during image build.",
        "remediation": "Download artifacts separately, verify checksums/signatures, then execute trusted local scripts only.",
        "cwe": "CWE-494",
        "framework": "CIS Docker Benchmark",
        "control": "Image Build Integrity",
    },
    {
        "rule_id": "DOCKER_APT_GET_UPGRADE",
        "title": "apt-get upgrade Used In Dockerfile",
        "severity": "Low",
        "pattern": re.compile(r"apt(-get)?\s+upgrade", re.IGNORECASE),
        "description": "apt-get upgrade can create non-reproducible builds.",
        "remediation": "Use minimal base images and install only required pinned packages.",
        "cwe": "CWE-1104",
        "framework": "CIS Docker Benchmark",
        "control": "Reproducible Builds",
    },
    {
        "rule_id": "DOCKER_SECRETS_IN_ENV",
        "title": "Secret Defined in Docker ENV",
        "severity": "Critical",
        "pattern": re.compile(
            r"^\s*ENV\s+.*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|SECRET_KEY)\s*=",
            re.IGNORECASE,
        ),
        "description": "Potential secret is defined in Dockerfile ENV instruction.",
        "remediation": "Remove secrets from Dockerfile. Use runtime secrets from a secrets manager or orchestrator.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    {
        "rule_id": "DOCKER_SECRETS_IN_ARG",
        "title": "Secret Defined in Docker ARG",
        "severity": "High",
        "pattern": re.compile(
            r"^\s*ARG\s+.*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|SECRET_KEY)",
            re.IGNORECASE,
        ),
        "description": "Potential secret is defined as Docker build argument.",
        "remediation": "Do not pass secrets via ARG. Use BuildKit secrets or CI/CD secret injection.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    {
        "rule_id": "DOCKER_AWS_KEY",
        "title": "AWS Access Key in Dockerfile",
        "severity": "Critical",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        "description": "AWS access key appears hardcoded in Dockerfile.",
        "remediation": "Remove key, rotate credential, and use IAM roles or external secret injection.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    {
        "rule_id": "DOCKER_SUDO_INSTALLED",
        "title": "sudo Installed in Container Image",
        "severity": "Medium",
        "pattern": re.compile(r"(apt(-get)?|apk|yum|dnf)\s+.*install\s+.*\bsudo\b", re.IGNORECASE),
        "description": "Installing sudo inside containers can increase privilege escalation risk.",
        "remediation": "Avoid installing sudo in containers. Run only required processes with least privilege.",
        "cwe": "CWE-250",
        "framework": "CIS Docker Benchmark",
        "control": "Least Privilege",
    },
    {
        "rule_id": "DOCKER_SSH_SERVER",
        "title": "SSH Server Installed in Container Image",
        "severity": "Medium",
        "pattern": re.compile(r"(apt(-get)?|apk|yum|dnf)\s+.*install\s+.*(openssh-server|ssh)", re.IGNORECASE),
        "description": "SSH server in containers increases attack surface.",
        "remediation": "Do not run SSH inside application containers. Use orchestration exec/logging mechanisms.",
        "cwe": "CWE-1008",
        "framework": "CIS Docker Benchmark",
        "control": "Attack Surface Reduction",
    },
    {
        "rule_id": "DOCKER_CHMOD_777",
        "title": "World-Writable Permissions Set",
        "severity": "Medium",
        "pattern": re.compile(r"chmod\s+(-R\s+)?777\b", re.IGNORECASE),
        "description": "World-writable permissions weaken filesystem security.",
        "remediation": "Use least-privilege file permissions such as 640/750 depending on need.",
        "cwe": "CWE-732",
        "framework": "CIS Docker Benchmark",
        "control": "Filesystem Permissions",
    },
    {
        "rule_id": "DOCKER_EXPOSE_SENSITIVE_PORT",
        "title": "Sensitive Port Exposed",
        "severity": "Medium",
        "pattern": re.compile(r"^\s*EXPOSE\s+.*\b(22|2375|2376|3306|5432|6379|27017|9200)\b", re.IGNORECASE),
        "description": "Dockerfile exposes a sensitive administrative or database port.",
        "remediation": "Expose only required application ports and restrict access at runtime/network level.",
        "cwe": "CWE-200",
        "framework": "CIS Docker Benchmark",
        "control": "Network Exposure",
    },
]

_RULE_BY_ID = {rule["rule_id"]: rule for rule in RULES}


def _iter_files(target: Path):
    if target.is_file():
        yield target
        return

    for path in target.rglob("*"):
        if not path.is_file():
            continue

        name = path.name.lower()
        suffix = path.suffix.lower()

        if suffix in DOCKER_EXTENSIONS or name in DOCKER_SPECIAL_NAMES:
            yield path


def _is_dockerfile(text: str, path: Path) -> bool:
    name = path.name.lower()

    if name in DOCKER_SPECIAL_NAMES or path.suffix.lower() in DOCKER_EXTENSIONS:
        return True

    return bool(re.search(r"^\s*FROM\s+", text, re.IGNORECASE | re.MULTILINE))


def _report_path(file_path: Path, target_root: Path) -> str:
    try:
        # as_posix(): report paths are a display contract.  str(Path(...)) uses
        # the OS separator, so on Windows this table showed bare names,
        # "a/b" paths and "a\b" paths side by side.
        #
        # Paths are relative to the SCAN TARGET, exactly as every other engine
        # stores them. Prepending target_root.name made docker findings the
        # only ones carrying a doubled project prefix
        # ("autogen-main/.devcontainer/Dockerfile" when the file is
        # ".devcontainer/Dockerfile" under the target), so their SARIF/Jira
        # URIs did not resolve inside the scanned tree.
        return file_path.relative_to(target_root).as_posix()
    except Exception:
        return str(file_path).replace("\\", "/")


def _priority(severity: str) -> str:
    return {
        "Critical": "P1",
        "High": "P2",
        "Medium": "P3",
        "Low": "P4",
        "Info": "P4",
    }.get(severity, "P3")


def _finding(
    rule: dict[str, Any],
    file_path: Path,
    line: int,
    snippet: str,
    target_root: Path,
) -> dict[str, Any]:
    rel_path = _report_path(file_path, target_root)
    absolute_path = str(file_path.resolve())

    return {
        "title": rule["title"],
        "rule_id": rule["rule_id"],
        "vuln_type": rule["rule_id"].lower(),
        "category": "Container Image Security",
        "issue_group": "Infrastructure / IaC",
        "issue_type": rule["title"],
        "severity": rule["severity"],
        "priority": _priority(rule["severity"]),
        "confidence": "HIGH",
        "language": "dockerfile",
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
        "detection": "Dockerfile IaC Static Analysis",
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


def _structured_finding(match: dict, file_path: Path, target_root: Path) -> dict:
    """Wrap a structured match in the SAME finding shape the regex path
    emits, plus ``resource_path`` — the resource-path evidence the gap
    plan asks for. Rule metadata comes from RULES, untouched."""
    rule = _RULE_BY_ID[match["rule_id"]]
    finding = _finding(
        rule=rule,
        file_path=file_path,
        line=match["line"],
        snippet=match["snippet"],
        target_root=target_root,
    )
    finding["resource_path"] = match["resource_path"]
    return finding


def scan_docker(target_path: str) -> list[dict[str, Any]]:
    target = Path(target_path)
    target_root = target if target.is_dir() else target.parent
    findings: list[dict[str, Any]] = []

    for file_path in _iter_files(target):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        if not _is_dockerfile(text, file_path):
            continue

        # Phase 3.1: parse into instruction records (continuations joined,
        # comment lines excluded). None signals an unexpected internal
        # failure -> the ORIGINAL regex engine below runs for this file.
        instructions = parse_dockerfile(text)

        if instructions is not None:
            for match in evaluate_docker_rules(RULES, instructions, text):
                findings.append(
                    _structured_finding(match, file_path, target_root),
                )
            continue

        lines = text.splitlines()
        emitted_once: set[str] = set()

        # Stage aliases declared by earlier FROM ... AS lines.  A bare
        # "FROM <alias>" resolves inside the file, so the unpinned-image
        # pattern must not flag it -- same semantics as the structured
        # engine above (an instruction's own alias never guards itself).
        stage_alias_lines: dict[str, int] = {}
        for idx, line in enumerate(lines, start=1):
            alias_m = re.match(r"\s*FROM\s+\S+\s+[Aa][Ss]\s+(\S+)", line)
            if alias_m:
                stage_alias_lines.setdefault(alias_m.group(1), idx)

        for rule in RULES:
            absence_regex = rule.get("requires_absence_regex")
            if absence_regex and absence_regex.search(text):
                continue

            once_per_file = bool(rule.get("once_per_file"))

            for idx, line in enumerate(lines, start=1):
                if rule["pattern"].search(line):
                    if rule["rule_id"] == "DOCKER_UNPINNED_BASE_IMAGE":
                        ref_m = re.match(r"\s*FROM\s+([^\s:@]+)", line)
                        declared = stage_alias_lines.get(ref_m.group(1)) if ref_m else None
                        if declared is not None and declared < idx:
                            continue
                    if once_per_file and rule["rule_id"] in emitted_once:
                        continue

                    findings.append(
                        _finding(
                            rule=rule,
                            file_path=file_path,
                            line=idx,
                            snippet=line,
                            target_root=target_root,
                        )
                    )

                    if once_per_file:
                        emitted_once.add(rule["rule_id"])
                        break

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="R-SecOpsX Dockerfile IaC Scanner")
    parser.add_argument("target", help="Target Dockerfile or directory")
    parser.add_argument("--output", help="Output JSON file", default=None)
    args = parser.parse_args()

    findings = scan_docker(args.target)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"[DOCKER-IAC] Findings found: {len(findings)}")
        print(f"[DOCKER-IAC] Output written: {output}")
    else:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()