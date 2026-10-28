from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

# T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
from core import file_index
from scanner.iac_models import (
    WORKLOAD_KINDS,
    evaluate_k8s_rules,
    parse_k8s_documents,
)


K8S_EXTENSIONS = {".yaml", ".yml", ".json"}


RULES = [
    {
        "rule_id": "K8S_PRIVILEGED_CONTAINER",
        "title": "Privileged Container",
        "severity": "High",
        "pattern": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
        "description": "Container is running in privileged mode, which may allow host escape.",
        "remediation": "Remove privileged: true and use least-privilege Linux capabilities.",
        "cwe": "CWE-250",
        "cis": "CIS Kubernetes Benchmark 5.2.1",
    },
    {
        "rule_id": "K8S_ALLOW_PRIVILEGE_ESCALATION",
        "title": "Privilege Escalation Allowed",
        "severity": "High",
        "pattern": re.compile(r"allowPrivilegeEscalation\s*:\s*true", re.IGNORECASE),
        "description": "Container allows privilege escalation.",
        "remediation": "Set allowPrivilegeEscalation: false.",
        "cwe": "CWE-269",
        "cis": "CIS Kubernetes Benchmark 5.2.5",
    },
    {
        "rule_id": "K8S_HOST_NETWORK",
        "title": "Host Network Enabled",
        "severity": "High",
        "pattern": re.compile(r"hostNetwork\s*:\s*true", re.IGNORECASE),
        "description": "Pod shares the host network namespace.",
        "remediation": "Avoid hostNetwork unless strictly required.",
        "cwe": "CWE-668",
        "cis": "CIS Kubernetes Benchmark 5.2.4",
    },
    {
        "rule_id": "K8S_HOST_PID",
        "title": "Host PID Enabled",
        "severity": "High",
        "pattern": re.compile(r"hostPID\s*:\s*true", re.IGNORECASE),
        "description": "Pod shares the host PID namespace.",
        "remediation": "Set hostPID: false or remove it.",
        "cwe": "CWE-668",
        "cis": "CIS Kubernetes Benchmark 5.2.2",
    },
    {
        "rule_id": "K8S_HOST_IPC",
        "title": "Host IPC Enabled",
        "severity": "High",
        "pattern": re.compile(r"hostIPC\s*:\s*true", re.IGNORECASE),
        "description": "Pod shares the host IPC namespace.",
        "remediation": "Set hostIPC: false or remove it.",
        "cwe": "CWE-668",
        "cis": "CIS Kubernetes Benchmark 5.2.3",
    },
    {
        "rule_id": "K8S_RUN_AS_ROOT",
        "title": "Container Runs As Root",
        "severity": "Medium",
        "pattern": re.compile(r"runAsUser\s*:\s*0\b", re.IGNORECASE),
        "description": "Container is explicitly configured to run as root.",
        "remediation": "Set runAsNonRoot: true and use a non-zero runAsUser.",
        "cwe": "CWE-250",
        "cis": "CIS Kubernetes Benchmark 5.2.6",
    },
    {
        "rule_id": "K8S_READ_ONLY_ROOT_FS_DISABLED",
        "title": "Read-Only Root Filesystem Disabled",
        "severity": "Medium",
        "pattern": re.compile(r"readOnlyRootFilesystem\s*:\s*false", re.IGNORECASE),
        "description": "Container root filesystem is writable.",
        "remediation": "Set readOnlyRootFilesystem: true where possible.",
        "cwe": "CWE-732",
        "cis": "CIS Kubernetes Benchmark 5.2.8",
    },
    {
        "rule_id": "K8S_NET_RAW_CAPABILITY",
        "title": "NET_RAW Capability Added",
        "severity": "Medium",
        "pattern": re.compile(r"-\s*NET_RAW\b", re.IGNORECASE),
        "description": "NET_RAW capability can allow packet spoofing and traffic inspection.",
        "remediation": "Drop NET_RAW capability unless explicitly required.",
        "cwe": "CWE-250",
        "cis": "CIS Kubernetes Benchmark 5.2.7",
    },
    {
        "rule_id": "K8S_LATEST_IMAGE_TAG",
        "title": "Container Image Uses latest Tag",
        "severity": "Medium",
        "pattern": re.compile(r"image\s*:\s*['\"]?[^'\"]+:latest['\"]?", re.IGNORECASE),
        "description": "Container image uses the mutable latest tag.",
        "remediation": "Pin images to immutable version tags or digests.",
        "cwe": "CWE-1104",
        "cis": "Container Image Governance",
    },
    {
        "rule_id": "K8S_IMAGE_PULL_ALWAYS",
        "title": "Image Pull Policy Always",
        "severity": "Low",
        "pattern": re.compile(r"imagePullPolicy\s*:\s*Always", re.IGNORECASE),
        "description": "ImagePullPolicy Always can introduce uncontrolled image drift.",
        "remediation": "Use pinned image tags or digests with controlled pull policy.",
        "cwe": "CWE-1104",
        "cis": "Container Image Governance",
    },
    {
        "rule_id": "K8S_POSTGRES_PASSWORD_ENV",
        "title": "PostgreSQL Password in Kubernetes Manifest",
        "severity": "High",
        "pattern": re.compile(r"(POSTGRES_PASSWORD|PGPASSWORD)\s*[:=]?\s*", re.IGNORECASE),
        "description": "Database password is defined directly in Kubernetes manifest.",
        "remediation": "Move database passwords to Kubernetes Secrets or an external secrets manager.",
        "cwe": "CWE-798",
        "cis": "Secret Management",
    },
    {
        "rule_id": "K8S_AWS_SECRET_ENV",
        "title": "AWS Credentials in Kubernetes Manifest",
        "severity": "Critical",
        "pattern": re.compile(r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[:=]?\s*", re.IGNORECASE),
        "description": "AWS credentials are defined directly in Kubernetes manifest.",
        "remediation": "Use IAM roles for service accounts or external secret management.",
        "cwe": "CWE-798",
        "cis": "Secret Management",
    },
]


MISSING_RULES = [
    {
        "rule_id": "K8S_MISSING_RUN_AS_NON_ROOT",
        "title": "Missing Non-Root Container Enforcement",
        "severity": "Medium",
        "description": "Container does not explicitly enforce non-root execution.",
        "remediation": "Set runAsNonRoot: true in pod or container securityContext.",
        "cwe": "CWE-250",
        "cis": "CIS Kubernetes Benchmark 5.2.6",
        "required_pattern": re.compile(r"runAsNonRoot\s*:\s*true", re.IGNORECASE),
    },
    {
        "rule_id": "K8S_MISSING_READ_ONLY_ROOT_FS",
        "title": "Missing Read-Only Root Filesystem",
        "severity": "Medium",
        "description": "Container does not explicitly enforce a read-only root filesystem.",
        "remediation": "Set readOnlyRootFilesystem: true where application design permits.",
        "cwe": "CWE-732",
        "cis": "CIS Kubernetes Benchmark 5.2.8",
        "required_pattern": re.compile(r"readOnlyRootFilesystem\s*:\s*true", re.IGNORECASE),
    },
    {
        "rule_id": "K8S_MISSING_RESOURCE_LIMITS",
        "title": "Missing CPU or Memory Resource Limits",
        "severity": "Medium",
        "description": "Container does not define CPU or memory resource limits.",
        "remediation": "Define CPU and memory limits under resources.limits.",
        "cwe": "CWE-770",
        "cis": "Kubernetes Resource Governance",
        "required_pattern": re.compile(
            r"limits\s*:\s*[\s\S]*?(cpu\s*:|memory\s*:)",
            re.IGNORECASE,
        ),
    },
    # 2026-10-21 prodtest/crAPI vs CNAP workload-3 + security-2: both engines
    # only knew the presence-of-bad forms (capabilities.add: [NET_RAW],
    # allowPrivilegeEscalation: true). CNAP fails the absence-of-good form and
    # every crAPI manifest genuinely lacks both controls (source-verified: no
    # capabilities or allowPrivilegeEscalation key anywhere under deploy/).
    # These are the CIS 5.2.5/5.2.7 checks (kube-bench treats an unset
    # allowPrivilegeEscalation and an undropped NET_RAW as failures; the
    # container runtime default keeps NET_RAW). Complementary to the presence
    # rules: a manifest explicitly set to the bad value is reported once, by
    # the presence rule -- required_pattern for APE is key-presence, so the
    # fallback engine stays consistent with the structured one.
    {
        "rule_id": "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION",
        "title": "Missing allowPrivilegeEscalation=false",
        "severity": "Medium",
        "description": "Container never sets allowPrivilegeEscalation: false; the runtime default permits privilege escalation.",
        "remediation": "Set allowPrivilegeEscalation: false in pod or container securityContext.",
        "cwe": "CWE-269",
        "cis": "CIS Kubernetes Benchmark 5.2.5",
        "required_pattern": re.compile(r"allowPrivilegeEscalation\s*:", re.IGNORECASE),
    },
    {
        "rule_id": "K8S_MISSING_NET_RAW_DROP",
        "title": "NET_RAW Capability Not Dropped",
        "severity": "Medium",
        "description": "Container does not drop NET_RAW (or ALL) capabilities; the runtime default retains NET_RAW.",
        "remediation": "Add NET_RAW or ALL to securityContext.capabilities.drop.",
        "cwe": "CWE-250",
        "cis": "CIS Kubernetes Benchmark 5.2.7",
        "required_pattern": re.compile(
            r"drop\s*:[\s\S]{0,200}?[\"']?(?:ALL|NET_RAW)[\"']?",
            re.IGNORECASE,
        ),
    },
]

_RULE_BY_ID = {
    rule["rule_id"]: rule for rule in (list(RULES) + list(MISSING_RULES))
}


def _is_kubernetes_file(text: str) -> bool:
    markers = [
        "apiVersion:",
        "kind:",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Service",
        "ConfigMap",
        "Secret",
        "Pod",
        "containers:",
        "securityContext:",
    ]
    return any(marker in text for marker in markers)


def _iter_files(target: Path):
    if target.is_file():
        if target.suffix.lower() in K8S_EXTENSIONS:
            yield target
        return

    # T-0.2: index query replaces target.rglob. This engine used to apply
    # NO directory skip at all; the shared union policy now covers it.
    yield from file_index.index_for(target).files(
        exts={e.lower() for e in K8S_EXTENSIONS})


def _line_number(index: int) -> int:
    return index + 1


def _find_anchor_line(lines: list[str]) -> tuple[int, str]:
    preferred_markers = [
        "containers:",
        "securityContext:",
        "spec:",
        "kind:",
        "apiVersion:",
    ]

    for marker in preferred_markers:
        for idx, line in enumerate(lines):
            if marker in line:
                return idx + 1, line.strip()

    return 1, lines[0].strip() if lines else ""


def _finding(
    rule: dict[str, Any],
    file_path: Path,
    line: int,
    snippet: str,
    target_root: Path,
) -> dict[str, Any]:
    try:
        # as_posix(): report paths are a display contract.  str(Path(...)) uses
        # the OS separator, so on Windows this table showed bare names,
        # "a/b" paths and "a\b" paths side by side.
        #
        # Paths are relative to the SCAN TARGET, exactly as every other engine
        # stores them (see scanner/iac_docker.py). Prepending target_root.name
        # made k8s findings carry a doubled project prefix that did not resolve
        # inside the scanned tree and could not be correlated with same-file
        # findings from other engines.
        rel_path = file_path.relative_to(target_root).as_posix()
    except Exception:
        rel_path = str(file_path).replace("\\", "/")

    severity = rule["severity"]
    absolute_path = str(file_path.resolve())

    return {
        "title": rule["title"],
        "rule_id": rule["rule_id"],
        "vuln_type": rule["rule_id"].lower(),
        "category": "Container Security",
        "issue_group": "Infrastructure / IaC",
        "issue_type": rule["title"],
        "severity": severity,
        "priority": {
            "Critical": "P1",
            "High": "P2",
            "Medium": "P3",
            "Low": "P4",
            "Info": "P4",
        }.get(severity, "P3"),
        "confidence": "HIGH",
        "language": "kubernetes",
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
        "cis": rule["cis"],
        "framework": "CIS Kubernetes Benchmark",
        "control": rule["cis"],
        "detection": "Kubernetes IaC Static Analysis",
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
    plan asks for. Rule metadata comes from RULES/MISSING_RULES, untouched."""
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


def _scan_missing_controls(
    text: str,
    lines: list[str],
    file_path: Path,
    target_root: Path,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Process each YAML document independently.
    # This prevents controls from one Kubernetes object from satisfying
    # controls belonging to another object.
    documents = re.split(r"(?m)^\s*---\s*$", text)

    line_offset = 0

    workload_kinds = WORKLOAD_KINDS

    def _strip_comments(document: str) -> str:
        cleaned: list[str] = []

        for raw_line in document.splitlines():
            stripped = raw_line.lstrip()

            # Ignore YAML comment-only lines.
            if stripped.startswith("#"):
                cleaned.append("")
                continue

            # Remove inline comments conservatively.
            if "#" in raw_line:
                before_hash = raw_line.split("#", 1)[0]
                cleaned.append(before_hash)
            else:
                cleaned.append(raw_line)

        return "\n".join(cleaned)

    def _get_kind(document: str) -> str:
        match = re.search(
            r"(?m)^\s*kind\s*:\s*([A-Za-z0-9_-]+)\s*$",
            document,
            re.IGNORECASE,
        )
        return match.group(1).strip() if match else ""

    for document in documents:
        document_lines = document.splitlines()
        cleaned_document = _strip_comments(document)

        if not cleaned_document.strip():
            line_offset += len(document_lines) + 1
            continue

        kind = _get_kind(cleaned_document)

        # Missing container controls apply only to workload resources.
        if kind not in workload_kinds:
            line_offset += len(document_lines) + 1
            continue

        # A workload must actually contain a containers section.
        if not re.search(r"(?m)^\s*containers\s*:", cleaned_document):
            line_offset += len(document_lines) + 1
            continue

        cleaned_lines = cleaned_document.splitlines()

        anchor_local_line = 1
        anchor_snippet = ""

        preferred_patterns = (
            r"^\s*containers\s*:",
            r"^\s*securityContext\s*:",
            r"^\s*spec\s*:",
            r"^\s*kind\s*:",
        )

        for pattern in preferred_patterns:
            found = False

            for idx, line in enumerate(cleaned_lines):
                if re.search(pattern, line, re.IGNORECASE):
                    anchor_local_line = idx + 1
                    anchor_snippet = line.strip()
                    found = True
                    break

            if found:
                break

        anchor_line = line_offset + anchor_local_line

        # Evaluate missing controls per container.
        #
        # A control satisfied by one container must never satisfy another
        # container in the same workload. Pod-level securityContext values
        # remain valid inherited controls for containers.
        containers_match = re.search(
            r"(?m)^(?P<indent>\s*)containers\s*:\s*$",
            cleaned_document,
        )

        if not containers_match:
            line_offset += len(document_lines) + 1
            continue

        containers_indent = len(containers_match.group("indent"))
        cleaned_lines = cleaned_document.splitlines()

        # Find the containers section and its individual "- name:" entries.
        containers_start = None

        for idx, current_line in enumerate(cleaned_lines):
            if re.match(r"^\s*containers\s*:\s*$", current_line):
                containers_start = idx
                break

        if containers_start is None:
            line_offset += len(document_lines) + 1
            continue

        container_items: list[tuple[int, int]] = []

        item_start = None
        item_indent = None

        for idx in range(containers_start + 1, len(cleaned_lines)):
            current_line = cleaned_lines[idx]

            if not current_line.strip():
                continue

            current_indent = len(current_line) - len(current_line.lstrip())

            # End of containers section when indentation returns to or
            # precedes the containers key.
            if current_indent <= containers_indent:
                if item_start is not None:
                    container_items.append((item_start, idx))
                break

            item_match = re.match(
                r"^(?P<indent>\s*)-\s+name\s*:",
                current_line,
                re.IGNORECASE,
            )

            if item_match:
                current_item_indent = len(item_match.group("indent"))

                if item_start is not None and current_item_indent == item_indent:
                    container_items.append((item_start, idx))

                item_start = idx
                item_indent = current_item_indent

        else:
            if item_start is not None:
                container_items.append((item_start, len(cleaned_lines)))

        # Defensive fallback for unusual manifests.
        if not container_items:
            container_items = [(containers_start + 1, len(cleaned_lines))]

        # Extract Pod-level securityContext. These settings are inherited
        # by containers unless explicitly overridden at container level.
        pod_security_context = ""

        pod_sc_match = re.search(
            r"(?ms)^\s*securityContext\s*:\s*$"
            r"(?P<body>.*?)(?=^\s*[A-Za-z0-9_-]+\s*:|\Z)",
            cleaned_document,
        )

        if pod_sc_match:
            pod_security_context = pod_sc_match.group(0)

        for container_start, container_end in container_items:
            container_lines = cleaned_lines[container_start:container_end]
            container_text = "\n".join(container_lines)

            # Locate the actual container name for useful evidence.
            container_name_match = re.search(
                r"^\s*-\s*name\s*:\s*(.+?)\s*$",
                container_text,
                re.IGNORECASE | re.MULTILINE,
            )

            container_name = (
                container_name_match.group(1).strip()
                if container_name_match
                else "container"
            )

            effective_text = container_text

            # Pod-level securityContext applies to the container.
            if pod_security_context:
                effective_text = (
                    pod_security_context
                    + "\n"
                    + container_text
                )

            # Anchor finding at the individual container.
            container_anchor_line = line_offset + container_start + 1
            container_anchor_snippet = (
                cleaned_lines[container_start].strip()
                or container_name
            )

            for rule in MISSING_RULES:
                required_pattern = rule["required_pattern"]

                if not required_pattern.search(effective_text):
                    findings.append(
                        _finding(
                            rule=rule,
                            file_path=file_path,
                            line=container_anchor_line,
                            snippet=container_anchor_snippet,
                            target_root=target_root,
                        )
                    )

        line_offset += len(document_lines) + 1

    return findings

def scan_kubernetes(target_path: str) -> list[dict[str, Any]]:
    target = Path(target_path)
    findings: list[dict[str, Any]] = []

    target_root = target if target.is_dir() else target.parent

    for file_path in _iter_files(target):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        if not _is_kubernetes_file(text):
            continue

        lines = text.splitlines()

        # Phase 3.1: parse into YAML object models (path -> line marks).
        # Valid YAML -> every rule is evaluated structurally and the
        # regex pass below is skipped; invalid YAML or PyYAML absent ->
        # parse returns None and the ORIGINAL regex engine runs for this
        # file — structure degrades to text, never to silence.
        parsed_documents = parse_k8s_documents(text)

        if parsed_documents is not None:
            for match in evaluate_k8s_rules(
                RULES, MISSING_RULES, parsed_documents, text,
            ):
                findings.append(
                    _structured_finding(match, file_path, target_root),
                )
            continue

        # Workload-aware, comment-safe primary Kubernetes rule scanning.
        #
        # Container/security rules must not be triggered by arbitrary text
        # contained in ConfigMaps, Secrets, Services, Roles, etc.
        #
        # Determine the Kubernetes resource kind for this YAML document.
        # Multi-document manifests are handled independently.
        workload_kinds = WORKLOAD_KINDS

        documents = re.split(r"(?m)^\s*---\s*$", text)
        document_line_offset = 0

        for document in documents:
            document_lines = document.splitlines()

            cleaned_lines = []

            for raw_line in document_lines:
                stripped = raw_line.lstrip()

                if stripped.startswith("#"):
                    cleaned_lines.append("")
                    continue

                cleaned_lines.append(raw_line.split("#", 1)[0])

            cleaned_document = "\n".join(cleaned_lines)

            kind_match = re.search(
                r"(?m)^\s*kind\s*:\s*([A-Za-z0-9_-]+)\s*$",
                cleaned_document,
                re.IGNORECASE,
            )

            kind = ""

            if kind_match:
                kind = kind_match.group(1).strip()

            if kind in workload_kinds:
                for idx, scan_line in enumerate(cleaned_lines):

                    if not scan_line.strip():
                        continue

                    for rule in RULES:
                        if rule["pattern"].search(scan_line):
                            findings.append(
                                _finding(
                                    rule=rule,
                                    file_path=file_path,
                                    line=document_line_offset + _line_number(idx),
                                    snippet=document_lines[idx],
                                    target_root=target_root,
                                )
                            )

            document_line_offset += len(document_lines) + 1

        findings.extend(
            _scan_missing_controls(
                text=text,
                lines=lines,
                file_path=file_path,
                target_root=target_root,
            )
        )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="R-SecOpsX Kubernetes IaC Scanner")
    parser.add_argument("target", help="Target file or directory")
    parser.add_argument("--output", help="Output JSON file", default=None)
    args = parser.parse_args()

    findings = scan_kubernetes(args.target)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"[K8S-IAC] Findings found: {len(findings)}")
        print(f"[K8S-IAC] Output written: {output}")
    else:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()



