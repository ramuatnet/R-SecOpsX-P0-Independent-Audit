from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from scanner.iac_models import evaluate_terraform_rules, parse_hcl2


TF_EXTENSIONS = {".tf", ".tfvars"}

# Phase 3.1: rules whose evaluation moved to parsed HCL2 object models
# (scanner/iac_models.py). For a file that PARSES, these ids are skipped
# in the regex pass and evaluated structurally; for a file that does not
# parse, the regex pass runs them exactly as before — structure degrades
# to text, never to silence. IAM/heredoc-secret rules deliberately stay
# on the regex path: jsonencode policy bodies are TEXT, not structure.
STRUCTURED_RULE_IDS = frozenset({
    "TF_OPEN_SECURITY_GROUP_INGRESS",
    "TF_OPEN_IPV6_INGRESS",
    "TF_PUBLIC_S3_ACL",
    "TF_S3_BLOCK_PUBLIC_ACCESS_DISABLED",
    "TF_UNENCRYPTED_S3_BUCKET",
    "TF_RDS_PUBLICLY_ACCESSIBLE",
    "TF_RDS_STORAGE_NOT_ENCRYPTED",
    "TF_EBS_ENCRYPTION_DISABLED",
})


RULES = [
    {
        "rule_id": "TF_OPEN_SECURITY_GROUP_INGRESS",
        "title": "Security Group Allows Ingress From 0.0.0.0/0",
        "severity": "Critical",
        "pattern": re.compile(r'cidr_blocks\s*=\s*\[.*0\.0\.0\.0/0.*\]', re.IGNORECASE),
        "description": "Security group ingress allows traffic from the public internet.",
        "remediation": "Restrict cidr_blocks to trusted IP ranges only.",
        "cwe": "CWE-284",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Network Access Control",
    },
    {
        "rule_id": "TF_OPEN_IPV6_INGRESS",
        "title": "Security Group Allows IPv6 Ingress From ::/0",
        "severity": "Critical",
        "pattern": re.compile(r'ipv6_cidr_blocks\s*=\s*\[.*::/0.*\]', re.IGNORECASE),
        "description": "Security group ingress allows traffic from all IPv6 addresses.",
        "remediation": "Restrict ipv6_cidr_blocks to trusted IPv6 ranges only.",
        "cwe": "CWE-284",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Network Access Control",
    },
    {
        "rule_id": "TF_PUBLIC_S3_ACL",
        "title": "S3 Bucket Allows Public ACL",
        "severity": "High",
        "pattern": re.compile(r'acl\s*=\s*["\']public-(read|read-write)["\']', re.IGNORECASE),
        "description": "S3 bucket ACL is publicly accessible.",
        "remediation": "Use private ACL and enable S3 Block Public Access.",
        "cwe": "CWE-284",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "S3 Public Access",
    },
    {
        "rule_id": "TF_S3_BLOCK_PUBLIC_ACCESS_DISABLED",
        "title": "S3 Block Public Access Disabled",
        "severity": "High",
        "pattern": re.compile(
            r'(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false',
            re.IGNORECASE,
        ),
        "description": "S3 public access protection is disabled.",
        "remediation": "Set all S3 public access block settings to true.",
        "cwe": "CWE-284",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "S3 Public Access",
    },
    {
        "rule_id": "TF_UNENCRYPTED_S3_BUCKET",
        "title": "S3 Bucket Encryption Not Configured",
        "severity": "Medium",
        "pattern": re.compile(r'resource\s+["\']aws_s3_bucket["\']', re.IGNORECASE),
        "description": "S3 bucket resource detected. Confirm server-side encryption is configured.",
        "remediation": "Add aws_s3_bucket_server_side_encryption_configuration.",
        "cwe": "CWE-311",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Data Encryption",
        "requires_absence": "aws_s3_bucket_server_side_encryption_configuration",
    },
    {
        "rule_id": "TF_RDS_PUBLICLY_ACCESSIBLE",
        "title": "RDS Instance Publicly Accessible",
        "severity": "High",
        "pattern": re.compile(r'publicly_accessible\s*=\s*true', re.IGNORECASE),
        "description": "RDS instance is publicly accessible.",
        "remediation": "Set publicly_accessible = false and place RDS in private subnets.",
        "cwe": "CWE-284",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Database Network Exposure",
    },
    {
        "rule_id": "TF_RDS_STORAGE_NOT_ENCRYPTED",
        "title": "RDS Storage Encryption Disabled",
        "severity": "High",
        "pattern": re.compile(r'storage_encrypted\s*=\s*false', re.IGNORECASE),
        "description": "RDS storage encryption is disabled.",
        "remediation": "Set storage_encrypted = true and use a managed KMS key.",
        "cwe": "CWE-311",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Database Encryption",
    },
    {
        "rule_id": "TF_EBS_ENCRYPTION_DISABLED",
        "title": "EBS Volume Encryption Disabled",
        "severity": "High",
        "pattern": re.compile(r'encrypted\s*=\s*false', re.IGNORECASE),
        "description": "Storage encryption appears disabled.",
        "remediation": "Enable encryption using KMS-managed keys.",
        "cwe": "CWE-311",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Storage Encryption",
    },
    {
        "rule_id": "TF_IAM_WILDCARD_ACTION",
        "title": "IAM Policy Allows Wildcard Action",
        "severity": "High",
        "pattern": re.compile(r'actions?\s*=\s*\[.*["\']\*["\'].*\]', re.IGNORECASE),
        "description": "IAM policy allows wildcard actions.",
        "remediation": "Replace wildcard actions with least-privilege actions.",
        "cwe": "CWE-732",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "IAM Least Privilege",
    },
    {
        "rule_id": "TF_IAM_WILDCARD_RESOURCE",
        "title": "IAM Policy Allows Wildcard Resource",
        "severity": "Medium",
        "pattern": re.compile(r'resources?\s*=\s*\[.*["\']\*["\'].*\]', re.IGNORECASE),
        "description": "IAM policy applies to wildcard resources.",
        "remediation": "Restrict resources to specific ARNs.",
        "cwe": "CWE-732",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "IAM Least Privilege",
    },
    {
        "rule_id": "TF_IAM_JSONENCODE_WILDCARD",
        "title": "IAM Policy JSON-encoded Wildcard Action/Resource",
        "severity": "High",
        "pattern": re.compile(r'(?:Action|Resource)\s*=\s*"\*"', re.IGNORECASE),
        "description": "IAM policy allows wildcard action or resource via jsonencode.",
        "remediation": "Replace wildcard actions/resources with least-privilege values.",
        "cwe": "CWE-732",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "IAM Least Privilege",
    },
    
    {
    "rule_id": "TF_ADMIN_POLICY_ATTACHED",
    "title": "Administrator Policy Attached",
    "severity": "Critical",
    "pattern": re.compile(
        r"arn:aws:iam::aws:policy/AdministratorAccess",
        re.IGNORECASE
    ),
    "description": "AdministratorAccess policy is attached.",
    "remediation": "Replace AdministratorAccess with scoped least-privilege permissions.",
    "cwe": "CWE-266",
    "framework": "CIS AWS Foundations Benchmark",
    "control": "Privileged Access Management",
    },

    {
        "rule_id": "TF_HARDCODED_AWS_ACCESS_KEY",
        "title": "Hardcoded AWS Access Key in Terraform",
        "severity": "Critical",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
        "description": "AWS access key appears hardcoded in Terraform.",
        "remediation": "Remove hardcoded keys and use IAM roles or secure variable injection.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    {
        "rule_id": "TF_HARDCODED_SECRET_VALUE",
        "title": "Hardcoded Secret Value in Terraform",
        "severity": "High",
        "pattern": re.compile(
            r'(password|secret|token|api_key|access_key|secret_key)\s*=\s*["\'](?!\$\{\s*var\.)[^"\']{8,}["\']',
            re.IGNORECASE,
        ),
        "description": "Potential secret value is hardcoded in Terraform.",
        "remediation": "Use sensitive variables, Vault, AWS Secrets Manager, or CI/CD secret injection.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    {
        "rule_id": "TF_USER_DATA_SECRET",
        "title": "Sensitive Data in user_data",
        "severity": "Medium",
        "pattern": re.compile(r'user_data\s*=', re.IGNORECASE),
        "description": "EC2 user_data may contain bootstrap secrets or credentials.",
        "remediation": "Avoid secrets in user_data; use instance roles and secure secret retrieval.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
]

_RULE_BY_ID = {rule["rule_id"]: rule for rule in RULES}
_STRUCTURED_RULES = [
    rule for rule in RULES if rule["rule_id"] in STRUCTURED_RULE_IDS
]


def _iter_files(target: Path):
    """Yield only Terraform files physically contained by target root.

    Resolve both the target and every candidate before yielding. This prevents
    junction/symlink/path-escape traversal from feeding external IaC files into
    the scanner.
    """
    try:
        root = target.resolve()
    except Exception:
        return

    if root.is_file():
        if root.suffix.lower() in TF_EXTENSIONS:
            yield root
        return

    # Do not use Path.rglob here: on Windows, directory junctions/reparse
    # points can be traversed without presenting as ordinary symlinks. Walk
    # top-down so escaped directories are pruned before descent.
    import os
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        safe_dirs = []
        for dirname in dirnames:
            child = current / dirname
            try:
                resolved_dir = child.resolve()
                if resolved_dir == root or root in resolved_dir.parents:
                    safe_dirs.append(dirname)
            except (OSError, RuntimeError):
                continue
        dirnames[:] = safe_dirs
        for filename in filenames:
            path = current / filename
            if path.suffix.lower() not in TF_EXTENSIONS:
                continue
            try:
                resolved = path.resolve()
                if resolved != root and root not in resolved.parents:
                    continue
                yield resolved
            except (OSError, RuntimeError):
                continue


def _is_terraform_file(text: str, path: Path) -> bool:
    if path.suffix.lower() in TF_EXTENSIONS:
        return True

    markers = [
        "resource ",
        "provider ",
        "variable ",
        "module ",
        "terraform {",
        "aws_",
        "azurerm_",
        "google_",
    ]
    return any(marker in text for marker in markers)


def _report_path(file_path: Path, target_root: Path) -> str:
    try:
        # as_posix(): report paths are a display contract.  str(Path(...)) uses
        # the OS separator, so on Windows this table showed bare names,
        # "a/b" paths and "a\b" paths side by side.
        return (Path(target_root.name) / file_path.relative_to(target_root)).as_posix()
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
        "category": "Cloud Infrastructure Security",
        "issue_group": "Infrastructure / IaC",
        "issue_type": rule["title"],
        "severity": rule["severity"],
        "priority": _priority(rule["severity"]),
        "confidence": "HIGH",
        "language": "terraform",
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
        "detection": "Terraform IaC Static Analysis",
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


def _is_literal_secret_assignment(line: str) -> bool:
    """Return True only for direct literal secret assignments.

    Terraform references and interpolation-only references are not
    hardcoded secret material.
    """
    stripped = line.strip()

    if not stripped:
        return False

    if stripped.startswith("#") or stripped.startswith("//"):
        return False

    assignment = re.search(
        r"^\s*(password|secret|token|api_key|access_key|secret_key)\s*=\s*(.+?)\s*$",
        stripped,
        re.IGNORECASE,
    )

    if not assignment:
        return False

    value = assignment.group(2).strip()

    # Terraform variable/reference expressions are not hardcoded secrets.
    reference_patterns = (
        r"^\$\{\s*(var|local|module|data|resource)\.",
        r"^(var|local|module|data|resource)\.",
    )

    if any(re.match(pattern, value, re.IGNORECASE) for pattern in reference_patterns):
        return False

    # A quoted Terraform interpolation containing only a reference
    # is also not hardcoded secret material.
    if re.fullmatch(
        r'"\s*\$\{\s*(var|local|module|data|resource)\.[^}]+\s*\}\s*"',
        value,
        re.IGNORECASE,
    ):
        return False

    # Only quoted literal values qualify.
    if len(value) < 2 or value[0] not in ('"', "'") or value[-1] != value[0]:
        return False

    # Empty literals are not secrets.
    literal = value[1:-1].strip()
    if not literal:
        return False

    # Do not treat interpolation-containing values as direct literals.
    if "${" in literal:
        return False

    return len(literal) >= 8
def _strip_terraform_comment(line: str) -> str:
    """Remove Terraform comments while preserving quoted strings."""

    result = []
    in_single = False
    in_double = False
    escaped = False
    index = 0

    while index < len(line):
        char = line[index]

        if escaped:
            result.append(char)
            escaped = False
            index += 1
            continue

        if char == "\\" and (in_single or in_double):
            result.append(char)
            escaped = True
            index += 1
            continue

        if char == '"' and not in_single:
            in_double = not in_double
            result.append(char)
            index += 1
            continue

        if char == "'" and not in_double:
            in_single = not in_single
            result.append(char)
            index += 1
            continue

        if not in_single and not in_double:
            if char == "#":
                break

            if char == "/" and index + 1 < len(line):
                if line[index + 1] == "/":
                    break

        result.append(char)
        index += 1

    return "".join(result)


def _terraform_logical_units(lines: list[str]) -> list[tuple[int, str]]:
    """Combine multiline Terraform expressions into logical scan units."""

    units: list[tuple[int, str]] = []

    current: list[str] = []
    start_line = 1

    square_depth = 0
    curly_depth = 0
    paren_depth = 0

    for index, raw_line in enumerate(lines, start=1):
        cleaned = _strip_terraform_comment(raw_line)

        if not current and not cleaned.strip():
            continue

        if not current:
            start_line = index

        current.append(cleaned)

        in_single = False
        in_double = False
        escaped = False

        for char in cleaned:
            if escaped:
                escaped = False
                continue

            if char == "\\" and (in_single or in_double):
                escaped = True
                continue

            if char == '"' and not in_single:
                in_double = not in_double
                continue

            if char == "'" and not in_double:
                in_single = not in_single
                continue

            if in_single or in_double:
                continue

            if char == "[":
                square_depth += 1
            elif char == "]":
                square_depth = max(0, square_depth - 1)
            elif char == "{":
                curly_depth += 1
            elif char == "}":
                curly_depth = max(0, curly_depth - 1)
            elif char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth = max(0, paren_depth - 1)

        joined = " ".join(part.strip() for part in current).strip()

        if square_depth == 0 and curly_depth == 0 and paren_depth == 0:
            if joined:
                units.append((start_line, joined))

            current = []

    if current:
        joined = " ".join(part.strip() for part in current).strip()

        if joined:
            units.append((start_line, joined))

    return units


def _s3_bucket_has_matching_encryption(
    bucket_name: str,
    logical_units: list[tuple[int, str]],
) -> bool:
    """Return True when the named S3 bucket has a matching encryption configuration."""

    if not bucket_name:
        return False

    expected_reference = re.compile(
        rf"\baws_s3_bucket\.{re.escape(bucket_name)}\.id\b",
        re.IGNORECASE,
    )

    encryption_resource = re.compile(
        r'resource\s+["\']aws_s3_bucket_server_side_encryption_configuration["\']'
        r'\s+["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    for _, logical_line in logical_units:
        resource_match = encryption_resource.search(logical_line)

        if not resource_match:
            continue

        config_name = resource_match.group(1)

        if config_name.lower() != bucket_name.lower():
            continue

        if expected_reference.search(logical_line):
            return True

    return False


def scan_terraform(target_path: str) -> list[dict[str, Any]]:
    target = Path(target_path)
    findings: list[dict[str, Any]] = []

    for file_path in _iter_files(target):
        try:
            text = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            continue

        if not _is_terraform_file(text, file_path):
            continue

        lines = text.splitlines()

        cleaned_lines = [
            _strip_terraform_comment(line)
            for line in lines
        ]

        cleaned_text = "\n".join(cleaned_lines)

        logical_units = _terraform_logical_units(lines)

        # Phase 3.1: parse into HCL2 object models. When the file parses,
        # the structured rule ids skip the regex pass and are evaluated on
        # resources/attributes below; when it does NOT parse (unbalanced
        # braces, malformed header), the regex pass runs them exactly as
        # before — structure degrades to text, never to silence.
        parsed = parse_hcl2(text)
        structured_ok = parsed.ok

        for rule in RULES:
            if structured_ok and rule["rule_id"] in STRUCTURED_RULE_IDS:
                continue

            absence = rule.get("requires_absence")

            # Whole-file secret rule: execute exactly once per file.
            # Keep this outside the logical-unit loop to prevent duplicate
            # amplification when multiple logical units match.
            if rule["rule_id"] == "TF_HARDCODED_SECRET_VALUE":
                for physical_index, physical_line in enumerate(lines):
                    if _is_literal_secret_assignment(physical_line):
                        findings.append(
                            _finding(
                                rule=rule,
                                file_path=file_path,
                                line=physical_index + 1,
                                snippet=physical_line.strip(),
                                target_root=target,
                            )
                        )
                continue

            for line_number, logical_line in logical_units:
                if not rule["pattern"].search(logical_line):
                    continue

                if rule["rule_id"] == "TF_UNENCRYPTED_S3_BUCKET":
                    bucket_match = re.search(
                        r'resource\s+["\']aws_s3_bucket["\']\s+["\']([^"\']+)["\']',
                        logical_line,
                        re.IGNORECASE,
                    )

                    if not bucket_match:
                        continue

                    bucket_name = bucket_match.group(1)

                    if _s3_bucket_has_matching_encryption(
                        bucket_name,
                        logical_units,
                    ):
                        continue

                findings.append(
                    _finding(
                        rule=rule,
                        file_path=file_path,
                        line=line_number,
                        snippet=logical_line,
                        target_root=target,
                    )
                )

        if structured_ok:
            for match in evaluate_terraform_rules(
                _STRUCTURED_RULES, text, parsed.blocks,
            ):
                findings.append(
                    _structured_finding(match, file_path, target),
                )

    return findings

def main() -> None:
    parser = argparse.ArgumentParser(description="R-SecOpsX Terraform IaC Scanner")
    parser.add_argument("target", help="Target Terraform file or directory")
    parser.add_argument("--output", help="Output JSON file", default=None)
    args = parser.parse_args()

    findings = scan_terraform(args.target)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"[TF-IAC] Findings found: {len(findings)}")
        print(f"[TF-IAC] Output written: {output}")
    else:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()


