from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

# T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
from core import file_index
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
    # --- Batch G21: AWS IAM policy-document least privilege ---------------
    # The pre-existing TF_IAM_WILDCARD_ACTION only catches a bare `"*"`
    # element. These close the gap Lacework/CNAP aws-iam-13 / aws-iam-8
    # surfaced on wrongsecrets aws/irsa.tf: full-service wildcards
    # (`secretsmanager:*`), partial wildcards (`secretsmanager:Get*`), and
    # the admin combination (wildcard action + wildcard resource).
    {
        "rule_id": "TF_AWS_IAM_WILDCARD_ACTION_SERVICE",
        "title": "IAM Policy Statement Allows Full-Service or Bare Wildcard Action",
        "severity": "High",
        "pattern": re.compile(
            r'actions?\s*=\s*\[[^\]]*(?:["\']\*["\']|["\'][a-z0-9-]+:\*["\'])',
            re.IGNORECASE,
        ),
        "description": "An IAM policy statement grants a bare '*' or full-service '<service>:*' action, violating least privilege.",
        "remediation": "Replace wildcard actions with the specific actions the workload requires.",
        "cwe": "CWE-732",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "IAM Least Privilege",
    },
    {
        "rule_id": "TF_AWS_IAM_PARTIAL_WILDCARD_ACTION",
        "title": "IAM Policy Statement Allows Partial Wildcard Action",
        "severity": "Medium",
        "pattern": re.compile(
            r'actions?\s*=\s*\[[^\]]*["\'][a-z0-9-]+:[A-Za-z0-9]*\*+[A-Za-z0-9]*["\']',
            re.IGNORECASE,
        ),
        "description": "An IAM policy statement grants a verb-level wildcard action (e.g. secretsmanager:Get*), which is broader than least privilege.",
        "remediation": "Enumerate the exact API actions instead of using verb wildcards.",
        "cwe": "CWE-732",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "IAM Least Privilege",
    },
    {
        "rule_id": "TF_AWS_IAM_ADMIN_WILDCARD",
        "title": "IAM Policy Allows Administrative Privileges (Wildcard Action + Resource)",
        "severity": "Critical",
        "pattern": re.compile(
            r'(?=.*actions?\s*=\s*\[[^\]]*(?:["\']\*["\']|["\'][a-z0-9-]+:\*["\']))'
            r'(?=.*resources?\s*=\s*\[[^\]]*["\']\*["\'])',
            re.IGNORECASE,
        ),
        "description": "An IAM policy statement combines a wildcard action with a wildcard resource, granting full administrative privileges.",
        "remediation": "Scope both the actions and the resources to the minimum required.",
        "cwe": "CWE-266",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Privileged Access Management",
    },
]

_RULE_BY_ID = {rule["rule_id"]: rule for rule in RULES}
_STRUCTURED_RULES = [
    rule for rule in RULES if rule["rule_id"] in STRUCTURED_RULE_IDS
]


# ---------------------------------------------------------------------------
# Batch G21: cloud-posture rules (CNAP's GKE/AKS/KeyVault/Storage/IAM posture
# families on wrongsecrets). Unlike RULES (which flag a matching pattern),
# these evaluate the ABSENCE or PRESENCE of a security control *within* a
# resource block. `kind`:
#   "absence"      -> flag when `pattern` is NOT found in the block (missing
#                     hardening control; secure config absent).
#   "presence"     -> flag when `pattern` IS found (explicitly insecure value).
#   "resource_type"-> flag any resource whose type is in `types`.
# Each rule is scoped to a set of terraform resource `types`.
POSTURE_RULES: list[dict[str, Any]] = [
    # ---- GKE cluster (google_container_cluster) -------------------------
    {
        "rule_id": "TF_GKE_PRIVATE_CONTROL_PLANE",
        "title": "GKE Control Plane Is Not Private",
        "severity": "Critical",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'private_cluster_config\s*\{[^}]*enable_private_endpoint\s*=\s*true',
            re.IGNORECASE,
        ),
        "description": "The GKE cluster's control plane endpoint is publicly reachable (private_cluster_config.enable_private_endpoint is not true).",
        "remediation": "Set private_cluster_config { enable_private_endpoint = true } so the API server is only reachable internally.",
        "cwe": "CWE-284",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Private Cluster",
    },
    {
        "rule_id": "TF_GKE_PRIVATE_NODES",
        "title": "GKE Nodes Are Not Private",
        "severity": "Medium",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'private_cluster_config\s*\{[^}]*private_nodes\s*=\s*true',
            re.IGNORECASE,
        ),
        "description": "GKE nodes are assigned public IPs (private_cluster_config.private_nodes is not true).",
        "remediation": "Set private_cluster_config { private_nodes = true } so nodes have only internal IPs.",
        "cwe": "CWE-284",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Private Cluster",
    },
    {
        "rule_id": "TF_GKE_NETWORK_POLICY",
        "title": "GKE Network Policy Not Enabled",
        "severity": "Medium",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'network_policy\s*\{[^}]*enabled\s*=\s*true',
            re.IGNORECASE,
        ),
        "description": "Kubernetes NetworkPolicy is disabled on the cluster, so pod traffic is unrestricted.",
        "remediation": "Add a network_policy block with enabled = true and enforce pod-level network policy.",
        "cwe": "CWE-923",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Network Policy",
    },
    {
        "rule_id": "TF_GKE_SECURE_BOOT",
        "title": "GKE Secure Boot Not Enabled",
        "severity": "High",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'shielded_instance_config\s*\{[^}]*enable_secure_boot\s*=\s*true',
            re.IGNORECASE,
        ),
        "description": "Shielded GKE nodes do not have secure boot enabled, so unsigned kernel modules can load.",
        "remediation": "Set node_config.shielded_instance_config { enable_secure_boot = true }.",
        "cwe": "CWE-494",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Shielded Nodes",
    },
    {
        "rule_id": "TF_GKE_INTEGRITY_MONITORING",
        "title": "GKE Integrity Monitoring Not Enabled",
        "severity": "Medium",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'shielded_instance_config\s*\{[^}]*enable_integrity_monitoring\s*=\s*true',
            re.IGNORECASE,
        ),
        "description": "Shielded GKE nodes do not have integrity monitoring, so boot-component tampering is not alerted.",
        "remediation": "Set node_config.shielded_instance_config { enable_integrity_monitoring = true }.",
        "cwe": "CWE-354",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Shielded Nodes",
    },
    {
        "rule_id": "TF_GKE_SHIELDED_NODES",
        "title": "GKE Shielded Nodes Not Enabled",
        "severity": "Medium",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(r'enable_shielded_nodes\s*=\s*true', re.IGNORECASE),
        "description": "Shielded GKE Nodes are not enabled on the cluster.",
        "remediation": "Set enable_shielded_nodes = true on the cluster.",
        "cwe": "CWE-1188",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Shielded Nodes",
    },
    {
        "rule_id": "TF_GKE_INTRANODE_VISIBILITY",
        "title": "GKE Intranode Visibility Not Enabled",
        "severity": "Medium",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'enable_intranode_visibility\s*=\s*true', re.IGNORECASE
        ),
        "description": "Intranode visibility is disabled, so flow logs between nodes are not captured.",
        "remediation": "Set enable_intranode_visibility = true on the cluster.",
        "cwe": "CWE-778",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Cluster Networking",
    },
    {
        "rule_id": "TF_GKE_ALIAS_IP",
        "title": "GKE Alias IP Ranges Not Enabled",
        "severity": "Medium",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(r'ip_allocation_policy\s*\{', re.IGNORECASE),
        "description": "Alias IP ranges are not configured on the cluster.",
        "remediation": "Add an ip_allocation_policy block to enable alias IP ranges.",
        "cwe": "CWE-1188",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Cluster Networking",
    },
    {
        "rule_id": "TF_GKE_CLIENT_CERT",
        "title": "GKE Client Certificate Authentication Not Disabled",
        "severity": "Medium",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'client_certificate_config\s*\{[^}]*issue_client_certificate\s*=\s*false',
            re.IGNORECASE,
        ),
        "description": "The cluster does not explicitly disable client-certificate authentication to the API server.",
        "remediation": "Set master_auth.client_certificate_config { issue_client_certificate = false }.",
        "cwe": "CWE-287",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Authentication",
    },
    {
        "rule_id": "TF_GKE_METADATA_SERVER",
        "title": "GKE Metadata Server (Workload Identity) Not Enabled",
        "severity": "Low",
        "types": {"google_container_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'workload_metadata_config\s*\{[^}]*node_metadata\s*=\s*"GKE_METADATA_SERVER"',
            re.IGNORECASE,
        ),
        "description": "The GKE metadata server is not enabled, so pods can read node metadata (kubelet credentials, instance identity tokens).",
        "remediation": "Set node_config.workload_metadata_config { node_metadata = \"GKE_METADATA_SERVER\" }.",
        "cwe": "CWE-200",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GKE Metadata Server",
    },
    # ---- GCP IAM: direct principal grants (google_*_iam_member) ----------
    {
        "rule_id": "TF_GCP_IAM_DIRECT_MEMBER",
        "title": "GCP IAM Permissions Granted Directly to a Principal",
        "severity": "Medium",
        "types": {
            "google_service_account_iam_member",
            "google_project_iam_member",
            "google_secret_manager_secret_iam_member",
            "google_storage_bucket_iam_member",
            "google_compute_instance_iam_member",
            "google_folder_iam_member",
            "google_organization_iam_member",
            "google_kms_crypto_key_iam_member",
            "google_kms_key_ring_iam_member",
        },
        "kind": "resource_type",
        "pattern": re.compile(r'.'),
        "description": "IAM permissions are granted directly to an individual principal (google_*_iam_member) instead of to a role/group, which is hard to audit and manage at scale.",
        "remediation": "Grant roles to groups or service accounts via google_*_iam_binding / google_*_iam_policy instead of per-principal _iam_member.",
        "cwe": "CWE-269",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GCP IAM Least Privilege",
    },
    # ---- GCP VPC: subnet flow logs --------------------------------------
    {
        "rule_id": "TF_GCP_SUBNET_FLOW_LOGS",
        "title": "GCP VPC Subnet Flow Logs Not Enabled",
        "severity": "Low",
        "types": {"google_compute_subnetwork"},
        "kind": "absence",
        "pattern": re.compile(r'log_config\s*\{', re.IGNORECASE),
        "description": "VPC flow logs are not enabled on the subnet, so traffic metadata is not recorded for audit.",
        "remediation": "Add a log_config block to the subnet to enable VPC flow logs.",
        "cwe": "CWE-778",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "VPC Flow Logging",
    },
    # ---- GCP Storage bucket logging --------------------------------------
    {
        "rule_id": "TF_GCP_STORAGE_LOGGING",
        "title": "GCP Storage Bucket Logging Not Enabled",
        "severity": "Low",
        "types": {"google_storage_bucket"},
        "kind": "absence",
        "pattern": re.compile(r'logging\s*\{', re.IGNORECASE),
        "description": "The GCS bucket does not have access logging enabled.",
        "remediation": "Add a logging block to the bucket to record access events.",
        "cwe": "CWE-778",
        "framework": "CIS Google Cloud Platform Benchmark",
        "control": "GCS Access Logging",
    },
    # ---- AWS Secrets Manager: KMS encryption ----------------------------
    {
        "rule_id": "TF_AWS_SECRETS_KMS",
        "title": "Secrets Manager Secret Not Encrypted with KMS",
        "severity": "High",
        "types": {"aws_secretsmanager_secret"},
        "kind": "absence",
        "pattern": re.compile(r'kms_key_id\s*=', re.IGNORECASE),
        "description": "The Secrets Manager secret does not specify a KMS CMK, so it relies on the default AWS-managed key.",
        "remediation": "Set kms_key_id to a customer-managed KMS key for the secret.",
        "cwe": "CWE-311",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "Secrets Encryption",
    },
    # ---- Azure AKS (azurerm_kubernetes_cluster) -------------------------
    {
        "rule_id": "TF_AZURE_AKS_NETWORK_POLICY",
        "title": "AKS Cluster Network Policy Not Configured",
        "severity": "High",
        "types": {"azurerm_kubernetes_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'network_profile\s*\{[^}]*network_policy\s*=', re.IGNORECASE
        ),
        "description": "The AKS cluster has no network policy, so pod traffic is unrestricted.",
        "remediation": "Set network_profile.network_policy to \"azure\" or \"calico\".",
        "cwe": "CWE-923",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "AKS Network Policy",
    },
    {
        "rule_id": "TF_AZURE_AKS_PRIVATE",
        "title": "AKS Cluster Is Not Private",
        "severity": "Medium",
        "types": {"azurerm_kubernetes_cluster"},
        "kind": "absence",
        "pattern": re.compile(
            r'private_cluster_enabled\s*=\s*true', re.IGNORECASE
        ),
        "description": "The AKS API server is reachable from the public internet (private_cluster_enabled is not true).",
        "remediation": "Set private_cluster_enabled = true so the API server is only reachable internally.",
        "cwe": "CWE-284",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "AKS Private Cluster",
    },
    {
        "rule_id": "TF_AZURE_AKS_DISK_ENCRYPTION",
        "title": "AKS Cluster Disk Encryption Set Not Configured",
        "severity": "Medium",
        "types": {"azurerm_kubernetes_cluster"},
        "kind": "absence",
        "pattern": re.compile(r'disk_encryption_set_id\s*=', re.IGNORECASE),
        "description": "The AKS cluster does not use a customer-managed disk encryption set.",
        "remediation": "Set disk_encryption_set_id to a customer-managed Azure Disk Encryption Set.",
        "cwe": "CWE-311",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "AKS Encryption",
    },
    {
        "rule_id": "TF_AZURE_AKS_POLICY_ADDON",
        "title": "AKS Azure Policy Add-on Not Enabled",
        "severity": "Low",
        "types": {"azurerm_kubernetes_cluster"},
        "kind": "absence",
        "pattern": re.compile(r'azure_policy_enabled\s*=\s*true', re.IGNORECASE),
        "description": "The AKS cluster does not enable the Azure Policy add-on for centralized policy enforcement.",
        "remediation": "Set azure_policy_enabled = true on the cluster.",
        "cwe": "CWE-1188",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "AKS Policy Enforcement",
    },
    {
        "rule_id": "TF_AZURE_AKS_MONITORING",
        "title": "AKS Logging to Azure Monitor Not Configured",
        "severity": "Low",
        "types": {"azurerm_kubernetes_cluster"},
        "kind": "absence",
        "pattern": re.compile(r'oms_agent\s*\{', re.IGNORECASE),
        "description": "The AKS cluster does not send container logs to Azure Monitor / Log Analytics.",
        "remediation": "Add an oms_agent block pointing at a Log Analytics workspace.",
        "cwe": "CWE-778",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "AKS Monitoring",
    },
    # ---- Azure Key Vault ------------------------------------------------
    {
        "rule_id": "TF_AZURE_KV_PURGE_PROTECTION",
        "title": "Azure Key Vault Purge Protection Disabled",
        "severity": "High",
        "types": {"azurerm_key_vault"},
        "kind": "presence",
        "pattern": re.compile(
            r'purge_protection_enabled\s*=\s*false', re.IGNORECASE
        ),
        "description": "Purge protection is explicitly disabled, allowing key vault secrets/keys to be permanently deleted.",
        "remediation": "Set purge_protection_enabled = true.",
        "cwe": "CWE-704",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Key Vault Purge Protection",
    },
    {
        "rule_id": "TF_AZURE_KV_NETWORK_ACL",
        "title": "Azure Key Vault Has No Network Access Restrictions",
        "severity": "High",
        "types": {"azurerm_key_vault"},
        "kind": "absence",
        "pattern": re.compile(r'network_acls\s*\{', re.IGNORECASE),
        "description": "The Key Vault has no network ACL, so it is reachable from any network.",
        "remediation": "Add a network_acls block with default_action = \"Deny\" and appropriate bypass/rules.",
        "cwe": "CWE-284",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Key Vault Network Access",
    },
    {
        "rule_id": "TF_AZURE_KV_SECRET_EXPIRATION",
        "title": "Azure Key Vault Secret Has No Expiration Date",
        "severity": "Medium",
        "types": {"azurerm_key_vault_secret"},
        "kind": "absence",
        "pattern": re.compile(r'expiration_date\s*=', re.IGNORECASE),
        "description": "The Key Vault secret has no expiration date set, so it is never rotated.",
        "remediation": "Set expiration_date on the secret.",
        "cwe": "CWE-613",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Key Vault Secret Rotation",
    },
    {
        "rule_id": "TF_AZURE_KV_SECRET_CONTENT_TYPE",
        "title": "Azure Key Vault Secret Has No Content Type",
        "severity": "Low",
        "types": {"azurerm_key_vault_secret"},
        "kind": "absence",
        "pattern": re.compile(r'content_type\s*=', re.IGNORECASE),
        "description": "The Key Vault secret has no content type defined, reducing secret-management metadata.",
        "remediation": "Set content_type on the secret (e.g. \"password\", \"certificate\").",
        "cwe": "CWE-1188",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Key Vault Secret Metadata",
    },
    # ---- Azure Storage account ------------------------------------------
    {
        "rule_id": "TF_AZURE_STORAGE_PUBLIC_ACCESS",
        "title": "Azure Storage Account Public Network Access Not Disabled",
        "severity": "High",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(
            r'public_network_access_enabled\s*=\s*false', re.IGNORECASE
        ),
        "description": "The storage account allows public network access.",
        "remediation": "Set public_network_access_enabled = false.",
        "cwe": "CWE-284",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Account Network Access",
    },
    {
        "rule_id": "TF_AZURE_STORAGE_HTTPS",
        "title": "Azure Storage Account HTTPS Not Enforced",
        "severity": "Critical",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(
            r'enable_https_traffic_only\s*=\s*true', re.IGNORECASE
        ),
        "description": "The storage account does not enforce HTTPS-only traffic.",
        "remediation": "Set enable_https_traffic_only = true.",
        "cwe": "CWE-319",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Account Encryption in Transit",
    },
    {
        "rule_id": "TF_AZURE_STORAGE_TLS",
        "title": "Azure Storage Account Minimum TLS Version Not 1.2",
        "severity": "High",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(
            r'min_tls_version\s*=\s*"TLS1_2"', re.IGNORECASE
        ),
        "description": "The storage account does not set the minimum TLS version to TLS 1.2.",
        "remediation": "Set min_tls_version = \"TLS1_2\".",
        "cwe": "CWE-326",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Account TLS Version",
    },
    {
        "rule_id": "TF_AZURE_STORAGE_DEFAULT_DENY",
        "title": "Azure Storage Network Rules Default Action Not Deny",
        "severity": "High",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(
            r'network_rules\s*\{[^}]*default_action\s*=\s*"Deny"', re.IGNORECASE
        ),
        "description": "The storage account network rules do not default to Deny, so unmatched traffic is allowed.",
        "remediation": "Add network_rules { default_action = \"Deny\" }.",
        "cwe": "CWE-284",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Account Network Rules",
    },
    {
        "rule_id": "TF_AZURE_STORAGE_BYPASS",
        "title": "Azure Storage Network Rules Bypass Not Set",
        "severity": "High",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(
            r'network_rules\s*\{[^}]*bypass\s*=', re.IGNORECASE
        ),
        "description": "The storage account network rules do not define which trusted Microsoft services may bypass them.",
        "remediation": "Add network_rules { bypass = [\"AzureServices\"] } (or the minimal required set).",
        "cwe": "CWE-284",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Account Network Rules",
    },
    {
        "rule_id": "TF_AZURE_STORAGE_CMK",
        "title": "Azure Storage Account Customer-Managed Key Not Configured",
        "severity": "High",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(r'customer_managed_key\s*\{', re.IGNORECASE),
        "description": "The storage account does not use a customer-managed key for encryption.",
        "remediation": "Add a customer_managed_key block referencing a Key Vault key.",
        "cwe": "CWE-311",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Account Encryption at Rest",
    },
    {
        "rule_id": "TF_AZURE_STORAGE_QUEUE_LOGGING",
        "title": "Azure Storage Queue Logging Not Enabled",
        "severity": "Low",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(
            r'queue_properties\s*\{[^}]*logging\s*\{', re.IGNORECASE
        ),
        "description": "The storage account does not enable queue service logging.",
        "remediation": "Add queue_properties { logging { read = true write = true delete = true } }.",
        "cwe": "CWE-778",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Queue Logging",
    },
    {
        "rule_id": "TF_AZURE_STORAGE_BLOB_LOGGING",
        "title": "Azure Storage Blob Logging Not Enabled",
        "severity": "Low",
        "types": {"azurerm_storage_account"},
        "kind": "absence",
        "pattern": re.compile(
            r'blob_properties\s*\{[^}]*logging\s*\{', re.IGNORECASE
        ),
        "description": "The storage account does not enable blob service access logging (read/write/delete requests are not recorded).",
        "remediation": "Add blob_properties { logging { read = true write = true delete = true } }.",
        "cwe": "CWE-778",
        "framework": "CIS Microsoft Azure Foundations Benchmark",
        "control": "Storage Blob Logging",
    },
]


# G21: file-level companion-resource checks for S3 bucket hardening. A bare
# `aws_s3_bucket` resource with no matching companion resource anywhere in the
# file is missing that hardening control (CNAP aws-storage-1/2/7/general-9).
S3_COMPANION_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "TF_AWS_S3_PUBLIC_ACCESS_ABSENT",
        "title": "S3 Bucket Missing Public Access Block",
        "severity": "High",
        "companion": "aws_s3_bucket_public_access_block",
        "description": "The S3 bucket has no aws_s3_bucket_public_access_block, so its public-access settings are unmanaged.",
        "remediation": "Add an aws_s3_bucket_public_access_block with all four block settings enabled.",
        "cwe": "CWE-284",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "S3 Public Access",
    },
    {
        "rule_id": "TF_AWS_S3_VERSIONING_ABSENT",
        "title": "S3 Bucket Versioning Not Enabled",
        "severity": "Medium",
        "companion": "aws_s3_bucket_versioning",
        "description": "The S3 bucket has no aws_s3_bucket_versioning, so object versions are not preserved.",
        "remediation": "Add an aws_s3_bucket_versioning resource with status = \"Enabled\".",
        "cwe": "CWE-693",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "S3 Versioning",
    },
    {
        "rule_id": "TF_AWS_S3_ACCESS_LOGGING_ABSENT",
        "title": "S3 Bucket Access Logging Not Enabled",
        "severity": "Medium",
        "companion": "aws_s3_bucket_logging",
        "description": "The S3 bucket has no aws_s3_bucket_logging, so request records are not captured.",
        "remediation": "Add an aws_s3_bucket_logging resource targeting a log bucket.",
        "cwe": "CWE-778",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "S3 Access Logging",
    },
    {
        "rule_id": "TF_AWS_S3_REPLICATION_ABSENT",
        "title": "S3 Bucket Cross-Region Replication Not Enabled",
        "severity": "Medium",
        "companion": "aws_s3_bucket_replication_configuration",
        "description": "The S3 bucket has no replication configuration, so objects are not replicated for redundancy/recovery.",
        "remediation": "Add an aws_s3_bucket_replication_configuration resource.",
        "cwe": "CWE-693",
        "framework": "CIS AWS Foundations Benchmark",
        "control": "S3 Replication",
    },
]


def _resource_type(unit_text: str) -> str | None:
    """Return the resource type for a logical unit that opens a
    ``resource "type" "name" {`` block, else None (data sources, modules,
    providers, variables, etc.)."""
    m = re.match(r'\s*resource\s+"([^"]+)"', unit_text)
    return m.group(1) if m else None


def _evaluate_posture_rules(
    logical_units: list[tuple[int, str]],
    cleaned_text: str,
    file_path: Path,
    target: Path,
) -> list[dict[str, Any]]:
    """Evaluate absence/presence-of-control posture rules per resource block,
    plus file-level S3 companion-resource checks."""
    out: list[dict[str, Any]] = []
    resource_units = [
        (ln, txt) for ln, txt in logical_units if _resource_type(txt)
    ]

    for rule in POSTURE_RULES:
        for ln, txt in resource_units:
            rtype = _resource_type(txt)
            if rtype not in rule["types"]:
                continue
            kind = rule["kind"]
            if kind == "resource_type":
                out.append(_finding(rule, file_path, ln, txt, target))
                continue
            matched = rule["pattern"].search(txt) is not None
            if kind == "absence" and not matched:
                out.append(_finding(rule, file_path, ln, txt, target))
            elif kind == "presence" and matched:
                out.append(_finding(rule, file_path, ln, txt, target))

    # File-level S3 companion checks. Scoped deliberately to *unconfigured*
    # buckets — `resource "aws_s3_bucket" "x" {}` with no inline acl /
    # encryption / versioning / logging. That is exactly the neglected-bucket
    # shape Lacework/CNAP flagged on wrongsecrets aws/shared-state/main.tf.
    # A bucket that declares any inline security config is left alone: most
    # orgs enforce BlockPublicAccess / encryption at the account level, which
    # Terraform does not manage here, so flagging every non-configured-inline
    # bucket would be a false-positive source. (Comment-stripped text so a
    # commented-out companion does not suppress the finding.)
    empty_bucket = re.compile(
        r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{\s*\}', re.IGNORECASE
    )
    for rule in S3_COMPANION_RULES:
        if rule["companion"] in cleaned_text:
            continue
        for ln, txt in resource_units:
            if _resource_type(txt) != "aws_s3_bucket":
                continue
            if not empty_bucket.search(txt):
                continue
            out.append(_finding(rule, file_path, ln, txt, target))

    return out


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

    # T-0.2: the one walk replaces this per-engine os.walk. Its Windows
    # junction containment pruning (reparse points do not present as
    # symlinks) is now walk-time policy for EVERY engine -- see
    # core/file_index.py (dirs_outside_root / files_outside_root counters).
    yield from file_index.index_for(target).files(
        exts={e.lower() for e in TF_EXTENSIONS})


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
        #
        # Paths are relative to the SCAN TARGET, exactly as every other engine
        # stores them (see scanner/iac_docker.py). Prepending target_root.name
        # made terraform findings carry a doubled project prefix
        # ("juice-shop-git/infrastructure/terraform/networking.tf" when the file
        # is "infrastructure/terraform/networking.tf" under the target), so
        # their SARIF/Jira URIs did not resolve inside the scanned tree and
        # they could not be correlated with same-file SAST/secret findings.
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

        # Batch G21: cloud-posture rules (absence/presence of controls) and
        # file-level S3 companion-resource checks. These run regardless of
        # HCL parse success — they operate on comment-stripped logical units,
        # which the regex path already produces for unparseable files too.
        findings.extend(
            _evaluate_posture_rules(logical_units, cleaned_text, file_path, target)
        )

    # Bucket C (2026-10-22): one statement, one claim. The statement-level
    # G21 rule already reports a bare "*" (its own scope says so), so the
    # pre-existing line rule yields on exactly the lines it claims and
    # keeps every line it does not. Kill-on-proof: the yielding row only
    # disappears when the surviving statement row exists on that line of
    # that file; the two rules stay independent everywhere else.
    service_lines = {
        (f.get("full_path") or f.get("file_path"), f.get("line"))
        for f in findings
        if f.get("rule_id") == "TF_AWS_IAM_WILDCARD_ACTION_SERVICE"
    }
    findings = [
        f for f in findings
        if f.get("rule_id") != "TF_IAM_WILDCARD_ACTION"
        or (f.get("full_path") or f.get("file_path"), f.get("line"))
        not in service_lines
    ]

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


