from __future__ import annotations

from scanner.iac_terraform import scan_terraform


def _findings_for(tmp_path, name, text):
    d = tmp_path / name
    d.mkdir()
    (d / "main.tf").write_text(text, encoding="utf-8")
    return scan_terraform(str(d))


def _ids(findings):
    return {f["rule_id"] for f in findings}


# ---------------------------------------------------------------------------
# GKE cluster: absence-of-secure-config family (CNAP gcp-network/security).
# ---------------------------------------------------------------------------

GKE_INSECURE = '''
resource "google_container_cluster" "gke" {
  name     = var.cluster_name
  location = var.region

  node_config {
    machine_type = "e2-standard-2"
  }
}
'''


GKE_HARDENED = '''
resource "google_container_cluster" "gke" {
  name     = var.cluster_name
  location = var.region

  enable_shielded_nodes = true
  enable_intranode_visibility = true

  private_cluster_config {
    enable_private_endpoint = true
    private_nodes            = true
  }

  network_policy {
    enabled = true
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  ip_allocation_policy {}

  node_config {
    machine_type = "e2-standard-2"
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    workload_metadata_config {
      node_metadata = "GKE_METADATA_SERVER"
    }
  }
}
'''


def test_gke_insecure_cluster_flags_posture_gaps(tmp_path):
    f = _findings_for(tmp_path, "gke_bad", GKE_INSECURE)
    ids = _ids(f)
    assert "TF_GKE_PRIVATE_CONTROL_PLANE" in ids
    assert "TF_GKE_PRIVATE_NODES" in ids
    assert "TF_GKE_NETWORK_POLICY" in ids
    assert "TF_GKE_SECURE_BOOT" in ids
    assert "TF_GKE_INTEGRITY_MONITORING" in ids
    assert "TF_GKE_SHIELDED_NODES" in ids
    assert "TF_GKE_INTRANODE_VISIBILITY" in ids
    assert "TF_GKE_ALIAS_IP" in ids
    assert "TF_GKE_CLIENT_CERT" in ids
    assert "TF_GKE_METADATA_SERVER" in ids


def test_gke_hardened_cluster_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "gke_good", GKE_HARDENED)
    ids = _ids(f)
    assert "TF_GKE_PRIVATE_CONTROL_PLANE" not in ids
    assert "TF_GKE_NETWORK_POLICY" not in ids
    assert "TF_GKE_SECURE_BOOT" not in ids
    assert "TF_GKE_SHIELDED_NODES" not in ids
    assert "TF_GKE_CLIENT_CERT" not in ids
    assert "TF_GKE_METADATA_SERVER" not in ids


def test_gke_posture_findings_on_resource_line(tmp_path):
    f = _findings_for(tmp_path, "gke_line", GKE_INSECURE)
    gke = [x for x in f if x["rule_id"] == "TF_GKE_PRIVATE_CONTROL_PLANE"]
    assert gke and gke[0]["line"] == 2


# ---------------------------------------------------------------------------
# GCP IAM: direct principal (member) grants (CNAP gcp-iam-2).
# ---------------------------------------------------------------------------

GCP_IAM_MEMBER = '''
resource "google_service_account_iam_member" "pod_sa" {
  service_account_id = google_service_account.workload.id
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project}.svc.id.goog[default/vault]"
}
'''

GCP_IAM_BINDING = '''
resource "google_service_account_iam_binding" "pod_sa" {
  service_account_id = google_service_account.workload.id
  role               = "roles/iam.workloadIdentityUser"
  members            = ["group:devs@example.com"]
}
'''


def test_gcp_iam_member_direct_grant_flagged(tmp_path):
    f = _findings_for(tmp_path, "iam_member", GCP_IAM_MEMBER)
    assert "TF_GCP_IAM_DIRECT_MEMBER" in _ids(f)


def test_gcp_iam_binding_group_not_flagged_as_direct_member(tmp_path):
    f = _findings_for(tmp_path, "iam_binding", GCP_IAM_BINDING)
    assert "TF_GCP_IAM_DIRECT_MEMBER" not in _ids(f)


# ---------------------------------------------------------------------------
# GCP VPC: subnet flow logs (CNAP gcp-vpc-1).
# ---------------------------------------------------------------------------

GCP_SUBNET_NO_FLOWLOG = '''
resource "google_compute_subnetwork" "master_subnet" {
  name          = "master"
  region        = var.region
  network       = google_compute_network.vpc.name
  ip_cidr_range = "10.32.0.0/28"
}
'''

GCP_SUBNET_FLOWLOG = '''
resource "google_compute_subnetwork" "master_subnet" {
  name          = "master"
  region        = var.region
  network       = google_compute_network.vpc.name
  ip_cidr_range = "10.32.0.0/28"

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
  }
}
'''


def test_gcp_subnet_without_flow_logs_flagged(tmp_path):
    f = _findings_for(tmp_path, "subnet_nolog", GCP_SUBNET_NO_FLOWLOG)
    assert "TF_GCP_SUBNET_FLOW_LOGS" in _ids(f)


def test_gcp_subnet_with_flow_logs_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "subnet_log", GCP_SUBNET_FLOWLOG)
    assert "TF_GCP_SUBNET_FLOW_LOGS" not in _ids(f)


# ---------------------------------------------------------------------------
# AWS IAM: service-scoped wildcard actions (CNAP aws-iam-13) and
# wildcard action + wildcard resource admin (CNAP aws-iam-8).
# ---------------------------------------------------------------------------

AWS_WILDCARD_ACTION = '''
data "aws_iam_policy_document" "user_policy" {
  statement {
    sid     = "cantreadsecrets"
    effect  = "Deny"
    actions = ["secretsmanager:*", "ssm:*"]
    resources = ["*"]
  }
}
'''

AWS_SCOPED_ACTIONS = '''
data "aws_iam_policy_document" "assume_role" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123:root"]
    }
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
  }
}
'''


def test_aws_service_wildcard_action_flagged(tmp_path):
    f = _findings_for(tmp_path, "aws_wild", AWS_WILDCARD_ACTION)
    ids = _ids(f)
    assert "TF_AWS_IAM_WILDCARD_ACTION_SERVICE" in ids
    assert "TF_AWS_IAM_ADMIN_WILDCARD" in ids


def test_aws_scoped_action_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "aws_scoped", AWS_SCOPED_ACTIONS)
    ids = _ids(f)
    assert "TF_AWS_IAM_WILDCARD_ACTION_SERVICE" not in ids
    assert "TF_AWS_IAM_ADMIN_WILDCARD" not in ids


# ---------------------------------------------------------------------------
# AWS Secrets Manager: KMS encryption (CNAP aws-security-8).
# ---------------------------------------------------------------------------

AWS_SECRET_NO_KMS = '''
resource "aws_secretsmanager_secret" "secret" {
  name                    = "wrongsecret"
  recovery_window_in_days = 0
}
'''

AWS_SECRET_KMS = '''
resource "aws_secretsmanager_secret" "secret" {
  name                    = "wrongsecret"
  recovery_window_in_days = 0
  kms_key_id              = aws_kms_key.secret.arn
}
'''


def test_aws_secret_without_kms_flagged(tmp_path):
    f = _findings_for(tmp_path, "aws_sec_nokms", AWS_SECRET_NO_KMS)
    assert "TF_AWS_SECRETS_KMS" in _ids(f)


def test_aws_secret_with_kms_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "aws_sec_kms", AWS_SECRET_KMS)
    assert "TF_AWS_SECRETS_KMS" not in _ids(f)


# ---------------------------------------------------------------------------
# AWS S3 shared-state bucket: absent hardening (CNAP aws-storage-*).
# ---------------------------------------------------------------------------

S3_BARE = '''
resource "aws_s3_bucket" "state" {}
'''

S3_HARDENED = '''
resource "aws_s3_bucket" "state" {}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "state" {
  bucket = aws_s3_bucket.state.id
  target_bucket = aws_s3_bucket.logs.id
}

resource "aws_s3_bucket_replication_configuration" "state" {
  role = aws_iam_role.rep.arn
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "replicate"
    status = "Enabled"
    destination { bucket = aws_s3_bucket.replica.arn }
  }
}
'''


def test_bare_s3_bucket_flags_hardening_gaps(tmp_path):
    f = _findings_for(tmp_path, "s3_bare", S3_BARE)
    ids = _ids(f)
    assert "TF_AWS_S3_PUBLIC_ACCESS_ABSENT" in ids
    assert "TF_AWS_S3_VERSIONING_ABSENT" in ids
    assert "TF_AWS_S3_ACCESS_LOGGING_ABSENT" in ids
    assert "TF_AWS_S3_REPLICATION_ABSENT" in ids


def test_hardened_s3_bucket_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "s3_good", S3_HARDENED)
    ids = _ids(f)
    assert "TF_AWS_S3_PUBLIC_ACCESS_ABSENT" not in ids
    assert "TF_AWS_S3_VERSIONING_ABSENT" not in ids
    assert "TF_AWS_S3_ACCESS_LOGGING_ABSENT" not in ids
    assert "TF_AWS_S3_REPLICATION_ABSENT" not in ids


# ---------------------------------------------------------------------------
# Azure AKS: absence-of-secure-config family (CNAP azure-network/encryption).
# ---------------------------------------------------------------------------

AKS_INSECURE = '''
resource "azurerm_kubernetes_cluster" "cluster" {
  name                = var.cluster_name
  location            = azurerm_resource_group.default.location
  resource_group_name = azurerm_resource_group.default.name
  dns_prefix          = "wrongsecrets"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_A2m_v2"
  }

  identity { type = "SystemAssigned" }
}
'''

AKS_HARDENED = '''
resource "azurerm_kubernetes_cluster" "cluster" {
  name                = var.cluster_name
  location            = azurerm_resource_group.default.location
  resource_group_name = azurerm_resource_group.default.name
  dns_prefix          = "wrongsecrets"

  private_cluster_enabled = true
  azure_policy_enabled     = true
  disk_encryption_set_id   = azurerm_disk_encryption_set.des.id

  api_server_access_profile {
    authorized_ip_ranges = ["10.0.0.0/24"]
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_A2m_v2"
  }

  identity { type = "SystemAssigned" }

  role_based_access_control_enabled = true

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.la.id
  }
}
'''


def test_aks_insecure_flags_posture_gaps(tmp_path):
    f = _findings_for(tmp_path, "aks_bad", AKS_INSECURE)
    ids = _ids(f)
    assert "TF_AZURE_AKS_NETWORK_POLICY" in ids
    assert "TF_AZURE_AKS_PRIVATE" in ids
    assert "TF_AZURE_AKS_DISK_ENCRYPTION" in ids
    assert "TF_AZURE_AKS_POLICY_ADDON" in ids
    assert "TF_AZURE_AKS_MONITORING" in ids


def test_aks_hardened_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "aks_good", AKS_HARDENED)
    ids = _ids(f)
    assert "TF_AZURE_AKS_NETWORK_POLICY" not in ids
    assert "TF_AZURE_AKS_PRIVATE" not in ids
    assert "TF_AZURE_AKS_DISK_ENCRYPTION" not in ids
    assert "TF_AZURE_AKS_POLICY_ADDON" not in ids
    assert "TF_AZURE_AKS_MONITORING" not in ids


# ---------------------------------------------------------------------------
# Azure Key Vault: purge protection (explicit false = TP), network ACL,
# secret expiration + content type (CNAP azure-secrets/security).
# ---------------------------------------------------------------------------

KV_BAD = '''
resource "azurerm_key_vault" "vault" {
  name                     = "wrongsecrets"
  location                 = "westeurope"
  resource_group_name      = "rg"
  tenant_id                = data.azurerm_client_config.current.tenant_id
  sku_name                 = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
}

resource "azurerm_key_vault_secret" "s1" {
  name         = "wrongsecret"
  value        = random_password.password.result
  key_vault_id = azurerm_key_vault.vault.id
}
'''

KV_GOOD = '''
resource "azurerm_key_vault" "vault" {
  name                     = "wrongsecrets"
  location                 = "westeurope"
  resource_group_name      = "rg"
  tenant_id                = data.azurerm_client_config.current.tenant_id
  sku_name                 = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault_secret" "s1" {
  name         = "wrongsecret"
  value        = random_password.password.result
  key_vault_id = azurerm_key_vault.vault.id
  expiration_date = "2027-01-01T00:00:00Z"
  content_type    = "password"
}
'''


def test_key_vault_purge_protection_false_flagged(tmp_path):
    f = _findings_for(tmp_path, "kv_bad", KV_BAD)
    ids = _ids(f)
    assert "TF_AZURE_KV_PURGE_PROTECTION" in ids
    assert "TF_AZURE_KV_NETWORK_ACL" in ids
    assert "TF_AZURE_KV_SECRET_EXPIRATION" in ids
    assert "TF_AZURE_KV_SECRET_CONTENT_TYPE" in ids


def test_key_vault_hardened_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "kv_good", KV_GOOD)
    ids = _ids(f)
    assert "TF_AZURE_KV_PURGE_PROTECTION" not in ids
    assert "TF_AZURE_KV_NETWORK_ACL" not in ids
    assert "TF_AZURE_KV_SECRET_EXPIRATION" not in ids
    assert "TF_AZURE_KV_SECRET_CONTENT_TYPE" not in ids


# ---------------------------------------------------------------------------
# Azure Storage account: absence-of-hardening family (CNAP azure-storage).
# ---------------------------------------------------------------------------

STORAGE_BARE = '''
resource "azurerm_storage_account" "account" {
  name                     = "wrongsecrets"
  resource_group_name      = azurerm_resource_group.default.name
  location                 = azurerm_resource_group.default.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
'''

STORAGE_GOOD = '''
resource "azurerm_storage_account" "account" {
  name                     = "wrongsecrets"
  resource_group_name      = azurerm_resource_group.default.name
  location                 = azurerm_resource_group.default.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  public_network_access_enabled = false
  enable_https_traffic_only     = true
  min_tls_version               = "TLS1_2"

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  customer_managed_key {
    key_vault_id       = azurerm_key_vault.kv.id
    key_name           = azurerm_key_vault_key.k.name
    key_version        = azurerm_key_vault_key.k.version
  }

  blob_properties {
    logging { read = true write = true delete = true }
  }

  queue_properties {
    logging { read = true write = true delete = true }
  }
}
'''


def test_bare_storage_account_flags_hardening_gaps(tmp_path):
    f = _findings_for(tmp_path, "storage_bare", STORAGE_BARE)
    ids = _ids(f)
    assert "TF_AZURE_STORAGE_PUBLIC_ACCESS" in ids
    assert "TF_AZURE_STORAGE_HTTPS" in ids
    assert "TF_AZURE_STORAGE_TLS" in ids
    assert "TF_AZURE_STORAGE_DEFAULT_DENY" in ids
    assert "TF_AZURE_STORAGE_CMK" in ids
    assert "TF_AZURE_STORAGE_BYPASS" in ids
    assert "TF_AZURE_STORAGE_BLOB_LOGGING" in ids


def test_hardened_storage_account_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "storage_good", STORAGE_GOOD)
    ids = _ids(f)
    assert "TF_AZURE_STORAGE_PUBLIC_ACCESS" not in ids
    assert "TF_AZURE_STORAGE_HTTPS" not in ids
    assert "TF_AZURE_STORAGE_TLS" not in ids
    assert "TF_AZURE_STORAGE_DEFAULT_DENY" not in ids
    assert "TF_AZURE_STORAGE_CMK" not in ids
    assert "TF_AZURE_STORAGE_BYPASS" not in ids
    assert "TF_AZURE_STORAGE_BLOB_LOGGING" not in ids


# ---------------------------------------------------------------------------
# GCP storage bucket logging (CNAP gcp-logging-3).
# ---------------------------------------------------------------------------

BUCKET_NO_LOGGING = '''
resource "google_storage_bucket" "state_bucket" {
  name     = "tfstate"
  location = var.region

  versioning { enabled = true }
}
'''

BUCKET_LOGGING = '''
resource "google_storage_bucket" "state_bucket" {
  name     = "tfstate"
  location = var.region

  versioning { enabled = true }

  logging { log_bucket = "logs" }
}
'''


def test_gcp_bucket_without_logging_flagged(tmp_path):
    f = _findings_for(tmp_path, "bucket_nolog", BUCKET_NO_LOGGING)
    assert "TF_GCP_STORAGE_LOGGING" in _ids(f)


def test_gcp_bucket_with_logging_not_flagged(tmp_path):
    f = _findings_for(tmp_path, "bucket_log", BUCKET_LOGGING)
    assert "TF_GCP_STORAGE_LOGGING" not in _ids(f)
