"""G22 — kubernetes posture join: V11 vs CNAP's 30 k8s findings
(wrongsecrets-master, 5 policies x 6 files).

Adjudication (Temp\\opencode\\g22_coverage.py, source-derived control facts):
  6 MATCHED / 24 JUSTIFIED-SILENT / 0 GAP.

These tests PIN that verdict set so a future rule change can never turn a
CNAP false positive into a V11 false positive (e.g. flagging
allowPrivilegeEscalation or NET_RAW on the fully hardened manifests), and
can never drop a rule that closes one of the 6 genuine control absences.
Fixtures mirror the six wrongsecrets manifests structurally; they use no
prodtest paths so they stay hermetic in CI.
"""

from __future__ import annotations

from scanner.iac_kubernetes import MISSING_RULES, RULES, scan_kubernetes

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return scan_kubernetes(str(p))


def _ids(rows):
    return {r["rule_id"] for r in rows}


def _line_of(text, marker):
    """1-based line of the first line equal to marker (stripped compare)."""
    wanted = marker.strip()
    for idx, line in enumerate(text.splitlines()):
        if line.strip() == wanted:
            return idx + 1
    raise AssertionError("marker not found: %r" % marker)


def _ids_at(rows, line):
    return {r["rule_id"] for r in rows if r["line"] == line}


# ---------------------------------------------------------------------------
# CNAP k8s-security-1/-2, workload-1/-2/-3 on the FULLY HARDENED manifests
# (wrongsecrets aws/vault + okteto x2): all five CNAP findings fired on
# these files anyway -> 24/30 of CNAP's grid is source-contradicted.
# V11 must emit NOTHING here.
# ---------------------------------------------------------------------------

HARDENED = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened
spec:
  template:
    spec:
      securityContext:
        runAsUser: 2000
        runAsGroup: 2000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: jeroenwillemsen/wrongsecrets:1.13.5
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault
          resources:
            requests:
              memory: 512Mi
              cpu: 200m
            limits:
              memory: 512Mi
              cpu: 1000m
"""


def test_hardened_manifest_yields_no_findings(tmp_path):
    """All five CNAP policies are source-contradicted on hardened files;
    V11 must stay completely silent (no escalation, no NET_RAW, no
    security-context or image rows invented out of nothing)."""
    rows = _scan(tmp_path, "hardened.yml", HARDENED)
    assert rows == [], [(r["rule_id"], r["line"]) for r in rows]


def test_hardened_manifest_no_posture_rule_ids(tmp_path):
    rows = _scan(tmp_path, "hardened2.yml", HARDENED)
    for rule_id in (
        "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_MISSING_NET_RAW_DROP",
        "K8S_MISSING_RUN_AS_NON_ROOT",
        "K8S_MISSING_READ_ONLY_ROOT_FS",
        "K8S_MISSING_RESOURCE_LIMITS",
        "K8S_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_NET_RAW_CAPABILITY",
        "K8S_LATEST_IMAGE_TAG",
        "K8S_IMAGE_PULL_ALWAYS",
    ):
        assert rule_id not in _ids(rows), rule_id


# ---------------------------------------------------------------------------
# wrongsecrets k8s/challenge53/debug-container.yml: securityContext present
# at pod AND container level, allowPrivilegeEscalation: false and drop [ALL]
# genuinely set -> CNAP security-2/workload-3/workload-1 are FPs here.
# V11 correctly fires only the two genuinely-missing controls (readOnly,
# limits) -- the adjudicated answer for this file.
# ---------------------------------------------------------------------------

DEBUG_LIKE = """apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsUser: 2000
    runAsNonRoot: true
    allowPrivilegeEscalation: false
  containers:
  - name: app
    image: jeroenwillemsen/wrongsecrets-challenge53-debug:1
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
"""


def test_debug_like_flags_only_genuinely_missing_controls(tmp_path):
    rows = _scan(tmp_path, "debug-container.yml", DEBUG_LIKE)
    assert _ids(rows) == {
        "K8S_MISSING_READ_ONLY_ROOT_FS",
        "K8S_MISSING_RESOURCE_LIMITS",
    }, sorted(_ids(rows))


def test_debug_like_does_not_flag_cnap_fp_controls(tmp_path):
    """APE=false + drop [ALL] + tagged ':1' image are present in source;
    CNAP fired security-2/workload-3/workload-1 here anyway (FP)."""
    rows = _scan(tmp_path, "debug-container-b.yml", DEBUG_LIKE)
    ids = _ids(rows)
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" not in ids
    assert "K8S_MISSING_NET_RAW_DROP" not in ids
    assert "K8S_LATEST_IMAGE_TAG" not in ids
    assert "K8S_MISSING_RUN_AS_NON_ROOT" not in ids  # pod-level true


# ---------------------------------------------------------------------------
# wrongsecrets k8s/challenge53/secret-challenge53-sidecar.yml: the bare
# 'sidecar' container has NO securityContext, no APE, no drop, no limits ->
# CNAP security-1, security-2 and workload-3 are GENUINE and V11 must fire
# (all anchored on the sidecar container's first line, L48 in the original).
# ---------------------------------------------------------------------------

SIDECAR = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-challenge-53
spec:
  template:
    spec:
      securityContext:
        runAsUser: 2000
        runAsGroup: 2000
        fsGroup: 2000
      containers:
      - image: jeroenwillemsen/wrongsecrets-challenge53:1.13.5
        name: secret-challenge-53
        imagePullPolicy: IfNotPresent
        resources:
          requests:
            memory: 32Mi
        securityContext:
          capabilities:
            drop:
              - ALL
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          privileged: false
      - image: jeroenwillemsen/wrongsecrets-challenge53-debug:1.13.5
        name: sidecar
        imagePullPolicy: IfNotPresent
"""


def test_sidecar_bare_container_fires_security_family(tmp_path):
    text = SIDECAR
    rows = _scan(tmp_path, "sidecar.yml", text)
    bare = _line_of(text, "- image: jeroenwillemsen/wrongsecrets-challenge53-debug:1.13.5")
    fired = _ids_at(rows, bare)
    assert fired == {
        "K8S_MISSING_RUN_AS_NON_ROOT",
        "K8S_MISSING_READ_ONLY_ROOT_FS",
        "K8S_MISSING_RESOURCE_LIMITS",
        "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_MISSING_NET_RAW_DROP",
    }, sorted(fired)


def test_sidecar_hardened_container_only_flags_missing_limits(tmp_path):
    text = SIDECAR
    rows = _scan(tmp_path, "sidecar-b.yml", text)
    first = _line_of(text, "- image: jeroenwillemsen/wrongsecrets-challenge53:1.13.5")
    fired = _ids_at(rows, first)
    # securityContext controls present -> only the requests-without-limits
    # defect is reported; no escalation/NET_RAW/runAsNonRoot/readOnly rows.
    assert fired == {"K8S_MISSING_RESOURCE_LIMITS"}, sorted(fired)


def test_sidecar_tagged_images_not_flagged_as_latest(tmp_path):
    rows = _scan(tmp_path, "sidecar-c.yml", SIDECAR)
    assert "K8S_LATEST_IMAGE_TAG" not in _ids(rows)
    assert "K8S_IMAGE_PULL_ALWAYS" not in _ids(rows)


# ---------------------------------------------------------------------------
# wrongsecrets k8s/sealed-secret-controller.yaml: image ':latest' (genuine
# workload-1), no allowPrivilegeEscalation anywhere (genuine security-2),
# no capabilities.drop (genuine workload-3) -> V11 must fire all three.
# Pod+container securityContext exist and runAsNonRoot/readOnly are set ->
# CNAP security-1 stays a FP and V11 must NOT invent those rows.
# ---------------------------------------------------------------------------

SEALED = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: sealed-secrets-controller
spec:
  template:
    spec:
      securityContext:
        fsGroup: 65534
      containers:
        - args: []
          command:
            - controller
          image: bitnami/sealed-secrets-controller:latest
          imagePullPolicy: Always
          name: sealed-secrets-controller
          securityContext:
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1001
"""


def test_sealed_like_genuine_absences_flagged(tmp_path):
    text = SEALED
    rows = _scan(tmp_path, "sealed.yml", text)
    container = _line_of(text, "- args: []")
    image = _line_of(text, "image: bitnami/sealed-secrets-controller:latest")
    pull = _line_of(text, "imagePullPolicy: Always")

    assert "K8S_LATEST_IMAGE_TAG" in _ids_at(rows, image)
    assert "K8S_IMAGE_PULL_ALWAYS" in _ids_at(rows, pull)
    fired = _ids_at(rows, container)
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" in fired
    assert "K8S_MISSING_NET_RAW_DROP" in fired
    assert "K8S_MISSING_RESOURCE_LIMITS" in fired
    # securityContext present with runAsNonRoot/readOnly true: no FP rows.
    assert "K8S_MISSING_RUN_AS_NON_ROOT" not in fired
    assert "K8S_MISSING_READ_ONLY_ROOT_FS" not in fired


def test_sealed_like_absent_escalation_not_double_reported(tmp_path):
    """A manifest that never mentions allowPrivilegeEscalation is reported
    once, by the MISSING rule (presence-rule claims explicit true)."""
    rows = _scan(tmp_path, "sealed-b.yml", SEALED)
    ids = _ids(rows)
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" in ids
    assert "K8S_ALLOW_PRIVILEGE_ESCALATION" not in ids


# ---------------------------------------------------------------------------
# CNAP workload-2 family (capabilities.add non-empty): no wrongsecrets
# manifest adds a capability -> all 6 CNAP workload-2 rows are FPs; the
# NET_RAW-only presence rule must stay quiet on drop-only manifests and
# must still fire on genuinely added capabilities.
# ---------------------------------------------------------------------------

ADD_CAP = """apiVersion: v1
kind: Pod
metadata:
  name: add-cap
spec:
  containers:
    - name: app
      image: acme/app:1.0.0
      securityContext:
        capabilities:
          add:
            - NET_RAW
"""


def test_added_net_raw_capability_flagged(tmp_path):
    rows = _scan(tmp_path, "add.yml", ADD_CAP)
    assert "K8S_NET_RAW_CAPABILITY" in _ids(rows)


def test_drop_only_capabilities_not_flagged_as_added(tmp_path):
    DROP_ONLY = """apiVersion: v1
kind: Pod
metadata:
  name: drop-only
spec:
  containers:
    - name: app
      image: acme/app:1.0.0
      securityContext:
        capabilities:
          drop:
            - ALL
"""
    rows = _scan(tmp_path, "drop.yml", DROP_ONLY)
    assert "K8S_NET_RAW_CAPABILITY" not in _ids(rows)
    assert "K8S_MISSING_NET_RAW_DROP" not in _ids(rows)


# ---------------------------------------------------------------------------
# Catalog + policy-map invariants: the 6 MATCHED findings depend on these
# rule ids existing; removing one silently re-opens a GAP.
# ---------------------------------------------------------------------------

SHIPPED_K8S_RULE_IDS = {
    "K8S_PRIVILEGED_CONTAINER",
    "K8S_ALLOW_PRIVILEGE_ESCALATION",
    "K8S_HOST_NETWORK",
    "K8S_HOST_PID",
    "K8S_HOST_IPC",
    "K8S_RUN_AS_ROOT",
    "K8S_READ_ONLY_ROOT_FS_DISABLED",
    "K8S_NET_RAW_CAPABILITY",
    "K8S_LATEST_IMAGE_TAG",
    "K8S_IMAGE_PULL_ALWAYS",
    "K8S_POSTGRES_PASSWORD_ENV",
    "K8S_AWS_SECRET_ENV",
    "K8S_MISSING_RUN_AS_NON_ROOT",
    "K8S_MISSING_READ_ONLY_ROOT_FS",
    "K8S_MISSING_RESOURCE_LIMITS",
    "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION",
    "K8S_MISSING_NET_RAW_DROP",
}

# CNAP policy suffix -> V11 rule family used by the G22 adjudication.
CNAP_POLICY_FAMILY = {
    "k8s-security-1": {
        "K8S_MISSING_RUN_AS_NON_ROOT",
        "K8S_MISSING_READ_ONLY_ROOT_FS",
        "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_MISSING_NET_RAW_DROP",
    },
    "k8s-security-2": {
        "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_ALLOW_PRIVILEGE_ESCALATION",
    },
    "k8s-workload-1": {"K8S_LATEST_IMAGE_TAG"},
    "k8s-workload-2": {"K8S_NET_RAW_CAPABILITY"},
    "k8s-workload-3": {"K8S_MISSING_NET_RAW_DROP", "K8S_NET_RAW_CAPABILITY"},
}


def test_shipped_k8s_rule_catalog_stable():
    catalog = {r["rule_id"] for r in RULES} | {r["rule_id"] for r in MISSING_RULES}
    assert catalog == SHIPPED_K8S_RULE_IDS, sorted(catalog ^ SHIPPED_K8S_RULE_IDS)


def test_cnap_policy_families_map_to_shipped_rules():
    catalog = {r["rule_id"] for r in RULES} | {r["rule_id"] for r in MISSING_RULES}
    for policy, family in CNAP_POLICY_FAMILY.items():
        missing = family - catalog
        assert not missing, "%s lost rules: %s" % (policy, sorted(missing))
