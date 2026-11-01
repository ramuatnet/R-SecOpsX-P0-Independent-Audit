"""T-9.9 docker-compose + helm (task.md §12 PHASE 9 "docker-compose + helm").

Gates pinned here:

* the deploy artifacts (Dockerfile, .dockerignore, docker-compose.yml,
  deploy/env.example, deploy/auth.example.json, deploy/helm chart) exist
  with the security posture FIXED in-file: tagged base image, uid
  10001:10001, EXPOSE 8080 only, HEALTHCHECK on the open /v1/health
  route, loopback host-port, read-only rootfs + tmpfs + no-new-privileges,
  non-root / read-only / no-privilege-escalation / drop-ALL / resource
  limits in the chart container + pod securityContext;
* fail-closed twice for auth: compose mounts deploy/auth.example.json
  read-only; the chart mounts an EXTERNAL Secret (<name>-auth) that is
  NOT in values.yaml -- the pod cannot start until the operator creates
  it (mount failure, no `optional:`), and serve itself exits rc2
  (auth_required_for_non_loopback / auth_file_unreadable) without a
  readable auth file on a non-loopback bind;
* our OWN engines agree the artifacts are clean (engine-zero: docker /
  compose file / compose dir / k8s helm dir / k8s over the compose file /
  secrets over deploy + compose + Dockerfile -- the eight measurements
  that drove the parse-clean deployment rewrite and the external-Secret
  design), and deployment.yaml parses via parse_k8s_documents so the
  structured Kubernetes path (not the fallback) evaluates the real
  container;
* no host absolute paths anywhere in the deploy sources.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]

DOCKERFILE = REPO / "Dockerfile"
DOCKERIGNORE = REPO / ".dockerignore"
COMPOSE = REPO / "docker-compose.yml"
HELM = REPO / "deploy" / "helm" / "rsecopsx"
CHART = HELM / "Chart.yaml"
VALUES = HELM / "values.yaml"
DEPLOYMENT = HELM / "templates" / "deployment.yaml"
SERVICE = HELM / "templates" / "service.yaml"
PVC = HELM / "templates" / "pvc.yaml"
NOTES = HELM / "templates" / "NOTES.txt"
HELPERS = HELM / "templates" / "_helpers.tpl"
SECRET_YAML = HELM / "templates" / "secret.yaml"
ENV_EXAMPLE = REPO / "deploy" / "env.example"
AUTH_EXAMPLE = REPO / "deploy" / "auth.example.json"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# A. artifact inventory -- external-Secret design is part of the contract
# ---------------------------------------------------------------------------


def test_required_artifacts_exist_and_secret_yaml_is_absent():
    for path in (DOCKERFILE, DOCKERIGNORE, COMPOSE, ENV_EXAMPLE, AUTH_EXAMPLE,
                 CHART, VALUES, HELPERS, DEPLOYMENT, SERVICE, PVC, NOTES):
        assert path.is_file(), f"missing deploy artifact: {path.name}"
    # external-Secret design: the chart materialises NO credential
    # material, so there is no kind: Secret template for the secrets
    # engine's K8S_SECRET_MATERIAL rule to (correctly) flag.
    assert not SECRET_YAML.exists()


# ---------------------------------------------------------------------------
# B. Dockerfile posture
# ---------------------------------------------------------------------------


def test_dockerfile_security_posture():
    text = _read(DOCKERFILE)
    assert "FROM python:3.14-slim-bookworm" in text  # tagged, never :latest
    assert "USER 10001:10001" in text
    assert "EXPOSE 8080" in text
    assert "HEALTHCHECK" in text and "/v1/health" in text
    # instruction checks run on non-comment lines only -- comments may
    # legitimately DISCUSS the forbidden instructions; verb checks are
    # first-token matches so `useradd` never reads as `ADD`.
    instructions = [ln for ln in text.splitlines()
                    if not ln.lstrip().startswith("#")]
    verbs = {ln.strip().split()[0].lower()
             for ln in instructions if ln.strip()}
    assert "add" not in verbs
    assert "maintainer" not in verbs
    body = "\n".join(instructions)
    assert re.search(r"\b(?:curl|wget)\b[^;\n]*\|\s*(?:/bin/)?(?:ba)?sh",
                     body) is None
    assert "chmod 777" not in body
    assert ":latest" not in body


def test_dockerfile_cmd_is_fail_closed_serve():
    text = _read(DOCKERFILE)
    # non-loopback bind and auth file must travel together: serve exits
    # rc2 (auth_required_for_non_loopback) without one.
    for token in ("--serve", "--serve-host", "0.0.0.0",
                  "--auth-file", "/etc/rsecopsx/auth.json"):
        assert token in text


def test_dockerfile_env_carries_no_credentials():
    for line in _read(DOCKERFILE).splitlines():
        stripped = line.strip()
        assert not stripped.startswith("ARG "), stripped
        if stripped.startswith("ENV "):
            assert re.search(
                r"(PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIAL)",
                stripped, re.IGNORECASE) is None, stripped


# ---------------------------------------------------------------------------
# C. docker-compose posture
# ---------------------------------------------------------------------------


def test_compose_parses_with_hardened_api_service():
    import yaml

    doc = yaml.safe_load(_read(COMPOSE))
    assert doc["name"] == "rsecopsx"
    api = doc["services"]["api"]
    assert api["image"] == "rsecopsx/api:0.1.0"
    assert api["user"] == "10001:10001"
    assert api["read_only"] is True
    assert "/tmp" in api["tmpfs"]
    assert "no-new-privileges:true" in api["security_opt"]
    assert api["ports"] == ["127.0.0.1:8080:8080"]
    assert "./deploy/auth.example.json:/etc/rsecopsx/auth.json:ro" in \
        api["volumes"]
    assert "privileged" not in api
    joined = _read(COMPOSE)
    assert "docker.sock" not in joined


def test_compose_images_are_pinned():
    import yaml

    doc = yaml.safe_load(_read(COMPOSE))
    for name, svc in doc["services"].items():
        image = svc["image"]
        assert ":" in image, (name, image)
        assert not image.endswith(":latest"), (name, image)


def test_compose_db_password_is_plain_env_interpolation():
    import yaml

    doc = yaml.safe_load(_read(COMPOSE))
    env = doc["services"]["db"]["environment"]
    # ${VAR:default} at a credential key is reported as a hardcoded
    # fallback (CONFIG_CONTEXTUAL_CREDENTIAL); plain ${VAR} is not.  The
    # fail-closed property survives either way: the postgres image
    # refuses to initialise with an empty password.
    assert env["POSTGRES_PASSWORD"] == "${RSX_DB_PASSWORD}"
    assert ":?" not in env["POSTGRES_PASSWORD"]
    assert ":-" not in env["POSTGRES_PASSWORD"]


def test_compose_db_is_optin_profile_with_healthchecks():
    import yaml

    doc = yaml.safe_load(_read(COMPOSE))
    assert doc["services"]["db"]["profiles"] == ["postgres"]
    for name, svc in doc["services"].items():
        assert "healthcheck" in svc, name
        assert "restart" in svc, name
    api_test = doc["services"]["api"]["healthcheck"]["test"]
    assert any("/v1/health" in str(part) for part in api_test)


# ---------------------------------------------------------------------------
# D. helm chart posture
# ---------------------------------------------------------------------------


def test_chart_metadata():
    import yaml

    chart = yaml.safe_load(_read(CHART))
    assert chart["apiVersion"] == "v2"
    assert chart["name"] == "rsecopsx"
    assert chart["type"] == "application"
    assert chart["version"] == "0.1.0"
    assert chart["appVersion"] == "0.1.0"


def test_values_defaults_and_no_auth_block():
    import yaml

    values = yaml.safe_load(_read(VALUES))
    assert values["image"]["tag"] == "0.1.0"
    assert values["image"]["pullPolicy"] == "IfNotPresent"
    assert values["replicaCount"] == 1
    res = values["resources"]
    for side in ("requests", "limits"):
        assert set(res[side]) == {"cpu", "memory"}, side
    # external-Secret design: no credential-shaped key can ever sit in
    # `helm get values` output.
    assert "auth" not in values
    assert "token" not in values
    assert "REPLACE_ME" not in _read(VALUES)


def test_deployment_template_text_contracts():
    text = _read(DEPLOYMENT)
    for needle in (
        "runAsNonRoot: true",
        "readOnlyRootFilesystem: true",
        "allowPrivilegeEscalation: false",
        "- ALL",
        "runAsUser: 10001",
        "path: /v1/health",
        "image: '{{ .Values.image.repository }}:{{ .Values.image.tag }}'",
        "secretName: '{{ printf \"%s-auth\" (include \"rsecopsx.name\" .) }}'",
        "claimName: '{{ include \"rsecopsx.name\" . }}-data'",
    ):
        assert needle in text, needle
    assert text.count("path: /v1/health") == 2  # readiness + liveness
    # parse-clean pin: no helm control lines, so the raw template parses
    # and the structured Kubernetes path sees the real container.
    assert "{{- include" not in text
    for bad in ("privileged: true", "runAsUser: 0", ":latest",
                "imagePullPolicy: Always", "hostNetwork", "NET_RAW",
                "POSTGRES_PASSWORD", "AKIA", "stringData"):
        assert bad not in text, bad


def test_deployment_template_parses_with_structured_controls():
    from scanner.iac_models import parse_k8s_documents

    docs = parse_k8s_documents(_read(DEPLOYMENT))
    assert docs is not None, "deployment.yaml must parse (structured path)"
    assert len(docs) == 1
    data = docs[0].data
    assert data["kind"] == "Deployment"
    pod = data["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    cont = pod["containers"][0]
    sc = cont["securityContext"]
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["runAsNonRoot"] is True
    assert sc["runAsUser"] == 10001
    assert sc["capabilities"]["drop"] == ["ALL"]
    secret = [v for v in pod["volumes"] if v["name"] == "auth"][0]["secret"]
    # the WHOLE reference is one helm expression (no literal suffix
    # after `}}`), so the secrets engine's code-reference exemption applies
    name = secret["secretName"]
    assert name.startswith("{{ ") and name.endswith(" }}")


def test_deployment_secret_mount_is_fail_closed():
    text = _read(DEPLOYMENT)
    # no `optional:` on the secret volume: a missing Secret blocks pod
    # start (mount failure) instead of degrading to no-auth.
    assert "optional:" not in text
    assert "--auth-file" in text


def test_notes_txt_documents_external_secret_and_airgap():
    text = _read(NOTES)
    for needle in ("kubectl create secret generic", "Fail-closed",
                   "port-forward", "/v1/health", "IfNotPresent",
                   "auth.example.json"):
        assert needle in text, needle


def test_service_and_pvc_template_shapes():
    service = _read(SERVICE)
    assert "ClusterIP" in service or ".Values.service.type" in service
    assert ".Values.service.port" in service
    pvc = _read(PVC)
    assert "ReadWriteOnce" in pvc
    assert ".Values.persistence.size" in pvc


# ---------------------------------------------------------------------------
# E. auth / env example contracts
# ---------------------------------------------------------------------------


def test_auth_example_loads_for_serve_with_placeholder_token():
    from analysis.serve.auth import ROLE_RANK, load_auth_file

    cfg = load_auth_file(str(AUTH_EXAMPLE))
    assert len(cfg.tokens) == 1
    assert cfg.tokens[0]["role"] == "admin"
    assert cfg.tokens[0]["role"] in ROLE_RANK
    # placeholder pin: the committed example never carries a real token
    assert cfg.tokens[0]["token"] == "REPLACE_ME_BEFORE_DEPLOY"


def test_env_example_is_placeholder_only():
    text = _read(ENV_EXAMPLE)
    assert "RSX_DB_PASSWORD=CHANGE_ME_BEFORE_USE" in text


# ---------------------------------------------------------------------------
# F. no host absolute paths in deploy sources
# ---------------------------------------------------------------------------


def test_no_host_absolute_paths_in_deploy_sources():
    # container paths (/var/lib/..., /etc/..., /app) are legitimate;
    # host checkout paths are not.  The drive-letter forms are anchored
    # with a lookbehind so http://... never matches.
    bad_literals = ("/home/", "/Users/", "/c/Users", "/d/Users")
    drive = re.compile(r"(?<![A-Za-z])[A-Za-z]:[/\\]")
    files = [DOCKERFILE, DOCKERIGNORE, COMPOSE, ENV_EXAMPLE, AUTH_EXAMPLE,
             CHART, VALUES, HELPERS, DEPLOYMENT, SERVICE, PVC, NOTES]
    for path in files:
        text = _read(path)
        for lit in bad_literals:
            assert lit not in text, (path.name, lit)
        assert drive.search(text) is None, path.name


# ---------------------------------------------------------------------------
# G. engine-zero integration -- the batch gate (all eight measurements)
# ---------------------------------------------------------------------------


def test_docker_engine_zero_on_dockerfile():
    from scanner.iac_docker import scan_docker

    assert scan_docker(str(DOCKERFILE)) == []


def test_compose_engine_zero_on_file_and_repo_dir():
    from scanner.iac_compose import scan_compose

    assert scan_compose(str(COMPOSE)) == []
    assert scan_compose(str(REPO)) == []


def test_k8s_engine_zero_on_helm_dir_and_compose_file():
    from scanner.iac_kubernetes import scan_kubernetes

    assert scan_kubernetes(str(REPO / "deploy" / "helm")) == []
    assert scan_kubernetes(str(COMPOSE)) == []


def test_secrets_engine_zero_on_deploy_compose_and_dockerfile():
    from scanner.secret_intelligence import scan_secret_intelligence

    for target in (str(REPO / "deploy"), str(COMPOSE), str(DOCKERFILE)):
        rows = scan_secret_intelligence(target)["secret_intelligence_findings"]
        assert rows == [], (target, rows[:3])
