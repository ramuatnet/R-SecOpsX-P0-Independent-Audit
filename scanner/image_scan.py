"""T-9.19 container image scanning (task.md section 13, last §13 item).

Scans a REAL container image rather than its Dockerfile source:

* config posture -- from `docker image inspect` (local daemon) or from
  a `docker save` tarball's manifest.json + config blob.  Rules cover
  root user, mutable/latest or missing tags, missing digest pinning,
  secret-shaped ENV entries, sensitive exposed ports, missing
  HEALTHCHECK;
* layer content -- only via the tarball path (docker save output):
  secret file paths (id_rsa/.env/credentials..., public certificates
  deliberately excluded) and private-key material, content-bounded to
  a 4 MiB read per member so a 400 MB layer never materializes.

OFFLINE INVARIANT: this engine NEVER pulls.  `docker image inspect`
against a missing local image is a could-not-run (exit 2), never a
registry fetch; a pre-saved tarball needs no daemon at all.  The
daemon is used for local IPC only.  Layer rules require a saved
tarball (`docker save <ref> -o image.tar`), because a save's layer
blobs live inside the tar while inspect only exposes config.

Exit codes: 0 scanned (findings or clean), 2 could-not-run (missing
daemon, image not local, unreadable tarball, non-docker layout).

NOT ADOPTED: trivy, grype, docker scout, snyk -- the named-vendor
image scanners need an online CVE/OS feed, which the offline no-
required-deps invariant forbids; this is in-house posture + layer
content scanning instead (std-lib tarfile/json only).  OS-package
CVE matching is NOT claimed anywhere in this module.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tarfile
from typing import Any

#: Content bound per layer member: only this many bytes are read for
#: the private-key needle (resource bound, disclosed in docstring).
CONTENT_BOUND = 4 * 1024 * 1024

# Assembled from fragments: the engine source itself must not carry a
# complete private-key literal (repo self-scan stays clean).
_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----")

_SECRET_ENV_KEY_RE = re.compile(
    r"PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|SECRET_KEY",
    re.IGNORECASE)

#: Basenames (exact) that are secret material by shape.  ``.pem`` is
#: deliberately absent: public certificates live under that suffix.
_SECRET_BASENAMES = frozenset({
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    ".env", "credentials.json", ".netrc", "kubeconfig",
})
_SECRET_SUFFIXES = (".pfx", ".p12")

#: Parity with scanner/iac_docker.py DOCKER_EXPOSE_SENSITIVE_PORT.
_SENSITIVE_PORTS = frozenset(
    {"22", "2375", "2376", "3306", "5432", "6379", "27017", "9200"})

RULES: list[dict[str, Any]] = [
    {
        "rule_id": "IMAGE_RUNS_AS_ROOT",
        "title": "Image Runs As Root",
        "severity": "High",
        "description": "Image config declares an empty or root USER, so "
                       "the container process runs as root.",
        "remediation": "Set a non-root USER in the image config "
                       "(USER <uid>:<gid>).",
        "cwe": "CWE-250",
        "framework": "CIS Docker Benchmark",
        "control": "Least Privilege Container User",
    },
    {
        "rule_id": "IMAGE_LATEST_TAG",
        "title": "Image Tag Is Mutable (latest)",
        "severity": "Medium",
        "description": "Image is tagged latest (or has no tag component), "
                       "so the tag is mutable and deploys are not pinned.",
        "remediation": "Tag images with an immutable version and deploy "
                       "by digest where possible.",
        "cwe": "CWE-1104",
        "framework": "CIS Docker Benchmark",
        "control": "Image Version Pinning",
    },
    {
        "rule_id": "IMAGE_UNTAGGED",
        "title": "Image Has No Tag",
        "severity": "Medium",
        "description": "Image carries no tag at all (docker commit-style "
                       "or stripped reference), so nothing pins what "
                       "was deployed.",
        "remediation": "Tag the image with an immutable version before "
                       "shipping it.",
        "cwe": "CWE-1104",
        "framework": "CIS Docker Benchmark",
        "control": "Image Version Pinning",
    },
    {
        "rule_id": "IMAGE_DIGEST_UNPINNED",
        "title": "Image Not Pinned By Digest",
        "severity": "Low",
        "description": "Local image has no RepoDigests, so its content "
                       "cannot be tied to an immutable registry digest.",
        "remediation": "Reference the image by digest "
                       "(repo@sha256:...) in deployments.",
        "cwe": "CWE-1104",
        "framework": "CIS Docker Benchmark",
        "control": "Image Version Pinning",
    },
    {
        "rule_id": "IMAGE_ENV_SECRET",
        "title": "Secret Shaped ENV In Image Config",
        "severity": "Critical",
        "description": "Image config carries an ENV entry whose key looks "
                       "like a credential and whose value is non-empty.",
        "remediation": "Remove secrets from image ENV; inject credentials "
                       "at runtime from a secrets manager.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    {
        "rule_id": "IMAGE_EXPOSE_SENSITIVE_PORT",
        "title": "Sensitive Port Exposed",
        "severity": "Medium",
        "description": "Image config exposes a sensitive administrative "
                       "or database port.",
        "remediation": "Expose only required application ports and "
                       "restrict access at runtime/network level.",
        "cwe": "CWE-200",
        "framework": "CIS Docker Benchmark",
        "control": "Network Exposure",
        "ports": sorted(_SENSITIVE_PORTS),
    },
    {
        "rule_id": "IMAGE_MISSING_HEALTHCHECK",
        "title": "Image Missing HEALTHCHECK",
        "severity": "Low",
        "description": "Image config defines no HEALTHCHECK, so the "
                       "orchestrator cannot detect an unresponsive "
                       "container.",
        "remediation": "Add a HEALTHCHECK that probes the application's "
                       "health endpoint.",
        "cwe": "CWE-1059",
        "framework": "CIS Docker Benchmark",
        "control": "Container Health Monitoring",
    },
    {
        "rule_id": "IMAGE_LAYER_SECRET_PATH",
        "title": "Secret File Inside Image Layer",
        "severity": "High",
        "description": "An image layer contains a file whose path shape "
                       "identifies credential material (private keys, "
                       ".env, credentials).",
        "remediation": "Rebuild without the file; mount secrets at "
                       "runtime instead of baking them into layers.",
        "cwe": "CWE-798",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
    {
        "rule_id": "IMAGE_LAYER_PRIVATE_KEY",
        "title": "Private Key Material Inside Image Layer",
        "severity": "Critical",
        "description": "An image layer's content (first 4 MiB of the "
                       "member) contains PEM private-key material.",
        "remediation": "Rebuild without the key; provision keys at "
                       "runtime from a secret store.",
        "cwe": "CWE-321",
        "framework": "Secret Management",
        "control": "Credential Protection",
    },
]

_RULE_BY_ID = {rule["rule_id"]: rule for rule in RULES}


class ImageScanError(RuntimeError):
    """could-not-run: the scan could not be performed at all."""


def _priority(severity: str) -> str:
    return {
        "Critical": "P1",
        "High": "P2",
        "Medium": "P3",
        "Low": "P4",
        "Info": "P4",
    }.get(severity, "P3")


def _finding(rule: dict[str, Any], source: str, evidence: str,
             snippet: str = "", line: int = 1) -> dict[str, Any]:
    # line: image findings are NOT SCA/SBOM family, so the legal
    # anchor is a positive document line (ufib G1 reserves line 0 for
    # package+CVE claims only -- source-family findings must point
    # somewhere).  Config/inspect output is one compact JSON document,
    # so line 1 IS its real location; layer members carry their true
    # line when content matched, else line 1 = the file-level claim.
    text = snippet or evidence
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
        "language": "container-image",
        "file": source,
        "file_name": source.rsplit("/", 1)[-1],
        "file_path": source,
        "full_path": source,
        "line": line,
        "snippet": text,
        "evidence": evidence,
        "description": rule["description"],
        "remediation": [rule["remediation"]],
        "recommendation": rule["remediation"],
        "cwe": rule["cwe"],
        "framework": rule["framework"],
        "control": rule["control"],
        "detection": "Container Image Scanning",
        "occurrences": [
            {"file": source, "file_name": source.rsplit("/", 1)[-1],
             "file_path": source, "full_path": source, "line": line,
             "snippet": text},
        ],
        "affected_files": [source],
        "instances": 1,
    }


def _is_root_user(user) -> bool:
    if user is None:
        return True                      # no USER in config: root by default
    name = str(user).split(":", 1)[0].strip()
    if not name:
        return True
    return name in {"root", "0"}


def findings_from_config(meta: dict, *, source: str) -> list[dict]:
    """Config-posture findings from a normalized image metadata dict.

    Expected keys: user, env, exposed, healthcheck, tags, digests.
    ``digests`` may be None (unknown on the tarball path) which skips
    the digest rule instead of guessing.
    """
    findings: list[dict[str, Any]] = []
    add = findings.append

    if _is_root_user(meta.get("user")):
        add(_finding(_RULE_BY_ID["IMAGE_RUNS_AS_ROOT"], source,
                     evidence="user=%r" % (meta.get("user"),)))

    tags = [str(t) for t in (meta.get("tags") or [])]
    if not tags:
        add(_finding(_RULE_BY_ID["IMAGE_UNTAGGED"], source,
                     evidence="RepoTags=[]"))
    elif any((":" not in t) or t.rsplit(":", 1)[-1] == "latest"
             for t in tags):
        add(_finding(_RULE_BY_ID["IMAGE_LATEST_TAG"], source,
                     evidence="tags=%s" % (tags,)))

    digests = meta.get("digests", None)
    if digests == []:
        add(_finding(_RULE_BY_ID["IMAGE_DIGEST_UNPINNED"], source,
                     evidence="RepoDigests=[]"))
    elif digests:                      # non-empty: pinned, fine
        pass

    for entry in (meta.get("env") or []):
        text = str(entry)
        key, sep, value = text.partition("=")
        if sep and value.strip() and _SECRET_ENV_KEY_RE.search(key):
            add(_finding(_RULE_BY_ID["IMAGE_ENV_SECRET"], source,
                         evidence="ENV %s=<redacted>" % key.strip()))

    exposed = meta.get("exposed") or {}
    for port_key in sorted(str(p) for p in exposed):
        port = port_key.split("/", 1)[0]
        if port in _SENSITIVE_PORTS:
            add(_finding(_RULE_BY_ID["IMAGE_EXPOSE_SENSITIVE_PORT"],
                         source, evidence="EXPOSE %s" % port_key))

    if not (meta.get("healthcheck") or {}):
        add(_finding(_RULE_BY_ID["IMAGE_MISSING_HEALTHCHECK"], source,
                     evidence="Healthcheck=none"))

    return findings


def _is_secret_path(member: str) -> bool:
    name = member.replace("\\", "/").rstrip("/")
    base = name.rsplit("/", 1)[-1].lower()
    if base in _SECRET_BASENAMES:
        return True
    return base.endswith(_SECRET_SUFFIXES)


def findings_from_layer(members: dict, *, source: str) -> list[dict]:
    """Layer findings from {member_path: bytes} (content may already be
    truncated by the caller; the 4 MiB bound is enforced here too)."""
    findings: list[dict[str, Any]] = []
    for path in sorted(members):
        if _is_secret_path(path):
            findings.append(_finding(
                _RULE_BY_ID["IMAGE_LAYER_SECRET_PATH"], source,
                evidence=path, snippet="layer member: %s" % path))
        content = members[path][:CONTENT_BOUND]
        match = _PRIVATE_KEY_RE.search(content)
        if match:
            line = content[:match.start()].count(b"\n") + 1
            findings.append(_finding(
                _RULE_BY_ID["IMAGE_LAYER_PRIVATE_KEY"], source,
                evidence=path,
                snippet="private-key marker in %s" % path,
                line=line))
    return findings


def _meta_from_config_blob(config_blob: dict, tags) -> dict:
    cfg = config_blob.get("config") or {}
    return {
        "user": cfg.get("User"),
        "env": cfg.get("Env") or [],
        "exposed": cfg.get("ExposedPorts") or {},
        "healthcheck": cfg.get("Healthcheck"),
        "tags": list(tags or []),
        # docker-save tarballs carry no digest table: unknown, not empty.
        "digests": None,
    }


def scan_image_tar(tar_path) -> list[dict]:
    """Scan a docker save tarball: config posture + layer content.

    Raises ImageScanError (could-not-run) for unreadable/non-docker
    tarballs.  Layer members are read bounded (4 MiB per member) so
    large layers stream without materializing.
    """
    path = pathlib.Path(tar_path)
    if not path.is_file():
        raise ImageScanError(
            "could-not-run: image tarball not found: %s" % path)

    try:
        with tarfile.open(path, mode="r:*") as outer:
            try:
                manifest_file = outer.extractfile("manifest.json")
            except KeyError:
                manifest_file = None
            if manifest_file is None:
                raise ImageScanError(
                    "could-not-run: %s has no manifest.json "
                    "(non-docker tarball; OCI-layout-only exports are "
                    "not supported)" % path)
            manifest = json.load(manifest_file)
            if not manifest:
                raise ImageScanError(
                    "could-not-run: %s manifest.json is empty" % path)
            entry = manifest[0]
            tags = entry.get("RepoTags") or []

            config_file = outer.extractfile(entry["Config"])
            if config_file is None:
                raise ImageScanError(
                    "could-not-run: config blob missing from %s" % path)
            config_blob = json.load(config_file)

            meta = _meta_from_config_blob(config_blob, tags)
            source = str(path)
            findings = findings_from_config(meta, source=source)

            for layer_name in entry.get("Layers") or []:
                try:
                    layer_file = outer.extractfile(layer_name)
                except KeyError:
                    layer_file = None
                if layer_file is None:
                    findings.append(_finding(
                        _RULE_BY_ID["IMAGE_LAYER_SECRET_PATH"], source,
                        evidence=layer_name,
                        snippet="layer blob missing from tarball"))
                    continue
                try:
                    with tarfile.open(fileobj=layer_file,
                                      mode="r:*") as layer:
                        members = {}
                        for member in layer.getmembers():
                            if not member.isfile():
                                continue
                            handle = layer.extractfile(member)
                            if handle is None:
                                continue
                            members[member.name] = handle.read(
                                CONTENT_BOUND)
                        findings.extend(findings_from_layer(
                            members, source=source))
                except tarfile.TarError as exc:
                    # annotate, never drop silently: a layer we cannot
                    # read still shows up as a finding row
                    findings.append(_finding(
                        _RULE_BY_ID["IMAGE_LAYER_SECRET_PATH"], source,
                        evidence=layer_name,
                        snippet="layer unreadable: %s" % exc))
            return findings
    except ImageScanError:
        raise
    except (tarfile.TarError, OSError, ValueError,
            json.JSONDecodeError) as exc:
        raise ImageScanError(
            "could-not-run: cannot read image tarball %s: %s"
            % (path, exc)) from exc


def _inspect(ref: str) -> dict:
    """docker image inspect -- local daemon IPC, NEVER a pull."""
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", ref],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ImageScanError(
            "could-not-run: docker not available (%s); this engine "
            "never pulls" % exc) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:300]
        raise ImageScanError(
            "could-not-run: image %r not found locally (%s); this "
            "engine never pulls -- load or build it first, or scan a "
            "docker save tarball" % (ref, detail))
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ImageScanError(
            "could-not-run: unparseable inspect output for %r: %s"
            % (ref, exc)) from exc
    if not data:
        raise ImageScanError(
            "could-not-run: inspect returned nothing for %r" % ref)
    return data[0]


def _meta_from_inspect(obj: dict) -> dict:
    cfg = obj.get("Config") or {}
    return {
        "user": cfg.get("User"),
        "env": cfg.get("Env") or [],
        "exposed": cfg.get("ExposedPorts") or {},
        "healthcheck": cfg.get("Healthcheck"),
        "tags": obj.get("RepoTags") or [],
        "digests": obj.get("RepoDigests") or [],
    }


def scan_image_ref(ref: str) -> list[dict]:
    """Config-posture findings for a LOCAL image via docker inspect.

    Layer content rules need the saved tarball path
    (``docker save <ref> -o image.tar`` then --image-tar): inspect
    exposes config only, and this engine never pulls.
    """
    obj = _inspect(ref)
    meta = _meta_from_inspect(obj)
    return findings_from_config(meta, source="docker://%s" % ref)


def scan_images(refs=(), tar=None) -> list[dict]:
    """Convenience wrapper used by main.py: scan each local ref and
    optionally one tarball; raises ImageScanError on the first
    could-not-run (the caller annotates the reason)."""
    findings: list[dict] = []
    for ref in (refs or []):
        findings.extend(scan_image_ref(str(ref)))
    if tar:
        findings.extend(scan_image_tar(tar))
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan a container image (config posture +, with a "
                    "saved tarball, layer content).  Never pulls.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--image-ref", action="append", metavar="REF",
        help="scan this LOCAL image via docker image inspect "
             "(repeatable; never pulls)")
    group.add_argument(
        "--image-tar", metavar="PATH",
        help="scan a docker save tarball (config + layer content)")
    parser.add_argument(
        "--json", action="store_true",
        help="print {source, findings} JSON on stdout")
    args = parser.parse_args(argv)

    try:
        if args.image_tar:
            source = args.image_tar
            findings = scan_image_tar(args.image_tar)
        else:
            source = ";".join(args.image_ref)
            findings = []
            for ref in args.image_ref:
                findings.extend(scan_image_ref(ref))
    except ImageScanError as exc:
        sys.stderr.write("%s\n" % exc)
        return 2

    if args.json:
        print(json.dumps({"source": source, "findings": findings},
                         indent=2, default=str))
    else:
        print("%s: %d finding(s)" % (source, len(findings)))
        for item in findings:
            print("  [%s] %s :: %s"
                  % (item["severity"], item["rule_id"], item["evidence"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
