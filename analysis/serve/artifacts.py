"""T-9.5 artifact store -- durable, tenancy-scoped scan artifacts.

task.md section 12 PHASE 9 lists "artifact store" between Postgres and
the UI: the platform-side durable layer for scan artifacts (reports,
manifests, SBOM slices) that the API -- and later the SPA -- read and
write with the SAME credential tenancy as jobs.

Contracts:

* content-addressed digests ("sha256:" + sha256 of the final bytes);
* logical NAMES never paths (charset [A-Za-z0-9._-], so no traversal);
* id canon ``art_`` + sha256(name)[:12] unscoped, tenant+name when
  scoped (webhook_id_for precedent, frozen by test from this batch);
* caps as model constants (MAX_ARTIFACTS, MAX_ARTIFACT_BYTES), read
  through the module reference so tests can monkeypatch;
* replace-on-put (idempotent re-stow, bump created_at);
* verify-on-read opt-in (digest mismatch -> artifact_content_corrupt);
* cross-tenant get/delete miss (404-shaped, never an existence oracle);
* unscoped operator sees all (T-9.2 convention).

The store never touches the network (AST-pinned banned imports).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from . import model

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_KIND_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class ArtifactInvalid(Exception):
    """Artifact rejected; .reason is machine-readable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def artifact_id_for(name: str, tenant=None) -> str:
    """Stable artifact primary key (shared by both backends' callers).

    Bare name when unscoped; tenant+name when scoped so two tenants can
    store the SAME name without squatting on each other's primary key.
    """
    canon = name if not tenant else f"{tenant}\n{name}"
    return "art_" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:12]


def _normalize_content(content) -> bytes:
    """Canonical final bytes for every accepted content shape."""
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, (dict, list, int, float, bool)):
        return json.dumps(content, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")
    raise ArtifactInvalid("artifact_content_invalid")


def _validate_name(name) -> None:
    if not isinstance(name, str) or not _NAME_RE.match(name) \
            or name in (".", ".."):
        raise ArtifactInvalid("artifact_name_invalid")


def _validate_kind(kind) -> None:
    if not isinstance(kind, str) or not _KIND_RE.match(kind):
        raise ArtifactInvalid("artifact_kind_invalid")


def _meta(row: dict) -> dict:
    """Public meta shape (no content blob)."""
    return {k: row[k] for k in ("id", "name", "kind", "digest", "size",
                                "created_at", "tenant", "job_id")}


def put(backend, name, content, kind=None, tenant=None, job_id=None,
        now=0.0) -> dict:
    """Store (or replace) one artifact; returns its meta (no content)."""
    _validate_name(name)
    _validate_kind(kind)
    if job_id is not None and (
            not isinstance(job_id, str) or not _JOB_ID_RE.match(job_id)):
        raise ArtifactInvalid("artifact_job_id_invalid")
    blob = _normalize_content(content)
    cap = model.MAX_ARTIFACT_BYTES
    if len(blob) > cap:
        raise ArtifactInvalid(f"cap_artifact_bytes_{cap}")
    aid = artifact_id_for(name, tenant)
    existing = backend.get_artifact(aid)
    if existing is None:
        # cap is GLOBAL across tenants (disclosed, like webhooks);
        # replacing an existing artifact at the cap is free
        count = len(backend.list_artifacts())
        if count >= model.MAX_ARTIFACTS:
            raise ArtifactInvalid(f"cap_artifacts_{model.MAX_ARTIFACTS}")
        row = {
            "id": aid, "name": name, "kind": kind,
            "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
            "size": len(blob), "content": blob, "created_at": now,
            "tenant": tenant or "", "job_id": job_id,
        }
        backend.insert_artifact(row, now)
    else:
        row = {
            "id": aid, "name": name, "kind": kind,
            "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
            "size": len(blob), "content": blob, "created_at": now,
            "tenant": existing.get("tenant") or "",
            "job_id": job_id,
        }
        backend.update_artifact(aid, row, now)
    return _meta(row)


def _resolve(backend, key, tenant):
    """Dual resolution: art_ ids first, else tenant-scoped name canon."""
    # art_ + 12 hex chars = 16 (webhook's wh_ + 12 is 15 -- do not mix)
    if isinstance(key, str) and key.startswith("art_") and len(key) == 16:
        row = backend.get_artifact(key, tenant=tenant)
        if row is not None:
            return row
    if not isinstance(key, str):
        return None
    return backend.get_artifact(artifact_id_for(key, tenant),
                                tenant=tenant)


def get(backend, key, tenant=None, verify=False):
    """Row + content, or None (miss / cross-tenant -> 404-shaped).

    ``art_``-prefixed keys are tried as ids first so an unscoped
    operator can read a scoped row by the id from a list; every lookup
    stays tenant-filtered.
    """
    row = _resolve(backend, key, tenant)
    if row is None:
        return None
    if verify:
        blob = row["content"]
        if isinstance(blob, memoryview):
            blob = bytes(blob)
        if "sha256:" + hashlib.sha256(blob).hexdigest() != row["digest"]:
            raise ArtifactInvalid("artifact_content_corrupt")
    return row


def list_artifacts(backend, tenant=None, kind=None) -> "list[dict]":
    """Metas only (no content), ORDER BY name, id (backend-enforced)."""
    return backend.list_artifacts(tenant=tenant, kind=kind)


def delete(backend, key, tenant=None) -> bool:
    """Delete one artifact by id or name; False on miss (idempotent)."""
    row = _resolve(backend, key, tenant)
    if row is None:
        return False
    return backend.delete_artifact(row["id"], tenant=tenant)


def encode_content(blob: bytes) -> "tuple[str, str]":
    """(encoding, content-string) for an API GET body."""
    try:
        return "utf-8", blob.decode("utf-8")
    except UnicodeDecodeError:
        return "base64", base64.b64encode(blob).decode("ascii")
