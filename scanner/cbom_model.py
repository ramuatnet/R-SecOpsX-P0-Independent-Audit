from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import json


CBOM_SCHEMA_VERSION = "1.0"


@dataclass
class CBOMAsset:
    asset_id: str
    algorithm: str
    algorithm_family: str | None = None
    key_size: int | None = None
    library: str | None = None
    library_version: str | None = None
    protocol: str | None = None
    certificate: str | None = None
    key_usage: str | None = None
    application: str | None = None

    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0

    source_file: str | None = None
    source_line: int | None = None

    quantum_relevance: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def stable_asset_id(
    algorithm: str,
    library: str | None = None,
    application: str | None = None,
    source_file: str | None = None,
    key_size: int | None = None,
) -> str:
    """Deterministic identity for a cryptographic asset.

    key_size is PART OF THE IDENTITY. Omitting it made RSA-2048 and RSA-4096 at
    the same library, application and source file collide on one id -- measured,
    both produced CBOM-4075ef5a41e50a0c -- so the inventory could not record
    which key strength was deployed and a migration plan keyed on asset_id would
    merge two different assets into one.
    """
    payload = "|".join(
        [
            algorithm.strip().lower(),
            str(key_size or ""),
            (library or "").strip().lower(),
            (application or "").strip().lower(),
            (source_file or "").strip().lower(),
        ]
    )

    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    return f"CBOM-{digest}"


def create_cbom_asset(
    *,
    algorithm: str,
    algorithm_family: str | None = None,
    key_size: int | None = None,
    library: str | None = None,
    library_version: str | None = None,
    protocol: str | None = None,
    certificate: str | None = None,
    key_usage: str | None = None,
    application: str | None = None,
    evidence: list[dict[str, Any]] | None = None,
    confidence: float = 0.0,
    source_file: str | None = None,
    source_line: int | None = None,
) -> CBOMAsset:

    return CBOMAsset(
        asset_id=stable_asset_id(
            algorithm,
            library,
            application,
            source_file,
            key_size,
        ),
        algorithm=algorithm,
        algorithm_family=algorithm_family,
        key_size=key_size,
        library=library,
        library_version=library_version,
        protocol=protocol,
        certificate=certificate,
        key_usage=key_usage,
        application=application,
        evidence=evidence or [],
        confidence=max(0.0, min(1.0, confidence)),
        source_file=source_file,
        source_line=source_line,
    )


def cbom_to_json(assets: list[CBOMAsset]) -> str:
    return json.dumps(
        {
            "schema_version": CBOM_SCHEMA_VERSION,
            "bom_type": "CBOM",
            "assets": [asset.to_dict() for asset in assets],
        },
        indent=2,
        sort_keys=True,
    )