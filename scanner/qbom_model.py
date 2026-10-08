from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import json
import re

# Bare symmetric families the corpus emits as display labels, and what can be said
# about them without a key size. See scanner/symmetric_families.py for the full
# derivation: Grover's algorithm halves an n-bit key, so the broken-or-not question
# is answerable from the family alone while the margin question is not.
GROVER_REDUCIBLE_FAMILIES = {
    "aes", "arx", "chacha20", "poly1305", "blowfish", "camellia",
    "serpent", "twofish",
}

# 64-bit effective key -> about 32 bits under Grover, below any acceptable floor.
# 3DES was also retired by NIST SP 800-131A Rev. 2 (2023) independently of quantum
# computing, so this is not a speculative classification.
GROVER_DESTROYED_FAMILIES = {"des", "3des", "tripledes", "blowfish"}

_MARGIN_NOT_QUANTIFIABLE_NOTE = (
    "Grover's algorithm halves the effective key length. The primitive is not "
    "broken, but no key size was recorded, so the residual margin cannot be "
    "quantified."
)

_DESTROYED_NOTE = (
    "64-bit effective key; Grover's algorithm reduces it to roughly 32 bits, "
    "which is below any acceptable floor. Also retired by NIST SP 800-131A "
    "Rev. 2 independently of quantum computing."
)


def resolve_symmetric_family(normalized: str) -> tuple[str | None, str | None]:
    """Resolve a normalised symmetric token. Returns (status, caveat).

    `status` is None when the token is not a symmetric family this table covers,
    so the caller falls through to its other rules unchanged. Deliberately NOT
    claimed here: TLS/SSL is a protocol rather than a primitive and its quantum
    impact comes from its key exchange; MD5 and RC4 have no quantum-relevant role.
    Inventing a status for those would be a claim the evidence cannot support.
    """
    if not normalized:
        return None, None
    if normalized in GROVER_DESTROYED_FAMILIES:
        return QUANTUM_MARGIN_CRITICAL, _DESTROYED_NOTE
    if normalized in GROVER_REDUCIBLE_FAMILIES:
        # A parameterised name (aes-256) already encodes its size and needs no
        # caveat; a bare family name does not, and says so.
        #
        # NOTE the string literal. `QUANTUM_IMPACT_ASSESSED` is the SET of hash and
        # cipher names, not the status value -- returning it here made
        # classify_quantum_status("AES") return a set, which then failed as an
        # unhashable dict key two frames away, at the risk-mapping lookup rather
        # than anywhere near the cause. Same name, two different things.
        return "QUANTUM_IMPACT_ASSESSED", _MARGIN_NOT_QUANTIFIABLE_NOTE
    return None, None


QBOM_SCHEMA_VERSION = "1.0"


QUANTUM_VULNERABLE_ALGORITHMS = {
    "rsa",
    "rsa-1024",
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
    "ecc",
    "ecdsa",
    "ecdh",
    "ed25519",
    "ed448",
    "dh",
    "dsa",
}


PQC_ALGORITHMS = {
    "ml-kem",
    "ml-dsa",
    "slh-dsa",
}


QUANTUM_IMPACT_ASSESSED = {
    "aes-128",
    "aes-192",
    "aes-256",
    "sha-1",
    "sha-224",
    "sha-256",
    "sha-384",
    "sha-512",
}

# Grover destroys these outright rather than merely reducing their margin: a 64-bit
# key leaves about 32 bits of effective security, below any acceptable floor. Kept
# separate from QUANTUM_VULNERABLE, which means "broken by Shor", so the two
# mechanisms do not share one label and produce one piece of migration advice.
QUANTUM_MARGIN_CRITICAL = "QUANTUM_MARGIN_CRITICAL"


MIGRATION_STATES = {
    "NOT_ASSESSED",
    "DISCOVERED",
    "QUANTUM_VULNERABLE",
    "PQC_AVAILABLE",
    "MIGRATION_PLANNED",
    "MIGRATION_IN_PROGRESS",
    "PQC_MIGRATED",
    "VALIDATED",
}


@dataclass
class QBOMAsset:
    qbom_id: str

    algorithm: str
    quantum_status: str

    key_size: int | None = None

    application: str | None = None
    library: str | None = None
    library_version: str | None = None
    protocol: str | None = None
    certificate: str | None = None

    protected_data: str | None = None
    data_lifetime: str | None = None
    business_criticality: str | None = None
    internet_exposed: bool | None = None

    migration_status: str = "NOT_ASSESSED"
    pqc_replacement: str | None = None

    quantum_risk: str = "UNKNOWN"
    migration_priority: str = "UNKNOWN"

    # What this classification does NOT establish. A verdict without its caveat
    # overstates it, so the caveat travels with the asset rather than being left
    # in the reader's head.
    classification_note: str | None = None

    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0

    cbom_asset_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def stable_qbom_id(
    algorithm: str,
    application: str | None = None,
    cbom_asset_id: str | None = None,
    key_size: int | None = None,
) -> str:

    # key_size is part of the identity. Without it RSA-2048 and RSA-4096 at the
    # same call site share one id, and a cryptographic inventory cannot then say
    # which strength is deployed.
    payload = "|".join(
        [
            algorithm.strip().lower(),
            str(key_size or ""),
            (application or "").strip().lower(),
            (cbom_asset_id or "").strip().lower(),
        ]
    )

    digest = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:16]

    return f"QBOM-{digest}"


# Display-name forms the corpus actually emits, mapped to the canonical token.
# Measured against 3,191 real CBOM entries: "DES / 3DES" (3011), "AES" (93),
# "SHA1" (37), "MD5" (19). Before this, seven of eight distinct values in the
# corpus classified as UNKNOWN.
_DISPLAY_ALIASES = {
    "des": "3des",
    "tripledes": "3des",
    "3des": "3des",
    "sha1": "sha-1",
    "sha-1": "sha-1",
    "md5": "md5",
    "md-5": "md5",
    "rc4": "rc4",
    "tls": "tls",
    "ssl": "ssl",
    "tls-ssl": "tls",
    "hardcoded-private-key": "private-key",
}

# Families whose real-world names carry a parameter-set or hash suffix:
# ML-KEM-768 and ML-DSA-65 are NIST parameter sets of those families, and
# SLH-DSA-SHA2-128s is a hash-and-size variant of SLH-DSA. None of them is a
# distinct algorithm, so the family is what the classifier should see.
#
# MATCHING IS BY PREFIX, NOT BY STRIPPING A SUFFIX. Two earlier attempts stripped
# a trailing numeric group and both were wrong:
#
#   * the strip lived inside normalize_algorithm, so scoping algorithm_family
#     alone left SHA-256 -> "sha" -> UNKNOWN
#   * the pattern demanded 3-5 digits, so ML-DSA-65 (2 digits) and
#     SLH-DSA-SHA2-128s (trailing letter) did not strip at all
#
# A name belongs to a family when it equals the family token or begins with it
# followed by a separator. That is safe by construction: for a symmetric cipher or
# a hash no PQC family is a prefix, so the key length is never discarded -- and
# for a symmetric primitive the length IS the quantum-relevant fact, since
# Grover's advantage scales with it. AES-128 is impact-assessed rather than
# vulnerable precisely because of that.
PQC_FAMILIES = {
    "ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "falcon",
    "sphincs", "mceliece", "hqc", "ntruprime",
}

# Trailing digits run straight into the family name, as in the pre-standardisation
# spellings "Kyber768" and "Dilithium3". Applied only when what remains is a known
# PQC family, so it can never match a symmetric cipher or a hash.
_RUN_TOGETHER_RE = re.compile(r"\d+$")


def pqc_family_of(normalized: str) -> str | None:
    """The PQC family a normalised token belongs to, or None.

    Three spellings of a family member are recognised: the family token itself, a
    hyphenated parameter set ("ml-kem-768"), and the run-together form used by the
    pre-standardisation names ("Kyber768", "Dilithium3"). The run-together form
    only applies to a known PQC family, so no symmetric cipher or hash can be
    matched this way -- which is what keeps AES-256 and SHA-512 intact.
    """
    if not normalized:
        return None
    for fam in PQC_FAMILIES:
        if normalized == fam or normalized.startswith(fam + "-"):
            return fam
    # "Kyber768" / "Dilithium3": a PQC family immediately followed by digits.
    # Scoped to the known families so that "aes256" or "sha512" cannot match, and
    # so the key length of a symmetric primitive is never discarded.
    stripped = _RUN_TOGETHER_RE.sub("", normalized)
    if stripped != normalized and stripped in PQC_FAMILIES:
        return stripped
    return None


def normalize_algorithm(value: str | None) -> str:
    """Canonical token for family lookup.

    Handles the forms this product's own CBOM emits -- display names with spaces
    and slashes, underscore variants, digit/hyphen hash spellings, and
    parameter-set suffixes -- so the classifier sees family names rather than
    presentation strings.
    """
    if not value:
        return ""

    raw = value.strip().lower()
    if not raw:
        return ""

    # "DES / 3DES" and similar compound display names: take the LAST token, which
    # is the specific algorithm in a "weak / specific" pair.
    for sep in ("/", ",", ";", "|"):
        if sep in raw:
            raw = raw.split(sep)[-1]

    raw = raw.replace("_", "-").replace(" ", "-")
    while "--" in raw:
        raw = raw.replace("--", "-")
    raw = raw.strip("-")

    alias = _DISPLAY_ALIASES.get(raw)
    if alias:
        return alias

    # No suffix stripping here. A name is normalised, never truncated: stripping
    # "-256" from "aes-256" destroys the cipher's identity and is what regressed
    # the symmetric primitives. Parameter-set reduction happens in
    # pqc_family_of, which only applies to recognised PQC families.
    return raw


def algorithm_family(value: str | None) -> str:
    """Family token for lookup.

    Returns the PQC family when the name is a parameter set or hash variant of
    one, and the normalised name unchanged otherwise -- so AES-256 stays AES-256
    and SHA-512 stays sha-512 rather than collapsing to a bare family and losing
    the key length.
    """
    normalized = normalize_algorithm(value)
    return pqc_family_of(normalized) or normalized


def classify_quantum_status(
    algorithm: str,
) -> str:
    """Classify by FAMILY, with an exact match preferred.

    Family lookup is what makes "ML-KEM-768" resolve to PQC rather than UNKNOWN:
    it is a parameter set of the ML-KEM family, not a distinct algorithm.

    Three correctness properties are preserved deliberately.

    AES-128/192/256 are QUANTUM_IMPACT_ASSESSED, never QUANTUM_VULNERABLE --
    Grover halves the key, which reduces the margin but does not break the cipher.

    ed25519 IS QUANTUM_VULNERABLE -- Shor breaks it precisely BECAUSE it is strong.
    Any key-size-based oracle gets both of those backwards, which is why severity
    and quantum classification stay two separate axes.

    A bare symmetric family name with no key size is still classifiable on the
    broken-or-not axis. Grover-reducible is knowable from the family alone; only
    the magnitude needs the size. Reporting bare "AES" -- 93 real occurrences in
    the corpus -- as UNKNOWN asserts we cannot place it at all, which is false.
    The size uncertainty is carried separately by `classification_note` rather
    than by discarding the classification.
    """
    normalized = normalize_algorithm(algorithm)
    if not normalized:
        return "UNKNOWN"

    if normalized in QUANTUM_VULNERABLE_ALGORITHMS:
        return "QUANTUM_VULNERABLE"

    if normalized in PQC_ALGORITHMS:
        return "PQC"

    if pqc_family_of(normalized):
        return "PQC"

    if normalized in QUANTUM_IMPACT_ASSESSED:
        return "QUANTUM_IMPACT_ASSESSED"

    family = algorithm_family(algorithm)
    if family != normalized:
        if family in QUANTUM_VULNERABLE_ALGORITHMS:
            return "QUANTUM_VULNERABLE"
        if family in PQC_ALGORITHMS:
            return "PQC"
        if family in QUANTUM_IMPACT_ASSESSED:
            return "QUANTUM_IMPACT_ASSESSED"

    status, _note = resolve_symmetric_family(normalized)
    if status:
        return status

    return "UNKNOWN"


def classification_note(
    algorithm: str,
    key_size: int | None = None,
) -> str | None:
    """What the classification does NOT establish, stated explicitly.

    A classification without its caveat overstates it. This returns a note when the
    verdict is sound but its magnitude is not -- bare AES with no recorded key size,
    or a Grover-destroyed symmetric primitive -- and None when the verdict is
    unqualified.
    """
    normalized = normalize_algorithm(algorithm)
    _status, note = resolve_symmetric_family(normalized)
    if not note:
        return None
    if normalized in QUANTUM_IMPACT_ASSESSED and key_size is not None:
        # The parameterised form already encodes the size, so no caveat is needed.
        return None
    return note


def derive_migration_priority(
    *,
    quantum_status: str,
    business_criticality: str | None = None,
    internet_exposed: bool | None = None,
    protected_data: str | None = None,
) -> str:
    """Migration order for an asset.

    Only statuses that imply work get a priority. `NONE` here means "this asset
    generates no migration action from the evidence we have" -- which is NOT the
    same claim as "this asset is fine", and is why an UNKNOWN algorithm returns
    NONE rather than a reassuring rank.
    """
    if quantum_status not in {"QUANTUM_VULNERABLE", QUANTUM_MARGIN_CRITICAL}:
        return "NONE"

    critical = (
        (business_criticality or "").upper()
        in {"CRITICAL", "HIGH"}
    )

    sensitive = bool(protected_data)

    exposed = internet_exposed is True

    if critical and (exposed or sensitive):
        return "CRITICAL"

    if critical or exposed or sensitive:
        return "HIGH"

    return "MEDIUM"


def create_qbom_asset(
    *,
    algorithm: str,
    key_size: int | None = None,
    application: str | None = None,
    library: str | None = None,
    library_version: str | None = None,
    protocol: str | None = None,
    certificate: str | None = None,
    protected_data: str | None = None,
    data_lifetime: str | None = None,
    business_criticality: str | None = None,
    internet_exposed: bool | None = None,
    migration_status: str = "NOT_ASSESSED",
    pqc_replacement: str | None = None,
    evidence: list[dict[str, Any]] | None = None,
    confidence: float = 0.0,
    cbom_asset_id: str | None = None,
) -> QBOMAsset:

    if migration_status not in MIGRATION_STATES:
        raise ValueError(
            f"Invalid migration_status: {migration_status}"
        )

    quantum_status = classify_quantum_status(
        algorithm
    )

    priority = derive_migration_priority(
        quantum_status=quantum_status,
        business_criticality=business_criticality,
        internet_exposed=internet_exposed,
        protected_data=protected_data,
    )

    note = classification_note(algorithm, key_size)

    return QBOMAsset(
        qbom_id=stable_qbom_id(
            algorithm,
            application,
            cbom_asset_id,
            key_size,
        ),
        algorithm=algorithm,
        quantum_status=quantum_status,
        key_size=key_size,
        application=application,
        library=library,
        library_version=library_version,
        protocol=protocol,
        certificate=certificate,
        protected_data=protected_data,
        data_lifetime=data_lifetime,
        business_criticality=business_criticality,
        internet_exposed=internet_exposed,
        migration_status=migration_status,
        pqc_replacement=pqc_replacement,
        # Mirrors the status instead of collapsing to a binary. The previous
        # form was "HIGH if QUANTUM_VULNERABLE else LOW", which reported an
        # algorithm the tool had never heard of as LOW risk. "We cannot
        # classify this" and "this is fine" are different claims and only the
        # first is supported by the evidence. Absence must never be reported as
        # reassurance.
        quantum_risk={
            "QUANTUM_VULNERABLE": "HIGH",
            # Grover destroys the margin outright rather than reducing it, so the
            # risk rating is HIGH even though Shor is not what breaks it. The
            # separate status value is what keeps the mechanism visible.
            QUANTUM_MARGIN_CRITICAL: "HIGH",
            "PQC": "LOW",
            "QUANTUM_IMPACT_ASSESSED": "LOW",
            "UNKNOWN": "UNKNOWN",
        }[quantum_status],
        migration_priority=priority,
        classification_note=note,
        evidence=evidence or [],
        confidence=max(0.0, min(1.0, confidence)),
        cbom_asset_id=cbom_asset_id,
    )


def qbom_to_json(assets: list[QBOMAsset]) -> str:
    return json.dumps(
        {
            "schema_version": QBOM_SCHEMA_VERSION,
            "bom_type": "QBOM",
            "assets": [asset.to_dict() for asset in assets],
        },
        indent=2,
        sort_keys=True,
    )