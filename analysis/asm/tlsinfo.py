"""T-6.1: TLS certificate inventory, expiry and trust grade.

Two layers, split so the deterministic half is testable without a
socket:

  * ``analyze_cert``  -- PURE: DER bytes + an explicit ``as_of`` clock ->
    subject/issuer/SANs/validity/sha256 fingerprint/self-signed/expiry
    grade.  ``as_of`` is injected (never read from the wall clock
    inside) so two runs over the same certificate with the same clock
    argument emit byte-identical output -- that is what makes the
    "reproducible run-to-run" inventory gate meaningful.
  * ``probe_certificate`` -- network: verified handshake first (so
    chain/trust failures are RECORDED rather than crashing the probe),
    then an unverified retry to still inventory an untrusted cert.

Grade vocabulary matches the DAST ``dast.tls_grade`` precedent (A/E/T)
plus U:  ``A`` trusted-valid, ``T`` self-signed, ``E`` expired at
``as_of``, ``U`` untrusted chain / hostname mismatch (not self-signed).
Deeper Mozilla-policy grading stays declared-not-modelled, same as T-5.3.

No-cryptography machines: DER is still fingerprinted (hashlib is
stdlib) and trust/expiry VERIFICATION still works via the handshake
result; subject/issuer/SAN/date string extraction degrades to a
disclosed ``dates_pending_cryptography`` flag -- never a crash.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Callable

MAX_DER_BYTES = 64 * 1024            # certificates are a few KiB; cap untrusted input


def _to_utc(dt) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def analyze_cert(der: bytes, as_of: datetime | None = None,
                 verified: bool = False,
                 verify_error: str | None = None) -> dict:
    """Inventory one certificate (DER).  Pure except for the optional
    cryptography import; ``as_of`` defaults to the wall clock only when
    the caller does not care about reproducibility -- tests and the
    inventory gate always pass it."""
    if not der or len(der) > MAX_DER_BYTES:
        raise ValueError("certificate DER missing or oversized")
    now = _to_utc(as_of) if as_of is not None else datetime.now(timezone.utc)
    record: dict = {
        "sha256": hashlib.sha256(der).hexdigest(),
        "verified": bool(verified),
        "verify_error": verify_error,
        "self_signed": None,
        "expired": None,
        "days_left": None,
        "not_before": None,
        "not_after": None,
        "subject": None,
        "issuer": None,
        "sans": [],
        "grade": None,
        "dates_pending_cryptography": False,
    }
    try:
        from cryptography import x509                         # noqa: PLC0415
        from cryptography.x509.oid import NameOID            # noqa: PLC0415
    except ImportError:
        # No DER parse without cryptography: trust outcome from the
        # handshake still grades, everything else is disclosed pending.
        record["dates_pending_cryptography"] = True
        if verify_error and "self-signed" in verify_error.lower():
            record["self_signed"] = True
            record["grade"] = "T"
        elif verified:
            record["grade"] = "A"
        else:
            record["grade"] = "U"
        return record

    cert = x509.load_der_x509_certificate(der)
    nb = _to_utc(cert.not_valid_before_utc)
    na = _to_utc(cert.not_valid_after_utc)
    record["not_before"] = nb.isoformat().replace("+00:00", "Z")
    record["not_after"] = na.isoformat().replace("+00:00", "Z")
    record["expired"] = na < now
    record["days_left"] = (na - now).days
    record["self_signed"] = cert.issuer == cert.subject

    oid_labels = (
        (NameOID.COMMON_NAME, "CN"),
        (NameOID.ORGANIZATION_NAME, "O"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
        (NameOID.COUNTRY_NAME, "C"),
    )

    def _name(name) -> str:
        parts = []
        for oid, label in oid_labels:
            vals = name.get_attributes_for_oid(oid)
            if vals:
                parts.append(f"{label}={vals[0].value}")
        return ", ".join(parts) if parts else str(name)

    record["subject"] = _name(cert.subject)
    record["issuer"] = _name(cert.issuer)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        record["sans"] = sorted(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    # fingerprint algorithm recorded for auditability (sha256 of DER is
    # the standard pinning key)
    record["fingerprint_algo"] = "sha256"

    if record["self_signed"]:
        record["grade"] = "T"
    elif record["expired"]:
        record["grade"] = "E"
    elif verified and not verify_error:
        record["grade"] = "A"
    else:
        record["grade"] = "U"
    return record


def _verify_error_text(exc: Exception) -> str:
    """Normalize an SSL verification failure to a short, stable string."""
    reason = getattr(exc, "verify_message", None) or str(exc)
    return f"{type(exc).__name__}: {reason}"[:200]


ProbeSocket = Callable[[str, int, float, bool], bytes]
# (host, port, timeout, require_verified) -> DER


def ssl_probe(host: str, port: int, timeout: float,
              require_verified: bool) -> bytes:
    """Live default: one handshake, return the peer DER.  Raises the
    original SSL error (the caller records it and retries the other
    mode)."""
    if require_verified:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True) or b""


def probe_certificate(host: str, port: int = 443,
                      timeout: float = 5.0,
                      as_of: datetime | None = None,
                      probe: ProbeSocket = ssl_probe) -> dict:
    """Probe ``host:port``: verified handshake first, unverified retry
    for inventory if verification fails.  Connection-level failures
    (refused/timeout/DNS) raise -- the inventory layer records them as
    per-host skips, never as 'no certificate exists'."""
    now = as_of or datetime.now(timezone.utc)
    verify_error: str | None = None
    der: bytes | None = None
    try:
        der = probe(host, port, timeout, True)
        verified = True
    except ssl.SSLCertVerificationError as exc:
        verify_error = _verify_error_text(exc)
        verified = False
    except (ssl.SSLError, OSError) as exc:
        # TLS handshake broke or unreachable: still try one unverified
        # pass? No -- a dead endpoint has no cert to inventory; raise so
        # the caller marks the host skipped with the reason.
        raise
    if der is None or not der:
        der = probe(host, port, timeout, False)
    if not der:
        raise ssl.SSLError("peer returned no certificate")
    return analyze_cert(der, as_of=now, verified=verified,
                        verify_error=verify_error)


def probe_certificate_live(host: str, port: int = 443, timeout: float = 5.0,
                           as_of: datetime | None = None) -> dict:
    """Convenience wrapper binding the live socket probe."""
    return probe_certificate(host, port, timeout, as_of=as_of, probe=ssl_probe)
