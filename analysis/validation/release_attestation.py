"""T-9.13 SLSA + sigstore-signed releases (task.md section 13).

sigstore (cosign / Fulcio / Rekor) and slsa-verifier are NOT adopted:
both need network transparency-log access, OIDC identities and a Go
toolchain, none of which the offline/airgap scan invariant can
require -- the same named-tool precedent as petgraph/axum/Rego/
OIDC-SAML/cargo-fuzz.  This module provides the in-house equivalent
that CAN run offline:

  * a deterministic, in-toto-SLSA-shaped provenance statement
    (subject sha256 digests over release artifacts, builder id,
    config-source digest, tool version);
  * HMAC-SHA256 signing of the canonical statement bytes
    (``hmac.compare_digest`` for verification); no wall-clock time
    goes into the signed payload, so the same inputs always produce
    the same signature;
  * a verify CLI with EXIT CODES 0 (valid) / 1 (invalid) / 2
    (could-not-run).

Honest SLSA wording: the statement claims ``slsa_build_level: 1``
(self-attested build recipe, no third-party transparency log).  A
higher level or keyless sigstore flow remains possible only when the
deployment environment has network access and a real signing
identity; the disclosure above is the committed boundary.

KEY HANDLING: the HMAC key is never read from anywhere except an
explicit --key-file or RSECOPSX_RELEASE_KEY; it is never echoed in
errors or logs.  The default release flow is
``python -m analysis.validation.release_attestation``.

EXIT CODES:
    0  success (attested / verified)
    1  verification failed (bad signature, tampered subject, wrong key)
    2  could-not-run (missing files, missing key, bad arguments)
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_16
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_16

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

SCHEMA = "rsecopsx.release_attestation/v1"
IN_TOTO_TYPE = "https://in-toto.io/Statement/v0.1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILDER_ID = "https://rsecopsx.local/builder/inhouse-deterministic"
BUILD_TYPE = "https://rsecopsx.local/builder/v1"
ALG = "HMAC-SHA256"
# What the attestor hashes by default: the offline deploy surface.
DEFAULT_GLOBS = (
    "Dockerfile",
    "docker-compose.yml",
    "pyproject.toml",
    "deploy/**/*",
)


def canonical_json(obj) -> bytes:
    """Deterministic bytes for signing: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def hash_file(path: "str | os.PathLike") -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root: "str | os.PathLike", globs=DEFAULT_GLOBS) -> str:
    """Digest over the sorted (relpath, sha256) pairs of the default
    release surface -- the config source for the provenance."""
    root = Path(root)
    pairs = []
    for pattern in globs:
        for p in sorted(root.glob(pattern)):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                pairs.append((rel, hash_file(p)))
    pairs.sort()
    return hashlib.sha256(canonical_json(pairs)).hexdigest()


def collect_subjects(root: "str | os.PathLike",
                     globs=DEFAULT_GLOBS) -> "list[dict]":
    root = Path(root)
    names: "list[tuple[str, str]]" = []
    seen: "set[str]" = set()
    for pattern in globs:
        for p in sorted(root.glob(pattern)):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if rel in seen:
                continue
            seen.add(rel)
            names.append((rel, hash_file(p)))
    names.sort()
    return [{"name": rel, "digest": {"sha256": digest}}
            for rel, digest in names]


def build_statement(root: "str | os.PathLike", tool_version: str,
                    globs=DEFAULT_GLOBS, source_commit: str = "unknown"
                    ) -> dict:
    """In-toto Statement with an SLSA-shaped predicate.

    Deterministic: no timestamps, no hostnames, no PIDs.  Every field
    is a function of the inputs, so attestations are reproducible.
    """
    root = Path(root)
    subjects = collect_subjects(root, globs)
    if not subjects:
        raise ValueError("no release artifacts matched under %s" % root)
    return {
        "_type": IN_TOTO_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": subjects,
        "predicate": {
            "buildType": BUILD_TYPE,
            "builder": {"id": BUILDER_ID},
            "invocation": {
                "configSource": {
                    "digest": {"sha256": hash_tree(root, globs)},
                    "entryPoint": "python -m "
                                  "analysis.validation.release_attestation",
                },
            },
            "metadata": {
                "toolVersion": tool_version,
                "sourceCommit": source_commit,
            },
            # Honest level: self-attested recipe, no transparency log.
            "slsa": {
                "buildLevel": 1,
                "note": "self-attested; sigstore/Rekor NOT adopted "
                        "(offline invariant, see module docstring)",
            },
        },
    }


def load_key(key_file: "str | os.PathLike | None" = None) -> bytes:
    """Read the HMAC key from --key-file or RSECOPSX_RELEASE_KEY only.

    Never logs or returns the key material in exceptions.
    """
    if key_file:
        try:
            raw = Path(key_file).read_bytes().strip()
        except OSError as exc:
            raise ValueError("key file unreadable") from exc
        if not raw:
            raise ValueError("key file is empty")
        return raw
    env = os.environ.get("RSECOPSX_RELEASE_KEY")
    if env:
        return env.encode("utf-8")
    raise ValueError("no key: pass --key-file or set RSECOPSX_RELEASE_KEY")


def sign(statement: dict, key: bytes) -> "dict":
    if not key:
        raise ValueError("empty key")
    digest = hmac.new(key, canonical_json(statement), hashlib.sha256)
    return {
        "schema": SCHEMA,
        "alg": ALG,
        "keyId": hashlib.sha256(key).hexdigest()[:WINDOW_16],
        "sig": digest.hexdigest(),
    }


def verify(statement: dict, signature: dict, key: bytes) -> "bool":
    """Constant-time comparison; any tamper (statement or signature
    fields) must fail."""
    if not isinstance(signature, dict) or not key:
        return False
    if signature.get("alg") != ALG or signature.get("schema") != SCHEMA:
        return False
    if signature.get("keyId") != hashlib.sha256(key).hexdigest()[:WINDOW_16]:
        return False
    expected = hmac.new(key, canonical_json(statement),
                        hashlib.sha256).hexdigest()
    got = str(signature.get("sig") or "")
    return hmac.compare_digest(expected, got)


def attest(root: "str | os.PathLike", key: bytes, *,
           tool_version: str, source_commit: str = "unknown",
           out_dir: "str | os.PathLike | None" = None,
           globs=DEFAULT_GLOBS) -> "tuple[dict, dict, Path]":
    """Build + sign; write provenance.intoto.json and .sig beside
    out_dir (default: root).  Returns (statement, signature, dir)."""
    statement = build_statement(root, tool_version, globs, source_commit)
    signature = sign(statement, key)
    dest = Path(out_dir) if out_dir is not None else Path(root)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "provenance.intoto.json").write_text(
        json.dumps(statement, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    (dest / "provenance.intoto.json.sig").write_text(
        json.dumps(signature, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return statement, signature, dest


def verify_dir(directory: "str | os.PathLike", key: bytes) -> "tuple[str, str]":
    """Return (status, reason); status in ok | invalid | could-not-run."""
    directory = Path(directory)
    spath = directory / "provenance.intoto.json"
    gpath = directory / "provenance.intoto.json.sig"
    if not spath.is_file() or not gpath.is_file():
        return "could-not-run", "missing provenance.intoto.json or .sig"
    try:
        statement = json.loads(spath.read_text(encoding="utf-8"))
        signature = json.loads(gpath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return "could-not-run", "unreadable provenance: %s" % exc
    if not verify(statement, signature, key):
        return "invalid", ("signature mismatch (statement tampered, "
                           "wrong key, or alg/keyId mismatch)")
    return "ok", "ok"


def main(argv: "list[str] | None" = None) -> int:
    from core.config import TOOL_VERSION

    parser = argparse.ArgumentParser(
        prog="python -m analysis.validation.release_attestation",
        description="T-9.13 SLSA-shaped release attestation "
                    "(sigstore NOT adopted; offline HMAC signing).")
    sub = parser.add_subparsers(dest="cmd")
    p_att = sub.add_parser("attest", help="build + sign a statement")
    p_att.add_argument("--root", default=".", help="release tree root")
    p_att.add_argument("--out-dir", default=None,
                       help="where to write provenance files "
                            "(default: root)")
    p_att.add_argument("--key-file", default=None)
    p_att.add_argument("--source-commit", default="unknown")
    p_ver = sub.add_parser("verify", help="verify a signed statement")
    p_ver.add_argument("--dir", default=".", help="directory holding the "
                                                  "provenance files")
    p_ver.add_argument("--key-file", default=None)
    p_ver.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not args.cmd:
        parser.print_help()
        return 2
    try:
        key = load_key(args.key_file)
    except (OSError, ValueError):
        print("[ATTESTATION] could-not-run: key unavailable "
              "(pass --key-file or set RSECOPSX_RELEASE_KEY)")
        return 2

    if args.cmd == "attest":
        try:
            statement, signature, dest = attest(
                args.root, key, tool_version=TOOL_VERSION,
                source_commit=args.source_commit, out_dir=args.out_dir)
        except (OSError, ValueError) as exc:
            print("[ATTESTATION] could-not-run: %s" % exc)
            return 2
        print("[ATTESTATION] signed %d subjects -> %s (level 1, "
              "sigstore NOT adopted)" % (len(statement["subject"]), dest))
        return 0

    status, reason = verify_dir(args.dir, key)
    valid = status == "ok"
    if args.json:
        original = sys.stdout
        try:
            import io as _io
            wrapper = _io.TextIOWrapper(original.buffer, encoding="utf-8",
                                        errors="replace")
            sys.stdout = wrapper
            print(json.dumps({"status": status, "valid": valid,
                              "reason": reason}))
            wrapper.flush()
        finally:
            sys.stdout = original
            try:
                wrapper.detach()
            except Exception:
                pass
    elif valid:
        print("[ATTESTATION] VALID (%s)" % reason)
    else:
        print("[ATTESTATION] %s: %s" % (status.upper(), reason))
    return {"ok": 0, "invalid": 1, "could-not-run": 2}[status]


if __name__ == "__main__":
    raise SystemExit(main())
