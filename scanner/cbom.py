from __future__ import annotations

import re
from pathlib import Path

from scanner.sast import _skip
# T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
from core import file_index


SCANNABLE_EXT = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".yml", ".yaml", ".xml",
    ".config", ".properties", ".env"
}


CRYPTO_RULES = [
    {
        "component": "MD5",
        "category": "Weak Hashing",
        "pattern": re.compile(
            r"(?:hashlib\.md5\s*\(|crypto\.createHash\(\s*['\"]md5['\"]|"
            r"CryptoJS\.MD5\s*\(|\bmd5\s*\()",
            re.I,
        ),
        "risk": "HIGH",
        "recommendation": "Replace MD5 with SHA-256 or stronger approved hashing."
    },
    {
        "component": "SHA1",
        "category": "Weak Hashing",
        "pattern": re.compile(
            r"(?:hashlib\.sha1\s*\(|crypto\.createHash\(\s*['\"]sha1['\"]|"
            r"CryptoJS\.SHA1\s*\(|\bsha1\s*\()",
            re.I,
        ),
        "risk": "HIGH",
        "recommendation": "Replace SHA-1 with SHA-256 or SHA-3."
    },
    {
        "component": "DES / 3DES",
        "category": "Weak Encryption",
        "pattern": re.compile(
            r"(?:DES\.new|TripleDES|DESede|3DES|"
            r"Cipher\.getInstance\(\s*['\"][^'\"]*(?:DES|DESede|3DES))",
            re.I,
        ),
        "risk": "CRITICAL",
        "recommendation": "Replace DES/3DES with AES-256-GCM or ChaCha20-Poly1305."
    },
    {
        "component": "RC4",
        "category": "Weak Encryption",
        "pattern": re.compile(
            r"(?:RC4|RC4Drop|ARC4|Cipher\.getInstance\(\s*['\"]RC4)",
            re.I,
        ),
        "risk": "CRITICAL",
        "recommendation": "Remove RC4. Use modern authenticated encryption."
    },
    {
        "component": "AES",
        "category": "Approved Encryption",
        "pattern": re.compile(
            r"(?:AES\.new|new\s+AES\b|CryptoJS\.AES|"
            r"Cipher\.getInstance\(\s*['\"]AES|"
            r"crypto\.createCipher(?:iv)?\(\s*['\"]aes[-_])",
            re.I,
        ),
        "risk": "LOW",
        "recommendation": "Verify AES mode is GCM/CTR with secure key management."
    },
    {
        "component": "RSA",
        "category": "Asymmetric Cryptography",
        "pattern": re.compile(
            r"(?:generate_private_key|RSAPrivateKey|RSA\.generate|RSA\.new|"
            r"crypto\.(?:publicEncrypt|privateEncrypt|publicDecrypt|privateDecrypt|"
            r"generateKeyPair|generateKeyPairSync)\b|"
            r"Cipher\.getInstance\(\s*['\"][^'\"]*RSA|"
            r"crypto\.create(?:Sign|Verify)\(\s*['\"][^'\"]*RSA)",
            re.I,
        ),
        "risk": "MEDIUM",
        "recommendation": "Verify RSA key size is at least 2048-bit; plan PQC migration."
    },
    {
        "component": "ECC",
        "category": "Asymmetric Cryptography",
        "pattern": re.compile(
            r"(?:crypto\.(?:createECDH|createSign|createVerify)\b|"
            r"(?:ECDSA|ECDH|EllipticCurve|secp256r1|prime256v1)"
            r"\s*(?:[.(=:]|$))",
            re.I,
        ),
        "risk": "MEDIUM",
        "recommendation": "Verify approved curves and plan post-quantum transition."
    },
    {
        "component": "TLS / SSL",
        "category": "Transport Cryptography",
        "pattern": re.compile(
            r"(?:SSLContext|PROTOCOL_TLS(?:_CLIENT|_SERVER)?|PROTOCOL_SSL|"
            r"ssl\.(?:create_default_context|SSLContext|wrap_socket|"
            r"PROTOCOL_TLS|PROTOCOL_TLS_CLIENT|PROTOCOL_TLS_SERVER)|"
            r"tls\.(?:connect|createSecureContext|TLSSocket)|"
            r"https\.(?:request|createServer|Agent)|"
            r"requests\.(?:get|post|request)\([^)]*verify\s*=|"
            r"urllib3\.HTTPSConnectionPool|http\.client\.HTTPSConnection)",
            re.I,
        ),
        "risk": "MEDIUM",
        "recommendation": "Ensure TLS 1.2+ only; disable SSL/TLS 1.0/1.1."
    },
    {
        "component": "Hardcoded Private Key",
        "category": "Key Material",
        "pattern": re.compile(
            r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            re.I,
        ),
        "risk": "CRITICAL",
        "recommendation": "Remove private key from source and rotate exposed key material."
    },
    {
        "component": "Hardcoded Certificate",
        "category": "Certificate Material",
        "pattern": re.compile(
            r"-----BEGIN CERTIFICATE-----",
            re.I,
        ),
        "risk": "MEDIUM",
        "recommendation": "Verify certificate purpose and avoid embedding sensitive material."
    },
]


# ---------------------------------------------------------------------------
# Purpose model (Phase 4.2)
# ---------------------------------------------------------------------------
# cbomctl (lvlrSajjad/cbomctl -- one of the 240 CBOM-ecosystem tools in
# cyclonedx_github_repositories.csv) evaluates a policy verdict per crypto
# asset; an algorithm asset with NO cryptoFunctions list yields INDET
# because there is nothing to evaluate. Two shapes hit that hole in our
# inventory:
#   * ECC -- one rule matches ECDSA (sign), ECDH (key-agree) and bare curve
#     usage alike, so the old static map could not name a function set;
#   * any future rule outside the exporter's map -- the fallback branch
#     emitted primitive "unknown" and no functions.
# _detect_purpose disambiguates the concrete algorithm and its function
# set from the CALL SITE (the evidence text the rule already matched),
# falling back to the family's capability set when the call site is
# inconclusive. Every algorithm asset therefore leaves the scanner with a
# non-empty cryptoFunctions list and an explicit purpose_source tag --
# "no indeterminate verdicts" is the Phase 4.2 gate.
#
# Token sets are lower-case substrings of the evidence window. They are
# matched against the same evidence line the finding already cites; the
# tokens found are surfaced as detection keywords so a consumer can see
# WHICH signal produced the purpose.

_SIGNATURE_TOKENS = (
    "signature", "createsign", "createverify", ".sign(", ".verify(",
    "pss", "ecdsa", "eddsa", "withrsa",
)
_KEY_AGREEMENT_TOKENS = (
    "ecdh", "createdh", "keyagreement", "key_agreement", "derive", "diffie",
)
_ENCRYPTION_TOKENS = (
    "cipher", "encrypt", "decrypt", "oaep", "createcipher", "ecies", "pkcs1",
)

# Family -> (algorithm, primitive, crypto_functions, purpose).
# Only algorithm families appear here; TLS/SSL and key/certificate material
# are non-algorithm asset types and carry no cryptoFunctions field.
_FAMILY_DEFAULTS = {
    "MD5": ("MD5", "hash", ["digest"], "hashing"),
    "SHA1": ("SHA-1", "hash", ["digest"], "hashing"),
    "DES / 3DES": ("3DES", "block-cipher", ["encrypt", "decrypt"], "encryption"),
    "RC4": ("RC4", "stream-cipher", ["encrypt", "decrypt"], "encryption"),
    "AES": ("AES", "block-cipher", ["encrypt", "decrypt"], "encryption"),
    "RSA": ("RSA", "pke", ["encrypt", "decrypt", "sign", "verify"], "public-key"),
    # ECC deliberately broad: ECDSA, ECDH and bare curve usage all match
    # one rule. When the call site does not say which, the union of the
    # family's capabilities is the honest determinate answer -- present and
    # conservative, rather than an empty list that reads as INDET.
    "ECC": ("ECC", "unknown", ["keygen", "sign", "verify", "keyderive"],
            "asymmetric (call-site inconclusive)"),
}


def _detect_purpose(component: str, evidence: str) -> dict | None:
    """Disambiguate an algorithm family's purpose from its call site.

    Returns None for non-algorithm components (TLS/SSL, key and
    certificate material). For algorithm families the result always
    carries a non-empty cryptoFunctions list: call-site tokens when the
    evidence names the usage, the family capability set otherwise, with
    purpose_source saying which one produced it.

    RSA and ECC are the two genuinely ambiguous families (a bare RSA key
    pair can sign or encrypt; bare ECC can be ECDSA or ECDH), so only
    those two are re-classified by call site -- a hash is always a hash
    and a block cipher is always a block cipher.
    """
    family = _FAMILY_DEFAULTS.get(component)
    if family is None:
        return None

    algorithm, primitive, functions, purpose = family
    text = (evidence or "").lower()
    source = "family"
    keywords: list[str] = []

    def _hit(tokens: tuple[str, ...]) -> list[str]:
        return [t for t in tokens if t in text]

    if component == "ECC":
        hits = _hit(_SIGNATURE_TOKENS)
        if hits:
            algorithm, primitive = "ECDSA", "signature"
            functions, purpose = ["sign", "verify"], "signature"
            source, keywords = "call-site", hits
        else:
            hits = _hit(_KEY_AGREEMENT_TOKENS)
            if hits:
                algorithm, primitive = "ECDH", "key-agree"
                functions, purpose = ["keyderive", "keygen"], "key-agreement"
                source, keywords = "call-site", hits
            else:
                hits = _hit(_ENCRYPTION_TOKENS)
                if hits:
                    algorithm, primitive = "ECIES", "pke"
                    functions, purpose = ["encrypt", "decrypt"], "public-key-encryption"
                    source, keywords = "call-site", hits
    elif component == "RSA":
        hits = _hit(_SIGNATURE_TOKENS)
        if hits:
            primitive, functions = "signature", ["sign", "verify"]
            purpose, source, keywords = "signature", "call-site", hits
        else:
            hits = _hit(_ENCRYPTION_TOKENS)
            if hits:
                primitive, functions = "pke", ["encrypt", "decrypt"]
                purpose, source, keywords = "encryption", "call-site", hits

    return {
        "algorithm": algorithm,
        "primitive": primitive,
        "crypto_functions": list(functions),
        "purpose": purpose,
        "purpose_source": source,
        "detection_keywords": keywords,
        "confidence": 3 if source == "call-site" else 2,
    }


def _should_scan(path: Path) -> bool:
    """
    CBOM source-scope filter.

    CBOM inventories cryptographic usage/assets in application source.
    Third-party dependency trees and generated/build artifacts are
    excluded so dependency implementation details are not reported
    as application crypto assets.
    """
    if not path.is_file():
        return False

    if _skip(path):
        return False

    return path.suffix.lower() in SCANNABLE_EXT


def _make_cbom_item(rule: dict, filepath: str, line: int, evidence: str) -> dict:
    item = {
        "bom_type": "CBOM",
        "component": rule["component"],
        "category": rule["category"],
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
    }
    # Purpose model (Phase 4.2): algorithm families carry a determinate
    # primitive/cryptoFunctions/purpose derived from the call site; the
    # exporter prefers these over its static family map.
    purpose = _detect_purpose(rule["component"], evidence)
    if purpose:
        item.update(purpose)
    return item


def _extract_evidence(source: str, match, max_chars: int = 2000) -> str:
    """Preserve complete crypto regex match plus bounded surrounding context."""
    if not source or match is None:
        return ""

    start = max(0, match.start())
    end = min(len(source), match.end())

    # Never truncate the actual regex match.
    match_text = source[start:end]

    if len(match_text) >= max_chars:
        return match_text

    context_budget = max_chars - len(match_text)
    left_budget = context_budget // 2
    right_budget = context_budget - left_budget

    left = max(0, start - left_budget)
    right = min(len(source), end + right_budget)

    return source[left:right].strip()

def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)

    if not _should_scan(path):
        return []

    try:
        source = file_index.read_source(path)
    except OSError:
        return []
    if source is None:
        return []

    findings = []
    lines = source.splitlines()
    # One crypto observation per (component, line): a single source line can
    # satisfy one rule's pattern several times (ssl.PROTOCOL_TLS_CLIENT on
    # line 39 of the fixture matched three alternatives), and three copies
    # of the same observation in a BOM are a schema-valid way to overstate
    # inventory size -- the same duplicate-rule inflation the corpus counts
    # as false positives.
    seen: set[tuple[str, int]] = set()

    for rule in CRYPTO_RULES:
        for match in rule["pattern"].finditer(source):
            line_no = source[:match.start()].count("\n") + 1
            dedupe_key = (str(rule["component"]), line_no)
            if dedupe_key in seen:
                continue
            source_line = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""

            if source_line.lstrip().startswith(("#", "//", "*")):
                continue

            evidence = _extract_evidence(source, match)

            if (
                rule["component"] == "RSA"
                and "-----BEGIN " in evidence
                and "PRIVATE KEY-----" in evidence
            ):
                continue

            seen.add(dedupe_key)
            findings.append(
                _make_cbom_item(
                    rule,
                    str(path),
                    line_no,
                    evidence
                )
            )

    return findings


def generate_cbom(target_path: str) -> list[dict]:
    target = Path(target_path)

    results = []

    if target.is_file():
        return scan_file(str(target))

    if not target.exists():
        return []

    # T-0.2: index query replaces target.rglob; the skip policy is walk-time.
    for path in file_index.index_for(target).files(pred=_should_scan):
        results.extend(scan_file(str(path)))

    return results


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", default="cbom.json")
    args = parser.parse_args()

    cbom = generate_cbom(args.target)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2)

    print(f"[CBOM] Items found: {len(cbom)}")
    print(f"[CBOM] Output written: {args.output}")
