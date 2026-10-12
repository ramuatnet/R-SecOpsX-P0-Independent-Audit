from __future__ import annotations

import re
from pathlib import Path

from scanner.sast import _skip


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
    return {
        "bom_type": "CBOM",
        "component": rule["component"],
        "category": rule["category"],
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
    }


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
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
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

    for path in target.rglob("*"):
        if _should_scan(path):
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
