#!/usr/bin/env python3
"""
Simple QBOM (Quantum Bill of Materials) scanner for Python source code.
Scans .py files for cryptographic usage and outputs a JSON CBOM-like
inventory with quantum‑risk classification.

NOTE: This is a prototype for illustration. For production‑grade CBOM
generation use tools like qScan, IBM Quantum Safe Explorer, or PQC‑MAT.
"""

import ast
import json
import os
import sys
import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Set, Tuple


# ----------------------------------------------------------------------
# Data models (mirroring a minimal CycloneDX component)
# ----------------------------------------------------------------------
@dataclass
class CryptoAsset:
    name: str                      # e.g., "RSA-2048"
    algorithm: str                 # e.g., "RSA"
    key_size: Optional[int] = None # bits, if applicable
    mode: Optional[str] = None     # e.g., "GCM", "CBC"
    library: Optional[str] = None  # e.g., "cryptography"
    file_path: str = ""            # where it was found
    line_no: int = 0               # approximate line number
    quantum_risk: str = ""         # "broken", "weakened", "safe"
    notes: str = ""                # extra info


# ----------------------------------------------------------------------
# Classification tables (based on NIST IR 8547 & Grover/shor impacts)
# ----------------------------------------------------------------------
BROKEN_ALGS = {
    "RSA",
    "ECDSA",
    "ECDH",
    "DH",
    "DSA",
    "EC",
}
WEAKENED_ALGS = {
    "AES-128",
    "AES-192",
    "SHA-256",
    "SHA-1",
    "MD5",
}
SAFE_ALGS = {
    "ML-KEM",
    "ML-DSA",
    "SLH-DSA",
    "XMSS",
    "AES-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
}


def classify_algorithm(algo: str, key_size: Optional[int]) -> str:
    """Return quantum risk classification."""
    # Normalize
    algo_up = algo.upper().replace("-", "")
    # Handle key‑size specific cases
    if algo.upper().startswith("AES"):
        if key_size is None:
            return "unknown"
        if key_size >= 256:
            return "safe"
        elif key_size >= 192:
            return "weakened"
        else:
            return "broken"  # AES-128 is considered weakened by Grover
    if algo.upper().startswith("SHA") or algo.upper().startswith("SHA3"):
        if key_size is None:
            return "unknown"
        # Grover reduces collision resistance to sqrt; treat <384 as weakened
        if key_size >= 384:
            return "safe"
        else:
            return "weakened"
    # Direct lookup
    if algo in BROKEN_ALGS:
        return "broken"
    if algo in SAFE_ALGS:
        return "safe"
    # fallback
    return "unknown"


# ----------------------------------------------------------------------
# AST visitor to collect crypto usage
# ----------------------------------------------------------------------
class CryptoVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.assets: List[CryptoAsset] = []
        self.imports: Dict[str, str] = {}  # alias -> full module path
        self.modules: Set[str] = set()     # imported module names

    # Helper to create asset
    def _add_asset(
        self,
        name: str,
        algorithm: str,
        key_size: Optional[int] = None,
        mode: Optional[str] = None,
        library: Optional[str] = None,
        line_no: int = 0,
        notes: str = "",
    ):
        risk = classify_algorithm(algorithm, key_size)
        self.assets.append(
            CryptoAsset(
                name=name,
                algorithm=algorithm,
                key_size=key_size,
                mode=mode,
                library=library,
                file_path=self.filename,
                line_no=line_no,
                quantum_risk=risk,
                notes=notes,
            )
        )

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            full = alias.name
            asname = alias.asname
            self.modules.add(full)
            if asname:
                self.imports[asname] = full
                # Also allow the full name to be used without alias
                self.imports[full] = full
            else:
                self.imports[full] = full
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                asname = alias.asname
                self.modules.add(full)
                if asname:
                    self.imports[asname] = full
                    # Also allow the full name to be used without alias
                    self.imports[full] = full
                else:
                    self.imports[full] = full
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func = node.func
        # Resolve function name (support attribute chains like cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key)
        if isinstance(func, ast.Attribute):
            func_name = self._get_attribute_name(func)
        elif isinstance(func, ast.Name):
            func_name = func.id
        else:
            self.generic_visit(node)
            return

        # Map common crypto calls to assets
        self._match_crypto_call(func_name, node, node.lineno)
        self.generic_visit(node)

    def _get_attribute_name(self, node: ast.Attr) -> str:
        """Recursively build dotted name."""
        if isinstance(node.value, ast.Attribute):
            return f"{self._get_attribute_name(node.value)}.{node.attr}"
        elif isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        else:
            return node.attr

    def _match_crypto_call(self, func_name: str, node: ast.Call, lineno: int):
        """Heuristic matching – extend as needed."""
        # Normalize for matching
        lower = func_name.lower()

        # Determine which crypto library patterns to apply based on substrings in func_name
        is_cryptography = "cryptography" in lower
        is_crypto = "crypto" in lower and not is_cryptography  # avoid double match
        is_hashlib = "hashlib" in lower
        is_ssl = "ssl" in lower

        # DEBUG PRINT
        print(f"DEBUG: func_name={func_name}, lower={lower}, is_cryptography={is_cryptography}, is_crypto={is_crypto}, is_hashlib={is_hashlib}, is_ssl={is_ssl}", file=sys.stderr)

        # cryptography library patterns
        if is_cryptography:
            if "rsa" in lower and ("generate" in lower or "privatekey" in lower):
                self._add_asset(
                    name="RSA",
                    algorithm="RSA",
                    library="cryptography",
                    line_no=lineno,
                    notes="RSA key generation",
                )
            if "ecdsa" in lower or "ec" in lower:
                self._add_asset(
                    name="ECDSA",
                    algorithm="ECDSA",
                    library="cryptography",
                    line_no=lineno,
                    notes="Elliptic curve signature/key gen",
                )
            if "aes" in lower:
                key = self._extract_key_size(node.args, node.keywords)
                mode = self._extract_mode(node.args, node.keywords)
                self._add_asset(
                    name=f"AES-{key or '?' }",
                    algorithm="AES",
                    key_size=key,
                    mode=mode,
                    library="cryptography",
                    line_no=lineno,
                    notes="AES encryption",
                )
            if "sha" in lower:
                hash_name = func_name.upper()
                key = self._extract_hash_size(func_name)
                self._add_asset(
                    name=hash_name,
                    algorithm=hash_name,
                    key_size=key,
                    library="cryptography",
                    line_no=lineno,
                    notes="Hash function",
                )

        # hazmat primitives (cryptography.hazmat.primitives)
        if "hazmat" in lower:
            if "rsa" in lower:
                self._add_asset(
                    name="RSA",
                    algorithm="RSA",
                    library="cryptography",
                    line_no=lineno,
                    notes="RSA primitive usage",
                )
            if "ec" in lower:
                self._add_asset(
                    name="ECDH/ECDSA",
                    algorithm="ECDH",
                    library="cryptography",
                    line_no=lineno,
                    notes="Elliptic curve primitive",
                )
            if "aes" in lower:
                key = self._extract_key_size(node.args, node.keywords)
                mode = self._extract_mode(node.args, node.keywords)
                self._add_asset(
                    name=f"AES-{key or '?' }",
                    algorithm="AES",
                    key_size=key,
                    mode=mode,
                    library="cryptography",
                    line_no=lineno,
                    notes="AES via hazmat",
                )
            if "sha2" in lower or "sha3" in lower:
                key = self._extract_hash_size(func_name)
                self._add_asset(
                    name=func_name.upper(),
                    algorithm=func_name.upper(),
                    key_size=key,
                    library="cryptography",
                    line_no=lineno,
                    notes="Hash via hazmat",
                )

        # PyCryptodome / Crypto
        if is_crypto:
            if "RSA" in func_name:
                self._add_asset(
                    name="RSA",
                    algorithm="RSA",
                    library="PyCryptodome",
                    line_no=lineno,
                    notes="RSA usage",
                )
            if "AES" in func_name:
                key = self._extract_key_size(node.args, node.keywords)
                mode = self._extract_mode(node.args, node.keywords)
                self._add_asset(
                    name=f"AES-{key or '?' }",
                    algorithm="AES",
                    key_size=key,
                    mode=mode,
                    library="PyCryptodome",
                    line_no=lineno,
                    notes="AES usage",
                )
            if "SHA" in func_name:
                key = self._extract_hash_size(func_name)
                self._add_asset(
                    name=func_name.upper(),
                    algorithm=func_name.upper(),
                    key_size=key,
                    library="PyCryptodome",
                    line_no=lineno,
                    notes="Hash usage",
                )

        # ssl/stdlib
        if is_ssl:
            if func_name in ("create_default_context", "wrap_socket", "SSLContext"):
                self._add_asset(
                    name="TLS",
                    algorithm="TLS",
                    library="ssl",
                    line_no=lineno,
                    notes="TLS socket creation – inspect cipher suite for quantum risk",
                )

        # hashlib
        if is_hashlib:
            if func_name in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                             "sha3_224", "sha3_256", "sha3_384", "sha3_512"):
                key = len(func_name.replace("sha", "").replace("_", "")) * 4  # rough
                self._add_asset(
                    name=func_name.upper(),
                    algorithm=func_name.upper(),
                    key_size=key,
                    library="hashlib",
                    line_no=lineno,
                    notes="Hashlib hash",
                )

    # ------------------------------------------------------------------
    # Helpers to infer key size / mode from call arguments (very simplistic)
    # ------------------------------------------------------------------
    def _extract_key_size(self, args, keywords) -> Optional[int]:
        for kw in keywords:
            if kw.arg == "key_size":
                if isinstance(kw.value, ast.Constant):
                    return kw.value.value
        for a in args:
            if isinstance(a, ast.Constant) and isinstance(a.value, int):
                return a.value
        return None

    def _extract_mode(self, args, keywords) -> Optional[str]:
        for kw in keywords:
            if kw.arg in ("mode", "cipher"):
                if isinstance(kw.value, ast.Constant):
                    return kw.value.value
        for a in args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                return a.value
        return None

    def _extract_hash_size(self, name: str) -> Optional[int]:
        # e.g., sha256 -> 256, sha3_512 -> 512
        m = re.search(r"(\d+)$", name)
        if m:
            return int(m.group(1))
        return None


def scan_file(path: str) -> List[CryptoAsset]:
    with open(path, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read(), filename=path)
        except SyntaxError as e:
            print(f"[!] Skipping {path}: syntax error – {e}", file=sys.stderr)
            return []
    visitor = CryptoVisitor(path)
    visitor.visit(tree)
    return visitor.assets


def scan_directory(root: str) -> List[CryptoAsset]:
    all_assets: List[CryptoAsset] = []
    for dirpath, _, filenames in os.walk(root):
        for f in filenames:
            if f.endswith(".py"):
                full = os.path.join(dirpath, f)
                all_assets.extend(scan_file(full))
    return all_assets


def to_cyclonedx(assets: List[CryptoAsset]) -> dict:
    """Convert to a minimal CycloneDX 1.6 BOM (components only)."""
    components = []
    for a in assets:
        comp = {
            "name": a.name,
            "type": "library",  # CycloneDX expects type; we treat crypto primitives as libs
            "version": "0.0.0",  # placeholder
            "purl": None,
            "hashes": [],
            "licenses": [],
            "cpes": [],
            "swid": None,
            "properties": [
                {"name": "crypto:algorithm", "value": a.algorithm},
                {"name": "crypto:key_size", "value": str(a.key_size) if a.key_size else ""},
                {"name": "crypto:mode", "value": a.mode or ""},
                {"name": "crypto:library", "value": a.library or ""},
                {"name": "crypto:quantum_risk", "value": a.quantum_risk},
                {"name": "crypto:file", "value": a.file_path},
                {"name": "crypto:line", "value": str(a.line_no)},
                {"name": "crypto:notes", "value": a.notes},
            ],
        }
        components.append(comp)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2025-09-26T00:00:00Z",
            "tools": [{"vendor": "Hermes", "name": "QBOM Scanner", "version": "0.1.0"}],
        },
        "components": components,
    }
    return bom


def main():
    if len(sys.argv) < 2:
        print("Usage: python qbom_scanner.py <path-to-source>", file=sys.stderr)
        sys.exit(1)
    root = sys.argv[1]
    assets = scan_directory(root)
    if not assets:
        print("[*] No cryptographic usage detected.", file=sys.stderr)
    bom = to_cyclonedx(assets)
    print(json.dumps(bom, indent=2))


if __name__ == "__main__":
    main()