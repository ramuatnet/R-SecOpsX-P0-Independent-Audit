"""PEM redaction for artifact writers.

A BOM (or any exported document) is the artifact most likely to be handed
to third parties -- registries, auditors, customers, CI artifacts -- so it
is the worst possible place for the scan to republish the secret it just
found. The CBOM "Hardcoded Private Key" rule's evidence field IS the PEM
block, and every serialization path that copied that field verbatim leaked
the key:

    reporting/cyclonedx_export.py   rsecopsx:raw property (main SBOM)
    reporting/cyclonedx_bom_export  evidence property (CycloneDX 1.6 CBOM)
    scanner/crypto_quantum_analyzer evidence -> Security_QBOM.pq.json

All three paths route through :func:`redact_pem` so the pattern exists in
one place. The standalone export paths (clean_report.json, SARIF, the PDF)
are deliberately NOT redacted: showing the operator the material they must
rotate is the report's job. Exports leave the trust boundary; reports do
not.
"""
from __future__ import annotations

import re

# Complete block, or from an unterminated BEGIN to the end of the string.
# The second alternative exists because callers slice evidence to a fixed
# length: redact-after-slice left a BEGIN header whose END line had been
# cut away, so the first pattern matched nothing and the key body survived.
# Order of operations is therefore part of the contract: redact the full
# text first, slice the redacted result afterwards.
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----"
    r"|-----BEGIN [A-Z0-9 ]+-----.*\Z",
    re.S,
)

PEM_PLACEHOLDER = "[REDACTED PEM BLOCK]"


def redact_pem(text: str) -> str:
    """Replace any PEM-labelled block with a placeholder.

    Handles both complete blocks and blocks truncated by the caller's own
    windowing. Non-str input is returned unchanged so the function can be
    mapped over heterogeneous values without type branching.
    """
    if not isinstance(text, str) or not text:
        return text
    return _PEM_BLOCK.sub(PEM_PLACEHOLDER, text)


def redact_pem_deep(value):
    """Recursively redact PEM blocks in strings inside dicts/lists.

    Used by serialization paths that embed whole records (the raw item in
    the main SBOM, evidence dicts in the PQ QBOM), where a secret can sit
    at any depth rather than at the top of a known field.
    """
    if isinstance(value, str):
        return redact_pem(value)
    if isinstance(value, dict):
        return {k: redact_pem_deep(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_pem_deep(v) for v in value]
    return value
