"""T-6.1: hash primitives for asset correlation (pure, no network).

``murmur3_32`` is the exact MurmurHash3 x86 32-bit reference algorithm --
implemented here rather than pulled as a dependency because the offline
invariant forbids new required runtime deps, and favicon hashes only
correlate if every scanner in the fleet computes the SAME integer from
the same bytes.  Test vectors pin the implementation: the canonical
``mmh3.hash('foo') == -156908512``, ``0`` for empty, ``0x248bfa47``
"hello", ``0x5e928f0f`` "hello world" (the latter two cross-checked
against an independent transcription of the C reference).

``favicon_hash`` follows the de-facto Shodan recipe: mmh3 of the string
``data:image/x-icon;base64,<b64>`` (the favicon bytes base64-wrapped in
the HTML data-URI form).  The recipe is a CONVENTION, not a spec -- we
pin it here and in tests so our hashes stay comparable to Shodan/censys
lookups, and so a future "asset correlation" join can trust equality.
"""
from __future__ import annotations

import base64
import struct


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit.  Returns the hash as a signed int32, the
    convention Shodan-style favicon hashes use (so a raw hash of
    0xFF.. becomes -1, not 4294967295)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("murmur3_32 expects bytes")
    key = bytes(data)
    length = len(key)
    nblocks = length // 4
    h = seed & 0xFFFFFFFF
    for i in range(nblocks):
        k = struct.unpack_from("<I", key, i * 4)[0]
        k = (k * 0xCC9E2D51) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * 0x1B873593) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = key[nblocks * 4:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) in (2, 3):
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = (k1 * 0xCC9E2D51) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * 0x1B873593) & 0xFFFFFFFF
        h ^= k1
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    # signed int32, the Shodan convention
    return h - 0x100000000 if h >= 0x80000000 else h


def favicon_hash(icon_bytes: bytes, mime: str = "image/x-icon") -> int:
    """Shodan-compatible favicon hash of raw icon bytes.

    Same bytes + same mime => same hash on every machine; the correlation
    value comes from NOT inventing a variant recipe.
    """
    b64 = base64.b64encode(bytes(icon_bytes)).decode("ascii")
    return murmur3_32(f"data:{mime};base64,{b64}".encode("ascii"))
