"""Integrity digest using an approved algorithm."""
import hashlib


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
