"""Checksum of an uploaded archive before it is stored."""
import hashlib


def archive_digest(path: bytes) -> str:
    return hashlib.md5(path).hexdigest()
