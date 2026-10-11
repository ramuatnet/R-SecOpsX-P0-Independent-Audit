"""Envelope encryption for records at rest."""
from Crypto.Cipher import AES


def seal(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt_and_digest(data)
