"""Both a weak digest and a weak cipher, on separate lines."""
import hashlib
from Crypto.Cipher import DES


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def legacy_encrypt(key: bytes, data: bytes) -> bytes:
    return DES.new(key, DES.MODE_ECB).encrypt(data)
