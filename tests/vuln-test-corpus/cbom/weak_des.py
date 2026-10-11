"""Legacy field encryption for records migrated from the old platform."""
from Crypto.Cipher import DES

BLOCK = "DES/ECB/PKCS5Padding"


def encrypt_field(key: bytes, data: bytes) -> bytes:
    return DES.new(key, DES.MODE_ECB).encrypt(data)
