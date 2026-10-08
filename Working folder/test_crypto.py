import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

# RSA key generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# AES encryption
key = b'\x00' * 32  # AES-256 key
iv = b'\x00' * 16
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()

# SHA-256 digest
digest = hashes.Hash(hashes.SHA256())
digest.update(b'hello world')