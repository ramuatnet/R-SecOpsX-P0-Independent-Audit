"""Signing keypair generated once per deployment."""
from Crypto.PublicKey import RSA


def new_signing_key(bits: int = 3072):
    return RSA.generate(bits)
