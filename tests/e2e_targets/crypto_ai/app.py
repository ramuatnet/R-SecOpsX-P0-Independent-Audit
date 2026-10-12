"""Crypto and AI usage so the CBOM/AI-BOM artifacts carry real components.

Every construct here matches one scanner rule on purpose: MD5/SHA-1 weak
hashing, AES encryption, RSA key generation, TLS context setup, and a
hardcoded PEM private key. The AI side imports two providers so the AI-BOM
has more than one component.
"""
import hashlib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import ssl

import openai
from langchain.chat_models import ChatOpenAI

# Hardcoded private key (key material -- reported, never republished).
_FAKE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyMockKeyMaterialNotReal000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000
-----END RSA PRIVATE KEY-----"""


def weak_digest(data: bytes) -> str:
    md5_hex = hashlib.md5(data).hexdigest()
    sha1_hex = hashlib.sha1(data).hexdigest()
    return md5_hex + sha1_hex


def encrypt_block(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.encrypt(plaintext)


def make_key() -> RSA.RsaKey:
    return RSA.generate(2048)


def tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def ask_model(prompt: str) -> str:
    client = openai.OpenAI()
    chat = ChatOpenAI(model_name="gpt-4o-mini", temperature=0)
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    ).choices[0].message.content
