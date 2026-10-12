"""A deliberately clean target: nothing here should raise a finding."""

import hashlib


def normalise(value: str) -> str:
    return value.strip().lower()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_config(path: str) -> str:
    # A fixed literal path, not user input: not a traversal.
    with open("/etc/app/config.json", encoding="utf-8") as handle:
        return handle.read()
