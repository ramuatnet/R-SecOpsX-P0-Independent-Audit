"""SYNTHETIC TEST FIXTURE — an invented placeholder for a "moved" module.

This file is not historical source code. It exists so the quarantine-record
contract tests can assert that a manifest records files that actually live in
its directory. It contains no real logic and represents no real module.
"""


def synthetic_placeholder_a() -> str:
    """Return a constant so the file is definition-bearing, nothing more."""
    return "synthetic-fixture-a"
