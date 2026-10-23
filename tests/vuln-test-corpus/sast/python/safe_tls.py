"""Same upstream call with verification left on (the default): an invalid or
mismatched certificate fails the call instead of being accepted."""
import requests

UPSTREAM = "https://inventory.internal/api"


def load_inventory():
    return requests.get(UPSTREAM, verify=True, timeout=10).json()
