"""TLS validation disabled: certificate verification is switched off for an
outbound call, so any intercepted or spoofed endpoint is accepted as trusted."""
import requests

UPSTREAM = "https://inventory.internal/api"


def load_inventory():
    return requests.get(UPSTREAM, verify=False, timeout=10).json()
