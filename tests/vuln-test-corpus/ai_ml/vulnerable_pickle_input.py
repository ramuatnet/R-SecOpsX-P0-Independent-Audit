"""Model state accepted from the network is unpickled directly (Phase 6).

pickle.loads executes whatever the byte stream says, and request bodies are
attacker-controlled in every web framework: CWE-502 by construction, whether
or not a rule reports it.
"""
import pickle

from flask import request


def load_state():
    return pickle.loads(request.data)
