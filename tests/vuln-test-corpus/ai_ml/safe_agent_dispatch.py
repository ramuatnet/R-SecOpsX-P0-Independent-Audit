"""An agent dispatches through an allowlist and reads its key from the env.

Control for vulnerable_agent_eval.py and vulnerable_hardcoded_key.py. The tool
name only selects from a fixed mapping -- no eval, no getattr on request data --
and the credential comes from the environment, so nothing here is CWE-94 or
CWE-798.
"""
import os


def lookup_order(order_id):
    return {"id": order_id}


TOOLS = {"lookup_order": lookup_order}

KEY = os.environ.get("OPENAI_API_KEY")


def dispatch(name, arg):
    fn = TOOLS.get(name)
    if fn is None:
        raise ValueError("unknown tool")
    return fn(arg)
