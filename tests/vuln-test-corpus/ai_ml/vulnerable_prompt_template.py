"""A prompt template is compiled from a request parameter (Phase 6).

Environment.from_string compiles template syntax held in a string at runtime.
Here that string is request data, so the template language is
attacker-controlled -- server-side template injection, CWE-94.

EXPECTED TO BE MISSED. The engine has no rule for jinja2 ``from_string`` built
from request data today, and this label exists so the gap is measured rather
than disappearing from the corpus. Label is from the CWE semantics of the
shape, not from anything the scanner reports.
"""
from flask import request
from jinja2 import Environment

env = Environment()


def render_prompt():
    template = request.args.get("t")
    return env.from_string(template).render()
