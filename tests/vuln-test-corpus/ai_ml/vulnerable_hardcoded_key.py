"""An AI provider key is committed to the repository (Phase 6).

A credential literal in source is CWE-798 whether or not the secret detector
has a pattern for this provider's key format. The literal below authorises
nothing, but nothing in the code says so: it is committed exactly the way a
live key would be.
"""
import openai

openai.api_key = "sk-proj-AbCdEf0123456789AbCdEf0123456789AbCdEf01"

MODEL = "gpt-4o"


def complete(prompt):
    return openai.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
    )
