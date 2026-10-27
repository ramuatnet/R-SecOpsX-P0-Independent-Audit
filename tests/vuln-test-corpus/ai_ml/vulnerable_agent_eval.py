"""An agent executes the code its model returned (Phase 6).

The completion is untrusted input: the model's output is shaped by whatever an
attacker puts in the prompt, and eval() of it runs in the host process, so
this is CWE-94 from an external control sphere.
"""
import openai


def run_agent(client, prompt):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    code = resp.choices[0].message.content
    return eval(code)
