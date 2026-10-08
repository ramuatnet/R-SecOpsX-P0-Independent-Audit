"""Verified OWASP GenAI/Agentic mapping metadata for V11.

Mapping identifiers are metadata, not detector names. Tool-poisoning is
conditional: ASI02 for misuse/exploitation; ASI04 where evidence establishes
agentic supply-chain compromise.
"""
OWASP_LLM = {
    "PROMPT_INJECTION": {"namespace":"LLM01:2025","title":"Prompt Injection","mapping_mode":"DIRECT"},
}
OWASP_ASI = {
    "ASI01":{"title":"Agent Goal Hijack"},
    "ASI02":{"title":"Tool Misuse and Exploitation"},
    "ASI03":{"title":"Identity & Privilege Abuse"},
    "ASI04":{"title":"Agentic Supply Chain Vulnerabilities"},
    "ASI05":{"title":"Unexpected Code Execution"},
    "ASI06":{"title":"Memory & Context Poisoning"},
    "ASI07":{"title":"Insecure Inter-Agent Communication"},
    "ASI08":{"title":"Cascading Failures"},
    "ASI09":{"title":"Human-Agent Trust Exploitation"},
    "ASI10":{"title":"Rogue Agents"},
}
def map_technique(technique, *, supply_chain=False, misuse=False):
    t=(technique or "").upper()
    if t in {"PROMPT_INJECTION","LLM_PROMPT_INJECTION"}:
        return dict(OWASP_LLM["PROMPT_INJECTION"])
    if t in {"TOOL_POISONING","MCP_TOOL_POISONING"}:
        ids=[]
        if misuse: ids.append("ASI02")
        if supply_chain: ids.append("ASI04")
        return {"technique":"TOOL_POISONING","owasp":ids,"mapping_mode":"CONDITIONAL"}
    if t in OWASP_ASI:
        return {"technique":t,"owasp":[t],"mapping_mode":"DIRECT"}
    return {"technique":t,"owasp":[],"mapping_mode":"UNMAPPED"}
