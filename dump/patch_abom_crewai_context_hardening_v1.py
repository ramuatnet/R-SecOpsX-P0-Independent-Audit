from pathlib import Path
p = Path(r"D:\Data\Code test\R-SecOpsX_V11\scanner\abom.py")
s = p.read_text(encoding="utf-8-sig")
anchor = "def _looks_like_comment_or_type_declaration(path: Path, evidence: str) -> bool:"
pos = s.find(anchor)
if pos < 0: raise SystemExit("Expected ABOM anchor not found.")
end = s.find("\ndef _rule_allowed", pos)
if end < 0: raise SystemExit("Expected ABOM rule anchor not found.")
helper = r'''
def _python_regex_match_is_string_or_comment(source: str, match_start: int) -> bool:
    try:
        import tokenize
        from io import StringIO
        lines = source.splitlines(True)
        for tok in tokenize.generate_tokens(StringIO(source).readline):
            if tok.type not in (tokenize.STRING, tokenize.COMMENT): continue
            (sl, sc), (el, ec) = tok.start, tok.end
            start = sum(len(x) for x in lines[:sl - 1]) + sc
            finish = sum(len(x) for x in lines[:el - 1]) + ec
            if start <= match_start < finish: return True
    except (SyntaxError, tokenize.TokenError, IndentationError): return False
    return False

def _generic_crewai_evidence_is_valid(path: Path, source: str, match, line_no: int) -> bool:
    if path.suffix.lower() != ".py": return True
    if _python_regex_match_is_string_or_comment(source, match.start()): return False
    try: tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, TypeError): return False
    imports = _python_import_map(tree)
    if any(str(v).lower() == "crewai" or str(v).lower().startswith("crewai.") for v in imports.values()): return True
    lines = source.splitlines()
    line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    return bool(re.search(r"\bcrewai\s*\.\s*(Agent|Task)\s*\(", line, re.IGNORECASE))
'''
if "def _generic_crewai_evidence_is_valid(" not in s: s = s[:end] + helper + s[end:]
old = '''                if rule["framework"] == "CrewAI" and rule["component"] == "Agent" and GENERIC_AGENT_RE.search(match.group(0)) and not _contains_any(window,AI_AGENT_CONTEXT_TERMS):
                    continue
                if rule["framework"] == "CrewAI" and rule["component"] == "Task" and GENERIC_TASK_RE.search(match.group(0)) and not _contains_any(window,AI_TASK_CONTEXT_TERMS):
                    continue
'''
new = '''                if rule["framework"] == "CrewAI" and rule["component"] in {"Agent", "Task"}:
                    if not _generic_crewai_evidence_is_valid(path, source, match, line_no):
                        continue
'''
if old not in s: raise SystemExit("Expected CrewAI generic-rule block not found.")
s = s.replace(old, new, 1)
p.write_text(s, encoding="utf-8")
print("[PASS] CrewAI evidence hardening applied")