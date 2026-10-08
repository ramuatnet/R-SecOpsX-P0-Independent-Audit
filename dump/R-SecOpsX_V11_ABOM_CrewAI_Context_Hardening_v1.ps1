$ErrorActionPreference = "Stop"
$Root = "D:\Data\Code test\R-SecOpsX_V11"
$Prod = Join-Path $Root "scanner\abom.py"
$BackupDir = Join-Path $Root "backup"
$TestsDir = Join-Path $Root "tests"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $BackupDir "abom.py.before_crewai_context_hardening_v1_$Stamp.py"
$Test = Join-Path $TestsDir "test_v11_abom_crewai_context_hardening_v1.py"
$PatchFile = Join-Path $Root "dump\patch_abom_crewai_context_hardening_v1.py"
New-Item -ItemType Directory -Force -Path $BackupDir,$TestsDir | Out-Null
$Original = [IO.File]::ReadAllText($Prod,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($Backup,$Original,[Text.UTF8Encoding]::new($false))
Write-Host "[PASS] Backup: $Backup"
$Patch = @'
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
'@
$TestContent = @'
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.abom import scan_file

def write(name, text):
    p = ROOT / "tests" / "fixtures" / "abom_crewai_context_hardening" / name
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text, encoding="utf-8"); return p

def main():
    real = ROOT / "analysis" / "benchmark_controlled_llm.py"
    rows = scan_file(str(real))
    bad = [x for x in rows if x.get("framework") == "CrewAI" and x.get("component") in {"Agent","Task"}]
    assert not bad, f"benchmark CrewAI false positive remains: {bad}"
    print("[PASS] benchmark fixture strings do not become CrewAI findings")
    genuine = write("genuine_crewai_agent.py", "from crewai import Agent\nagent = Agent(role='researcher', goal='research')\n")
    rows2 = scan_file(str(genuine)); assert any(x.get("framework") == "CrewAI" and x.get("component") == "Agent" for x in rows2), rows2
    print("[PASS] genuine CrewAI Agent remains detected")
    alias = write("genuine_crewai_alias.py", "from crewai import Agent as CrewAgent\nagent = CrewAgent(role='researcher', goal='research')\n")
    rows3 = scan_file(str(alias)); assert any(x.get("framework") == "CrewAI" and x.get("component") == "Agent" for x in rows3), rows3
    print("[PASS] CrewAI Agent alias remains detected")
    generic = write("generic_agent.py", "def agent(user_prompt, model, secret):\n    return model(user_prompt, secret)\n")
    rows4 = scan_file(str(generic)); assert not any(x.get("framework") == "CrewAI" for x in rows4), rows4
    print("[PASS] generic agent() is not attributed to CrewAI")
    comment = write("comment_agent.py", "# Agent(role='researcher')\ndef run():\n    return 1\n")
    rows5 = scan_file(str(comment)); assert not any(x.get("framework") == "CrewAI" for x in rows5), rows5
    print("[PASS] commented Agent() is not attributed to CrewAI")
    print("ABOM_CREWAI_CONTEXT_HARDENING_V1_ACCEPTED")
if __name__ == "__main__": main()
'@
[IO.File]::WriteAllText($PatchFile,$Patch,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($Test,$TestContent,[Text.UTF8Encoding]::new($false))
try {
    python $PatchFile; if ($LASTEXITCODE -ne 0) { throw "Patch failed." }
    python -m py_compile $Prod; if ($LASTEXITCODE -ne 0) { throw "Production compilation failed." }
    Write-Host "[PASS] Production compilation"
    python $Test; if ($LASTEXITCODE -ne 0) { throw "Acceptance test failed." }
    Write-Host "============================================================"
    Write-Host "ABOM_CREWAI_CONTEXT_HARDENING_V1_ACCEPTED"
    Write-Host "[PASS] Benchmark false-positive prevention"
    Write-Host "[PASS] Genuine CrewAI detection retained"
    Write-Host "[PASS] Alias detection retained"
    Write-Host "[PASS] Comment/string suppression"
    Write-Host "[PASS] Backup: $Backup"
    Write-Host "============================================================"
} catch {
    [IO.File]::WriteAllText($Prod,$Original,[Text.UTF8Encoding]::new($false))
    Write-Host "[PASS] Production source restored from original content."
    throw
}
