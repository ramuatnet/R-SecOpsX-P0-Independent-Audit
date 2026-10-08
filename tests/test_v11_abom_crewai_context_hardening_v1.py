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