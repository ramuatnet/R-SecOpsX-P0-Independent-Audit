from __future__ import annotations
import ast, subprocess, sys, time
from pathlib import Path

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
PROD = ROOT / "scanner" / "abom.py"
BACKUP_DIR = ROOT / "backup"
TEST = ROOT / "tests" / "test_v11_abom_ast_import_v1.py"
MARKER = "# --- V11 ABOM AST/IMPORT RESOLUTION v1 ---"

HELPER = r'''# --- V11 ABOM AST/IMPORT RESOLUTION v1 ---
def _abom_parse_ast(source: str):
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return None

def _abom_import_map(tree):
    result = {}
    if tree is None:
        return result
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
    return result

def _abom_component_id(framework, component, filepath):
    key = f"{framework}|{component}|{filepath}".replace("\\", "/").lower()
    return "ABOM-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]

def _abom_import_evidence(item, import_map):
    framework = str(item.get("framework", "")).lower()
    component = str(item.get("component", "")).lower()
    matches = []
    for local, target in import_map.items():
        t = target.lower()
        if framework == "crewai" and "crewai" in t and component in t:
            matches.append(f"{local} -> {target}")
        elif framework == "langchain" and "langchain" in t and component in t:
            matches.append(f"{local} -> {target}")
        elif framework == "autogen" and "autogen" in t and component in t:
            matches.append(f"{local} -> {target}")
    return matches

def _abom_enrich_item(item, filepath, tree, import_map):
    evidence_types = ["REGEX"]
    if tree is not None:
        evidence_types.append("AST")
    imports = _abom_import_evidence(item, import_map)
    if imports:
        evidence_types.append("IMPORT_RESOLUTION")
    item["component_id"] = _abom_component_id(item.get("framework", ""), item.get("component", ""), filepath)
    item["evidence_type"] = evidence_types
    item["import_resolution"] = imports
    item["confidence_level"] = "HIGH" if imports else ("MEDIUM" if tree is not None else "LOW")
    return item
# --- END V11 ABOM AST/IMPORT RESOLUTION v1 ---'''

TEST_SOURCE = '''from pathlib import Path\nimport tempfile\nfrom scanner import abom\n\ndef case(text):\n    d = Path(tempfile.mkdtemp(prefix="abom_v1_"))\n    p = d / "case.py"\n    p.write_text(text, encoding="utf-8")\n    return p\n\ndef main():\n    p = case("from crewai import Agent as CrewAgent\\nagent = CrewAgent(role='analyst')\\n")\n    rows = abom.scan_file(str(p))\n    row = next((x for x in rows if x.get("component") == "Agent"), None)\n    assert row is not None, rows\n    assert row["component_id"].startswith("ABOM-")\n    assert "AST" in row["evidence_type"]\n    assert "IMPORT_RESOLUTION" in row["evidence_type"]\n    assert row["confidence_level"] == "HIGH"\n    print("[PASS] AST verification")\n    print("[PASS] import/alias resolution")\n\n    p2 = case("Agent(role='generic')\\n")\n    rows2 = abom.scan_file(str(p2))\n    assert not any(x.get("framework") == "CrewAI" and x.get("confidence_level") == "HIGH" for x in rows2)\n    print("[PASS] generic Agent negative/context regression")\n\n    p3 = case("from crewai import Agent as CrewAgent\\na=CrewAgent()\\nb=CrewAgent()\\n")\n    rows3 = [x for x in abom.scan_file(str(p3)) if x.get("component") == "Agent"]\n    assert rows3 and len({x["component_id"] for x in rows3}) == 1\n    print("[PASS] deterministic component_id")\n\n    for key in ("bom_type","framework","component","category","file","line","evidence","tools_detected","memory_detected","human_approval_detected","asset_scope","validation_only","risk","recommendation"):\n        assert key in rows3[0], key\n    print("[PASS] existing ABOM fields preserved")\n    print("ABOM_AST_IMPORT_V1_ACCEPTED")\n\nif __name__ == "__main__":\n    main()\n'''

def main():
    if not PROD.exists(): raise SystemExit(f"Production file not found: {PROD}")
    original = PROD.read_text(encoding="utf-8-sig")
    if MARKER in original: raise SystemExit("ABOM v1 already installed; refusing duplicate patch.")
    tree = ast.parse(original, filename=str(PROD))
    funcs = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name in ("_make_item", "scan_file"):
        if name not in funcs: raise SystemExit(f"Required function missing: {name}")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = BACKUP_DIR / f"abom.py.before_abom_ast_import_v1_{stamp}.py"
    backup.write_text(original, encoding="utf-8")
    lines = original.splitlines()
    text = "\n".join(lines)
    needed = []
    if "import ast" not in text: needed.append("import ast")
    if "import hashlib" not in text: needed.append("import hashlib")
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if not s or s.startswith("#") or s.startswith("import ") or s.startswith("from "): i += 1
        else: break
    if needed:
        lines[i:i] = needed; i += len(needed)
    lines[i:i] = HELPER.splitlines()
    source = "\n".join(lines) + "\n"
    tree = ast.parse(source, filename=str(PROD))
    scan = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "scan_file")
    anchor = None
    for n in ast.walk(scan):
        if isinstance(n, ast.Assign) and "source.splitlines" in (ast.get_source_segment(source, n) or ""):
            anchor = n; break
    if anchor is None: raise SystemExit("scan_file source.splitlines() anchor not found.")
    lines = source.splitlines()
    indent = " " * (anchor.col_offset + 4)
    lines[anchor.lineno-1:anchor.lineno-1] = [f"{indent}abom_tree = _abom_parse_ast(source)", f"{indent}abom_import_map = _abom_import_map(abom_tree)"]
    source = "\n".join(lines) + "\n"
    tree = ast.parse(source, filename=str(PROD))
    scan = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "scan_file")
    appends = []
    for n in ast.walk(scan):
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
            c=n.value
            if isinstance(c.func, ast.Attribute) and c.func.attr == "append" and isinstance(c.func.value, ast.Name) and c.func.value.id == "findings": appends.append(n)
    if not appends: raise SystemExit("findings.append() anchor not found in scan_file.")
    lines = source.splitlines()
    for n in sorted(appends, key=lambda x:x.end_lineno, reverse=True):
        indent = " " * n.col_offset
        lines[n.end_lineno:n.end_lineno] = [f"{indent}findings[-1] = _abom_enrich_item(findings[-1], str(path), abom_tree, abom_import_map)"]
    patched = "\n".join(lines) + "\n"
    ast.parse(patched, filename=str(PROD))
    PROD.write_text(patched, encoding="utf-8")
    TEST.write_text(TEST_SOURCE, encoding="utf-8")
    try:
        subprocess.run([sys.executable, "-m", "py_compile", str(PROD)], cwd=ROOT, check=True)
        print("[PASS] Production compilation")
        subprocess.run([sys.executable, str(TEST)], cwd=ROOT, check=True)
        print("[PASS] ABOM AST/import acceptance")
        print("="*68); print("R-SecOpsX V11 - ABOM AST/IMPORT RESOLUTION v1 ACCEPTED"); print("="*68)
        print(f"[PASS] Backup: {backup}")
    except Exception:
        PROD.write_text(original, encoding="utf-8")
        print("[PASS] Production source restored from original content.")
        raise

if __name__ == "__main__": main()
