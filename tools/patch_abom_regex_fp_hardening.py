from pathlib import Path
from datetime import datetime
import shutil

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "abom.py"
BACKUP_DIR = ROOT / "backup"

if not TARGET.exists():
    raise SystemExit(f"ERROR: Target not found: {TARGET}")

source = TARGET.read_text(encoding="utf-8-sig")

OLD = '''                if _looks_like_comment_or_type_declaration(path,evidence):
                    continue
                window = _nearby_window(lines,line_no)
                if rule["framework"] == "CrewAI" and rule["component"] in {"Agent", "Task"}:
                    if not _generic_crewai_evidence_is_valid(path, source, match, line_no):
                        continue
                if not _rule_allowed(rule,evidence,window,path):
                    continue
'''

NEW = '''                if _looks_like_comment_or_type_declaration(path,evidence):
                    continue

                # Python regex hardening:
                # Regex is retained as a legacy fallback, but matches occurring
                # inside Python strings/comments must never become findings.
                if path.suffix.lower() == ".py":
                    if _python_regex_match_is_string_or_comment(
                        source, match.start()
                    ):
                        continue

                window = _nearby_window(lines,line_no)

                # CrewAI keeps its existing semantic validation.
                if rule["framework"] == "CrewAI" and rule["component"] in {"Agent", "Task"}:
                    if not _generic_crewai_evidence_is_valid(path, source, match, line_no):
                        continue

                # LlamaIndex ReActAgent regex detection must not classify an
                # unrelated object method or arbitrary identifier as a
                # framework component. For Python, require import/AST context.
                if (
                    path.suffix.lower() == ".py"
                    and rule["framework"] == "LlamaIndex"
                    and rule["component"] == "ReAct Agent"
                ):
                    try:
                        tree = ast.parse(source, filename=str(path))
                    except (SyntaxError, ValueError, TypeError):
                        continue

                    imports = _python_import_map(tree)

                    # Accept only when ReActAgent is actually imported from
                    # LlamaIndex, including aliases.
                    react_imported = False

                    for imported_name, imported_target in imports.items():
                        target = str(imported_target).lower()

                        if imported_name == "ReActAgent":
                            if target.endswith(".reactagent"):
                                react_imported = True
                                break

                        if (
                            imported_name != "ReActAgent"
                            and target.endswith(".reactagent")
                            and "llama_index" in target
                        ):
                            react_imported = True
                            break

                    # Also allow a direct LlamaIndex module reference such as
                    # llama_index...ReActAgent(...).
                    if not react_imported:
                        line = evidence
                        if not re.search(
                            r"\\bllama_index(?:\\.[A-Za-z_][A-Za-z0-9_]*)*\\s*\\.\\s*ReActAgent\\s*\\(",
                            line,
                            re.IGNORECASE,
                        ):
                            continue

                if not _rule_allowed(rule,evidence,window,path):
                    continue
'''

if OLD not in source:
    raise SystemExit(
        "ERROR: Expected regex validation block was not found. "
        "No source change made."
    )

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
backup = BACKUP_DIR / f"abom.py.before_regex_fp_hardening_{timestamp}.py"
shutil.copy2(TARGET, backup)

TARGET.write_text(source.replace(OLD, NEW, 1), encoding="utf-8")

print("[PASS] Python regex string/comment suppression added")
print("[PASS] LlamaIndex ReActAgent regex contextual validation added")
print("[PASS] Existing CrewAI validation preserved")
print(f"[BACKUP] {backup}")
