
from pathlib import Path
import py_compile
import shutil
from datetime import datetime

TARGET = Path(r".\scanner\advanced_ai_security.py")

if not TARGET.exists():
    raise SystemExit(f"ABORT: target not found: {TARGET}")

source = TARGET.read_text(encoding="utf-8")

MARKER = "_COMPILED_ADVANCED_AI_PATTERNS"
if MARKER in source:
    raise SystemExit("ABORT: compiled Advanced-AI patterns already exist. No change made.")

START = "def scan_advanced_ai_file(filepath: str, content: str) -> list[dict]:"
if START not in source:
    raise SystemExit("ABORT: scan_advanced_ai_file() not found. No change made.")

OLD = """            for pattern in rule["patterns"]:
                if re.search(pattern, line, re.I):
"""

NEW = """            for pattern in compiled_patterns:
                if pattern.search(line):
"""

if source.count(OLD) != 1:
    raise SystemExit(f"ABORT: expected exactly 1 regex loop, found {source.count(OLD)}. No change made.")

RULE_LOOP = """    for lineno, line in enumerate(lines, start=1):
        for rule in ADVANCED_AI_RULES:
"""
COMPILED_RULE_LOOP = """    for lineno, line in enumerate(lines, start=1):
        for rule, compiled_patterns in _COMPILED_ADVANCED_AI_PATTERNS:
"""

if source.count(RULE_LOOP) != 1:
    raise SystemExit(f"ABORT: expected exactly 1 rule loop, found {source.count(RULE_LOOP)}. No change made.")

COMPILED_BLOCK = """_COMPILED_ADVANCED_AI_PATTERNS = [
    (
        rule,
        tuple(re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]),
    )
    for rule in ADVANCED_AI_RULES
]


"""

patched = source.replace(START, COMPILED_BLOCK + START, 1)
patched = patched.replace(RULE_LOOP, COMPILED_RULE_LOOP, 1)
patched = patched.replace(OLD, NEW, 1)

if patched.count(MARKER) != 1 or OLD in patched or COMPILED_RULE_LOOP not in patched:
    raise SystemExit("ABORT: post-patch safety validation failed. No change made.")

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
backup = TARGET.with_name(f"{TARGET.name}.precompiled_patterns_{stamp}.bak")
shutil.copy2(TARGET, backup)

try:
    TARGET.write_text(patched, encoding="utf-8")
    py_compile.compile(str(TARGET), doraise=True)
except Exception as exc:
    TARGET.write_text(source, encoding="utf-8")
    raise SystemExit(f"PATCH FAILED: {exc}\nORIGINAL RESTORED\nBACKUP RETAINED: {backup}")

print("PATCH=ADVANCED AI STATIC REGEX PRECOMPILATION")
print(f"TARGET={TARGET.resolve()}")
print(f"BACKUP={backup.resolve()}")
print("RULES_REMOVED=0")
print("PATTERNS_REMOVED=0")
print("FINDING_LOGIC_REMOVED=0")
print("CONTRACT_LOGIC_CHANGED=0")
print("SUPPRESSION_LOGIC_CHANGED=0")
print("COMPILE=PASS")
print("PRODUCTION_PATCH=APPLIED")
