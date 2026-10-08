from __future__ import annotations

import py_compile
import shutil
from pathlib import Path
from datetime import datetime

TARGET = Path(r"D:\Data\Code test\R-SecOpsX_V8_FP_Hardened_Final-2\V8 Original\scanner\advanced_ai_security.py")

if not TARGET.exists():
    raise SystemExit(f"ERROR: target not found: {TARGET}")

text = TARGET.read_text(encoding="utf-8")

OLD = """    for lineno, line in enumerate(lines, start=1):
        for rule in ADVANCED_AI_RULES:
            for pattern in rule["patterns"]:
                if re.search(pattern, line, re.I):
                    findings.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "vuln_type": rule["vuln_type"],
                        "severity": rule["severity"],
                        "file": filepath,
                        "line": lineno,
                        "snippet": line.strip(),
                        "detection": "Advanced AI Security Heuristic",
                        "ai_security_taxonomy": rule["rule_id"].split("_")[0],
                    })
                    break
"""

NEW = """    for lineno, line in enumerate(lines, start=1):
        for rule, compiled_patterns in _COMPILED_ADVANCED_AI_PATTERNS:
            for pattern in compiled_patterns:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "vuln_type": rule["vuln_type"],
                        "severity": rule["severity"],
                        "file": filepath,
                        "line": lineno,
                        "snippet": line.strip(),
                        "detection": "Advanced AI Security Heuristic",
                        "ai_security_taxonomy": rule["rule_id"].split("_")[0],
                    })
                    break
"""

if "_COMPILED_ADVANCED_AI_PATTERNS" in text:
    raise SystemExit("ABORT: compiled-pattern patch already exists; no change made.")

if OLD not in text:
    raise SystemExit(
        "ABORT: expected Advanced-AI scan loop was not found exactly. No change made."
    )

marker = "\n\ndef scan_advanced_ai_file(filepath: str, content: str) -> list[dict]:"

compiled_block = """

_COMPILED_ADVANCED_AI_PATTERNS = [
    (
        rule,
        tuple(re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]),
    )
    for rule in ADVANCED_AI_RULES
]
"""

if marker not in text:
    raise SystemExit("ABORT: expected scan function boundary was not found.")

backup = TARGET.with_name(
    TARGET.name + ".precompiled_patterns_" +
    datetime.now().strftime("%Y%m%d_%H%M%S") + ".bak"
)
shutil.copy2(TARGET, backup)

patched = text.replace(marker, compiled_block + marker, 1).replace(OLD, NEW, 1)
TARGET.write_text(patched, encoding="utf-8")

try:
    py_compile.compile(str(TARGET), doraise=True)
except Exception:
    TARGET.write_text(text, encoding="utf-8")
    raise SystemExit(f"ERROR: compile failed; production file restored. Backup: {backup}")

print("=== ADVANCED AI PRODUCTION PATCH ===")
print(f"TARGET={TARGET}")
print(f"BACKUP={backup}")
print("PATCH=STATIC REGEX PRECOMPILATION ONLY")
print("RULES_REMOVED=0")
print("PATTERNS_REMOVED=0")
print("FINDING_LOGIC_REMOVED=0")
print("COMPILE=PASS")
print("PRODUCTION_PATCH=APPLIED")
