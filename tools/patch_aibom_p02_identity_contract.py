from pathlib import Path
from datetime import datetime
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

source = TARGET.read_text(encoding="utf-8-sig")

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
backup = BACKUP_DIR / f"aibom.py.before_p02_identity_contract_{stamp}.py"
shutil.copy2(TARGET, backup)

old_make = '''def _make_aibom_item(rule: dict, filepath: str, line: int, evidence: str, model_hint: str | None = None) -> dict:
    return {
        "bom_type": "AI-BOM",
        "provider": rule["provider"],
        "component": rule["component"],
        "model_hint": model_hint or "",
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
    }
'''

new_make = '''def _make_aibom_item(
    rule: dict,
    filepath: str,
    line: int,
    evidence: str,
    model_hint: str | None = None,
    *,
    detection_mode: str | None = None,
    evidence_type: list[str] | None = None,
    confidence: str | None = None,
    confidence_score: float | None = None,
    import_resolution: str | None = None,
) -> dict:
    provider = str(rule["provider"])
    component = str(rule["component"])

    # P0.2 canonical semantic identity.
    # Identity MUST NOT depend on file path, line number, alias,
    # evidence text, detection mechanism, or model hint.
    identity_source = f"{provider}|{component}".encode("utf-8")
    component_id = (
        "AIBOM-COMP-"
        + __import__("hashlib").sha256(identity_source)
        .hexdigest()
        .upper()[:20]
    )

    item = {
        "bom_type": "AI-BOM",
        "provider": provider,
        "component": component,
        "component_id": component_id,
        "model_hint": model_hint or "",
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
        "detection_mode": detection_mode,
        "evidence_type": sorted(
            set(evidence_type or [])
        ),
        "confidence": confidence,
        "confidence_score": confidence_score,
    }

    if import_resolution:
        item["import_resolution"] = import_resolution

    return item
'''

if old_make not in source:
    raise SystemExit(
        "ERROR: expected _make_aibom_item() contract not found."
    )

source = source.replace(old_make, new_make, 1)

old_ast_call = '''        findings.append(
            _make_aibom_item(
                rule,
                str(path),
                line_no,
                evidence,
                None,
            )
        )

        findings[-1]["import_resolution"] = resolution
'''

new_ast_call = '''        findings.append(
            _make_aibom_item(
                rule,
                str(path),
                line_no,
                evidence,
                None,
                detection_mode="AST+IMPORT_RESOLUTION",
                evidence_type=["AST", "IMPORT_RESOLUTION"],
                confidence="HIGH",
                confidence_score=0.90,
                import_resolution=resolution,
            )
        )
'''

if old_ast_call not in source:
    raise SystemExit(
        "ERROR: expected AST finding construction block not found."
    )

source = source.replace(old_ast_call, new_ast_call, 1)

old_regex_call = '''                findings.append(
                    _make_aibom_item(
                        rule,
                        str(path),
                        line_no,
                        evidence,
                        model_hint
                    )
                )
'''

new_regex_call = '''                findings.append(
                    _make_aibom_item(
                        rule,
                        str(path),
                        line_no,
                        evidence,
                        model_hint,
                        detection_mode="REGEX",
                        evidence_type=["REGEX"],
                        confidence="LOW",
                        confidence_score=0.40,
                    )
                )
'''

if old_regex_call not in source:
    raise SystemExit(
        "ERROR: expected regex finding construction block not found."
    )

source = source.replace(old_regex_call, new_regex_call, 1)

TARGET.write_text(source, encoding="utf-8")

print("[PASS] Canonical AI-BOM component identity added")
print("[PASS] AST/import provenance added at finding creation")
print("[PASS] AST confidence contract added: HIGH / 0.90")
print("[PASS] Regex confidence contract preserved: LOW / 0.40")
print("[PASS] Detection mode explicitly assigned")
print(f"[BACKUP] {backup}")
