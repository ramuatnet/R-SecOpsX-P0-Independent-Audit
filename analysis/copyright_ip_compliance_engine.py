from __future__ import annotations
try:
    from analysis.spans import WINDOW_300, WINDOW_EVIDENCE
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_300, WINDOW_EVIDENCE

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


COPYRIGHT_PATTERNS = [
    ("AGPL_LICENSE_TEXT", r"affero\s+general\s+public\s+license|agpl", "critical"),
    ("GPL_LICENSE_TEXT", r"gnu\s+general\s+public\s+license|gplv?3|gplv?2", "high"),
    ("SPDX_AGPL", r"SPDX-License-Identifier\s*:\s*AGPL-[\w\.\+\-]+", "critical"),
    ("SPDX_GPL", r"SPDX-License-Identifier\s*:\s*GPL-[\w\.\+\-]+", "high"),
    ("COPYRIGHT_NOTICE", r"copyright\s*(?:\(c\)|©)?\s*\d{4}", "medium"),
    ("ALL_RIGHTS_RESERVED", r"all\s+rights\s+reserved", "high"),
    ("PROPRIETARY_NOTICE", r"proprietary\s+and\s+confidential", "high"),
    ("CONFIDENTIAL_NOTICE", r"confidential\s+information", "high"),
    ("UNAUTHORIZED_COPYING", r"unauthorized\s+copying|distribution\s+is\s+prohibited", "high"),
    ("THIRD_PARTY_CODE", r"third[-\s]?party\s+code|derived\s+from|based\s+on", "medium"),
    ("UNKNOWN_LICENSE", r"license\s*:\s*unknown|\bunlicensed\b", "medium"),
    ("NO_LICENSE_FOUND", r"no\s+license\s+provided", "medium"),
]


SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".kt", ".swift",
    ".html", ".css", ".scss", ".sql", ".sh", ".yaml", ".yml", ".json",
    ".md", ".txt", ".xml", ".toml", ".ini", ".cfg"
}


IMPORTANT_FILENAMES = {
    "license", "license.txt", "license.md",
    "copying", "copying.txt", "copying.md",
    "notice", "notice.txt", "notice.md",
    "copyright",
    "authors", "authors.txt", "authors.md",
}


EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules",
    "dist", "build", "__pycache__", "reports",
    ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
    "target", "coverage", ".next"
}


def _severity_score(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(str(severity).lower(), 1)


def _priority_for(severity: str) -> str:
    severity = str(severity).lower()
    if severity == "critical":
        return "P0"
    if severity == "high":
        return "P1"
    if severity == "medium":
        return "P2"
    return "P3"


def _safe_read(path: Path) -> str:
    from core import file_index
    text = file_index.read_source(path, encoding="utf-8", errors="ignore")
    return text if text is not None else ""


def _should_scan_file(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()

    if any(part.lower() in EXCLUDED_DIRS for part in path.parts):
        return False

    return suffix in SOURCE_EXTENSIONS or name in IMPORTANT_FILENAMES


def _decision_from_findings(findings: List[Dict[str, Any]]) -> str:
    if any(f.get("rule_id") in {"AGPL_LICENSE_TEXT", "SPDX_AGPL"} for f in findings):
        return "AGPL_RESTRICTED_LICENSE_REVIEW_REQUIRED"

    if any(f.get("rule_id") in {"GPL_LICENSE_TEXT", "SPDX_GPL"} for f in findings):
        return "GPL_RESTRICTED_LICENSE_REVIEW_REQUIRED"

    if any(f.get("severity") == "critical" for f in findings):
        return "COPYRIGHT_REVIEW_REQUIRED"

    if any(f.get("rule_id") in {
        "PROPRIETARY_NOTICE",
        "ALL_RIGHTS_RESERVED",
        "CONFIDENTIAL_NOTICE",
        "UNAUTHORIZED_COPYING",
    } for f in findings):
        return "PROPRIETARY_OR_RESTRICTED_NOTICE_DETECTED"

    if any(f.get("rule_id") == "THIRD_PARTY_CODE" for f in findings):
        return "THIRD_PARTY_CODE_REVIEW"

    if any(f.get("rule_id") in {"UNKNOWN_LICENSE", "NO_LICENSE_FOUND"} for f in findings):
        return "UNKNOWN_LICENSE_REVIEW"

    if findings:
        return "UNKNOWN_IP_ORIGIN"

    return "NO_COPYRIGHT_SIGNAL"


def _review_action_for(rule_id: str, severity: str) -> str:
    if rule_id in {"AGPL_LICENSE_TEXT", "SPDX_AGPL"}:
        return "Perform legal/open-source governance review before redistribution or network-service deployment."
    if rule_id in {"GPL_LICENSE_TEXT", "SPDX_GPL"}:
        return "Review copyleft obligations, redistribution model, linking model, and source-disclosure requirements."
    if rule_id in {"PROPRIETARY_NOTICE", "CONFIDENTIAL_NOTICE", "ALL_RIGHTS_RESERVED", "UNAUTHORIZED_COPYING"}:
        return "Validate code origin, ownership rights, redistribution permissions, and approval evidence."
    if rule_id == "THIRD_PARTY_CODE":
        return "Confirm third-party attribution, license terms, and permitted usage."
    if rule_id in {"UNKNOWN_LICENSE", "NO_LICENSE_FOUND"}:
        return "Identify applicable license and document usage rights before release."
    if severity == "critical":
        return "Escalate for copyright/IP review before release."
    if severity == "high":
        return "Review with legal/open-source governance before release."
    return "Track as an IP-origin governance indicator."


def analyze_copyright_ip_compliance(project_path: str) -> Dict[str, Any]:
    root = Path(project_path)
    findings: List[Dict[str, Any]] = []

    if not root.exists():
        return {
            "summary_status": "COPYRIGHT_IP_SCAN_FAILED",
            "engine": "COPYRIGHT_IP_COMPLIANCE_V1",
            "error": f"Path does not exist: {project_path}",
            "files_scanned": 0,
            "total_findings": 0,
            "findings": [],
            "summary": {},
        }

    files_scanned = 0

    # T-0.2 (task.md): the one walk's index; this engine's EXCLUDED_DIRS
    # are part of the shared union policy applied at the one walk.
    from core import file_index
    for path in file_index.index_for(root).files(pred=_should_scan_file):
        files_scanned += 1
        text = _safe_read(path)

        if not text:
            continue

        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule_id, pattern, severity in COPYRIGHT_PATTERNS:
                match = re.search(pattern, line, flags=re.IGNORECASE)
                if not match:
                    continue

                effective_severity = severity
                stripped_line = line.strip()

                # A GPL text match in a source-code comment is a contextual/governance
                # signal, not sufficient evidence of a project-wide GPL licensing
                # obligation. Preserve the finding, but lower comment-only matches
                # to MEDIUM. Explicit license files remain HIGH.
                _name_upper = path.name.upper()
                is_license_file = (
                    _name_upper in {
                        "LICENSE",
                        "LICENSE.TXT",
                        "LICENSE.MD",
                        "COPYING",
                        "COPYING.TXT",
                        "COPYING.MD",
                    }
                    or _name_upper.startswith("LICENSE.")
                    or _name_upper.startswith("COPYING.")
                )
                is_comment_line = (
                    stripped_line.startswith("//")
                    or stripped_line.startswith("/*")
                    or stripped_line.startswith("*")
                    or stripped_line.startswith("#")
                )

                if (
                    rule_id == "GPL_LICENSE_TEXT"
                    and is_comment_line
                    and not is_license_file
                ):
                    effective_severity = "medium"

                findings.append({
                    "rule_id": rule_id,
                    "title": rule_id.replace("_", " ").title(),
                    "severity": effective_severity,
                    "priority": _priority_for(severity),
                    "file": str(path),
                    "line": line_no,
                    "snippet": line.strip()[:WINDOW_300],
                    "description": (
                        "Potential copyright, license, proprietary-code, "
                        "or IP-origin compliance indicator detected."
                    ),
                    "evidence_type": "SOURCE_TEXT_PATTERN",
                    "evidence_match": match.group(0)[:WINDOW_EVIDENCE],
                    "engine": "COPYRIGHT_IP_COMPLIANCE_V1",
                    "confidence": "Medium",
                    "recommended_action": _review_action_for(rule_id, severity),
                    "legal_determination": False,
                    "review_required": severity in {"critical", "high", "medium"},
                })

    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")

    decision = _decision_from_findings(findings)

    risk_score = min(
        100,
        sum(_severity_score(str(f.get("severity", "low"))) * 5 for f in findings)
    )

    review_required = decision != "NO_COPYRIGHT_SIGNAL"

    return {
        "summary_status": "COPYRIGHT_IP_COMPLIANCE_COMPLETED",
        "engine": "COPYRIGHT_IP_COMPLIANCE_V1",
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "risk_score": risk_score,
        "decision": decision,
        "review_required": review_required,
        "legal_determination": False,
        "findings": findings,
        "summary": {
            "copyright_ip_findings": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "decision": decision,
            "risk_score": risk_score,
            "review_required": review_required,
        },
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(analyze_copyright_ip_compliance(target), indent=2))