from __future__ import annotations

import re
from pathlib import Path
from scanner.sast import _skip


SCANNABLE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs"
}

# Framework rules are language-scoped.  API-BOM patterns such as Django's
# ``path(...)`` are intentionally generic enough to appear in unrelated
# languages, so a regex match alone must never establish framework identity.
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".ts", ".jsx", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "ruby": {".rb"},
    "php": {".php"},
    "csharp": {".cs"},
}


def _rule_applies_to_path(rule: dict, path: Path) -> bool:
    """Return True only when the rule's declared language matches the file.

    This is a hard safety boundary: framework regexes are not allowed to
    classify a source file into another programming language.
    """
    allowed = LANGUAGE_EXTENSIONS.get(str(rule.get("language") or "").lower(), set())
    return path.suffix.lower() in allowed


API_RULES = [
    {
        "framework": "Flask",
        "language": "python",
        "patterns": [
            r"@app\.route\s*\(\s*[\"']([^\"']+)[\"'](?:[^)]*methods\s*=\s*\[([^\]]+)\])?",
            r"@blueprint\.route\s*\(\s*[\"']([^\"']+)[\"'](?:[^)]*methods\s*=\s*\[([^\]]+)\])?",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate route authentication, authorization, input validation, and CSRF controls."
    },
    {
        "framework": "FastAPI",
        "language": "python",
        "patterns": [
            r"@(?:app|api|router)\.(get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate dependency-based auth, request validation, and sensitive data exposure."
    },
    {
        "framework": "Django",
        "language": "python",
        "patterns": [
            r"path\s*\(\s*[\"']([^\"']+)[\"']",
            r"re_path\s*\(\s*[rR]?[\"']([^\"']+)[\"']",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate Django middleware, auth decorators, CSRF protection, and object authorization."
    },
    {
        "framework": "Express",
        "language": "javascript",
        "patterns": [
            r"\b(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate authentication middleware, request validation, and authorization checks."
    },
    {
        "framework": "Spring",
        "language": "java",
        "patterns": [
            r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*[\"']([^\"']+)[\"']",
            r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate Spring Security authorization, input validation, and object-level access control."
    },
    {
        "framework": "Go HTTP",
        "language": "go",
        "patterns": [
            r"http\.HandleFunc\s*\(\s*[\"']([^\"']+)[\"']",
            r"\brouter\.HandleFunc\s*\(\s*[\"']([^\"']+)[\"']",
            r"\br\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*[\"']([^\"']+)[\"']",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate handler auth, request parsing, and object authorization."
    },
    {
        "framework": "Ruby Rails",
        "language": "ruby",
        "patterns": [
            r"\b(get|post|put|delete|patch)\s+[\"']([^\"']+)[\"']",
            r"\bresources\s+:([A-Za-z_]\w*)",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate controller authorization, strong parameters, and CSRF protection."
    },
    {
        "framework": "PHP Laravel",
        "language": "php",
        "patterns": [
            r"Route::(get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate middleware auth, CSRF protection, and request validation."
    },
    {
        "framework": "ASP.NET",
        "language": "csharp",
        "patterns": [
            r"\[Http(Get|Post|Put|Delete|Patch)(?:\s*\(\s*[\"']([^\"']+)[\"']\s*\))?\]",
            r"\[Route\s*\(\s*[\"']([^\"']+)[\"']\s*\)\]",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate authorization attributes, model binding, and object access checks."
    },
]


SENSITIVE_PATH_HINTS = [
    "admin",
    "delete",
    "payment",
    "payments",
    "account",
    "accounts",
    "user",
    "users",
    "order",
    "orders",
    "token",
    "secret",
    "password",
    "login",
    "auth",
]


ROUTE_PARAM_RE = re.compile(
    r"(<[^>]+>|\{[^}]+\}|:[A-Za-z_]\w*)"
)


def _should_scan(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in SCANNABLE_EXT


def _line_for_offset(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


def _extract_methods(framework: str, match: re.Match) -> list[str]:
    groups = match.groups()

    if framework == "Flask":
        if len(groups) >= 2 and groups[1]:
            raw = groups[1]
            methods = re.findall(r"[\"']([A-Z]+)[\"']", raw)
            return methods or ["GET"]
        return ["GET"]

    if framework in {"FastAPI", "Express", "Go HTTP", "Ruby Rails", "PHP Laravel"}:
        method = groups[0] if groups else ""
        if method and method.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            return [method.upper()]
        return ["UNKNOWN"]

    if framework == "Spring":
        first = groups[0] if groups else ""
        mapping = {
            "GetMapping": "GET",
            "PostMapping": "POST",
            "PutMapping": "PUT",
            "DeleteMapping": "DELETE",
            "PatchMapping": "PATCH",
        }
        return [mapping.get(first, "UNKNOWN")]

    if framework == "ASP.NET":
        first = groups[0] if groups else ""
        if first:
            return [first.upper()]
        return ["UNKNOWN"]

    return ["UNKNOWN"]


def _extract_route(framework: str, match: re.Match) -> str:
    groups = match.groups()

    if not groups:
        return ""

    if framework == "Flask":
        return groups[0] or ""

    if framework in {"FastAPI", "Express", "Go HTTP", "Ruby Rails", "PHP Laravel"}:
        if len(groups) >= 2:
            return groups[1] or groups[0] or ""
        return groups[0] or ""

    if framework == "Spring":
        if len(groups) >= 2 and groups[1]:
            return groups[1]
        return groups[0] or ""

    if framework == "Django":
        return groups[0] or ""

    if framework == "ASP.NET":
        if len(groups) >= 2 and groups[1]:
            return groups[1]
        return groups[0] or ""

    return groups[0] or ""


def _classify_route_risk(route: str, methods: list[str]) -> str:
    lower = route.lower()

    if any(method in {"DELETE", "PUT", "PATCH"} for method in methods):
        return "HIGH"

    if any(hint in lower for hint in SENSITIVE_PATH_HINTS):
        return "HIGH"

    if any(method == "POST" for method in methods):
        return "MEDIUM"

    return "LOW"


def _auth_hint(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 6)
    end = min(len(lines), line_no + 8)
    window = "\n".join(lines[start:end]).lower()

    if any(token in window for token in [
        "login_required",
        "jwt_required",
        "authorize",
        "permission",
        "is_authenticated",
        "requiresauth",
        "security",
        "preauthorize",
        "rolesallowed",
        "authmiddleware",
        "passport.authenticate",
        "[authorize]",
        "@preauthorize",
    ]):
        return "AUTH_HINT_PRESENT"

    return "AUTH_HINT_NOT_OBSERVED"


def _make_apibom_item(
    rule: dict,
    filepath: str,
    line: int,
    evidence: str,
    route: str,
    methods: list[str],
    route_params: list[str],
    auth: str
) -> dict:
    risk = _classify_route_risk(route, methods)

    return {
        "bom_type": "API-BOM",
        "framework": rule["framework"],
        "language": rule["language"],
        "file": filepath,
        "line": line,
        "route": route,
        "methods": methods,
        "route_params": route_params,
        "auth_hint": auth,
        "evidence": evidence.strip(),
        "risk": risk,
        "recommendation": rule["recommendation"],
    }


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)

    if not _should_scan(path):
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = []
    lines = source.splitlines()

    for rule in API_RULES:
        if not _rule_applies_to_path(rule, path):
            continue

        compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in rule["patterns"]
        ]

        for pattern in compiled_patterns:
            for match in pattern.finditer(source):
                line_no = _line_for_offset(source, match.start())
                evidence = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""

                if evidence.lstrip().startswith(("#", "//", "*")):
                    continue

                route = _extract_route(rule["framework"], match)
                methods = _extract_methods(rule["framework"], match)

                route_params = ROUTE_PARAM_RE.findall(route)
                auth = _auth_hint(lines, line_no)

                findings.append(
                    _make_apibom_item(
                        rule,
                        str(path),
                        line_no,
                        evidence,
                        route,
                        methods,
                        route_params,
                        auth
                    )
                )

    return deduplicate(findings)


def deduplicate(items: list[dict]) -> list[dict]:
    seen = set()
    final = []

    for item in items:
        key = (
            item.get("framework"),
            item.get("file"),
            item.get("route"),
            tuple(item.get("methods", [])),
            item.get("line"),
        )

        if key in seen:
            continue

        seen.add(key)
        final.append(item)

    return final


def _portable_api_path(filepath: str, target: Path) -> str:
    """Return an API-BOM path relative to the scan root.

    Absolute machine-specific paths are not useful in reports or portable
    artifacts.  If the supplied target is a file, its parent is the root.
    """
    path = Path(filepath)
    root = target if target.is_dir() else target.parent
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        # Defensive fallback for unusual path/symlink layouts.
        return path.name


def _normalize_api_paths(items: list[dict], target: Path) -> list[dict]:
    for item in items:
        if item.get("file"):
            item["file"] = _portable_api_path(str(item["file"]), target)
    return items


def generate_apibom(target_path: str) -> list[dict]:
    target = Path(target_path)

    if target.is_file():
        if _skip(target):
            return []
        return _normalize_api_paths(scan_file(str(target)), target)

    if not target.exists():
        return []

    results = []
    for path in target.rglob("*"):
        if _skip(path):
            continue
        if _should_scan(path):
            results.extend(scan_file(str(path)))

    results = deduplicate(results)
    return _normalize_api_paths(results, target)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", default="apibom.json")
    args = parser.parse_args()

    apibom = generate_apibom(args.target)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(apibom, f, indent=2)

    print(f"[API-BOM] Items found: {len(apibom)}")
    print(f"[API-BOM] Output written: {args.output}")