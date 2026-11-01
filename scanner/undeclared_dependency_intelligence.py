from __future__ import annotations

"""
R-SecOpsX Undeclared Dependency Intelligence v1

Purpose:
    Discover third-party packages imported/required by source code but not
    represented in the project's dependency manifests.

Design:
    - Static source inspection only; no network access.
    - No vulnerability is inferred merely from undeclared status.
    - Existing SBOM/dependency intelligence remains authoritative for package
      version/CVE/EPSS/KEV/reachability evidence.
    - Local/internal imports are excluded where they can be resolved as files.
    - Results are deterministic: paths and records are sorted.
"""

import ast
import json
import re
from pathlib import Path
from typing import Any


SUPPORTED_SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php",
}

MANIFEST_NAMES = {
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
    "pyproject.toml", "pipfile", "pipfile.lock",
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.json", "go.mod", "go.sum",
}

PYTHON_STDLIB = {
    "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii",
    "bisect", "calendar", "collections", "concurrent", "contextlib",
    "copy", "csv", "datetime", "decimal", "difflib", "email", "enum",
    "errno", "functools", "gc", "getopt", "glob", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "importlib", "inspect", "io",
    "itertools", "json", "keyword", "logging", "math", "mimetypes",
    "multiprocessing", "numbers", "operator", "os", "pathlib", "pickle",
    "platform", "pprint", "queue", "random", "re", "secrets", "shlex",
    "shutil", "signal", "socket", "sqlite3", "statistics", "string",
    "subprocess", "sys", "tempfile", "textwrap", "threading", "time",
    "traceback", "types", "typing", "unittest", "urllib", "uuid",
    "warnings", "weakref", "xml", "zipfile",
}


def _norm(value: str) -> str:
    return str(value or "").strip().lower().replace("\\", "/")


def _package_root(import_name: str) -> str:
    value = str(import_name or "").strip()
    if value.startswith("."):
        return ""
    return value.split(".", 1)[0].strip()


def _npm_package_root(import_name: str) -> str:
    value = str(import_name or "").strip()
    if value.startswith("@"):
        parts = value.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else value
    return value.split("/", 1)[0]


def _looks_like_relative_import(value: str) -> bool:
    return value.startswith((".", "/"))


def _read_text(path: Path) -> str:
    from core import file_index
    text = file_index.read_source(path)
    return text if text is not None else ""


def _is_local_python_import(root: Path, source: Path, top: str) -> bool:
    if not top:
        return True
    source_dir = source.parent
    candidates = [
        source_dir / f"{top}.py",
        source_dir / top / "__init__.py",
        root / f"{top}.py",
        root / top / "__init__.py",
    ]
    return any(p.exists() for p in candidates)


def _python_imports(root: Path, path: Path) -> list[dict[str, Any]]:
    source = _read_text(path)
    if not source:
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    records = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = _package_root(alias.name)
                if top in PYTHON_STDLIB or _is_local_python_import(root, path, top):
                    continue
                records.append({
                    "ecosystem": "pypi",
                    "package": top,
                    "import_name": alias.name,
                    "line": node.lineno,
                    "source_file": str(path.relative_to(root)).replace("\\", "/"),
                    "source_kind": "python_import",
                })
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            top = _package_root(node.module or "")
            if top in PYTHON_STDLIB or _is_local_python_import(root, path, top):
                continue
            records.append({
                "ecosystem": "pypi",
                "package": top,
                "import_name": node.module or "",
                "line": node.lineno,
                "source_file": str(path.relative_to(root)).replace("\\", "/"),
                "source_kind": "python_from_import",
            })
    return records


JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[^'"]+?\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]""",
    re.MULTILINE,
)
PHP_RE = re.compile(r"(?m)^\s*(?:use|require|require_once|include|include_once)\s+['\"]?([^;'\"]+)")
JAVA_RE = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)\s*;")


def _text_imports(root: Path, path: Path) -> list[dict[str, Any]]:
    source = _read_text(path)
    if not source:
        return []

    suffix = path.suffix.lower()
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        matches = JS_IMPORT_RE.finditer(source)
        ecosystem = "npm"
        records = []
        for m in matches:
            raw = m.group(1).strip()
            if _looks_like_relative_import(raw) or raw.startswith("#"):
                continue
            package = _npm_package_root(raw)
            line = source.count("\n", 0, m.start()) + 1
            records.append({
                "ecosystem": ecosystem,
                "package": package,
                "import_name": raw,
                "line": line,
                "source_file": str(path.relative_to(root)).replace("\\", "/"),
                "source_kind": "javascript_import",
            })
        return records

    if suffix == ".php":
        records = []
        for m in PHP_RE.finditer(source):
            raw = m.group(1).strip()
            if raw.startswith(".") or raw.startswith("/"):
                continue
            package = raw.split("\\", 1)[0]
            line = source.count("\n", 0, m.start()) + 1
            records.append({
                "ecosystem": "composer",
                "package": package,
                "import_name": raw,
                "line": line,
                "source_file": str(path.relative_to(root)).replace("\\", "/"),
                "source_kind": "php_use_or_include",
            })
        return records

    if suffix == ".java":
        records = []
        for m in JAVA_RE.finditer(source):
            raw = m.group(1).strip()
            top = raw.split(".", 1)[0]
            # java/javax/jakarta are treated as platform namespaces here.
            if top in {"java", "javax", "jakarta"}:
                continue
            line = source.count("\n", 0, m.start()) + 1
            records.append({
                "ecosystem": "maven",
                "package": ".".join(raw.split(".")[:3]),
                "import_name": raw,
                "line": line,
                "source_file": str(path.relative_to(root)).replace("\\", "/"),
                "source_kind": "java_import",
            })
        return records

    return []


def _requirements_names(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        m = re.match(r"([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*(?:[<>=!~].*)?$", line)
        if m:
            names.add(m.group(1).lower().replace("_", "-"))
    return names


def _package_json_names(data: dict[str, Any]) -> set[str]:
    names = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundledDependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            names.update(str(k).lower() for k in value)
        elif isinstance(value, list):
            names.update(str(k).lower() for k in value)
    return names


def _composer_names(data: dict[str, Any]) -> set[str]:
    names = set()
    for key in ("require", "require-dev", "suggest"):
        value = data.get(key)
        if isinstance(value, dict):
            names.update(str(k).lower() for k in value)
    return names


def _go_names(text: str) -> set[str]:
    return {
        m.group(1).strip().lower()
        for m in re.finditer(r"(?m)^\s*([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+)\s+v", text)  # sast-ignore PY_REDOS_NESTED_QUANTIFIER bounded dependency-name regex over size-capped text
    }


def _maven_group_names(text: str) -> set[str]:
    groups = set(re.findall(r"<groupId>\s*([^<]+)\s*</groupId>", text, flags=re.I))
    return {g.strip().lower() for g in groups if g.strip()}


def collect_declared_dependencies(root: Path) -> dict[str, set[str]]:
    declared = {"pypi": set(), "npm": set(), "composer": set(), "maven": set(), "go": set()}

    # T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
    from core import file_index
    for path in sorted(file_index.index_for(root).files(
            pred=lambda p: p.name.lower() in MANIFEST_NAMES)):
        name = path.name.lower()
        text = _read_text(path)

        if name in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "pipfile", "pipfile.lock"}:
            declared["pypi"].update(_requirements_names(text))
        elif name in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
            if name == "package.json":
                try:
                    declared["npm"].update(_package_json_names(json.loads(text)))
                except Exception:
                    pass
            else:
                # Lockfiles are intentionally treated as declarations too.
                declared["npm"].update(
                    m.group(1).lower()
                    for m in re.finditer(r'"(@?[^"\s]+)"\s*:', text)
                )
        elif name == "composer.json":
            try:
                declared["composer"].update(_composer_names(json.loads(text)))
            except Exception:
                pass
        elif name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
            declared["maven"].update(_maven_group_names(text))
        elif name in {"go.mod", "go.sum"}:
            declared["go"].update(_go_names(text))
        elif name == "pyproject.toml":
            # Conservative extraction: dependency strings inside common TOML arrays.
            for match in re.finditer(r"""["']([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:[<>=!~].*)?["']""", text):
                declared["pypi"].add(match.group(1).lower().replace("_", "-"))

    return declared


def _match_declared(record: dict[str, Any], declared: dict[str, set[str]]) -> bool:
    ecosystem = record["ecosystem"]
    package = str(record["package"]).lower()

    if ecosystem == "pypi":
        aliases = {package, package.replace("_", "-"), package.replace("-", "_")}
        return bool(aliases & declared["pypi"])

    if ecosystem == "npm":
        return package in declared["npm"]

    if ecosystem == "composer":
        return package in declared["composer"] or any(
            package == item.split("/", 1)[-1] for item in declared["composer"]
        )

    if ecosystem == "maven":
        return package in declared["maven"] or any(package.startswith(x + ".") for x in declared["maven"])

    if ecosystem == "go":
        return package in declared["go"]

    return False


def analyze_undeclared_dependencies(root_path: str | Path, sbom: list[dict] | None = None) -> dict[str, Any]:
    root = Path(root_path).resolve()
    declared = collect_declared_dependencies(root)

    imports = []
    # T-0.2: index query; the inline dir-skip set is walk policy now.
    from core import file_index
    for path in sorted(file_index.index_for(root).files(
            pred=lambda p: p.suffix.lower() in SUPPORTED_SOURCE_SUFFIXES)):
        if path.suffix.lower() == ".py":
            imports.extend(_python_imports(root, path))
        else:
            imports.extend(_text_imports(root, path))

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in imports:
        key = (record["ecosystem"], record["package"])
        grouped.setdefault(key, []).append(record)

    sbom_names = set()
    for item in sbom or []:
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "").lower()
        name = str(item.get("name") or item.get("package") or "").lower()
        if ecosystem and name:
            sbom_names.add((ecosystem, name))

    records = []
    for (ecosystem, package), occurrences in sorted(grouped.items()):
        is_declared = _match_declared({"ecosystem": ecosystem, "package": package}, declared)
        if is_declared:
            continue

        records.append({
            "package": package,
            "ecosystem": ecosystem,
            "declared": False,
            "status": "UNDECLARED",
            "source_count": len(occurrences),
            "sources": sorted(occurrences, key=lambda x: (x["source_file"], x["line"], x["import_name"])),
            "sbom_match": (ecosystem, package) in sbom_names,
            "evidence_type": "STATIC_SOURCE_IMPORT",
            "confidence": "HIGH" if len(occurrences) >= 1 else "LOW",
            "reason": "Third-party import/requirement observed in source code but no matching dependency declaration was found in supported project manifests.",
        })

    summary = {
        "total_import_records": len(imports),
        "unique_imported_packages": len(grouped),
        "undeclared_package_count": len(records),
        "declared_package_count": len(grouped) - len(records),
        "by_ecosystem": {},
    }
    for item in records:
        eco = item["ecosystem"]
        summary["by_ecosystem"][eco] = summary["by_ecosystem"].get(eco, 0) + 1

    return {
        "status": "COMPLETED",
        "analysis_scope": "STATIC_SOURCE_IMPORT_VS_MANIFEST",
        "declared_dependencies": {
            k: sorted(v) for k, v in sorted(declared.items())
        },
        "undeclared_dependencies": records,
        "summary": summary,
    }


def enrich_report_payload_with_undeclared_dependencies(
    payload: dict[str, Any],
    root_path: str | Path,
) -> dict[str, Any]:
    result = dict(payload)
    analysis = analyze_undeclared_dependencies(root_path, result.get("sbom") or [])
    result["undeclared_dependency_intelligence"] = analysis
    result["undeclared_dependency_summary"] = analysis["summary"]

    # Keep this as a separate evidence collection. Existing vulnerability
    # findings are not rewritten and no CVE/risk is fabricated here.
    result.setdefault("metadata", {})["undeclared_dependency_count"] = analysis["summary"]["undeclared_package_count"]
    result["metadata"]["undeclared_dependency_status"] = analysis["status"]
    return result
