import os
import re
import json


SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs"
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", "target", ".next"
}

REACHABILITY_ALIASES = {
    "log4j": {"log4j-core", "log4j-api", "org.apache.logging.log4j"},
    "spring-core": {"org.springframework.core"},
    "spring-web": {"org.springframework.web"},
    "spring-webmvc": {"org.springframework.web.servlet"},
    "lodash": {"lodash", "lodash-es"},
    "node-fetch": {"node-fetch", "node_fetch", "nodefetch"},
    "jackson-databind": {"com.fasterxml.jackson.databind"},
    "jackson-core": {"com.fasterxml.jackson.core"},
    "struts2-core": {"org.apache.struts2"},
}

def _safe_read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return []

def _iter_project_files(project_root):
    # T-0.2 (task.md): the one walk's index; SKIP_DIRS is walk policy now.
    # Contract kept: yields STRINGS (callers do os.path.relpath/basename).
    from core import file_index
    for path in file_index.index_for(project_root).files(
            exts={e.lower() for e in SOURCE_EXTENSIONS},
            names={"package.json", "pom.xml", "build.gradle"}):
        yield str(path)

def extract_source_references(project_root):
    references = []
    for path in _iter_project_files(project_root):
        rel_path = os.path.relpath(path, project_root)
        filename = os.path.basename(path)
        ext = os.path.splitext(filename)[1].lower()
        lines = _safe_read(path)

        if filename == "package.json":
            try:
                data = json.loads("".join(lines))
                for section in ["dependencies", "optionalDependencies", "peerDependencies"]:
                    for pkg in data.get(section, {}).keys():
                        references.append({
                            "package_reference": pkg,
                            "file": rel_path, "line": 0,
                            "reference": section,
                            "method": "manifest_reference",
                            "language": "javascript",
                        })
                # devDependencies are intentionally not treated as runtime reachability.
            except Exception:
                pass
            continue

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                continue
            found = []

            if ext == ".py":
                found += re.findall(r"^\s*import\s+([a-zA-Z_][\w.]*)", line)
                found += re.findall(r"^\s*from\s+([a-zA-Z_][\w.]*)\s+import\s+", line)
                found += re.findall(r"importlib\.import_module\(\s*['\"]([^'\"]+)['\"]", line)
                found += re.findall(r"__import__\(\s*['\"]([^'\"]+)['\"]", line)
                language = "python"

            elif ext in {".js", ".ts", ".jsx", ".tsx"}:
                found += re.findall(r"\brequire\(\s*['\"]([^'\"]+)['\"]\s*\)", line)
                found += re.findall(r"\bfrom\s+['\"]([^'\"]+)['\"]", line)
                found += re.findall(r"\bimport\s+['\"]([^'\"]+)['\"]", line)
                language = "javascript"

            elif ext == ".java":
                found += re.findall(r"^\s*import\s+(?:static\s+)?([a-zA-Z_][\w.]*)", line)
                found += re.findall(r"Class\.forName\(\s*['\"]([^'\"]+)['\"]", line)
                language = "java"

            elif ext == ".cs":
                found += re.findall(r"^\s*using\s+([a-zA-Z_][\w.]*)", line)
                found += re.findall(r"Type\.GetType\(\s*['\"]([^'\"]+)['\"]", line)
                language = "csharp"

            elif filename == "pom.xml":
                found += re.findall(r"<artifactId>\s*([^<]+)\s*</artifactId>", line)
                found += re.findall(r"<groupId>\s*([^<]+)\s*</groupId>", line)
                language = "maven"

            elif filename == "build.gradle":
                found += re.findall(
                    r"(?:implementation|api|compileOnly|runtimeOnly)\s+['\"]([^'\"]+)['\"]",
                    line,
                )
                language = "maven"

            else:
                continue

            for ref in found:
                clean_ref = str(ref).strip()
                if clean_ref:
                    references.append({
                        "package_reference": clean_ref,
                        "file": rel_path,
                        "line": line_no,
                        "reference": stripped[:160],
                        "method": "import_reference",
                        "language": language,
                    })
    return references

def _normalize_npm(name):
    name = str(name or "").strip().lower()
    if name.startswith("@"):
        parts = name.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else name
    return name

def _normalize_python(name):
    return str(name or "").strip().lower().replace("-", "_").split(".")[0]

def _normalize_maven(name):
    return str(name or "").strip().lower()

def _reference_matches_package(reference, package_name, ecosystem=None):
    """Strict, language-aware matching. Never use substring/proximity matching."""
    ref = str(reference or "").strip()
    pkg = str(package_name or "").strip()
    eco = str(ecosystem or "").strip().lower()

    if not ref or not pkg:
        return False

    if eco in {"npm", "javascript", "node"}:
        refn = _normalize_npm(ref)
        pkgn = _normalize_npm(pkg)
        if refn == pkgn:
            return True
        # Subpath import: import "lodash/map" legitimately observes lodash.
        if not pkgn.startswith("@") and refn.startswith(pkgn + "/"):
            return True
        if pkgn.startswith("@") and refn.startswith(pkgn + "/"):
            return True
        return False

    if eco in {"pypi", "python"}:
        return _normalize_python(ref) == _normalize_python(pkg)

    if eco in {"maven", "java"}:
        pkgn = _normalize_maven(pkg)
        # Exact GAV artifact form.
        if ref.lower() == pkgn:
            return True
        if ":" in pkgn:
            group, artifact = pkgn.split(":", 1)
            refn = ref.lower()
            # A Java import is evidence only when it identifies the package's
            # group and artifact/module, not merely a generic group name.
            artifact_tokens = [x for x in re.split(r"[-_.]+", artifact) if len(x) >= 3]
            if group and refn.startswith(group + "."):
                return any(tok in refn.split(".") for tok in artifact_tokens)
        for alias in REACHABILITY_ALIASES.get(pkg.lower(), set()):
            if ref.lower().startswith(alias.lower()):
                return True
        return False

    return ref.lower() == pkg.lower()

def map_references_to_sbom(references, sbom):
    enriched = []
    for package in sbom:
        pkg = dict(package)
        name = pkg.get("name") or pkg.get("package") or ""
        ecosystem = pkg.get("ecosystem", "")
        def _reference_ecosystem_compatible(ref):
            language = str(ref.get("language") or "").strip().lower()
            eco = str(ecosystem or "").strip().lower()

            if not language or not eco:
                return True

            if eco in {"pypi", "python"}:
                return language in {"python", "py"}

            if eco in {"npm", "javascript", "node"}:
                return language in {"javascript", "js", "typescript", "ts", "node"}

            if eco in {"maven", "java"}:
                return language in {"java", "kotlin", "scala"}

            return True

        matches = [
            ref for ref in references
            if ref.get("method") == "import_reference"
            and _reference_ecosystem_compatible(ref)
            and _reference_matches_package(
                ref.get("package_reference"), name, ecosystem
            )
        ]

        manifest_matches = [
            ref for ref in references
            if ref.get("method") == "manifest_reference"
            and _reference_ecosystem_compatible(ref)
            and _reference_matches_package(
                ref.get("package_reference"), name, ecosystem
            )
        ]

        if matches:
            pkg["reachable"] = True
            pkg["reachability_status"] = "OBSERVED_IMPORT"
            pkg["reachability_confidence"] = 0.85
            pkg["reachability_confidence_label"] = "MEDIUM"
            pkg["reachability_method"] = "language_aware_import_match"
            pkg["reachability_evidence_type"] = "STATIC_IMPORT_REFERENCE"
            pkg["reachability_evidence"] = [
                {k: ref.get(k) for k in ("file","line","reference","method","language")}
                for ref in matches[:10]
            ]
        elif manifest_matches:
            pkg["reachable"] = False
            pkg["reachability_status"] = "MANIFEST_REFERENCED"
            pkg["reachability_confidence"] = 0.65
            pkg["reachability_confidence_label"] = "MEDIUM"
            pkg["reachability_method"] = "manifest_only"
            pkg["reachability_evidence_type"] = "STATIC_MANIFEST_DECLARATION"
            pkg["reachability_evidence"] = [
                {k: ref.get(k) for k in ("file","line","reference","method","language")}
                for ref in manifest_matches[:10]
            ]
        else:
            pkg["reachable"] = False
            pkg["reachability_status"] = "NOT_OBSERVED"
            pkg["reachability_method"] = "no_language_aware_reference_observed"
            pkg["reachability_confidence"] = 0.30
            pkg["reachability_confidence_label"] = "LOW"
            pkg["reachability_evidence_type"] = "NO_STATIC_REFERENCE_OBSERVED"
            pkg["reachability_evidence"] = []
        enriched.append(pkg)
    return enriched


def generate_reachability_summary(enriched_sbom):
    summary = {
        "total_packages": len(enriched_sbom),
        "reachable_packages": 0,
        "manifest_referenced_packages": 0,
        "not_observed_packages": 0,
        "unknown_packages": 0,
        "direct_reachable": 0,
        "transitive_reachable": 0,
    }

    for pkg in enriched_sbom:
        status = pkg.get("reachability_status")
        dep_type = str(pkg.get("dependency_type", "")).lower()

        if status in {"REACHABLE", "OBSERVED_IMPORT"}:
            summary["reachable_packages"] += 1

            if pkg.get("direct") is True or dep_type == "direct":
                summary["direct_reachable"] += 1
            elif pkg.get("direct") is False or dep_type == "transitive":
                summary["transitive_reachable"] += 1

        elif status == "MANIFEST_REFERENCED":
            summary["manifest_referenced_packages"] += 1

        elif status == "NOT_OBSERVED":
            summary["not_observed_packages"] += 1

        else:
            summary["unknown_packages"] += 1

    return summary


def _valid_vulnerability_id(value):
    text = str(value or "").strip()
    return bool(text) and text.upper() not in {"NONE", "NULL", "UNKNOWN", "N/A", "NA"}


def _has_vulnerability(pkg):
    if int(pkg.get("vulnerability_count", 0) or 0) > 0:
        return True

    for key in ["cve", "advisory_id", "primary_vulnerability_id", "source_vulnerability_id"]:
        if _valid_vulnerability_id(pkg.get(key)):
            return True

    for cve in pkg.get("cve_list") or []:
        if _valid_vulnerability_id(cve):
            return True

    for advisory in pkg.get("advisory_ids") or []:
        if _valid_vulnerability_id(advisory):
            return True

    vulns = pkg.get("vulnerabilities") or []
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue

            vid = (
                v.get("cve")
                or v.get("advisory_id")
                or v.get("id")
                or v.get("ghsa_id")
            )

            if _valid_vulnerability_id(vid):
                return True

    return False


def prioritize_reachable_vulnerabilities(enriched_sbom):
    summary = {
        "vulnerable_packages": 0,
        "reachable_vulnerable_packages": 0,
        "not_observed_vulnerable_packages": 0,
        "unknown_reachability_vulnerable_packages": 0,
    }

    for pkg in enriched_sbom:
        vulnerable = _has_vulnerability(pkg)
        status = pkg.get("reachability_status", "UNKNOWN")

        pkg["reachable_vulnerability"] = False
        pkg["reachability_priority"] = "NOT_APPLICABLE"

        if not vulnerable:
            continue

        summary["vulnerable_packages"] += 1

        if status in {"REACHABLE", "OBSERVED_IMPORT"}:
            pkg["reachable_vulnerability"] = True
            pkg["reachability_priority"] = "REACHABLE_VULNERABLE"
            summary["reachable_vulnerable_packages"] += 1

        elif status == "NOT_OBSERVED":
            pkg["reachability_priority"] = "NOT_OBSERVED_VULNERABLE"
            summary["not_observed_vulnerable_packages"] += 1

        else:
            pkg["reachability_priority"] = "UNKNOWN_REACHABILITY_VULNERABLE"
            summary["unknown_reachability_vulnerable_packages"] += 1

    return {
        "sbom": enriched_sbom,
        "reachability_vulnerability_summary": summary,
    }


def analyze_reachability(project_root, sbom):
    references = extract_source_references(project_root)
    enriched_sbom = map_references_to_sbom(references, sbom)

    priority_result = prioritize_reachable_vulnerabilities(enriched_sbom)
    enriched_sbom = priority_result.get("sbom", enriched_sbom)

    summary = generate_reachability_summary(enriched_sbom)

    return {
        "sbom": enriched_sbom,
        "reachability_summary": summary,
        "reachability_vulnerability_summary": priority_result.get(
            "reachability_vulnerability_summary",
            {},
        ),
        "reachability_references_count": len(references),
    }