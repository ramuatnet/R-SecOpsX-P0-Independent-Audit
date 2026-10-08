"""
R-SecOpsX V10 - Analysis Context V2

Purpose
-------
Classify security findings by repository analysis context.

This module is intentionally independent of the legacy
scanner.analysis_context implementation.

Security contract
-----------------
1. Findings are never removed.
2. Findings are never marked invalid merely because of path context.
3. Context classification is not credential-validity determination.
4. Primary-count policy is independent from finding preservation.
5. Evaluation evidence remains available according to configuration.
6. Repository-relative path matching is deterministic.
7. Application-specific paths belong in configuration, not Python code.

Supported contexts
------------------
production
test
fixture
mock
generated
third_party
benchmark_synthetic
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import fnmatch


DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "analysis_context.yaml"
)


DEFAULT_CONTEXT: dict[str, Any] = {
    "analysis_scope": "production",
    "context_classification": "production",
    "is_synthetic": False,
    "suppressed_from_primary_count": False,
    "preserved_for_evaluation": True,
    "preserve_findings": True,
    "preserve_evidence": True,
}


SYNTHETIC_CLASSIFICATIONS = {
    "test",
    "fixture",
    "mock",
    "benchmark_synthetic",
}


def _normalise_path(value: str | Path) -> str:
    """Return a deterministic slash-separated lower-case path."""
    text = str(value or "").replace("\\", "/").strip()

    while text.startswith("./"):
        text = text[2:]

    return text.lower()


def _load_yaml_config(config_path: Path) -> dict[str, Any]:
    """Load the configured analysis-context YAML file."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required to load analysis-context configuration."
        ) from exc

    if not config_path.is_file():
        raise FileNotFoundError(
            f"Analysis context configuration not found: {config_path}"
        )

    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(
            f"Invalid analysis context configuration: {config_path}"
        )

    return data


def load_analysis_context_config(
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Load analysis-context configuration."""
    path = (
        Path(config_path).resolve()
        if config_path is not None
        else DEFAULT_CONFIG_PATH
    )

    return _load_yaml_config(path)


def _analysis_context(config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("analysis_context", {})

    if isinstance(value, dict):
        return value

    return {}


def _enabled(config: dict[str, Any]) -> bool:
    return bool(_analysis_context(config).get("enabled", False))


def _path_rules(config: dict[str, Any]) -> dict[str, list[str]]:
    rules = _analysis_context(config).get("path_rules", {})

    if not isinstance(rules, dict):
        return {}

    result: dict[str, list[str]] = {}

    for classification, patterns in rules.items():
        if not isinstance(patterns, list):
            continue

        result[str(classification)] = [
            str(pattern)
            for pattern in patterns
            if pattern is not None
        ]

    return result


def _matches_pattern(path: str | Path, pattern: str | Path) -> bool:
    """
    Match repository-relative path against a configured glob.

    In addition to fnmatch semantics, patterns ending in /** match the
    directory itself and all descendants.
    """
    candidate = _normalise_path(path)
    configured = _normalise_path(pattern)

    if not candidate or not configured:
        return False

    if fnmatch.fnmatch(candidate, configured):
        return True

    if configured.endswith("/**"):
        prefix = configured[:-3].rstrip("/")

        if candidate == prefix:
            return True

        if candidate.startswith(prefix + "/"):
            return True

    return False


def _repository_relative_path(
    value: str | Path,
    target_root: str | Path | None = None,
) -> str:
    """
    Convert a scanner-emitted path into repository-relative form.

    Handles:
      - relative paths
      - ./relative paths
      - Windows absolute paths
      - POSIX absolute paths
      - target-name-prefixed paths
      - Windows separators
    """
    if not value:
        return ""

    text = str(value).replace("\\", "/").strip()

    if not target_root:
        return _normalise_path(text)

    try:
        root = Path(target_root).resolve()
    except Exception:
        return _normalise_path(text)

    try:
        candidate = Path(text)

        if candidate.is_absolute():
            try:
                return candidate.resolve().relative_to(root).as_posix().lower()
            except (ValueError, OSError, RuntimeError):
                pass
    except (OSError, ValueError, RuntimeError):
        pass

    root_name = root.name.replace("\\", "/").lower()
    lower = text.lower()

    prefix = root_name + "/"

    if lower.startswith(prefix):
        return lower[len(prefix):]

    return _normalise_path(text)


def _finding_path(finding: dict[str, Any]) -> str:
    """
    Extract the best available file/path field from a finding.
    """
    for key in (
        "file_path",
        "file",
        "full_path",
        "absolute_path",
        "path",
    ):
        value = finding.get(key)

        if value:
            return str(value)

    return ""


def classify_path(
    file_path: str | Path,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Classify an ordinary repository path.

    First matching configured context wins according to explicit priority.
    Production is the fallback.
    """
    if config is None:
        config = load_analysis_context_config()

    if not _enabled(config):
        return dict(DEFAULT_CONTEXT)

    path = _normalise_path(file_path)
    rules = _path_rules(config)

    priority = (
        "third_party",
        "generated",
        "fixture",
        "mock",
        "test",
    )

    for classification in priority:
        for pattern in rules.get(classification, []):
            if _matches_pattern(path, pattern):
                synthetic = classification in SYNTHETIC_CLASSIFICATIONS

                return {
                    "analysis_scope": classification,
                    "context_classification": classification,
                    "is_synthetic": synthetic,
                    "suppressed_from_primary_count": False,
                    "preserved_for_evaluation": True,
                    "preserve_findings": True,
                    "preserve_evidence": True,
                    "matched_pattern": pattern,
                }

    return dict(DEFAULT_CONTEXT)


def classify_benchmark_path(
    file_path: str | Path,
    profile: str,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Apply a configured benchmark profile.

    Benchmark policy controls primary-count treatment, but does not
    delete or invalidate findings.
    """
    if config is None:
        config = load_analysis_context_config()

    base = classify_path(file_path, config)

    context_config = _analysis_context(config)

    profiles = context_config.get("benchmark_profiles", {})

    if not isinstance(profiles, dict):
        return base

    benchmark = profiles.get(profile)

    if not isinstance(benchmark, dict):
        return base

    if not bool(benchmark.get("enabled", False)):
        return base

    synthetic_paths = benchmark.get("synthetic_paths", [])

    if not isinstance(synthetic_paths, list):
        return base

    path = _normalise_path(file_path)

    for pattern in synthetic_paths:
        pattern_text = str(pattern)

        if not _matches_pattern(path, pattern_text):
            continue

        classification = str(
            benchmark.get(
                "classification",
                "benchmark_synthetic",
            )
        )

        return {
            "analysis_scope": classification,
            "context_classification": classification,
            "is_synthetic": True,
            "suppressed_from_primary_count": bool(
                benchmark.get(
                    "suppress_from_primary_security_count",
                    False,
                )
            ),
            "preserved_for_evaluation": bool(
                benchmark.get(
                    "preserve_for_evaluation",
                    True,
                )
            ),
            "preserve_findings": bool(
                benchmark.get(
                    "preserve_findings",
                    True,
                )
            ),
            "preserve_evidence": bool(
                benchmark.get(
                    "preserve_evidence",
                    True,
                )
            ),
            "benchmark_profile": profile,
            "matched_pattern": pattern_text,
        }

    return base


def enrich_finding_context(
    finding: dict[str, Any],
    config: dict[str, Any] | None = None,
    benchmark_profile: str | None = None,
    target_root: str | Path | None = None,
) -> dict[str, Any]:
    """
    Return a copy of one finding enriched with analysis context.

    Original finding fields are retained.
    """
    if config is None:
        config = load_analysis_context_config()

    result = dict(finding)

    original_path = _finding_path(finding)

    relative_path = _repository_relative_path(
        original_path,
        target_root=target_root,
    )

    if benchmark_profile:
        context = classify_benchmark_path(
            relative_path,
            profile=benchmark_profile,
            config=config,
        )
    else:
        context = classify_path(
            relative_path,
            config=config,
        )

    result.update(context)

    result["context_path"] = relative_path
    result["context_is_not_validity"] = True

    return result


def enrich_findings_context(
    findings: list[dict[str, Any]] | None,
    config: dict[str, Any] | None = None,
    benchmark_profile: str | None = None,
    target_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """
    Enrich all findings without removing or suppressing any finding.

    Context classification is metadata only.
    """
    if findings is None:
        return []

    return [
        enrich_finding_context(
            finding,
            config=config,
            benchmark_profile=benchmark_profile,
            target_root=target_root,
        )
        for finding in findings
    ]


def classify_findings(
    findings: list[dict[str, Any]] | None,
    config: dict[str, Any] | None = None,
    benchmark_profile: str | None = None,
    target_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Alias for enrich_findings_context."""
    return enrich_findings_context(
        findings,
        config=config,
        benchmark_profile=benchmark_profile,
        target_root=target_root,
    )


def primary_count_findings(
    findings: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Return findings eligible for primary security aggregation.

    This does NOT mutate or delete the original findings.
    """
    return [
        finding
        for finding in (findings or [])
        if not bool(
            finding.get("suppressed_from_primary_count", False)
        )
    ]


def evaluation_findings(
    findings: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Return findings preserved for evaluation.

    This does NOT mutate or delete the original findings.
    """
    return [
        finding
        for finding in (findings or [])
        if bool(
            finding.get("preserved_for_evaluation", True)
        )
    ]
