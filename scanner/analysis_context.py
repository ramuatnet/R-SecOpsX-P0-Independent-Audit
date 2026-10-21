"""
R-SecOpsX V10 - Analysis Context Classification

Purpose
-------
Classify detected findings according to repository/application context.

This module DOES NOT determine whether a credential is valid, fake,
inactive, test-only, production-only, or compromised.

Context is classification evidence only.

Security contract
-----------------
1. Findings are never removed.
2. Findings are never suppressed by this module.
3. Severity is never changed.
4. Confidence is never changed.
5. Evidence is never changed.
6. Secret validity is never established from path context.
7. Test/fixture/mock/benchmark context means REVIEW CONTEXT only.
8. Configuration controls path classification.
9. Absolute scanner paths are normalized against target_root.
10. Benchmark profiles are optional and application-specific.
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


DEFAULT_CONTEXT = {
    "analysis_scope": "production",
    "context_classification": "production",
    "is_synthetic": False,
    "preserved_for_evaluation": True,
}


def _normalise_path(value: str | Path) -> str:
    """Normalize path separators and leading ./ segments."""
    text = str(value or "").replace("\\", "/").strip()

    while text.startswith("./"):
        text = text[2:]

    return text.lower()


def _context_relative_path(
    value: str | Path,
    target_root: str | Path | None = None,
) -> str:
    """
    Convert a scanner-emitted path to repository-relative form.

    Supports:
      - absolute Windows paths
      - absolute POSIX paths
      - repository-name-prefixed paths
      - ./relative paths
      - ordinary relative paths
    """
    if not value:
        return ""

    text = str(value).replace("\\", "/").strip()

    if not target_root:
        return _normalise_path(text)

    try:
        root = Path(target_root).resolve()
        candidate = Path(text)

        if candidate.is_absolute():
            try:
                return candidate.resolve().relative_to(root).as_posix().lower()
            except ValueError:
                pass

        root_name = root.name.lower()
        lower = text.lower()

        prefix = root_name + "/"

        if lower.startswith(prefix):
            return lower[len(prefix):]

        while lower.startswith("./"):
            lower = lower[2:]

        return lower

    except Exception:
        return _normalise_path(text)


def _load_yaml_config(config_path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        # PyYAML is optional repo-wide (scanner/mlbom.py, scanner/iac_models.py
        # both degrade). Enrichment is additive-only metadata and never
        # suppresses findings, so a missing PyYAML must not abort the scan:
        # degrade to an empty config (enrichment disabled). Keeps the CLI's
        # documented "stdlib-only" contract honoured by CI's bare runner.
        import logging

        logging.getLogger(__name__).debug(
            "PyYAML unavailable; skipping analysis-context enrichment for %s",
            config_path,
        )
        return {}

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
    path = (
        Path(config_path).resolve()
        if config_path is not None
        else DEFAULT_CONFIG_PATH
    )

    return _load_yaml_config(path)


def _analysis_context_section(
    config: dict[str, Any],
) -> dict[str, Any]:
    section = config.get("analysis_context", {})

    if not isinstance(section, dict):
        return {}

    return section


def _enabled(config: dict[str, Any]) -> bool:
    return bool(
        _analysis_context_section(config).get("enabled", False)
    )


def _path_rules(
    config: dict[str, Any],
) -> dict[str, list[str]]:
    context = _analysis_context_section(config)

    rules = context.get("path_rules", {})

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


def _matches_pattern(
    path: str,
    pattern: str,
) -> bool:
    path = _normalise_path(path)
    pattern = _normalise_path(pattern)

    if fnmatch.fnmatch(path, pattern):
        return True

    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")

        if path == prefix:
            return True

        if path.startswith(prefix + "/"):
            return True

    return False


def classify_path(
    file_path: str | Path,
    config: dict[str, Any] | None = None,
    target_root: str | Path | None = None,
) -> dict[str, Any]:
    """
    Classify an ordinary application path.

    Production is the fallback.

    No suppression decision is made here.
    """
    if config is None:
        config = load_analysis_context_config()

    relative_path = _context_relative_path(
        file_path,
        target_root=target_root,
    )

    if not _enabled(config):
        result = dict(DEFAULT_CONTEXT)
        result["context_path"] = relative_path
        result["context_is_not_validity"] = True
        return result

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
            if _matches_pattern(relative_path, pattern):
                return {
                    "analysis_scope": classification,
                    "context_classification": classification,
                    "is_synthetic": classification in {
                        "test",
                        "fixture",
                        "mock",
                    },
                    "preserved_for_evaluation": True,
                    "context_path": relative_path,
                    "context_is_not_validity": True,
                    "matched_pattern": pattern,
                }

    return {
        "analysis_scope": "production",
        "context_classification": "production",
        "is_synthetic": False,
        "preserved_for_evaluation": True,
        "context_path": relative_path,
        "context_is_not_validity": True,
    }


def classify_benchmark_path(
    file_path: str | Path,
    profile: str,
    config: dict[str, Any] | None = None,
    target_root: str | Path | None = None,
) -> dict[str, Any]:
    """
    Apply an optional application-specific benchmark profile.

    Benchmark classification changes context metadata only.

    It does NOT suppress findings.
    """
    if config is None:
        config = load_analysis_context_config()

    relative_path = _context_relative_path(
        file_path,
        target_root=target_root,
    )

    base = classify_path(
        relative_path,
        config=config,
    )

    context = _analysis_context_section(config)

    profiles = context.get("benchmark_profiles", {})

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

    for pattern in synthetic_paths:
        if not _matches_pattern(
            relative_path,
            str(pattern),
        ):
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
            "preserved_for_evaluation": True,
            "context_path": relative_path,
            "context_is_not_validity": True,
            "benchmark_profile": profile,
            "matched_pattern": str(pattern),
        }

    return base


def _finding_file_path(
    finding: dict[str, Any],
) -> str:
    return str(
        finding.get("file_path")
        or finding.get("file")
        or finding.get("full_path")
        or finding.get("absolute_path")
        or finding.get("path")
        or ""
    )


def enrich_finding_context(
    finding: dict[str, Any],
    config: dict[str, Any] | None = None,
    benchmark_profile: str | None = None,
    target_root: str | Path | None = None,
) -> dict[str, Any]:
    """
    Return one finding enriched with context metadata.

    The original finding is copied and never modified in-place.
    """
    if config is None:
        config = load_analysis_context_config()

    result = dict(finding)

    file_path = _finding_file_path(finding)

    if benchmark_profile:
        context = classify_benchmark_path(
            file_path,
            profile=benchmark_profile,
            config=config,
            target_root=target_root,
        )
    else:
        context = classify_path(
            file_path,
            config=config,
            target_root=target_root,
        )

    result.update(context)

    return result


def enrich_findings_context(
    findings: list[dict[str, Any]] | None,
    config: dict[str, Any] | None = None,
    benchmark_profile: str | None = None,
    target_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """
    Enrich all findings with analysis context.

    IMPORTANT:
        This function never suppresses or removes findings.
    """
    if config is None:
        config = load_analysis_context_config()

    return [
        enrich_finding_context(
            finding,
            config=config,
            benchmark_profile=benchmark_profile,
            target_root=target_root,
        )
        for finding in (findings or [])
    ]


def classify_findings(
    findings: list[dict[str, Any]] | None,
    config: dict[str, Any] | None = None,
    benchmark_profile: str | None = None,
    target_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Compatibility alias for analysis-context enrichment."""
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
    Return findings eligible for primary reporting.

    Current R-SecOpsX contract:
        ALL detected findings remain primary/reportable.

    Context classification is not a suppression mechanism.
    """
    return list(findings or [])


def evaluation_findings(
    findings: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Return findings preserved for benchmark/evaluation purposes.
    """
    return [
        finding
        for finding in (findings or [])
        if finding.get(
            "preserved_for_evaluation",
            True,
        )
    ]


def analysis_context_summary(
    findings: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """
    Produce deterministic context statistics without suppressing findings.
    """
    items = list(findings or [])

    by_context: dict[str, int] = {}

    for finding in items:
        context = str(
            finding.get(
                "context_classification",
                "production",
            )
        )

        by_context[context] = (
            by_context.get(context, 0) + 1
        )

    return {
        "total_findings": len(items),
        "primary_reportable_findings": len(
            primary_count_findings(items)
        ),
        "evaluation_findings": len(
            evaluation_findings(items)
        ),
        "synthetic_findings": sum(
            1
            for finding in items
            if finding.get("is_synthetic") is True
        ),
        "context_counts": by_context,
        "suppression_applied": False,
        "context_is_not_validity": True,
    }
