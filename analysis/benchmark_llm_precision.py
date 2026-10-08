from __future__ import annotations

import sys
import time
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# IMPORTANT:
# The benchmark must use the same production LLM scanner as main.py.
from scanner.llm_security import scan_llm_file

from scanner.llm_context_precision import classify_findings


TARGET = Path(
    r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64"
)

SCAN_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".php", ".rb", ".cs",
    ".yml", ".yaml", ".json", ".txt", ".md",
    ".sh", ".ps1", ".bat",
}

SKIP_NAMES = {
    "readme.md",
    "license.md",
    "changelog.md",
}

SKIP_PARTS = {
    "docs",
    "documentation",
    "examples",
    "tests",
    "test",
}


def _skip_path(path: Path) -> bool:
    """
    Reproduce the production LLM scan scope as closely as possible.

    main.py uses its centralized _skip() before the LLM-specific exclusions.
    We import that policy directly instead of duplicating its implementation.
    """
    try:
        from main import _skip
        return bool(_skip(path))
    except Exception:
        # Safe fallback for standalone benchmark execution.
        return False


def _should_scan(path: Path) -> bool:
    if not path.is_file():
        return False

    # Same centralized production exclusion policy.
    if _skip_path(path):
        return False

    if path.suffix.lower() not in SCAN_EXT:
        return False

    name = path.name.lower()
    parts = {p.lower() for p in path.parts}

    if name in SKIP_NAMES:
        return False

    if name.startswith("expected_"):
        return False

    if "_expected" in name:
        return False

    if name.endswith("_expected.json"):
        return False

    if parts.intersection(SKIP_PARTS):
        return False

    return True


def main() -> None:
    print("=" * 72)
    print("R-SecOpsX LLM CONTEXT PRECISION BENCHMARK")
    print("=" * 72)

    files: list[tuple[str, str]] = []
    file_cache: dict[str, str] = {}

    # ------------------------------------------------------------
    # File selection
    # ------------------------------------------------------------
    for p in TARGET.rglob("*"):
        if not _should_scan(p):
            continue

        try:
            content = p.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except Exception:
            continue

        path = str(p)

        files.append((path, content))
        file_cache[path] = content

    print(f"Scanner-scope files: {len(files)}")

    # ------------------------------------------------------------
    # Raw production-equivalent LLM scan
    # ------------------------------------------------------------
    t0 = time.time()

    raw: list[dict] = []

    for filepath, content in files:
        try:
            raw.extend(
                scan_llm_file(
                    filepath,
                    content,
                )
            )
        except Exception:
            continue

    t_raw = time.time()

    # ------------------------------------------------------------
    # Context precision classification
    # ------------------------------------------------------------
    classified = classify_findings(
        raw,
        file_cache,
    )

    actionable = [
        x for x in classified
        if x.get("actionable") is True
    ]

    contextual = [
        x for x in classified
        if x.get("actionable") is not True
    ]

    print()
    print(f"Raw LLM findings:       {len(raw)}")
    print(f"Actionable candidates:  {len(actionable)}")
    print(f"Contextual/non-action:  {len(contextual)}")
    print(f"Raw scan seconds:       {t_raw - t0:.2f}")
    print(f"Total seconds:          {time.time() - t0:.2f}")

    # ------------------------------------------------------------
    # Context / relevance distribution
    # ------------------------------------------------------------
    print()
    print("Context / relevance distribution:")

    dist = Counter(
        x.get("security_relevance", "UNKNOWN")
        for x in classified
    )

    for key, count in dist.most_common():
        print(f"  {key:<30} {count}")

    # ------------------------------------------------------------
    # Context class distribution
    # ------------------------------------------------------------
    print()
    print("Context class distribution:")

    ctx = Counter(
        x.get("context_class", "UNKNOWN")
        for x in classified
    )

    for key, count in ctx.most_common():
        print(f"  {key:<30} {count}")

    # ------------------------------------------------------------
    # Rule distribution
    # ------------------------------------------------------------
    print()
    print("Rule distribution AFTER precision filtering:")

    rules = Counter(
        x.get("rule_id", "UNKNOWN")
        for x in actionable
    )

    for key, count in rules.most_common():
        print(f"  {key:<50} {count}")

    # ------------------------------------------------------------
    # Actionable findings
    # ------------------------------------------------------------
    print()
    print("Actionable candidates:")
    print("-" * 72)

    for i, finding in enumerate(actionable, 1):
        print(
            f"{i:3}. "
            f"{finding.get('rule_id', ''):45} "
            f"{finding.get('file', '')}:{finding.get('line', '')}"
        )

        print(
            f"     {finding.get('snippet', '')[:180]}"
        )


if __name__ == "__main__":
    main()