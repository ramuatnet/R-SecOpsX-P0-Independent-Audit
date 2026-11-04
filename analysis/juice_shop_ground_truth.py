"""Juice Shop benchmark ground-truth enrichment.

Conservative by design: a finding is marked DECLARED_INTENTIONAL only when the
finding evidence directly identifies a Juice Shop challenge key that exists in
data/static/challenges.yml. Absence of a direct challenge key is UNRESOLVED,
not proof of a false positive or an undeclared vulnerability.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_50
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_50

import re
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

CHALLENGE_KEY_RE = re.compile(r"(?:challenges\.)?([A-Za-z][A-Za-z0-9_]*Challenge|[A-Za-z][A-Za-z0-9_]*challenge)\b")
SOURCE_EXTENSIONS = {".ts", ".js", ".mjs", ".cjs", ".html", ".vue", ".jsx", ".tsx"}
CONTEXT_WINDOW = 120
EXPLICIT_REFERENCE_WINDOW = 160
CHALLENGE_GUARD_RE_TEMPLATE = r"(?:challengeUtils\.(?:solveIf|isChallengeEnabled)|utils\.isChallengeEnabled|isChallengeEnabled)\s*\(\s*(?:challenges\.)?{key}\b"
CATEGORY_VULN_HINTS = {
    "injection": ("injection", "nosql", "sql", "command", "eval", "template"),
    "sensitive data exposure": ("privacy", "secret", "credential", "exposure", "data_exposure"),
    "cryptographic issues": ("crypto", "weak_crypto", "md5", "sha1", "encryption"),
    "insecure deserialization": ("deserialization", "yaml", "pickle", "marshal"),
    "vulnerable components": ("dependency", "component", "supply_chain"),
    "broken anti automation": ("brute", "rate_limit", "api_abuse", "automation"),
    "broken authentication": ("auth", "login", "password", "credential"),
    "broken access control": ("idor", "access", "privilege", "path_traversal"),
    "server-side request forgery": ("ssrf", "request_forgery"),
    "xss": ("xss", "cross_site"),
    "unvalidated redirects": ("redirect",),
    "observability failures": ("log", "logging", "observability"),
    "api": ("api_", "api", "abuse"),
    "llm": ("llm", "prompt", "chatbot", "ai"),
}

JUICE_MARKERS = ("juice-shop", "juice_shop", "juice shop")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " | ".join(_text(v) for v in value[:WINDOW_50])
    if isinstance(value, dict):
        parts = []
        for k, v in value.items():
            parts.append(f"{k}: {_text(v)}")
        return " | ".join(parts)
    return str(value)


def _load_challenges(target: Path) -> tuple[dict[str, dict], str]:
    path = target / "data" / "static" / "challenges.yml"
    if not path.exists():
        return {}, "CHALLENGE_FILE_NOT_FOUND"
    if yaml is None:
        return {}, "PYAML_UNAVAILABLE"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}, "CHALLENGE_FILE_PARSE_ERROR"
    entries = raw if isinstance(raw, list) else []
    out: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if not key:
            continue
        out[key] = {
            "key": key,
            "name": item.get("name"),
            "category": item.get("category"),
            "difficulty": item.get("difficulty"),
            "tags": item.get("tags") or [],
        }
    return out, "LOADED"


def _looks_like_juice_shop(target: Path) -> bool:
    name = target.name.lower()
    if any(marker in name for marker in JUICE_MARKERS):
        return True
    return (target / "data" / "static" / "challenges.yml").exists()


def _finding_evidence(finding: dict) -> str:
    keys = (
        "title", "description", "snippet", "evidence", "taint_path",
        "attack_scenario", "rule_id", "issue_type", "issue_group",
        "occurrences", "affected_files",
    )
    return " | ".join(_text(finding.get(k)) for k in keys)


def _match_challenges(finding: dict, challenges: dict[str, dict]) -> list[dict]:
    evidence = _finding_evidence(finding)
    matches: list[dict] = []
    for key in sorted(set(CHALLENGE_KEY_RE.findall(evidence))):
        if key in challenges and _category_compatible(challenges[key], finding):
            matches.append(challenges[key])
    return matches



def _source_files(target: Path):
    # T-0.2 (task.md): the one walk's index; node_modules/dist/build are
    # shared union walk policy now.
    from core import file_index
    yield from file_index.index_for(target).files(
        exts={e.lower() for e in SOURCE_EXTENSIONS})


def _build_challenge_source_refs(target: Path, challenges: dict[str, dict]) -> dict[str, dict[str, list[int]]]:
    refs: dict[str, dict[str, list[int]]] = {k: {} for k in challenges}
    if not challenges:
        return refs
    patterns = {k: re.compile(r"\b(?:challenges\.)?" + re.escape(k) + r"\b") for k in challenges}
    for path in _source_files(target):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for key, pat in patterns.items():
            hits = [i + 1 for i, line in enumerate(lines) if pat.search(line)]
            if hits:
                refs[key][str(path)] = hits
    return refs


def _category_compatible(challenge: dict, finding: dict) -> bool:
    category = str(challenge.get("category") or "").lower()
    text = " ".join(str(finding.get(k) or "") for k in ("vuln_type", "rule_id", "title", "issue_type", "issue_group")).lower()
    hints = ()
    for cat, vals in CATEGORY_VULN_HINTS.items():
        if cat in category:
            hints = vals
            break
    if not hints:
        return False
    return any(h in text for h in hints)


def _resolve_finding_source_path(finding: dict, target: Path) -> Path | None:
    candidates = []
    for k in ("file", "file_path", "full_path"):
        v = str(finding.get(k) or "").strip()
        if v:
            candidates.append(Path(v))
    for raw in candidates:
        try:
            if raw.exists() and raw.is_file():
                return raw
        except Exception:
            pass
        # Normalize a target-relative suffix from Windows/Unix report paths.
        norm = str(raw).replace("\\", "/")
        target_norm = str(target).replace("\\", "/").rstrip("/")
        marker = target.name.replace("\\", "/")
        idx = norm.lower().find(marker.lower())
        if idx >= 0:
            suffix = norm[idx + len(marker):].lstrip("/")
            candidate = target / suffix
            if candidate.is_file():
                return candidate
        candidate = target / Path(norm).name
        if candidate.is_file():
            return candidate
    return None


def _source_block_context(lines: list[str], line: int, max_lines: int = 500) -> str:
    """Return a bounded lexical block around the finding line.

    JavaScript/TypeScript challenge guards are often placed later in the same
    route/callback as the vulnerable statement. A fixed +/-160 line window can
    miss that relationship. This helper uses lightweight brace depth to locate
    the enclosing block and caps the scan size.
    """
    if not lines:
        return ""
    idx = max(0, min(len(lines) - 1, (line or 1) - 1))

    def delta(segment: str) -> int:
        # This is deliberately lightweight; source snippets are only used as
        # evidence context, not parsed as executable code.
        return segment.count("{") - segment.count("}")

    # Depth at the finding line.
    depth = 0
    for i in range(idx + 1):
        depth += delta(lines[i])
    target_depth = max(depth, 0)

    lo = idx
    running = depth
    # Walk backwards until the block depth drops below the finding depth.
    for i in range(idx - 1, max(-1, idx - max_lines), -1):
        running -= delta(lines[i + 1])
        if running < target_depth:
            lo = i + 1
            break
        lo = i

    hi = idx
    running = depth
    for i in range(idx + 1, min(len(lines), idx + max_lines)):
        running += delta(lines[i])
        hi = i
        if running < target_depth:
            break

    return "\n".join(lines[lo:hi + 1])


def _explicit_source_challenge_matches(finding: dict, target: Path, challenges: dict[str, dict]) -> list[dict]:
    """Resolve an explicit challenge reference in the actual finding source file.

    This is stronger than filename proximity: the source must reference the
    declared challenge key in an explicit challenge guard/reference near the
    finding location, and the challenge category must match the finding.
    """
    source = _resolve_finding_source_path(finding, target)
    if source is None:
        return []
    try:
        lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    try:
        line = int(finding.get("line") or 0)
    except Exception:
        line = 0
    lo = max(1, line - EXPLICIT_REFERENCE_WINDOW) if line else 1
    hi = min(len(lines), line + EXPLICIT_REFERENCE_WINDOW) if line else len(lines)
    block = "\n".join(lines[lo-1:hi])
    # If the fixed window misses a guard that is later in the same handler,
    # expand only to the enclosing lexical block, never to the whole file.
    block_context = _source_block_context(lines, line, max_lines=500)
    search_blocks = [block]
    if block_context and block_context != block:
        search_blocks.append(block_context)
    out = []
    for key, challenge in challenges.items():
        ref_re = re.compile(r"\b(?:challenges\.)?" + re.escape(key) + r"\b")
        guard_re = re.compile(CHALLENGE_GUARD_RE_TEMPLATE.format(key=re.escape(key)), re.I)
        matched_block = next(
            (candidate for candidate in search_blocks if ref_re.search(candidate) and guard_re.search(candidate)),
            None,
        )
        if matched_block is None:
            continue
        if _category_compatible(challenge, finding):
            out.append(challenge)
    return out


def _contextual_matches(finding: dict, target: Path, challenges: dict[str, dict], refs: dict[str, dict[str, list[int]]]) -> list[dict]:
    file_value = str(finding.get("file") or finding.get("file_path") or finding.get("full_path") or "")
    if not file_value:
        return []
    file_name = Path(file_value.replace("\\", "/")).name
    try:
        line = int(finding.get("line") or 0)
    except Exception:
        line = 0
    matches = []
    for key, files in refs.items():
        for path_str, hits in files.items():
            if Path(path_str).name != file_name:
                continue
            if line and not any(abs(line - h) <= CONTEXT_WINDOW for h in hits):
                continue
            ch = challenges[key]
            if _category_compatible(ch, finding):
                matches.append(ch)
                break
    return matches


def enrich_juice_shop_ground_truth(payload: dict, target: str | Path) -> dict:
    """Enrich a report with conservative Juice Shop challenge ground truth."""
    target_path = Path(target).resolve()
    if not _looks_like_juice_shop(target_path):
        return payload

    challenges, load_status = _load_challenges(target_path)
    meta = payload.setdefault("metadata", {})
    summary = {
        "dataset": "OWASP_JUICE_SHOP",
        "target_version": "20.2.0" if "20.2.0" in str(target_path) else "UNKNOWN",
        "ground_truth_source": "data/static/challenges.yml",
        "ground_truth_source_status": load_status,
        "challenge_inventory_count": len(challenges),
        "method": "DIRECT_CHALLENGE_KEY_OR_EXPLICIT_SOURCE_REFERENCE_V3_OR_CONTEXT_V2",
        "declared_intentional_findings": 0,
        "undeclared_findings": 0,
        "unresolved_findings": 0,
        "adjudication_required": 0,
        "classification_complete": False,
    }

    findings = payload.get("findings") or []
    source_refs = _build_challenge_source_refs(target_path, challenges)
    covered: set[str] = set()
    basis_counts: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        matches = _match_challenges(finding, challenges)
        matching_basis = "DIRECT_CHALLENGE_KEY_EVIDENCE"
        if not matches:
            matches = _explicit_source_challenge_matches(finding, target_path, challenges)
            if matches:
                matching_basis = "EXPLICIT_SOURCE_CHALLENGE_REFERENCE_V3"
        if not matches:
            matches = _contextual_matches(finding, target_path, challenges, source_refs)
            if matches:
                matching_basis = "SOURCE_CONTEXT_CHALLENGE_REFERENCE_V2"
        if matches:
            primary = matches[0]
            gt = {
                "dataset": "OWASP_JUICE_SHOP",
                "status": "DECLARED_INTENTIONAL",
                "requires_adjudication": False,
                "challenge_key": primary["key"],
                "challenge_name": primary.get("name"),
                "challenge_category": primary.get("category"),
                "challenge_difficulty": primary.get("difficulty"),
                "challenge_tags": primary.get("tags") or [],
                "matched_challenge_count": len(matches),
                "ground_truth_source": "data/static/challenges.yml",
                "matching_basis": matching_basis,
            }
            covered.add(primary["key"])
            basis_counts[matching_basis] = basis_counts.get(matching_basis, 0) + 1
            summary["declared_intentional_findings"] += 1
        else:
            gt = {
                "dataset": "OWASP_JUICE_SHOP",
                "status": "UNRESOLVED",
                "requires_adjudication": True,
                "challenge_key": None,
                "challenge_name": None,
                "challenge_category": None,
                "ground_truth_source": "data/static/challenges.yml",
                "matching_basis": "NO_DIRECT_CHALLENGE_KEY_EVIDENCE",
            }
            summary["unresolved_findings"] += 1
            summary["adjudication_required"] += 1
        finding["benchmark_ground_truth"] = gt

    # No finding is called UNDECLARED solely because it failed to match a key.
    # UNDECLARED is reserved for future/manual adjudication evidence.
    summary["undeclared_findings"] = 0
    summary["classification_complete"] = True

    # ------------------------------------------------------------------
    # Reverse direction: challenge -> finding coverage.
    #
    # The forward direction alone reports "15 declared-intentional findings,
    # 1275 unresolved" with no denominator, which reads like a pass. With
    # ground truth loaded before the scan we also know how many of the
    # inventory's challenges received no mapped finding at all, which is the
    # only way recall can be stated.
    #
    # `challenges_missed` means "no finding matched this challenge under the
    # declared matching method". It is NOT evidence that the challenge is
    # absent or secure; it is a coverage measurement of this scanner against
    # a declared ground-truth inventory.
    # ------------------------------------------------------------------
    challenge_keys = sorted(challenges)
    missed = [k for k in challenge_keys if k not in covered]
    summary["challenges_total"] = len(challenge_keys)
    summary["challenges_covered_count"] = len(covered)
    summary["challenges_covered"] = sorted(covered)
    summary["challenges_missed_count"] = len(missed)
    summary["challenges_missed"] = missed
    summary["challenge_recall"] = (
        round(len(covered) / len(challenge_keys), 4) if challenge_keys else 0.0
    )
    summary["matching_basis_counts"] = dict(sorted(basis_counts.items()))
    summary["challenge_coverage_status"] = (
        "COMPLETE"
        if challenge_keys and not missed
        else "PARTIAL" if covered else "NONE"
    )
    summary["coverage_caveat"] = (
        "CHALLENGE_RECALL_MEASURES_SCANNER_COVERAGE_AGAINST_A_DECLARED_INVENTORY; "
        "A_MISSED_CHALLENGE_IS_NOT_PROOF_OF_ABSENCE_OR_OF_A_FALSE_NEGATIVE"
    )

    meta["benchmark_ground_truth_status"] = "JUICE_SHOP_GROUND_TRUTH_ENRICHED"
    meta["benchmark_ground_truth"] = summary
    return payload
