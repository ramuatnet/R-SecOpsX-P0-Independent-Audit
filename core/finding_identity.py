"""B3-ID stable finding identity (Phase A).

Contract: audit_output/B3_ID_PHASE_A_IMPLEMENTATION_CONTRACT.md @ aa4e2be.
Strictly additive: legacy ``fingerprint`` / ``root_key`` / ``group_key`` and
the SARIF ``primaryLocationLineHash`` formulas are NOT modified here -- the
only new finding field is ``finding_uid``.

UID (contract §"UID specification (exact)")::

    finding_uid = "b3id1-" + sha256(UTF8(
        "b3id/v1|{engine}|{rule_id}|{canonical_path}|{code_digest}|{ordinal}"
    ))[:32]

Design properties (all oracle-pinned in tests/test_finding_identity.py):
- deterministic: no random values, timestamps, worker ids or arrival info;
- line-shift stable: the line number is a LOCATION, never an identity input;
- rule preserving: rule identity (rule_id -> vuln_type -> title -> UNRULED)
  is a mandatory token component;
- instance preserving: identical duplicate code is separated by a
  deterministic ordinal, anchored to sorted (line, raw snippet) position --
  indistinguishable duplicates carry no other stable distinguishing
  information, and none is promised;
- CWD- and mount-independent: paths are canonically relativized against the
  scan target root, never against the process working directory;
- whitespace carries no identity (contract N6/L1 disclosed conflation class).
"""
from __future__ import annotations

import hashlib
import os
import re

UID_NAMESPACE = "b3id/v1"
UID_PREFIX = "b3id1-"
UID_RE = re.compile(r"^b3id1-[0-9a-f]{32}$")

_WS = re.compile(r"\s+")

# rule identity fallback chain (contract: first non-empty, else UNRULED)
_RULE_KEYS = ("rule_id", "vuln_type", "title")


def normalize_code(snippet: str) -> str:
    """Contract §2 whitespace policy v1: CRLF/CR -> LF, then REMOVE ALL
    whitespace. Case preserved; quoted strings, URLs, file paths, command
    arguments and SQL fragments are kept verbatim (the deduplicator.normalize
    STR-substitution defect is deliberately not repeated)."""
    s = str(snippet or "").replace("\r\n", "\n").replace("\r", "\n")
    return _WS.sub("", s)


def code_digest(snippet: str) -> str:
    """Full 64-hex SHA-256 over the normalized matched span."""
    return hashlib.sha256(normalize_code(snippet).encode("utf-8")).hexdigest()


def canonical_path(file_str: str, target_root: str) -> str:
    """Contract §3 canonical path.

    Separators unified first ("\\\" -> "/"), lexically normalized, casefolded
    on both sides, then relativized under ``target_root``. Paths outside the
    root keep their absolute POSIX form (no rename tolerance, symlinks are
    NOT resolved -- lexical only). Never touches the process CWD.
    """
    fwd = str(file_str or "").replace("\\", "/")
    root = os.path.normpath(
        str(target_root or "").replace("\\", "/")).replace("\\", "/").casefold().rstrip("/")
    p = os.path.normpath(fwd).replace("\\", "/").casefold().rstrip("/")
    if p == root:
        rel = ""
    elif root and p.startswith(root + "/"):
        rel = p[len(root) + 1:]
    else:
        rel = p  # outside root: lexical absolute fallback
    return rel


def rule_fallback(finding: dict) -> str:
    for key in _RULE_KEYS:
        value = finding.get(key)
        if value not in (None, ""):
            return str(value)
    return "UNRULED"


def engine_field(finding: dict) -> str:
    return str(finding.get("engine") or "unknown")


def id_fields(finding: dict, target_root: str) -> dict:
    """The four identity inputs (ordinal is assigned later, per group)."""
    return {
        "engine": engine_field(finding),
        "rule": rule_fallback(finding),
        "cp": canonical_path(str(finding.get("file") or ""), target_root),
        "dg": code_digest(str(finding.get("snippet") or "")),
    }


def _assert_token_safe(name: str, value: str) -> None:
    # contract L9: "|" is the reserved separator; fields are asserted free of
    # it so the token stays unambiguous (loud rejection, never silent).
    if "|" in value:
        raise ValueError(
            f"B3-ID: {name} contains the reserved separator '|': {value!r}")


def uid_for(engine: str, rule: str, cp: str, dg: str, ordinal: int) -> str:
    _assert_token_safe("engine", engine)
    _assert_token_safe("rule", rule)
    _assert_token_safe("canonical_path", cp)
    token = f"{UID_NAMESPACE}|{engine}|{rule}|{cp}|{dg}|{int(ordinal)}"
    uid = UID_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]
    if not UID_RE.match(uid):  # defensive; unreachable by construction
        raise ValueError(f"B3-ID: uid {uid!r} violates the pinned format")
    return uid


def assign_uids(findings: list, target_root: str) -> list:
    """Attach ``finding_uid`` to every finding; add NOTHING else and change
    NOTHING else (additive contract).

    Ordinal: 0-based index within the (engine, rule, canonical_path,
    code_digest) group, members ordered by (line, raw snippet) -- the group
    ordering is deterministic because deduplicate() has already collapsed
    same-(vuln_type, file, line) duplicates, so lines are unique inside a
    same-rule group; the raw-snippet tie-break is normative belt-and-braces.
    """
    groups: dict = {}
    for f in findings:
        flds = id_fields(f, target_root)
        try:
            line = int(f.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        key = (flds["engine"], flds["rule"], flds["cp"], flds["dg"])
        groups.setdefault(key, []).append((line, str(f.get("snippet") or ""), f))
    for members in groups.values():
        members.sort(key=lambda t: (t[0], t[1]))
        for ordinal, (_line, _snip, f) in enumerate(members):
            flds = id_fields(f, target_root)
            f["finding_uid"] = uid_for(
                flds["engine"], flds["rule"], flds["cp"], flds["dg"], ordinal)
    return findings


def sort_key(finding: dict, target_root: str) -> tuple:
    """Contract §4 ordering key (applied at S1, S2, and post-UID).

    AMENDMENT (tests-first discovery, disclosed): the key is
    (canonical_path, line) applied as a STABLE sort. The contract's draft
    full key (cp, rule, line, engine, digest, snippet) re-ordered same-line
    multi-rule findings WITHIN a file and flipped previously-DETERMINISTIC
    scan-order dedup winners (measured: corpus php-vulnerable.php:27
    PHP_PATH_USER_INPUT_VAR lost to PHP_INCLUDE_CONCAT_PATH), violating the
    contract's own §7 invariant "sorting does not change deduplication
    semantics". The only real nondeterminism in the pipeline is the
    cross-file as_completed interleave; keying on (canonical_path, line)
    removes exactly that while Python's stable sort preserves the engine's
    authoritative intra-file scan order. Determinism across repeat scans,
    worker counts, thread arrival and CWD is unaffected.
    """
    try:
        line = int(finding.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    return (
        canonical_path(str(finding.get("file") or ""), target_root),
        line,
    )


def sorted_canonically(findings: list, target_root: str) -> list:
    """Deterministic copy (S2). Reorder only -- membership unchanged, and
    intra-(path, line) order preserved (stable sort)."""
    return sorted(findings, key=lambda f: sort_key(f, target_root))


def sort_in_place(findings: list, target_root: str) -> None:
    """Deterministic in-place order (S1). Reorder only -- membership
    unchanged, intra-(path, line) order preserved (stable sort)."""
    findings.sort(key=lambda f: sort_key(f, target_root))
