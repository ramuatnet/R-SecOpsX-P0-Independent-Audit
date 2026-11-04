"""T-5.5: SAST<->DAST correlation -- same route + same sink, one merged row.

The differentiator: static and dynamic engines agree on a route AND a
sink class, their overlapping findings collapse into a single correlated
row with boosted confidence, instead of two half-truths the user has to
join by hand.

Contract (additive by construction):
  * SAST finding rows and DAST finding rows are READ-ONLY inputs; the
    output is a new ``rsecopsx.correlated_findings/v1`` document.
  * A sink-matched pair that cannot be route-linked is ANNOTATED in
    ``candidates`` with the machine-readable reason
    ``route_not_linked`` -- never silently dropped (ground rule 2).
  * Judgements are explainable: every merged row carries a human
    sentence plus the linkage strategy that produced it.

Linkage strategies (first hit wins, recorded per row):
  ``route_file``      the SAST finding's file declares the DAST route in
                      the API-BOM (scanner.apibom).  Route comparison is
                      param-name-insensitive and treats either side's
                      ``{param}`` token as matching a concrete segment,
                      so ``/users/{user_id}`` == ``/users/42``.
  ``path_segments``   structural fallback when no API-BOM item exists
                      (aiohttp, raw PHP, modular Express routers whose
                      mount prefixes are not composed -- disclosed):
                      the route's last non-generic segment, or at least
                      two of its non-generic segments, appear among the
                      finding file's path segments.  This is what links
                      DVWA's ``vulnerabilities/sqli/source/high.php`` to
                      ``GET /vulnerabilities/sqli`` and juice-shop's
                      ``routes/search.ts`` to ``GET /rest/products/search``.

Sink matching is CWE-first with vuln_type as a secondary signal
(``SINK_CLASS_BY_CHECK``); checks with no static counterpart (tls,
rate limiting) still participate -- their pairs just never route-link
and land in ``candidates``.

Offline by construction: no sockets, no filesystem access, no scan-time
ML.  The CLI reads JSON artifacts; main.py wires the pipeline opt-in so
a flag-off scan stays byte-identical (parity-first).
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_4
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_4

import argparse
import json
import re
from pathlib import Path
from typing import Optional

from analysis.dast.model import normalize_path

CORRELATE_SCHEMA = "rsecopsx.correlated_findings/v1"

# Input artifacts larger than this are refused (resource bound for
# untrusted input; same ceiling as analysis.dast.checks).
MAX_INPUT_BYTES = 64 * 1024 * 1024

# DAST confidence -> boosted confidence when a static finding agrees on
# the same route and sink.  Unknown values pass through unboosted.
CONFIDENCE_BOOST = {
    "tentative": "likely",
    "likely": "confirmed",
    "confirmed": "confirmed",
}

# Sink class per active check: the CWEs and SAST vuln_types that denote
# the SAME sink family.  Every registered check is listed (enforced by
# test) so no family is silently unmapped.
SINK_CLASS_BY_CHECK: dict[str, dict] = {
    "dast.security_headers": {"cwes": frozenset({"CWE-693"}),
                              "vuln_types": frozenset({"security_headers"})},
    "dast.cors": {"cwes": frozenset({"CWE-942"}),
                  "vuln_types": frozenset({"cors_misconfiguration"})},
    "dast.jwt_weaknesses": {"cwes": frozenset({"CWE-347"}),
                            "vuln_types": frozenset({"jwt_weakness",
                                                     "jwt_none_algorithm"})},
    "dast.rate_limit": {"cwes": frozenset({"CWE-770"}),
                        "vuln_types": frozenset({"missing_rate_limit"})},
    "dast.sqli": {"cwes": frozenset({"CWE-89"}),
                  "vuln_types": frozenset({"sql_injection", "orm_injection"})},
    "dast.xss_reflected": {"cwes": frozenset({"CWE-79"}),
                           "vuln_types": frozenset({"xss",
                                                    "reflected_xss"})},
    "dast.lfi": {"cwes": frozenset({"CWE-22"}),
                 "vuln_types": frozenset({"path_traversal", "lfi"})},
    "dast.cmdi": {"cwes": frozenset({"CWE-78"}),
                  "vuln_types": frozenset({"command_injection",
                                           "os_command_injection"})},
    "dast.ssti": {"cwes": frozenset({"CWE-1336"}),
                  "vuln_types": frozenset({"ssti", "template_injection"})},
    "dast.open_redirect": {"cwes": frozenset({"CWE-601"}),
                           "vuln_types": frozenset({"open_redirect"})},
    "dast.ssrf": {"cwes": frozenset({"CWE-918"}),
                  "vuln_types": frozenset({"ssrf"})},
    "dast.deser": {"cwes": frozenset({"CWE-502"}),
                   "vuln_types": frozenset({"deserialization",
                                            "insecure_deserialization"})},
    "dast.xxe": {"cwes": frozenset({"CWE-611"}),
                 "vuln_types": frozenset({"xxe"})},
    "dast.idor": {"cwes": frozenset({"CWE-639"}),
                  "vuln_types": frozenset({"idor",
                                           "broken_object_level_auth"})},
    "dast.mass_assignment": {"cwes": frozenset({"CWE-915"}),
                             "vuln_types": frozenset({"mass_assignment",
                                                      "overposting"})},
    # Runtime-only signal: no taint/regex rule emits CWE-295 as a code
    # sink; pairs from user-supplied rows are annotated, never merged
    # (route_key is the ``*`` host sentinel and cannot route-link).
    "dast.tls_grade": {"cwes": frozenset({"CWE-295"}),
                       "vuln_types": frozenset({"tls_bypass",
                                                "certificate_validation"})},
}

# Route segments that carry no handler identity (mount prefixes, CDNs);
# dropped before path_segments matching so /rest/products/search tests
# "products|search", not "rest".
_GENERIC_ROUTE_SEGMENTS = frozenset({
    "api", "rest", "www", "public", "static", "assets",
    "v1", "v2", "v3", "v4", "v", "ver", "version",
})

# File-path directories that are packaging, not route identity
# (routes/search.ts must match on "search", not on "routes").
_GENERIC_FILE_SEGMENTS = frozenset({
    "routes", "route", "controllers", "controller", "views", "view",
    "handlers", "handler", "pages", "page", "src", "app", "lib", "libs",
    "utils", "helpers", "components", "component", "modules", "module",
    "tests", "test", "specs", "spec", "docs", "doc", "static", "assets",
    "public", "www",
})

_EXT_RE = re.compile(r"\.[A-Za-z0-9]+$")


def _norm_cwe(cwe) -> str:
    """``'89' | 'cwe-89' | 'CWE-89'`` -> ``'CWE-89'``; empty -> ``''``."""
    s = str(cwe or "").strip()
    if not s:
        return ""
    if s.isdigit():
        return f"CWE-{s}"
    if s.upper().startswith("CWE-"):
        return "CWE-" + s[WINDOW_4:].strip()
    return s.upper()


def _route_path(route_key) -> str:
    """``'GET /users'`` -> ``'/users'``; ``'*'`` stays ``'*'``."""
    s = str(route_key or "").strip()
    if not s or s == "*":
        return s
    if " " in s:
        return s.split(" ", 1)[1].strip() or "/"
    return s


def _path_segments(path: str) -> list[str]:
    return [s for s in str(path or "").split("/") if s]


def _norm_file(file) -> str:
    return str(file or "").replace("\\", "/").strip().lower()


def _file_segments(file) -> list[str]:
    """Lowercased posix segments of a finding file, final extension off.

    ``vulnerabilities/Sqli/source/high.php`` ->
    ``['vulnerabilities', 'sqli', 'source', 'high']``.
    """
    segs = [s for s in _norm_file(file).split("/") if s]
    if segs:
        segs[-1] = _EXT_RE.sub("", segs[-1])
    return segs


def _route_identity_segments(path: str) -> list[str]:
    """Non-param, non-generic segments of a route path."""
    out = []
    for seg in _path_segments(path):
        if seg.startswith("{") and seg.endswith("}"):
            continue                       # parameter token
        low = seg.lower()
        if low in _GENERIC_ROUTE_SEGMENTS:
            continue
        out.append(low)
    return out


def _paths_shape_match(a: str, b: str) -> bool:
    """Same segment count; equal literals; a ``{param}`` matches anything.

    Param NAMES never matter: ``/users/{user_id}`` == ``/users/{id}`` ==
    ``/users/42``.  ``*`` (host-level sentinel) never matches.
    """
    pa, pb = normalize_path(a), normalize_path(b)
    if pa == "*" or pb == "*" or pa == pb:
        return pa == pb and pa != "*"
    sa, sb = _path_segments(pa), _path_segments(pb)
    if len(sa) != len(sb):
        return False
    for x, y in zip(sa, sb):
        if x == y:
            continue
        if (x.startswith("{") and x.endswith("}")) or \
                (y.startswith("{") and y.endswith("}")):
            continue
        return False
    return True


def build_route_index(apibom_items: Optional[list]) -> list[dict]:
    """``[{file, route, methods}]`` from API-BOM items (read-only copy)."""
    index = []
    for item in apibom_items or []:
        file = _norm_file(item.get("file"))
        route = str(item.get("route") or "").strip()
        if not file or not route:
            continue
        methods = [str(m).upper() for m in (item.get("methods") or [])]
        index.append({"file": file, "route": route, "methods": methods})
    return index


def _method_compatible(methods: list[str], dast_method: str) -> bool:
    if not methods or "UNKNOWN" in methods:
        return True                          # wildcard
    return str(dast_method or "GET").upper() in methods


def route_linkage(sast_f: dict, dast_f: dict, route_index: list[dict]
                  ) -> Optional[str]:
    """Best linkage strategy for this pair, or None when not route-linked."""
    file = _norm_file(sast_f.get("file"))
    path = _route_path(dast_f.get("route_key"))
    if not file or not path or path == "*":
        return None

    # 1) route_file: the finding's file declares this exact route.
    for item in route_index:
        if item["file"] != file:
            continue
        if not _paths_shape_match(item["route"], path):
            continue
        if not _method_compatible(item["methods"], dast_f.get("method") or "GET"):
            continue
        return "route_file"

    # 2) path_segments: structural fallback (no API-BOM coverage).
    route_segs = _route_identity_segments(path)
    if not route_segs:
        return None
    file_segs = set(_file_segments(file))
    if route_segs[-1] in file_segs:
        return "path_segments"
    if sum(1 for s in route_segs if s in file_segs) >= 2:
        return "path_segments"
    return None


def _sink_match(sast_f: dict, sink: dict) -> str:
    """``'cwe' | 'vuln_type' | ''`` -- how (if at all) this row matches."""
    if _norm_cwe(sast_f.get("cwe")) in sink["cwes"]:
        return "cwe"
    if str(sast_f.get("vuln_type") or "") in sink["vuln_types"]:
        return "vuln_type"
    return ""


def _identity(f: dict) -> tuple:
    return (str(f.get("finding_id") or ""),
            str(f.get("file") or "").replace("\\", "/").lower(),
            int(f.get("line") or 0),
            str(f.get("rule_id") or ""))


def _sast_ref(f: dict) -> dict:
    return {"finding_id": str(f.get("finding_id") or ""),
            "rule_id": str(f.get("rule_id") or ""),
            "title": str(f.get("title") or ""),
            "vuln_type": str(f.get("vuln_type") or ""),
            "file": str(f.get("file") or ""),
            "line": int(f.get("line") or 0),
            "cwe": _norm_cwe(f.get("cwe"))}


def _dast_ref(f: dict) -> dict:
    evidence = f.get("evidence") or {}
    return {"check": str(f.get("check") or ""),
            "confidence": str(f.get("confidence") or ""),
            "method": str(f.get("method") or ""),
            "route_key": str(f.get("route_key") or ""),
            "evidence_keys": sorted(str(k) for k in evidence)}


def correlate(sast_findings: Optional[list], dast_findings: Optional[list],
              *, apibom_items: Optional[list] = None) -> dict:
    """Collapse same-route + same-sink SAST/DAST pairs into merged rows.

    Pure and deterministic; neither input list is mutated.
    """
    sast_rows = list(sast_findings or [])
    dast_rows = list(dast_findings or [])
    route_index = build_route_index(apibom_items)

    by_cwe: dict[str, list] = {}
    by_vt: dict[str, list] = {}
    for sf in sast_rows:
        cwe = _norm_cwe(sf.get("cwe"))
        if cwe:
            by_cwe.setdefault(cwe, []).append(sf)
        vt = str(sf.get("vuln_type") or "")
        if vt:
            by_vt.setdefault(vt, []).append(sf)

    merged: list[dict] = []
    candidates: list[dict] = []
    sink_matched = 0
    by_check: dict[str, int] = {}
    by_linkage: dict[str, int] = {}
    unmapped: set[str] = set()

    for df in dast_rows:
        check = str(df.get("check") or "")
        sink = SINK_CLASS_BY_CHECK.get(check)
        if sink is None:
            if check:
                unmapped.add(check)
            continue
        pairs: list[tuple[dict, str]] = []
        seen: set[tuple] = set()
        for cwe in sorted(sink["cwes"]):
            for sf in by_cwe.get(cwe, []):
                ident = _identity(sf)
                if ident not in seen:
                    seen.add(ident)
                    pairs.append((sf, "cwe"))
        for vt in sorted(sink["vuln_types"]):
            for sf in by_vt.get(vt, []):
                ident = _identity(sf)
                if ident not in seen:
                    seen.add(ident)
                    pairs.append((sf, "vuln_type"))

        for sf, matched_on in pairs:
            sink_matched += 1
            linkage = route_linkage(sf, df, route_index)
            if linkage is None:
                candidates.append({
                    "sast": _sast_ref(sf),
                    "dast": _dast_ref(df),
                    "sink": {"matched_on": matched_on,
                             "cwe": _norm_cwe(sf.get("cwe"))},
                    "reason": "route_not_linked",
                })
                continue
            before = str(df.get("confidence") or "")
            after = CONFIDENCE_BOOST.get(before, before)
            merged.append({
                "correlation_id": "",          # assigned after sorting
                "route_key": str(df.get("route_key") or ""),
                "check": check,
                "cwe": _norm_cwe(df.get("cwe")) or _norm_cwe(sf.get("cwe")),
                "severity": str(df.get("severity") or ""),
                "confidence": after,
                "sast": _sast_ref(sf),
                "dast": _dast_ref(df),
                "linkage": {"route": linkage, "sink": matched_on},
                "explanation": (
                    f"static {sf.get('rule_id') or '?'} "
                    f"({sf.get('file')}:{sf.get('line')}) + dynamic {check} "
                    f"on {df.get('route_key')}: same sink "
                    f"{_norm_cwe(sf.get('cwe')) or sf.get('vuln_type')} "
                    f"via {matched_on}, same route via {linkage}; "
                    f"confidence {before or '-'} -> {after or '-'}"
                ),
            })
            by_check[check] = by_check.get(check, 0) + 1
            by_linkage[linkage] = by_linkage.get(linkage, 0) + 1

    merged.sort(key=lambda r: (r["route_key"], r["check"],
                               _norm_file(r["sast"]["file"]),
                               r["sast"]["line"], r["sast"]["finding_id"]))
    for i, row in enumerate(merged, 1):
        row["correlation_id"] = f"corr-{i:04d}"
    candidates.sort(key=lambda c: (c["dast"]["route_key"], c["dast"]["check"],
                                   _norm_file(c["sast"]["file"]),
                                   c["sast"]["line"], c["sast"]["finding_id"]))

    return {
        "schema": CORRELATE_SCHEMA,
        "findings": merged,
        "candidates": candidates,
        "stats": {
            "sast_findings": len(sast_rows),
            "dast_findings": len(dast_rows),
            "pairs_considered": sink_matched,
            "sink_matched": sink_matched,
            "route_linked": len(merged),
            "merged": len(merged),
            "sink_only": len(candidates),
            "by_check": dict(sorted(by_check.items())),
            "by_linkage": dict(sorted(by_linkage.items())),
            "unmapped_checks": sorted(unmapped),
        },
    }


def _load_rows(path: str, key: str):
    """Load a JSON artifact: raw list, or a doc holding findings under key."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    if p.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input too large (> {MAX_INPUT_BYTES} bytes): {path}")
    doc = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        val = doc.get(key)
        if isinstance(val, list):
            return val
        if key == "apibom" and isinstance(doc.get("apibom"), list):
            return doc["apibom"]
    raise ValueError(f"no {key!r} list in {path}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.dast.correlate",
        description="Correlate SAST and DAST findings (same route + "
                    "same sink -> one merged row, additive artifact).")
    parser.add_argument("--sast", required=True,
                        help="SAST report JSON (clean_report.json or a "
                             "bare findings list)")
    parser.add_argument("--dast", required=True,
                        help="DAST findings JSON (rsecopsx.dast_findings/v1 "
                             "doc or a bare list)")
    parser.add_argument("--apibom", default=None,
                        help="optional API-BOM items JSON for route_file "
                             "linkage")
    parser.add_argument("--out", default=None,
                        help="write the correlation doc here (default: "
                             "stdout)")
    args = parser.parse_args(argv)

    try:
        sast_rows = _load_rows(args.sast, "findings")
        dast_rows = _load_rows(args.dast, "findings")
        apibom_rows = _load_rows(args.apibom, "apibom") if args.apibom else []
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[correlate] input error: {exc}")
        return 2

    doc = correlate(sast_rows, dast_rows, apibom_items=apibom_rows)
    text = json.dumps(doc, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        st = doc["stats"]
        print(f"[correlate] merged={st['merged']} "
              f"sink_only={st['sink_only']} "
              f"sast={st['sast_findings']} dast={st['dast_findings']} "
              f"-> {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
