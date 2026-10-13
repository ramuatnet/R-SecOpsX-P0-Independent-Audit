"""Baseline diff: compare the current inventory against a previous one.

    from scanner.sbom_baseline import diff_baseline
    delta = diff_baseline(current_pkgs, "previous/clean_report.json")

Accepts three baseline shapes and normalises them all to package dicts:

    1. an SBOM file (CycloneDX/SPDX JSON)  -> scanner.sbom_reader.read_sbom
    2. a previous clean_report.json payload -> payload["sbom"]
    3. a bare list of package dicts         -> used verbatim

IDENTITY
--------
The versionless purl (type/namespace/name) when EVERY package on both
sides carries a purl, else (name.casefold(), ecosystem.casefold()). A
purl's version qualifier is stripped: version is never part of
identity, because "what changed" and "what entered/left the tree"
answer different questions during triage. Mixed schemes (one side
purl-less) fall back wholesale to name+ecosystem so a purl-derived key
can never silently fail to match a name-derived one.

VULNERABILITY DELTA
-------------------
Recorded "as found": the current side's advisory-enrichment result vs
the ids the baseline itself recorded (a previous clean_report's
pkg["vulnerabilities"]). A baseline SBOM file that never carried
vulnerability records contributes an empty baseline set, which makes
every current advisory look new - the summary therefore reports
`baseline_had_vulnerability_data` so a reader can tell "no advisories
before" from "no advisories RECORDED before". The baseline is never
re-queried against OSV: this is a diff, not a rescan.

The delta is report-only. It never changes exit codes and it never
modifies either inventory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _identity(pkg: dict, use_purl: bool) -> tuple:
    """Identity NEVER includes the version: a version move must surface as
    a CHANGE, not a remove+add pair.

    purl identity is the versionless purl (type/namespace/name) because a
    purl's version qualifier would otherwise make every bump a different
    component. The name fallback casefolds name+ecosystem.
    """
    if use_purl:
        from scanner.sbom_reader import parse_purl
        parsed = parse_purl(str(pkg.get("purl") or ""))
        return ("purl", parsed["type"],
                parsed["namespace"].casefold(), parsed["name"].casefold())
    return ("name",
            str(pkg.get("name") or "").casefold(),
            str(pkg.get("ecosystem") or "").casefold())


def _purl_identity_on_both_sides(current: list[dict],
                                 baseline: list[dict]) -> bool:
    """purl identity only when EVERY package on BOTH sides carries one.

    Mixed identity schemes would never match (a purl-derived key can
    never equal a name-derived key), silently turning one upgrade into
    a removal plus an addition. One purl-less package on either side
    drops the whole diff to the name+ecosystem scheme, which is the
    conservative choice: worst case a name collision reports a change
    that did not happen, never a silent identity miss.
    """
    return (bool(current) and bool(baseline)
            and all(str(p.get("purl") or "").strip() for p in current)
            and all(str(p.get("purl") or "").strip() for p in baseline))


def _summarise(pkg: dict) -> dict:
    out = {
        "name": pkg.get("name"),
        "version": pkg.get("version"),
        "ecosystem": pkg.get("ecosystem"),
        "license": pkg.get("license"),
        "purl": pkg.get("purl") or "",
    }
    vulns = pkg.get("vulnerabilities") or []
    out["vulnerability_count"] = len(vulns)
    return out


def _vuln_ids(pkg: dict) -> set[str]:
    ids = set()
    for record in pkg.get("vulnerabilities") or []:
        if isinstance(record, dict):
            rid = str(record.get("id") or "").strip()
            if rid:
                ids.add(rid)
        elif record:
            ids.add(str(record))
    return ids


def load_baseline(source: Any) -> tuple[list[dict], str]:
    """Normalise any baseline shape to (packages, description)."""
    if isinstance(source, list):
        return [p for p in source if isinstance(p, dict)], "package list"

    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError("baseline file does not exist: %s" % path)
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
        except ValueError:
            # Not valid JSON on its own -> an SBOM the reader parses.
            from scanner.sbom_reader import SbomReadError, read_sbom
            try:
                return read_sbom(str(path))["components"], str(path)
            except SbomReadError as exc:
                # Surface as ValueError: callers (main.py) catch
                # OSError/ValueError/TypeError, not SbomReadError.
                raise ValueError(str(exc)) from exc
        # Raw CycloneDX/SPDX documents are valid JSON with their own
        # component shapes: normalise them through the reader rather than
        # returning native (un-normalised) component dicts that would
        # never match the current inventory's field conventions.
        if isinstance(doc, dict) and (doc.get("bomFormat")
                                      or doc.get("spdxVersion")):
            from scanner.sbom_reader import read_sbom
            return read_sbom(str(path))["components"], str(path)
        # A clean_report payload carries its inventory under "sbom"; an
        # ingest document (read_sbom output) carries it under "components".
        if isinstance(doc, dict) and isinstance(doc.get("sbom"), list):
            return doc["sbom"], str(path)
        if isinstance(doc, dict) and isinstance(doc.get("components"), list):
            return doc["components"], str(path)
        if isinstance(doc, list):
            return [p for p in doc if isinstance(p, dict)], str(path)
        raise ValueError(
            "%s has no recognisable inventory (expected a clean_report "
            "payload with 'sbom', an SBOM with 'components', or a list)"
            % path)

    raise TypeError("baseline must be a path or a package list, got %s"
                    % type(source).__name__)


def diff_baseline(current: list[dict], baseline: Any) -> dict:
    """Compute the inventory/vulnerability delta between two inventories."""
    baseline_pkgs, baseline_desc = load_baseline(baseline)
    use_purl = _purl_identity_on_both_sides(current, baseline_pkgs)

    cur_by = {}
    for pkg in current:
        cur_by.setdefault(_identity(pkg, use_purl), pkg)
    base_by = {}
    for pkg in baseline_pkgs:
        base_by.setdefault(_identity(pkg, use_purl), pkg)

    added = [_summarise(p) for ident, p in sorted(cur_by.items())
             if ident not in base_by]
    removed = [_summarise(p) for ident, p in sorted(base_by.items())
               if ident not in cur_by]
    changed = []
    vuln_new = []
    vuln_resolved = []
    for ident in sorted(set(cur_by) & set(base_by)):
        cur, base = cur_by[ident], base_by[ident]
        cur_v = str(cur.get("version") or "unknown")
        base_v = str(base.get("version") or "unknown")
        if cur_v != base_v:
            changed.append({
                "name": cur.get("name"),
                "ecosystem": cur.get("ecosystem"),
                "from_version": base_v,
                "to_version": cur_v,
            })
        for rid in sorted(_vuln_ids(cur) - _vuln_ids(base)):
            vuln_new.append({"package": cur.get("name"),
                             "version": cur_v, "id": rid})
        for rid in sorted(_vuln_ids(base) - _vuln_ids(cur)):
            vuln_resolved.append({"package": base.get("name"),
                                  "version": base_v, "id": rid})

    baseline_had_vuln_data = any(_vuln_ids(p) for p in baseline_pkgs)

    return {
        "baseline_source": baseline_desc,
        "baseline_components": len(baseline_pkgs),
        "current_components": len(current),
        "added": added,
        "removed": removed,
        "changed": changed,
        "vulnerabilities_new": vuln_new,
        "vulnerabilities_resolved": vuln_resolved,
        "baseline_had_vulnerability_data": baseline_had_vuln_data,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "vulnerabilities_new": len(vuln_new),
            "vulnerabilities_resolved": len(vuln_resolved),
        },
    }
