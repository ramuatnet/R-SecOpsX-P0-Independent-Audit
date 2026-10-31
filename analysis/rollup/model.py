"""T-9.3 org/multi-repo rollup (D-1) -- pure envelope + collator.

The Phase 9 platform's data model, frozen early (opencodetask.md D-1):

* ``org_rollup.json`` schema v1 holds one scan envelope PER REPO --
  digest, timestamp, flags, summary counters, top techniques (A-6
  lineage), API posture (A-1), SBOM drift (B-2) -- plus org totals;
* the collator is PURE: no clock (``as_of`` is injected), no I/O, no
  network; input order NEVER affects output bytes (the D-1 gate: every
  permutation of the same manifests must serialize identically);
* validate_manifest / validate_rollup are the schema validators: one
  machine-readable reason string per problem, never a silent skip and
  never a raise-on-junk inside a batch that then loses the good rows --
  the collator refuses the WHOLE input loudly instead (a rollup that
  silently dropped a repo would misreport the org);
* ``api_posture`` and ``sbom_drift`` are OPTIONAL sections: absent
  means "not reported" (A-1's posture matrix and B-2's drift engine are
  not built yet), and the org totals then OMIT the matching data key
  rather than publishing a fabricated 0 that reads as "all clear";
* inputs are never mutated -- envelopes are deep-copied and normalized
  (flags sorted unique, techniques sorted by (-count, technique)).

``manifest_from_report`` maps a real scan payload onto the envelope:
the digest is the content address of the (rule_id, file, line) triple
set, so two scans of unchanged findings share a digest and any change
moves it.
"""
from __future__ import annotations

import hashlib
import json

MANIFEST_SCHEMA = "rsecopsx.scan_manifest/v1"
ORG_ROLLUP_SCHEMA = "rsecopsx.org_rollup/v1"

# summary keys always present in envelopes produced from a report
_SUMMARY_META = (("findings", "total_findings"),
                 ("sast", "sast_findings"),
                 ("sca", "sca_findings"))
_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


class RollupInvalid(Exception):
    """A rollup input failed validation; .reason is machine-readable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _first_bad_counter(prefix: str, doc: dict):
    """First (sorted) counter that is not a non-negative int -- or None."""
    for key in sorted(doc):
        value = doc[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return f"{prefix}:{key}"
    return None


def validate_manifest(man) -> "str | None":
    """Validate one per-repo envelope; None = valid, else one reason.

    Reason order is fixed (schema -> repo -> digest/timestamp -> flags
    -> summary -> techniques -> optional sections) so the same broken
    manifest always reports the SAME reason regardless of caller.
    """
    if not isinstance(man, dict):
        return "manifest_not_object"
    if man.get("schema") != MANIFEST_SCHEMA:
        return "manifest_schema"
    if "repo" not in man:
        return "repo_missing"
    repo = man["repo"]
    if not isinstance(repo, str):
        return "repo_not_a_string"
    if not repo.strip():
        return "repo_empty"
    for key, empty in (("digest", "digest_empty"),
                       ("timestamp", "timestamp_empty")):
        if key not in man:
            return f"{key}_missing"
        value = man[key]
        if not isinstance(value, str):
            return f"{key}_not_a_string"
        if not value:
            return empty
    if "flags" not in man:
        return "flags_missing"
    flags = man["flags"]
    if not isinstance(flags, list):
        return "flags_not_a_list"
    for i, item in enumerate(flags):
        if not isinstance(item, str):
            return f"flags_item_not_string:{i}"
    if "summary" not in man:
        return "summary_missing"
    summary = man["summary"]
    if not isinstance(summary, dict):
        return "summary_not_object"
    bad = _first_bad_counter("summary_bad_counter", summary)
    if bad is not None:
        return bad
    if "top_techniques" not in man:
        return "top_techniques_missing"
    techs = man["top_techniques"]
    if not isinstance(techs, list):
        return "top_techniques_not_a_list"
    for i, item in enumerate(techs):
        if not isinstance(item, dict):
            return f"technique_not_object:{i}"
        tid = item.get("technique")
        if not isinstance(tid, str) or not tid:
            return f"technique_missing:{i}"
        count = item.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return f"technique_count_bad:{i}"
    for key in ("api_posture", "sbom_drift"):
        if key in man:
            section = man[key]
            if not isinstance(section, dict):
                return f"{key}_not_object"
            bad = _first_bad_counter(f"{key}_bad_counter", section)
            if bad is not None:
                return bad
    return None


def manifest_from_report(report, repo=None, flags=None) -> dict:
    """Build the envelope for one scan report payload (pure).

    ``api_posture`` (A-1) and ``sbom_drift`` (B-2) are deliberately NOT
    synthesized: until those features ship, the envelope must show them
    as absent -- absent reads as "not reported", a fabricated empty
    section would read as "assessed and clean".
    """
    if not isinstance(report, dict):
        report = {}
    findings = [f for f in (report.get("findings") or [])
                if isinstance(f, dict)]
    meta = report.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    if repo is None:
        target = str(meta.get("target") or "")
        repo = target.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] \
            or "unknown"
    # content address of the finding identity set: same findings -> same
    # digest, any added/removed/moved row -> new digest
    triples = sorted(
        [str(f.get("rule_id") or ""), str(f.get("file") or ""),
         str(f.get("line") or "")]
        for f in findings)
    digest = "sha256:" + hashlib.sha256(
        json.dumps(triples, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()
    summary = {}
    for out_key, meta_key in _SUMMARY_META:
        value = meta.get(meta_key)
        summary[out_key] = (value if isinstance(value, int)
                            and not isinstance(value, bool) and value >= 0
                            else 0)
    dist = meta.get("severity_distribution")
    if not isinstance(dist, dict):
        dist = {}
    for sev in _SEVERITY_KEYS:
        value = dist.get(sev.capitalize())
        summary[sev] = (value if isinstance(value, int)
                        and not isinstance(value, bool) and value >= 0
                        else 0)
    counts: "dict[str, int]" = {}
    for f in findings:
        mitre = f.get("mitre")
        items = mitre if isinstance(mitre, list) else []
        for item in items:
            tid = item if isinstance(item, str) and item else None
            if isinstance(item, dict):
                raw = item.get("id")
                tid = raw if isinstance(raw, str) and raw else None
            if tid is not None:
                counts[tid] = counts.get(tid, 0) + 1
    techs = [{"technique": tid, "count": count}
             for tid, count in sorted(counts.items(),
                                      key=lambda kv: (-kv[1], kv[0]))]
    return {
        "schema": MANIFEST_SCHEMA,
        "repo": repo,
        "digest": digest,
        "timestamp": str(meta.get("scan_date") or ""),
        "flags": sorted(set(flags or [])),
        "summary": summary,
        "top_techniques": techs,
    }


def build_rollup(manifests, as_of) -> dict:
    """Collate envelopes into the org_rollup document (pure).

    Refuses the WHOLE input with RollupInvalid rather than dropping a
    bad row: a partial rollup would silently under-count the org.
    Duplicate repos are only tolerated when the envelopes are
    byte-identical after normalization (idempotent re-collation);
    conflicting content for one repo is an error regardless of input
    order.
    """
    if not isinstance(as_of, str):
        raise RollupInvalid("as_of_not_a_string")
    if not isinstance(manifests, list):
        raise RollupInvalid("rollup_inputs_not_a_list")
    normalized: "dict[str, str]" = {}
    dup_identical = 0
    errors: "list[str]" = []
    for man in manifests:
        reason = validate_manifest(man)
        if reason is not None:
            errors.append(reason)
            continue
        clean = json.loads(json.dumps(man))     # deep copy; input untouched
        clean["flags"] = sorted(set(clean["flags"]))
        clean["top_techniques"] = sorted(
            clean["top_techniques"],
            key=lambda t: (-t["count"], t["technique"]))
        canon = json.dumps(clean, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":"))
        repo = clean["repo"]
        if repo in normalized:
            if normalized[repo] == canon:
                dup_identical += 1
            else:
                errors.append(f"duplicate_repo_conflict:{repo}")
            continue
        normalized[repo] = canon
    if errors:
        raise RollupInvalid(",".join(sorted(set(errors))))
    repos = [json.loads(normalized[k]) for k in sorted(normalized)]

    counters: "dict[str, int]" = {}
    tech_counts: "dict[str, int]" = {}
    with_posture = with_drift = 0
    posture_totals: "dict[str, int]" = {}
    drift_totals: "dict[str, int]" = {}
    for r in repos:
        # per-key totals aggregate only repos REPORTING the key --
        # absent means not reported, never an implied zero
        for k, v in r["summary"].items():
            counters[k] = counters.get(k, 0) + v
        for t in r["top_techniques"]:
            tech_counts[t["technique"]] = (
                tech_counts.get(t["technique"], 0) + t["count"])
        if "api_posture" in r:
            with_posture += 1
            for k, v in r["api_posture"].items():
                posture_totals[k] = posture_totals.get(k, 0) + v
        if "sbom_drift" in r:
            with_drift += 1
            for k, v in r["sbom_drift"].items():
                drift_totals[k] = drift_totals.get(k, 0) + v
    totals = {
        "repos": len(repos),
        "counters": dict(sorted(counters.items())),
        "techniques": [{"technique": tid, "count": count}
                       for tid, count in sorted(tech_counts.items(),
                                                key=lambda kv: (-kv[1],
                                                                kv[0]))],
        "repos_with_api_posture": with_posture,
        "repos_with_sbom_drift": with_drift,
    }
    if with_posture:
        totals["api_posture"] = dict(sorted(posture_totals.items()))
    if with_drift:
        totals["sbom_drift"] = dict(sorted(drift_totals.items()))
    return {
        "schema": ORG_ROLLUP_SCHEMA,
        "as_of": as_of,
        "repos": repos,
        "totals": totals,
        "skips": [],
        "stats": {"repos": len(repos),
                  "duplicates_identical": dup_identical},
    }


def validate_rollup(doc) -> "str | None":
    """Validate a full org_rollup document; None = valid, else reason."""
    if not isinstance(doc, dict):
        return "rollup_not_object"
    if doc.get("schema") != ORG_ROLLUP_SCHEMA:
        return "rollup_schema"
    if not isinstance(doc.get("as_of"), str):
        return "rollup_as_of"
    repos = doc.get("repos")
    if not isinstance(repos, list):
        return "rollup_repos_not_a_list"
    seen: "list[str]" = []
    for item in repos:
        if not isinstance(item, dict):
            return "rollup_repo_not_object"
        reason = validate_manifest(item)
        if reason is not None:
            return f"rollup_repo_invalid:{reason}"
        seen.append(item.get("repo"))
    if seen != sorted(seen):
        return "rollup_repos_unsorted"
    if len(seen) != len(set(seen)):
        return "rollup_repo_duplicate"
    if not isinstance(doc.get("totals"), dict):
        return "rollup_totals_not_object"
    if not isinstance(doc.get("skips"), list):
        return "rollup_skips_not_a_list"
    if not isinstance(doc.get("stats"), dict):
        return "rollup_stats_not_object"
    return None
