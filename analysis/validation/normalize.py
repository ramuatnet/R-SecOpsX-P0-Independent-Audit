"""Map findings from any tool onto one canonical schema (Phase V0.2).

WHY THIS EXISTS
---------------
A corpus that can only be scored against its own scanner measures nothing
about interoperability. To diff R-SecOpsX against a peer tool, or to score
one corpus with both, their findings have to meet on common ground first:
the same field names, the same severity vocabulary, the same way of naming
the thing that was found.

WHAT COUNTS AS A GOOD NORMALIZATION
-----------------------------------
A normalizer earns trust by losing as little as possible and by never
inventing. Three rules follow from that:

    1. Absent is preserved as absent. A tool that reports no severity does
       not get handed one. ``None`` travels through so the comparator can
       see the gap; a fabricated ``"Medium"`` hides it, and hides it in the
       direction that flatters whichever tool produced the finding.

    2. Nothing is inferred from a score. A numeric severity of 3.1 does not
       become ``"High"`` by looking like one -- the mapping is the tool's
       own published scale, applied only where that tool is known to use
       it. Guessing here would let a normalizer silently relabel findings,
       which is how a comparison starts agreeing with itself.

    3. Original values are kept, not replaced. ``normalize_finding`` adds
       canonical fields and copies the source record to ``_source_finding``
       so a disagreement can always be traced back to what the tool
       actually said.

MATCHING IS ON CWE, NOT ON RULE ID
----------------------------------
Rule IDs are private vocabulary. ``TAINT_SQL_INJECTION``,
``JAVA_JDBC_SQL_CONCAT`` and ``java.lang.security.audit.sqli...`` all name
the same defect, and a comparator keyed on their literal spelling would
report three separate detections of one finding. CWE is the shared
vocabulary -- both the corpus labels and every tool here carry it -- so
findings are matched on ``(file, CWE, line)``. Rule ID is kept as a
tie-breaker and for reporting, never as the primary key.

See ``compare.finding_key`` for how the three parts are combined, and for
why ``line`` is allowed to differ by a configurable tolerance.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_LOG = logging.getLogger("rsx.analysis.validation.normalize")

# Canonical severity vocabulary. Title case is not cosmetic: group_by_severity
# and the security gate both key on the exact spelling.
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

# SARIF has no severity scale of its own; it carries a three-value "level"
# plus an optional CVSS-ish "security-severity" property. The level mapping
# below is SARIF's own documented semantics, not an approximation.
_SARIF_LEVEL_TO_SEVERITY = {
    "error": "High",
    "warning": "Medium",
    "note": "Info",
    "none": "Info",
}

# Peer-tool scales, each as that tool documents it.
_GRYPE_SEVERITY = {
    "negligible": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
    "unknown": None,
}

_SEMGREP_SEVERITY = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Info",
}

_CHECKOV_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": None,
}

_GITLEAKS_SEVERITY = {
    # gitleaks carries no severity at all -- its rules are all "secret found".
    # Returning None is the honest answer; inventing "High" for every hit
    # would make the tool look decisive while saying nothing.
}

_TRIVY_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "negligible": "Info",
    # trivy uses "Unknown" for an advisory whose severity the source never
    # stated. That is an absence of information, not a low-severity finding,
    # so it maps to None rather than being filed as a grade.
    "unknown": None,
}

SOURCES = ("rsecopsx", "sarif", "grype", "trivy", "semgrep", "checkov",
           "gitleaks", "kics")

# Canonical class for a CWE. This is the vocabulary V0.1's labels use, and
# the only place a CWE becomes a comparable identifier.
_CWE_TO_CLASS = {
    "CWE-89": "SAST-SQLI",
    "CWE-78": "SAST-CMDI",
    "CWE-22": "SAST-PATH",
    "CWE-502": "SAST-DESER",
    "CWE-94": "SAST-CODEINJ",
    "CWE-798": "SAST-HARDCRED",
    "CWE-79": "SAST-XSS",
    "CWE-215": "SAST-DEBUG",
}


def canonical_class(cwe: Any, rule_id: Any = None) -> str | None:
    """CWE -> canonical vulnerability class, or None if it has no class.

    Kept as a function rather than inlined so the comparator and the CLI
    agree on one spelling. A class that exists in one place and not the
    other is how two tools end up comparing different things while both
    reporting success.
    """
    if cwe and str(cwe).strip():
        mapped = _CWE_TO_CLASS.get(str(cwe).strip().upper())
        if mapped:
            return mapped
    return None


def _relpath(value: Any) -> str:
    """Normalise a path to forward slashes.

    Backslashes are not cosmetic here. R-SecOpsX emits Windows absolute
    paths, SARIF URIs and grype paths all use different separators, and a
    comparator that compares them literally reports every finding as unique
    because ``src\\a.py`` != ``src/a.py``.
    """
    if value is None:
        return ""
    return str(value).replace("\\", "/").strip()


def _basename(value: Any) -> str:
    """Last path segment, for comparing across tools that disagree on roots."""
    rel = _relpath(value)
    return rel.rsplit("/", 1)[-1] if rel else ""


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first(*values: Any) -> Any:
    """First value that is present and non-empty.

    Deliberately truthiness-free beyond emptiness: 0 is a real line number
    and an empty string is not a real value, so the two are distinguished
    rather than lumped together as falsy.
    """
    for v in values:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return None


# --------------------------------------------------------------------------
# Per-source normalizers. Each returns the canonical dict and never raises on
# a malformed record -- a peer tool emitting one odd shape should cost that
# record, not the whole comparison.
# --------------------------------------------------------------------------

def _from_rsecopsx(f: dict) -> dict:
    """R-SecOpsX's own finding shape (scanner.sast / the servlet pipeline).

    ``snippet`` is the evidence: it is the line of code the rule matched,
    which is what the corpus labels anchor on.
    """
    return {
        "rule_id": _first(f.get("rule_id"), f.get("vuln_type")),
        "class": canonical_class(f.get("cwe"), f.get("rule_id")),
        "file": _relpath(f.get("file")),
        "basename": _basename(f.get("file")),
        "line": _int_or_none(f.get("line")),
        "severity": _first(f.get("severity")),
        "cwe": _first(f.get("cwe")),
        "evidence": _first(f.get("snippet"), f.get("evidence"), f.get("title")),
        "cve": _first(f.get("cve")),
        "package": _first(f.get("package"), f.get("name")),
        "version": _first(f.get("version")),
    }


def _from_sarif(f: dict) -> dict:
    """One SARIF result object.

    SARIF's ``level`` is a three-value operational scale, not a security
    severity, so it maps to the coarse part of the vocabulary and the
    ``security-severity`` property carries the finer grade when present.
    Where both exist the property wins: it is the value the emitter
    computed for this specific finding, while ``level`` is often defaulted
    from the rule.
    """
    loc = (f.get("locations") or [{}])[0] or {}
    phys = loc.get("physicalLocation") or {}
    uri = (phys.get("artifactLocation") or {}).get("uri")
    line = _int_or_none((phys.get("region") or {}).get("startLine"))

    props = f.get("properties") or {}
    level = str(f.get("level") or "").lower()
    sev = _SARIF_LEVEL_TO_SEVERITY.get(level)

    # security-severity is a CVSS-like number as a string. Map it through the
    # CVSS qualitative scale, which is what that property is defined to hold.
    raw = _first(props.get("security-severity"))
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            sev = _score_to_severity(score)

    return {
        "rule_id": _first(f.get("ruleId"), f.get("rule")),
        "class": canonical_class(_first(props.get("cwe"), f.get("cwe"))),
        "file": _relpath(uri),
        "basename": _basename(uri),
        "line": line,
        "severity": sev,
        "cwe": _first(props.get("cwe"), f.get("cwe")),
        "evidence": _first(f.get("message"), f.get("messageText")),
        "cve": _first(props.get("cve")),
        "package": _first(props.get("package")),
        "version": _first(props.get("version")),
    }


def _score_to_severity(score: float) -> str | None:
    """CVSS qualitative scale. Used only where a tool publishes a score AS a
    severity, never to relabel a tool's own stated severity."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    if score == 0.0:
        return "Info"
    return None


def _from_grype(f: dict) -> dict:
    """One grype ``match`` object.

    grype separates the vulnerability from the artifact, and reports the
    package name where a SAST corpus would report a file. ``artifact.path``
    is present for file-scanned targets and absent for image scans, which is
    why a grype finding often has no line at all -- that absence is kept.
    """
    vuln = f.get("vulnerability") or {}
    artifact = f.get("artifact") or {}

    cve = _first(vuln.get("id"))
    aliases = vuln.get("relatedVulnerabilities") or []
    if not cve or not str(cve).startswith("CVE-"):
        for alias in aliases:
            aid = alias.get("id") if isinstance(alias, dict) else alias
            if aid and str(aid).startswith("CVE-"):
                cve = aid
                break

    # grype does NOT always carry the CVE in relatedVulnerabilities -- on the
    # corpus SBOM that field is null and advisories is [], while the CVE sits
    # in `cwes[].cve`:
    #
    #   "cwes": [{"cve": "CVE-2023-48631", "cwe": "CWE-20", ...}]
    #
    # Checking only the two conventional places left grype reporting
    # GHSA-prr3-c3m5-p7q2 where R-SecOpsX reports CVE-2023-48631 for the same
    # advisory, so a shared finding was reported as two disagreements. The
    # rule ID still carries grype's own id -- only the canonical CVE field is
    # aliased, which is what the field is for.
    if not cve or not str(cve).startswith("CVE-"):
        for entry in vuln.get("cwes") or []:
            if not isinstance(entry, dict):
                continue
            candidate = entry.get("cve")
            if candidate and str(candidate).upper().startswith("CVE-"):
                cve = candidate
                break

    sev = str(vuln.get("severity") or "").lower()
    # A severity grype does not define must stay None. Coercing an unknown
    # value to Medium would move findings upward and make recall look better.
    sev = _GRYPE_SEVERITY.get(sev, None)

    return {
        "rule_id": _first(vuln.get("id")),
        "class": None,
        "file": _relpath(_first(artifact.get("path"))),
        "basename": _basename(artifact.get("path")),
        "line": None,  # grype does not report line numbers
        "severity": sev,
        "cwe": None,
        "evidence": _first(vuln.get("description"), vuln.get("details")),
        "cve": cve,
        "package": _first(artifact.get("name")),
        "version": _first(artifact.get("version")),
    }


def _from_trivy(f: dict) -> dict:
    """One trivy ``Vulnerabilities`` entry.

    trivy reports a package, not a line: ``PkgName`` / ``InstalledVersion``
    take the place of a file and line, so ``line`` stays None and the finding
    matches on component identity instead -- the same way a grype finding
    does. Forcing a line here would be inventing one.

    Severity arrives in title case ("Critical") or upper case ("CRITICAL")
    depending on version and output format, so it is lower-cased before the
    lookup rather than being matched on one spelling and dropped on the
    other. A dropped severity would read as "trivy did not say", which is a
    different claim from "trivy said Critical".
    """
    sev_raw = str(f.get("Severity") or "").strip().lower()
    sev = _TRIVY_SEVERITY.get(sev_raw)

    cve = _first(f.get("VulnerabilityID"))
    if cve and not str(cve).upper().startswith("CVE-"):
        # trivy also reports GHSA- and TEMP- ids. Keep the tool's own id as
        # the rule id, and leave cve None unless it really is a CVE, so the
        # comparator never treats a GHSA identifier as if it were a CVE.
        for key in ("PrimaryURL", "VendorID"):
            candidate = f.get(key)
            if candidate and str(candidate).upper().startswith("CVE-"):
                cve = candidate
                break
        else:
            cve = None

    path = _first(f.get("PkgPath"), f.get("PkgIdentifier", {}).get("PkgID")
                  if isinstance(f.get("PkgIdentifier"), dict) else None,
                  f.get("Target"))

    return {
        "rule_id": _first(f.get("VulnerabilityID")),
        "class": None,
        "file": _relpath(path),
        "basename": _basename(path),
        "line": None,
        "severity": sev,
        "cwe": None,
        "evidence": _first(f.get("Title"), f.get("Description"),
                           f.get("VulnerabilityID")),
        "cve": cve,
        "package": _first(f.get("PkgName")),
        "version": _first(f.get("InstalledVersion")),
    }


def _from_kics(f: dict) -> dict:
    """One kics ``files`` entry, reached through its parent query.

    kics nests each finding under ``queries[].files[]``, so a flattening step
    in ``normalize_findings`` would be needed to reach it directly. This
    normalizer therefore takes one already-flattened file record, which is
    what ``_flatten_kics`` produces.

    PROVENANCE OF THIS SHAPE
    ------------------------
    kics is not installed on this machine, so unlike the grype and trivy
    normalizers this one was written from kics's documented JSON output
    rather than captured from a run. The invariant it satisfies is that a
    tool declared in PEER_TOOLS must be normalizable -- without this, a kics
    run would skip every finding as "unknown source" and report the peer as
    finding nothing, which reads as agreement. The first real kics run must
    confirm the field names; until then this is documented, not verified.
    """
    sev_raw = str(f.get("severity") or "").strip().lower()
    return {
        "rule_id": _first(f.get("query_id"), f.get("query_name")),
        "class": None,
        "file": _relpath(f.get("file_name")),
        "basename": _basename(f.get("file_name")),
        "line": _int_or_none(f.get("line")),
        "severity": _CHECKOV_SEVERITY.get(sev_raw.upper()),
        "cwe": None,
        "evidence": _first(f.get("search_key"), f.get("description"),
                           f.get("query_name")),
        "cve": None,
        "package": None,
        "version": None,
    }


def _flatten_kics(findings: list) -> list[dict]:
    """Expand kics's nested ``queries[].files[]`` into one record per file.

    Without this every kics query would be counted once no matter how many
    files it flags, understating the peer and making our own count look
    inflated by comparison.
    """
    flat: list[dict] = []
    for query in findings or []:
        if not isinstance(query, dict):
            continue
        files = query.get("files")
        if not isinstance(files, list) or not files:
            continue
        for entry in files:
            if not isinstance(entry, dict):
                continue
            merged = dict(entry)
            # The query carries the identity and severity; the file carries
            # the location. Both are needed for one canonical record.
            for key in ("query_id", "query_name", "severity", "description"):
                if query.get(key) is not None:
                    merged.setdefault(key, query.get(key))
            flat.append(merged)
    return flat


def _from_semgrep(f: dict) -> dict:
    """One semgrep ``result``.

    semgrep's CWE lives in the check ID as a suffix (``...sqli.taint``) or
    in ``extra.metadata.cwe`` as a list of strings like
    ``["CWE-89: Improper Neutralization ..."]``. The list form is parsed
    rather than ignored, because CWE is the matching key: a normalizer that
    dropped it would make every semgrep finding unmatchable and then report
    the tool as disagreeing with everything.
    """
    extra = f.get("extra") or {}
    meta = extra.get("metadata") or {}

    cwe = None
    raw_cwe = meta.get("cwe")
    if isinstance(raw_cwe, list) and raw_cwe:
        cwe = str(raw_cwe[0]).split(":")[0].strip()
    elif isinstance(raw_cwe, str) and raw_cwe.strip():
        cwe = raw_cwe.split(":")[0].strip()

    start = (f.get("start") or {})
    sev = _SEMGREP_SEVERITY.get(str(extra.get("severity") or "").strip())

    return {
        "rule_id": _first(f.get("check_id")),
        "class": canonical_class(cwe, f.get("check_id")),
        "file": _relpath(f.get("path")),
        "basename": _basename(f.get("path")),
        "line": _int_or_none(start.get("line")),
        "severity": sev,
        "cwe": cwe,
        "evidence": _first(extra.get("message"), f.get("check_id")),
        "cve": _first(meta.get("cve")),
        "package": _first(meta.get("package")),
        "version": _first(meta.get("version")),
    }


def _from_checkov(f: dict) -> dict:
    """One checkov ``check_result``.

    checkov is IaC-first: it reports a resource rather than a line of code,
    so ``file_line_range`` may carry the location and ``code_line`` the text.
    Severity is only present when the policy declares one.
    """
    resource = f.get("resource") or ""
    loc = f.get("file_line_range") or []
    line = None
    if isinstance(loc, list) and loc:
        line = _int_or_none(loc[0])

    code = f.get("code_line")
    if isinstance(code, dict):
        code = code.get("line") or code.get("snippet")

    return {
        "rule_id": _first(f.get("check_id"), f.get("check_type")),
        "class": None,
        "file": _relpath(_first(f.get("file"), resource)),
        "basename": _basename(_first(f.get("file"), resource)),
        "line": line,
        "severity": _CHECKOV_SEVERITY.get(str(f.get("severity") or "").strip()),
        "cwe": None,
        "evidence": _first(code, f.get("check_name")),
        "cve": None,
        "package": None,
        "version": None,
    }


def _from_gitleaks(f: dict) -> dict:
    """One gitleaks finding.

    gitleaks carries no severity and no CWE: a leaked secret is a leaked
    secret. Both stay None. Assigning "High" to every hit would be the
    normalizer inventing a judgement the tool never made, and it would make
    gitleaks look uniformly decisive.
    """
    return {
        "rule_id": _first(f.get("RuleID"), f.get("rule")),
        "class": None,
        "file": _relpath(f.get("File")),
        "basename": _basename(f.get("File")),
        "line": _int_or_none(_first(f.get("StartLine"), f.get("Line"))),
        "severity": None,
        "cwe": None,
        "evidence": _first(f.get("Secret"), f.get("Match")),
        "cve": None,
        "package": None,
        "version": None,
    }


_NORMALIZERS = {
    "rsecopsx": _from_rsecopsx,
    "sarif": _from_sarif,
    "grype": _from_grype,
    "trivy": _from_trivy,
    "semgrep": _from_semgrep,
    "checkov": _from_checkov,
    "gitleaks": _from_gitleaks,
    "kics": _from_kics,
}


def normalize_finding(finding: dict, source: str) -> dict:
    """Map one tool's finding onto the canonical schema.

    ``source`` names the emitter: one of ``SOURCES``. An unknown source is a
    programming error rather than data, so it raises -- silently guessing a
    shape would produce a normalized record that looks authoritative and is
    fabricated.

    The original record is preserved under ``_source_finding`` and the
    emitter under ``_source``. Nothing is dropped and nothing is invented:
    a field the tool did not report is ``None``, so the comparator can see
    the absence rather than being told a value the tool never chose.
    """
    if source not in _NORMALIZERS:
        raise ValueError(
            "unknown source %r -- expected one of %s" % (source, sorted(_NORMALIZERS)))

    if not isinstance(finding, dict):
        raise TypeError("finding must be a dict, got %s" % type(finding).__name__)

    try:
        out = _NORMALIZERS[source](finding)
    except Exception as exc:  # a bad record costs that record, not the run
        _LOG.warning("could not normalize a %s finding: %s", source, exc)
        out = {}

    # Guarantee every canonical key exists. A key that is missing and a key
    # that is None behave the same to a caller but differently to
    # dict.get-with-default, and the difference has caused silent mismatches.
    for key in ("rule_id", "class", "file", "basename", "line", "severity",
                "cwe", "evidence", "cve", "package", "version"):
        out.setdefault(key, None)

    out["_source"] = source
    out["_source_finding"] = finding
    return out


def normalize_findings(findings: list, source: str) -> list[dict]:
    """Normalize a collection, skipping records that fail rather than aborting.

    One malformed peer record must not discard the other 400, because the
    report then understates what the peer found and the diff reads as
    agreement that was never established.

    kics is flattened first: its findings are nested as
    ``queries[].files[]``, and one query may span several files. Feeding the
    query straight through would produce one record for all of them.
    """
    if source == "kics":
        findings = _flatten_kics(findings)

    out = []
    for f in findings or []:
        try:
            out.append(normalize_finding(f, source))
        except (TypeError, ValueError) as exc:
            _LOG.warning("skipping a malformed %s finding: %s", source, exc)
    return out


def normalize_corpus_finding(finding: dict, fixture_name: str) -> dict:
    """Normalize a ground-truth label into the same schema.

    Labels are already canonical, so this is mostly a pass-through -- but it
    routes through the same function for a reason. If the comparator ever
    treated the two sides differently, a mismatch could be an artefact of
    two code paths rather than a real disagreement, and no amount of
    staring at the output would reveal it.

    The canonical class is NOT re-derived here. ``normalize_finding`` already
    computes it from the label's CWE through the same code path a real
    finding takes. A second derivation would be a duplicate that could drift
    from the first, with nothing to notice the difference -- and a duplicate
    with no test is worse than no code at all.
    """
    record = dict(finding)
    # A label may name a file that differs from the fixture it sits beside
    # (SCA labels name the manifest; the fixture IS the manifest).
    record.setdefault("file", fixture_name)
    return normalize_finding(record, "rsecopsx")
