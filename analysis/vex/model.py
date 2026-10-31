"""SBOM/VEX service core -- ingest VEX statements + SBOM components, query.

task.md section 12 PHASE 9 "SBOM/VEX service".  Offline, pure, no server:
the service surface is this module + ``python -m analysis.vex.connect``;
a serve-route wrapper is deliberately NOT built (disclosed -- the CLI +
schema'd artifact is the v1 service).

INGEST (three VEX shapes, all JSON, parsed by hand -- no external dep):

* **R-SecOpsX VEX** -- the ``statements[]`` document our own
  ``reporting.vex_export.build_vex`` emits (security_report.vex.json);
  round-trip ingest is pinned by test.
* **CycloneDX** -- any CycloneDX JSON document's ``vulnerabilities[]``
  (analysis.state + affects[]).  This is exactly what
  ``scanner.sbom_reader`` preserves on ingest but refuses to merge: the
  mixing decision belongs to a QUERY surface, not to the scanner's own
  vulnerability records.
* **OpenVEX** -- a single-statement object (``status`` +
  ``vulnerability``/``products``).

Statuses normalize to the ``vex_export`` vocabulary
(``affected | not_affected | under_investigation | fixed``); CycloneDX
states map (exploitable->affected, in_triage->under_investigation,
resolved/resolved_with_pedigree->fixed).  A row with an unmappable
status is ANNOTATED into ``skips[]`` with reason
``statement_status_unrecognized:<raw>`` -- never silently dropped, never
guessed into a status it did not state.  Rows that are not objects, or
carry no vulnerability id, are annotated the same way.

CONFLICTS are report-only: the same (vulnerability, component) carrying
two different statuses yields a ``conflicts[]`` row (sorted, order-
independent) and a stats counter; statements are NEVER rewritten or
silently precedence-picked -- the consumer sees every statement.

SBOM side reuses ``scanner.sbom_reader.read_sbom`` (CycloneDX + SPDX
JSON) verbatim for membership; join is by bom-ref, purl, or name@version
and only COUNTS matched/unmatched statements.

QUERIES: ``--vulnerability`` (case-insensitive id), ``--component``
(bom-ref / purl / name@version / name), ``--status`` (vocabulary).  Each
query embeds its matching statements (sorted).  Absent inputs become
machine-readable ``not_provided`` skips (default run = exactly two).

Deterministic: no clocks, no uuids; statements sorted by a total key
(vulnerability, component key, source doc, status, ...); same inputs in
any order -> byte-identical output (test-pinned).  ``--as-of`` is
optional and only echoed when supplied.
"""
from __future__ import annotations

SCHEMA = "rsecopsx.vex_service/v1"

VEX_STATUSES = ("affected", "not_affected", "under_investigation", "fixed")

# CycloneDX analysis.state / neighbour vocabularies -> our vocabulary.
# Anything not here is a skip row with reason statement_status_unrecognized.
_STATUS_ALIASES = {
    "affected": "affected",
    "exploitable": "affected",
    "not_affected": "not_affected",
    "notaffected": "not_affected",
    "under_investigation": "under_investigation",
    "in_triage": "under_investigation",
    "fixed": "fixed",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
}

_SBOM_COMPONENT_KEYS = ("name", "version", "ecosystem", "license", "purl",
                        "cpe", "direct", "sbom_ref", "ingested_from")


class VexInvalid(RuntimeError):
    """A whole input document is unusable; ``.reason`` is machine-readable."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def normalize_status(raw):
    """Canonical status, or None when the raw value is not ours to guess."""
    if raw is None:
        return None
    text = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
    if not text:
        return None
    return _STATUS_ALIASES.get(text)


def component_key(component: dict) -> str:
    """Stable identity for a component row/statement product."""
    if not isinstance(component, dict):
        return ""
    purl = str(component.get("purl") or "").strip()
    if purl:
        return purl
    name = str(component.get("name") or "").strip()
    if not name:
        return ""
    version = str(component.get("version") or "").strip()
    return "%s@%s" % (name, version) if version else name


def _statement_row(*, vulnerability, component, status, justification,
                   detail, impact_statement, action_statement, timestamp,
                   source_doc, source_format):
    comp = component if isinstance(component, dict) else {}
    return {
        "vulnerability": str(vulnerability),
        "component": {
            "bom_ref": str(comp.get("bom_ref") or ""),
            "purl": str(comp.get("purl") or ""),
            "name": str(comp.get("name") or ""),
            "version": str(comp.get("version") or ""),
            "ecosystem": str(comp.get("ecosystem") or ""),
        },
        "status": status,
        "justification": (str(justification) if justification else None),
        "detail": (str(detail) if detail else None),
        "impact_statement": (str(impact_statement)
                             if impact_statement else None),
        "action_statement": (str(action_statement)
                             if action_statement else None),
        "timestamp": (str(timestamp) if timestamp else None),
        "source_doc": str(source_doc),
        "source_format": str(source_format),
    }


def _ours_statements(doc: dict, source: str, rows: list, skips: list):
    statements = doc.get("statements")
    if not isinstance(statements, list):
        raise VexInvalid("vex_statement_list_expected:%s" % source)
    for i, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            skips.append({"reason": "statement_not_object:%d" % i,
                          "source": source})
            continue
        vuln = stmt.get("vulnerability")
        if isinstance(vuln, dict):
            vuln = vuln.get("id")
        if not vuln:
            skips.append({"reason": "vulnerability_missing:%d" % i,
                          "source": source})
            continue
        raw_status = stmt.get("status")
        status = normalize_status(raw_status)
        if status is None and raw_status:
            skips.append({"reason": "statement_status_unrecognized:%s"
                          % str(raw_status), "source": source})
            continue
        product = stmt.get("product")
        if not isinstance(product, dict):
            product = {}
        # Our own export stores the package NAME under "component".
        comp = {"bom_ref": product.get("bom_ref"),
                "purl": product.get("purl"),
                "name": product.get("name") or product.get("component"),
                "version": product.get("version"),
                "ecosystem": product.get("ecosystem")}
        rows.append(_statement_row(
            vulnerability=vuln, component=comp,
            status=status, justification=stmt.get("justification"),
            detail=None,
            impact_statement=stmt.get("impact_statement"),
            action_statement=stmt.get("action_statement"),
            timestamp=stmt.get("timestamp"),
            source_doc=source, source_format="rsecopsx_vex"))


def _cdx_vulnerabilities(doc: dict, source: str, rows: list, skips: list):
    vulns = doc.get("vulnerabilities")
    if vulns is None:
        # CycloneDX documents without a vulnerabilities section are valid
        # VEX inputs carrying zero statements.
        return
    if not isinstance(vulns, list):
        raise VexInvalid("vex_statement_list_expected:%s" % source)
    for i, vuln in enumerate(vulns):
        if not isinstance(vuln, dict):
            skips.append({"reason": "statement_not_object:%d" % i,
                          "source": source})
            continue
        vid = vuln.get("id") or (vuln.get("source") or {}).get("id") \
            if isinstance(vuln.get("source"), dict) else vuln.get("id")
        if not vid:
            skips.append({"reason": "vulnerability_missing:%d" % i,
                          "source": source})
            continue
        analysis = vuln.get("analysis")
        if not isinstance(analysis, dict):
            analysis = {}
        raw_state = analysis.get("state")
        status = normalize_status(raw_state)
        if status is None and raw_state:
            skips.append({"reason": "statement_status_unrecognized:%s"
                          % str(raw_state), "source": source})
            continue
        affects = vuln.get("affects")
        targets = [a for a in (affects or []) if isinstance(a, dict)] or [{}]
        for target in targets:
            rows.append(_statement_row(
                vulnerability=vid,
                component={"bom_ref": str(target.get("ref") or ""),
                           "name": str(target.get("name") or ""),
                           "version": "", "purl": str(target.get("purl")
                                                       or "")},
                status=status, justification=analysis.get("justification"),
                detail=analysis.get("detail"),
                impact_statement=None, action_statement=None,
                timestamp=vuln.get("published") or vuln.get("updated"),
                source_doc=source, source_format="cyclonedx"))


def _openvex(doc: dict, source: str, rows: list, skips: list):
    if "status" not in doc:
        raise VexInvalid("unrecognised_vex_format:%s" % source)
    vuln = doc.get("vulnerability")
    if isinstance(vuln, dict):
        vuln = vuln.get("@id") or vuln.get("id")
    if not vuln:
        raise VexInvalid("vulnerability_missing:document")
    raw_status = doc.get("status")
    status = normalize_status(raw_status)
    if status is None:
        raise VexInvalid("statement_status_unrecognized:%s"
                         % str(raw_status or ""))
    products = doc.get("products")
    targets = [p for p in (products or []) if isinstance(p, dict)] or [{}]
    for target in targets:
        rows.append(_statement_row(
            vulnerability=vuln,
            component={"bom_ref": str(target.get("@id") or ""),
                       "purl": str(target.get("purl") or ""),
                       "name": str(target.get("name") or ""),
                       "version": str(target.get("version") or "")},
            status=status, justification=doc.get("justification"),
            detail=doc.get("status_notes") or doc.get("statusNotes"),
            impact_statement=None, action_statement=None,
            timestamp=doc.get("timestamp"),
            source_doc=source, source_format="openvex"))


def normalize_vex_doc(doc: dict, source: str) -> tuple[list, list]:
    """(rows, skips) for one VEX document; raises VexInvalid when fatal."""
    if not isinstance(doc, dict):
        raise VexInvalid("vex_not_an_object:%s" % source)
    rows: list = []
    skips: list = []
    if "statements" in doc:
        # Presence of the key selects OUR format; a non-list statements
        # field then fails loudly inside _ours_statements (a doc that
        # says it carries statements but carries a string is malformed,
        # not another format).
        _ours_statements(doc, source, rows, skips)
    elif str(doc.get("bomFormat") or "").lower() == "cyclonedx" or (
            "specVersion" in doc and "vulnerabilities" in doc):
        _cdx_vulnerabilities(doc, source, rows, skips)
    elif "vulnerabilities" in doc and isinstance(doc.get("vulnerabilities"),
                                                 list):
        _cdx_vulnerabilities(doc, source, rows, skips)
    else:
        _openvex(doc, source, rows, skips)
    return rows, skips


def sbom_component_row(component: dict) -> dict:
    """Fixed projection of a scanner.sbom_reader normalised component."""
    if not isinstance(component, dict):
        return {}
    return {k: component.get(k) for k in _SBOM_COMPONENT_KEYS}


def conflicts_for(statements: list) -> list:
    """(vulnerability, component) groups carrying >1 distinct status.

    Report-only: statements themselves are never rewritten.
    """
    groups: dict = {}
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        key = (str(stmt.get("vulnerability") or ""),
               component_key(stmt.get("component") or {}))
        groups.setdefault(key, set()).add(stmt.get("status"))
    out = []
    for (vuln, comp), statuses in groups.items():
        if len(statuses) > 1:
            out.append({
                "vulnerability": vuln,
                "component": comp,
                "statuses": sorted(str(s) for s in statuses),
            })
    out.sort(key=lambda c: (c["vulnerability"], c["component"]))
    return out


def _component_index(components: list) -> dict:
    index = {"bom_ref": {}, "purl": {}, "key": {}, "name": {}}
    for comp in components:
        if not isinstance(comp, dict):
            continue
        row = sbom_component_row(comp)
        if row.get("sbom_ref"):
            index["bom_ref"][row["sbom_ref"]] = row
        if row.get("purl"):
            index["purl"][row["purl"]] = row
        key = component_key(row)
        if key:
            index["key"][key] = row
        if row.get("name"):
            index["name"].setdefault(row["name"], row)
    return index


def match_statement(stmt: dict, index: dict) -> bool:
    """Does this statement's component exist in the ingested SBOM?

    CDX convention: an ``affects.ref`` is the component's bom-ref, but
    many emitters put the purl in the ref -- so bom_ref is checked
    against BOTH the bom-ref and purl indexes (and vice versa).
    """
    comp = stmt.get("component") or {}
    bom_ref = str(comp.get("bom_ref") or "")
    if bom_ref and (bom_ref in index["bom_ref"] or bom_ref in index["purl"]):
        return True
    purl = str(comp.get("purl") or "")
    if purl and (purl in index["purl"] or purl in index["bom_ref"]):
        return True
    key = component_key(comp)
    if key and (key in index["key"] or key in index["name"]):
        return True
    name = str(comp.get("name") or "")
    if name and name in index["name"]:
        return True
    return False


def run_queries(statements: list, components: list,
                specs: list) -> list:
    """Embedded query results: [{kind, input, count, statements, components}].

    ``specs`` is a list of (kind, value) with kind in
    vulnerability|component|status.  Invalid status values are rejected by
    the CLI's argparse choices before reaching here.
    """
    out = []
    for kind, value in specs:
        matched_stmts = []
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            if kind == "vulnerability":
                if str(stmt.get("vulnerability") or "").lower() == \
                        str(value).lower():
                    matched_stmts.append(stmt)
            elif kind == "status":
                if stmt.get("status") == value:
                    matched_stmts.append(stmt)
            elif kind == "component":
                comp = stmt.get("component") or {}
                if str(value) in (str(comp.get("bom_ref") or ""),
                                  str(comp.get("purl") or ""),
                                  component_key(comp),
                                  str(comp.get("name") or "")):
                    matched_stmts.append(stmt)
        matched_comps = []
        if kind == "component":
            for comp in components:
                row = sbom_component_row(comp)
                if str(value) in (str(row.get("sbom_ref") or ""),
                                  str(row.get("purl") or ""),
                                  component_key(row),
                                  str(row.get("name") or "")):
                    matched_comps.append(row)
        out.append({
            "kind": kind,
            "input": str(value),
            "count": len(matched_stmts),
            "statements": matched_stmts,
            "components": matched_comps,
        })
    return out


def build(vex_docs: list, sbom_docs: list, specs: list, as_of=None) -> dict:
    """Assemble the service document.

    ``vex_docs`` = [(source, parsed_doc), ...]; ``sbom_docs`` =
    [(source, read_sbom result), ...].  Fatal shape problems must already
    have been raised by the caller (VexInvalid / SbomReadError) so this
    stays a pure assembler.
    """
    statements: list = []
    skips: list = []
    for source, doc in vex_docs:
        rows, row_skips = normalize_vex_doc(doc, source)
        statements.extend(rows)
        skips.extend(row_skips)
    statements.sort(key=lambda s: (
        str(s.get("vulnerability") or ""),
        component_key(s.get("component") or {}),
        str(s.get("source_doc") or ""),
        str(s.get("status") or ""),
        str(s.get("source_format") or ""),
        str(s.get("justification") or ""),
        str(s.get("detail") or ""),
        str(s.get("timestamp") or "")))

    components: list = []
    for _source, doc in sbom_docs:
        for comp in doc.get("components") or []:
            if isinstance(comp, dict):
                components.append(sbom_component_row(comp))
    components.sort(key=lambda c: (component_key(c),
                                   str(c.get("name") or "")))

    conflicts = conflicts_for(statements)
    index = _component_index(components)
    matched = sum(1 for s in statements if match_statement(s, index))

    if not vex_docs:
        skips.append({"reason": "not_provided", "source": "vex"})
    if not sbom_docs:
        skips.append({"reason": "not_provided", "source": "sbom"})

    by_status: dict = {}
    for stmt in statements:
        key = stmt.get("status") or "unspecified"
        by_status[key] = by_status.get(key, 0) + 1

    doc_out = {
        "schema": SCHEMA,
        "statements": statements,
        "components": components,
        "conflicts": conflicts,
        "queries": run_queries(statements, components, specs),
        "skips": skips,
        "stats": {
            "statements": len(statements),
            "components": len(components),
            "conflicts": len(conflicts),
            "skipped_statements": sum(
                1 for s in skips if s.get("reason") != "not_provided"),
            "by_status": by_status,
            "statements_matched_to_sbom": matched,
            "statements_unmatched_to_sbom": len(statements) - matched,
        },
    }
    if as_of is not None:
        doc_out["as_of"] = as_of
    return doc_out
