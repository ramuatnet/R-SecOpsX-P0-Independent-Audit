from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from typing import Any

CONFIRMED_TYPES = {
    'path_traversal','ssrf','command_injection','code_injection','sql_injection',
    'nosql_injection','hardcoded_secret','insecure_deserialization','idor','bola',
}
CONTROL_GAP_TERMS = ('api_', 'control_gap', 'rate_limit', 'brute_force', 'abuse')


def classify_finding(f: dict[str, Any]) -> str:
    explicit = str(f.get('classification') or '').strip().lower()
    if explicit in {'confirmed','control_gap','heuristic','informational'}:
        return explicit
    vt = str(f.get('vuln_type') or '').strip().lower()
    rid = str(f.get('rule_id') or '').strip().lower()
    taint_validated = bool(
        f.get('taint_validated')
        or (
            isinstance(f.get('evidence_validation_detail'), dict)
            and f['evidence_validation_detail'].get('taint_validated')
        )
    )
    sink_validated = (
        f.get('sink_validated') is True
        or (
            isinstance(f.get('evidence_validation_detail'), dict)
            and f['evidence_validation_detail'].get('sink_valid') is True
        )
    )
    if (
        taint_validated
        and sink_validated
        and bool(f.get('evidence_valid', True))
    ):
        if vt in CONFIRMED_TYPES or any(x in vt for x in ('injection','traversal','ssrf','deserialization')):
            return 'confirmed'
    if vt.startswith('api_') or any(t in vt or t in rid for t in CONTROL_GAP_TERMS):
        return 'control_gap'
    if f.get('evidence_valid') is False:
        return 'informational'
    return 'heuristic'


def _attach_canonical_evidence(f: dict[str, Any]) -> dict[str, Any]:
    """Attach canonical V11 Evidence without changing legacy finding semantics."""
    try:
        from core.evidence_adapter import (
            normalize_finding_evidence,
            qualify_finding_evidence,
        )

        evidence = normalize_finding_evidence(f)
        f['canonical_evidence'] = evidence.to_dict()

        try:
            qualified = qualify_finding_evidence(f)
            f['canonical_qualified_evidence'] = qualified.to_dict()
            f['canonical_evidence_state'] = (
                'qualified' if qualified.qualified else 'not_qualified'
            )
        except Exception as exc:
            # Canonical Evidence exists, but qualification could not be
            # established. Do not reinterpret or overwrite legacy evidence.
            f['canonical_evidence_state'] = 'qualification_error'
            f['canonical_evidence_error'] = str(exc)

    except Exception as exc:
        # Preserve the established V11 finding contract. Canonical evidence
        # failure is explicitly surfaced rather than silently inferred.
        f['canonical_evidence_state'] = 'unavailable'
        f['canonical_evidence_error'] = str(exc)

    return f


def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:
    f = dict(f)
    f['classification'] = classify_finding(f)
    ev = f.get('evidence_valid')
    if ev is False:
        f['confidence'] = 'LOW'
        try: f['confidence_score'] = min(float(f.get('confidence_score', 0) or 0), 25.0)
        except Exception: f['confidence_score'] = 0
        if f['classification'] == 'confirmed': f['classification'] = 'informational'
    if f['classification'] in {'heuristic','control_gap'}:
        # Heuristics/control gaps are never promoted to Critical/High solely by pattern.
        if str(f.get('severity','')).lower() in {'critical','high'}:
            f['severity'] = 'Medium' if f['classification'] == 'control_gap' else 'Low'
    f.setdefault('evidence_state', 'validated' if ev is not False else 'invalid')
    return _attach_canonical_evidence(f)


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    findings = [normalize_finding(f) for f in (payload.get('findings') or []) if isinstance(f, dict)]
    payload['findings'] = findings
    c = Counter(f['classification'] for f in findings)
    payload['finding_classification_summary'] = dict(c)
    payload.setdefault('metadata', {})['finding_classification_summary'] = dict(c)
    return payload


def build_rule_telemetry(findings: list[dict], benchmark_labels: dict[str, dict] | None = None) -> dict:
    benchmark_labels = benchmark_labels or {}
    stats = defaultdict(lambda: {'tp':0,'fp':0,'unknown':0,'total':0,'precision':None})
    for f in findings:
        rule = str(f.get('rule_id') or f.get('vuln_type') or 'UNKNOWN')
        s = stats[rule]; s['total'] += 1
        label = str(f.get('benchmark_label') or '').lower()
        if not label and f.get('id') in benchmark_labels:
            label = str(benchmark_labels[f['id']].get('label','')).lower()
        if label in {'tp','true_positive','true positive'}: s['tp'] += 1
        elif label in {'fp','false_positive','false positive'}: s['fp'] += 1
        else: s['unknown'] += 1
    for s in stats.values():
        denom = s['tp'] + s['fp']
        s['precision'] = round(s['tp']/denom,4) if denom else None
    return dict(stats)

