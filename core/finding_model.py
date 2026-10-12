from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from typing import Any
import uuid

CONFIRMED_TYPES = {
    'path_traversal','ssrf','command_injection','code_injection','sql_injection',
    'nosql_injection','hardcoded_secret','insecure_deserialization','idor','bola',
}
CONTROL_GAP_TERMS = ('api_', 'control_gap', 'rate_limit', 'brute_force', 'abuse')


_RSECOPSX_CANONICAL_FINDING_ID_V1 = "rsecopsx-v11:finding:"

def _canonical_finding_id(f: dict) -> str:
    existing = str(f.get('finding_id') or '').strip()
    if existing:
        return existing

    parts = (
        str(f.get('rule_id') or '').strip(),
        str(f.get('vuln_type') or '').strip(),
        str(f.get('file') or f.get('path') or '').replace('\\', '/').strip(),
        str(f.get('line') if f.get('line') is not None else '').strip(),
        str(f.get('column') if f.get('column') is not None else '').strip(),
        str(f.get('sink_category') or '').strip(),
        str(f.get('source') or '').strip(),
        str(f.get('snippet') or '')[:1000].strip(),
    )
    seed = '|'.join(parts)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, _RSECOPSX_CANONICAL_FINDING_ID_V1 + seed))

_IAC_RULE_PREFIXES = ('tf_', 'k8s_', 'docker_')


def _is_iac_finding(f: dict[str, Any]) -> bool:
    """True when the finding is a reading of declarative infrastructure config.

    Checked via the issue_group the three IaC scanners all set, plus the
    rule-id prefixes main.py itself uses to count them (_apply_iac_metadata),
    so the definition stays consistent with the rest of the pipeline.
    """
    if str(f.get('issue_group') or '').strip().lower() == 'infrastructure / iac':
        return True
    rid = str(f.get('rule_id') or '').strip().lower()
    return rid.startswith(_IAC_RULE_PREFIXES)


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
    # IaC findings are direct readings of declarative configuration, not
    # guesses about data flow: the file states "Action = *" or "0.0.0.0/0"
    # and the scanner reports what it read. There is no taint path to
    # validate because the configuration itself is the evidence. Without
    # this branch every TF_/K8S_/DOCKER_ rule fell through to 'heuristic'
    # and normalize_finding then demotes heuristic findings from
    # Critical/High to Low -- which reported a 0.0.0.0/0 security group
    # (declared Critical, labelled Critical in the golden corpus) as Low.
    # Placed last so an explicit classification, a control-gap term match
    # or a failed evidence evaluation still wins.
    if _is_iac_finding(f):
        return 'confirmed'
    return 'heuristic'


def _attach_canonical_evidence(f: dict[str, Any]) -> dict[str, Any]:
    """Attach one canonical Evidence object and qualify that same object."""
    try:
        from core.evidence_adapter import (
            normalize_finding_evidence,
            qualify_finding_evidence,
        )

        # Qualification is the single construction path. Calling the
        # adapter twice would generate two independent evidence IDs.
        qualified = qualify_finding_evidence(f)
        qdict = qualified.to_dict()

        canonical = qdict.get('evidence')
        if canonical is None:
            # Preserve explicit failure if the adapter did not return evidence.
            raise ValueError(
                'QualifiedEvidence did not contain its canonical evidence object'
            )

        f['canonical_evidence'] = canonical
        f['canonical_qualified_evidence'] = qdict
        f['canonical_evidence_state'] = (
            'qualified' if qualified.qualified else 'not_qualified'
        )
        # A prior normalization attempt may have recorded a transient
        # canonical_evidence_error. Once qualification succeeds and the
        # canonical Evidence state is established, that stale error must
        # not remain in the final finding payload.
        f.pop('canonical_evidence_error', None)

    except Exception as exc:
        # Preserve the established V11 finding contract. Canonical evidence
        # failure is explicitly surfaced rather than silently inferred.
        f.pop('canonical_evidence', None)
        f.pop('canonical_qualified_evidence', None)
        f['canonical_evidence_state'] = 'unavailable'
        f['canonical_evidence_error'] = str(exc)

    return f


def normalize_finding(f: dict[str, Any]) -> dict[str, Any]:
    f = dict(f)
    f['finding_id'] = _canonical_finding_id(f)
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



