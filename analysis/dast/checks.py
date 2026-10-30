"""T-5.3: active DAST checks over the T-5.1 target model + T-5.2 sessions.

Safety posture (safe mode is the default and the only mode exercised by
the test suite):

* destructive verbs are never sent -- every probe mirrors the route's own
  declared method restricted to GET/POST; DELETE/PUT/PATCH routes are
  passive-only and every skipped probe is disclosed with a reason;
* scope allowlist: every constructed URL is verified against the
  configured base origin before it is fetched (hostile model paths such
  as ``//evil.test/x`` abort the route with ``scope_violation``);
* rate limit between requests + backoff on 429: the first 429 on a route
  records an observed rate-limit finding, backs off, and aborts the rest
  of that route's probes (machine-readable ``aborts`` rows);
* probe budget per route (MAX_PROBES_PER_ROUTE) with ``budget_exhausted``
  disclosure -- no unbounded fuzzing;
* evidence is bounded (MAX_EVIDENCE_CHARS / MAX_URL_CHARS) and JWT
  material is never stored -- only decoded header fields.

Detection notes (disclosed, per no-silent-drops):

* injection families (sqli/lfi/cmdi/ssti/ssrf/deser/xxe) are
  signature-based: a probe response carrying a known engine/file/shell
  signature is reported as ``likely``.  There is no baseline diff, so an
  endpoint that emits the signature for ANY input is a possible FP;
* xss is reflected-only: stored and DOM XSS are declared
  ``not_modelled`` (persistence semantics and a JS engine are out of
  scope here; DOM work belongs with a real browser);
* RFI (blind SSRF/XXE/RCE callbacks) needs T-5.4's OOB listener; the
  non-blind canaries are modelled here;
* jwt checks are offline structure checks (alg=none / missing exp) --
  no secret brute force;
* mass-assignment is a heuristic (injected privileged field echoed in a
  2xx body);
* rate-limit: an observed 429 is an ``observed`` finding; the missing
  rate-limit verdict only fires behind ``aggressive=True`` (bounded
  burst, default off);
* tls grade is live-only (a real TLS handshake; skipped with reason
  otherwise) and grades simplistically (A/E/T), not the Mozilla policy;
  the live path needs the optional ``cryptography`` package and is not
  exercised by the offline suite.
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, quote_plus, urlencode, urljoin, urlsplit

from analysis.dast.auth import build_sessions, load_profiles, session_headers
from analysis.dast.sources import MAX_SOURCE_BYTES

FINDINGS_SCHEMA = "rsecopsx.dast_findings/v1"

MAX_EVIDENCE_CHARS = 512
MAX_URL_CHARS = 2048
MAX_PROBES_PER_ROUTE = 16
BURST_N = 6
CORS_ORIGIN = "https://evil.test"
XSS_CANARY = "rsxXssCanary7f3c"
CMDI_CANARY = "RSXCMDcanary"

# urlencode leaves ``/`` and ``*`` intact (path-traversal payloads stay
# readable, glob/unquoted markers survive); everything else is escaped.
_QSAFE = "/*"

XXE_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)
MASS_EXTRA = {"is_admin": "true", "admin": "true",
              "role": "admin", "is_staff": "true"}

SQLI_PAYLOADS = ["'", "' OR '1'='1' --"]
XSS_PAYLOADS = ["<" + XSS_CANARY + ">"]
LFI_PAYLOADS = ["../../../../etc/passwd"]
CMDI_PAYLOADS = [";" + "echo " + CMDI_CANARY]
SSTI_PAYLOADS = ["{{987*654}}", "${987*654}"]
REDIRECT_PAYLOADS = ["https://evil.test/steal"]
SSRF_PAYLOADS = ["http://169.254.169.254/latest/meta-data/"]
DESER_PAYLOADS = ['O:8:"stdClass":0:{}', "rO0ABGO7vcHJvZmlsZQ"]

# T-5.4: which checks mint an OOB callback payload for blind bugs.  The
# URL is injected as a parameter VALUE (the target fetches it); a callback
# arriving for the token confirms (or promotes) the owning finding.
OOB_KIND_BY_CHECK = {"dast.ssrf": "ssrf", "dast.xxe": "xxe",
                     "dast.cmdi": "rce"}

SQLI_RE = re.compile(
    r"You have an error in your SQL|SQL syntax|mysql_[a-z_]+\(|mysqli?_|"
    r"pg_[a-z_]+\(|PostgreSQL.*ERROR|ORA-\d{4,5}|sqlite3?\.|SQLITE_ERROR"
    r"|SQLSTATE\[[0-9A-Z]+\]|Unclosed quotation mark|unterminated "
    r"quoted string|Warning.*mysql|syntax error at line", re.I)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
# standalone render of the SSTI payloads' product (987*654): neighbours
# must not be word chars/dots (hex-token/version fragments are not
# results).  The RARE product is the point -- a mundane marker like '49'
# matches challenge-number nav labels ("Challenge 49" on wrongsecrets)
# and CSRF-error pages, which two gate runs proved.
_SSTI_MARKER_RE = re.compile(r"(?<![\w.])645498(?![\w.])")
DESER_RE = re.compile(
    r"InvalidClassException|ClassNotFoundException|NotSerializableException"
    r"|StreamCorruptedException|ObjectInputStream|unserialize\(\)|__wakeup"
    r"|deserializ", re.I)
FILE_READ_SIGS = ("root:x:0:0:", "root:*:0:0:")
SSRF_SIGS = ("AccessKeyId", '"Code":"Success"', "aws_secret_access_key",
             "security-credentials", "ami-")
SSRF_ECHO_PRONE = "meta-data/"      # a reflected URL is not SSRF evidence
CMDI_OUT_RE = re.compile(r"uid=\d+|gid=\d+|root:x:0:0:")

# Registry: ids, severity, references, honest gap declarations.
CHECKS: list[dict] = [
    {"id": "dast.security_headers", "mode": "passive", "severity": "medium",
     "cwe": "CWE-693", "owasp": "A05:2021", "live_only": False,
     "not_modelled": [],
     "desc": "missing CSP/HSTS/X-Frame-Options/X-Content-Type-Options"},
    {"id": "dast.cors", "mode": "passive", "severity": "medium",
     "cwe": "CWE-942", "owasp": "A05:2021", "live_only": False,
     "not_modelled": [],
     "desc": "reflected Access-Control-Allow-Origin (+credentials)"},
    {"id": "dast.jwt_weaknesses", "mode": "passive", "severity": "high",
     "cwe": "CWE-347", "owasp": "A02:2021", "live_only": False,
     "not_modelled": ["secret_brute_force"],
     "desc": "alg=none / missing exp in observed JWTs (structure only)"},
    {"id": "dast.rate_limit", "mode": "passive", "severity": "medium",
     "cwe": "CWE-770", "owasp": "A04:2021", "live_only": False,
     "not_modelled": [],
     "desc": "observed 429 / missing rate limit behind --aggressive"},
    {"id": "dast.sqli", "mode": "probe", "severity": "high",
     "cwe": "CWE-89", "owasp": "A03:2021", "live_only": False,
     "not_modelled": [],
     "desc": "SQL error signatures in probe responses"},
    {"id": "dast.xss_reflected", "mode": "probe", "severity": "high",
     "cwe": "CWE-79", "owasp": "A03:2021", "live_only": False,
     "not_modelled": ["stored", "dom"],
     "desc": "unencoded reflection of a canary tag"},
    {"id": "dast.lfi", "mode": "probe", "severity": "high",
     "cwe": "CWE-22", "owasp": "A01:2021", "live_only": False,
     "not_modelled": ["rfi"],
     "desc": "traversal canary yields a file-content signature"},
    {"id": "dast.cmdi", "mode": "probe", "severity": "high",
     "cwe": "CWE-78", "owasp": "A03:2021", "live_only": False,
     "not_modelled": [],
     "desc": "echo canary with shell-output signature"},
    {"id": "dast.ssti", "mode": "probe", "severity": "high",
     "cwe": "CWE-1336", "owasp": "A03:2021", "live_only": False,
     "not_modelled": [],
     "desc": "template expression evaluated (49) rather than reflected"},
    {"id": "dast.open_redirect", "mode": "probe", "severity": "medium",
     "cwe": "CWE-601", "owasp": "A01:2021", "live_only": False,
     "not_modelled": [],
     "desc": "3xx Location pointing off the target origin"},
    {"id": "dast.ssrf", "mode": "probe", "severity": "high",
     "cwe": "CWE-918", "owasp": "A10:2021", "live_only": False,
     "not_modelled": ["blind_oob"],
     "desc": "non-blind metadata canary signatures (blind -> T-5.4)"},
    {"id": "dast.deser", "mode": "probe", "severity": "high",
     "cwe": "CWE-502", "owasp": "A08:2021", "live_only": False,
     "not_modelled": ["gadget_chain_identification"],
     "desc": "deserialization exception signatures in probe responses"},
    {"id": "dast.xxe", "mode": "probe", "severity": "high",
     "cwe": "CWE-611", "owasp": "A05:2021", "live_only": False,
     "not_modelled": ["blind_oob"],
     "desc": "XXE file-read signature on declared POST routes"},
    {"id": "dast.idor", "mode": "probe", "severity": "high",
     "cwe": "CWE-639", "owasp": "A01:2021", "live_only": False,
     "not_modelled": [],
     "desc": "two roles fetch the same object with identical 200 bodies"},
    {"id": "dast.mass_assignment", "mode": "probe", "severity": "medium",
     "cwe": "CWE-915", "owasp": "A04:2021", "live_only": False,
     "not_modelled": [],
     "desc": "privileged field echoed in a 2xx body (heuristic)"},
    {"id": "dast.tls_grade", "mode": "passive", "severity": "high",
     "cwe": "CWE-295", "owasp": "A02:2021", "live_only": True,
     "not_modelled": ["mozilla_policy_grade"],
     "desc": "live handshake grade A/E/T (skipped when not live)"},
]
_CHECK_BY_ID = {c["id"]: c for c in CHECKS}


@dataclass
class ProbeResponse:
    url: str
    status: int
    body: str
    headers: dict


@dataclass
class CheckContext:
    base_url: str
    routes: list
    fetch: Callable
    rate_limit_s: float = 0.5
    aggressive: bool = False
    live: bool = False
    sessions: Optional[dict] = None
    role_routes: Optional[dict] = None
    timeout_s: float = 10.0
    user_agent: str = "R-SecOpsX-DAST/0.2 (+active; safe-mode GET/POST only)"
    backoff_sleep: Callable[[float], None] = time.sleep
    backoff_s: float = 5.0
    throttle_sleep: Callable[[float], None] = time.sleep
    # T-5.4: optional OOB client (duck-typed: .mint(kind)->(url,token),
    # .confirm(token, timeout)->interaction).  None disables all OOB.
    oob: Optional[object] = None
    oob_wait_s: float = 0.0
    # T-5.5: path prefixes that receive NO request at all -- not even the
    # baseline.  An authenticated scan that probes /logout.php ends its
    # own session mid-run; excluded routes are disclosed as per-check
    # skips (excluded_path), never silently dropped.
    exclude_paths: tuple = ()


def _method_of(route) -> str:
    return str(route.get("method") or "GET").upper()


def _eff_method(route) -> str:
    m = _method_of(route)
    return m if m in ("GET", "POST") else "GET"


def _on_scope(url: str, base_url: str) -> bool:
    b, u = urlsplit(base_url), urlsplit(url)
    if u.scheme not in ("http", "https"):
        return False
    if (u.hostname or "").lower() != (b.hostname or "").lower():
        return False
    bp = b.port or (443 if b.scheme == "https" else 80)
    up = u.port or (443 if u.scheme == "https" else 80)
    return bp == up


MAX_REDIRECT_HOPS = 3


def _redirect_target(status: int, headers: dict, current_url: str,
                     original_url: str) -> Optional[str]:
    """Same-origin next hop for a 3xx, or None (keep the response as-is).

    Cross-origin Locations are never followed: that 3xx IS the
    open-redirect signal, and following it would leave the scope anchor.
    Same-origin hops (trailing-slash canonicalization and friends) are
    followed so the probe reaches the real endpoint instead of a
    redirect stub -- bounded by ``MAX_REDIRECT_HOPS`` in the caller.
    """
    if not (300 <= int(status) < 400):
        return None
    loc = str((headers or {}).get("location") or "").strip()
    if not loc:
        return None
    nxt = urljoin(current_url, loc)
    if nxt == current_url:
        return None                          # self-redirect: stop, no loop
    if not _on_scope(nxt, original_url):
        return None                          # cross-origin: observable 3xx
    return nxt


def _excerpt(body: str, at: Optional[int] = None) -> str:
    body = body or ""
    if at is None:
        return body[:MAX_EVIDENCE_CHARS]
    start = max(0, int(at) - 64)
    return body[start:start + MAX_EVIDENCE_CHARS]


def _build_request(ctx: CheckContext, route, *, target=None, payload=None,
                   extra_body=None):
    """(url, method, data) with ``payload`` at ``target`` (None = baseline)."""
    m = _eff_method(route)
    path = str(route.get("path") or "/")
    pairs: list[tuple[str, str]] = []
    body: dict = {}
    for p in route.get("params") or []:
        name = str(p.get("name") or "").strip()
        if not name:
            continue
        loc = str(p.get("in") or "unknown").lower()
        val = str(payload) if (target is not None and name == target) else "1"
        if m == "GET":
            if loc in ("query", "unknown"):
                pairs.append((name, val))
        elif loc == "query":
            pairs.append((name, val))
        elif loc in ("body", "unknown"):
            body[name] = val
    if extra_body:
        body.update(extra_body)
    url = urljoin(ctx.base_url, path if path.startswith("/") else "/" + path)
    if pairs:
        url += "?" + urlencode(pairs, quote_via=quote, safe=_QSAFE)
    data = body if (m == "POST" and body) else None
    return url, m, data


def _excluded_route(route, ctx: CheckContext) -> bool:
    """True when the route resolves onto an exclude_paths prefix.

    The path is normalized through the same ``urljoin`` as the request,
    so model artifacts like ``/../../logout.php`` (link-extraction
    variants) collapse onto ``/logout.php`` and match the prefix too.
    """
    if not ctx.exclude_paths:
        return False
    path = urlsplit(urljoin(ctx.base_url,
                            str(route.get("path") or "/"))).path or "/"
    for raw in ctx.exclude_paths:
        p = str(raw or "").strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        if path.startswith(p):
            return True
    return False


def _targets(route) -> list[str]:
    """Mutation points, deduped, in model order."""
    m = _eff_method(route)
    out: list[str] = []
    for p in route.get("params") or []:
        name = str(p.get("name") or "").strip()
        loc = str(p.get("in") or "unknown").lower()
        if not name:
            continue
        if m == "GET" and loc in ("query", "unknown"):
            out.append(name)
        elif m == "POST" and loc in ("query", "body", "unknown"):
            out.append(name)
    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


def _b64json(segment: str) -> Optional[dict]:
    try:
        pad = "=" * (-len(segment) % 4)
        obj = json.loads(base64.urlsafe_b64decode(segment + pad)
                         .decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:                     # noqa: BLE001 - malformed token
        return None


class _Runner:
    """Accumulates findings/skips/aborts; owns the fetch budget and 429."""

    def __init__(self, ctx: CheckContext):
        self.ctx = ctx
        self.findings: list[dict] = []
        self.skips: list[dict] = []
        self.aborts: list[dict] = []
        self.probed_requests = 0
        self.route: dict = {}
        self.route_key = "*"
        self.route_probe_count = 0
        self.route_aborted = False
        self.rate_seen = False
        self.tls_done = False
        # T-5.4: ordered pending entries awaiting a callback.  A list of
        # {token, route_key, check_id, route, kind} -- NOT a token-keyed
        # dict, because a fixed test RNG can mint the same token for two
        # checks and the collision must not drop either entry.
        self.oob_pending: list = []
        self.oob_confirmed = 0
        self.effective_cap = MAX_PROBES_PER_ROUTE
        # T-5.2 sessions attach to EVERY request the runner makes (the
        # authenticated scan session = first profile in file order with
        # status ok and non-empty headers; the "none" strategy stays the
        # unauthenticated baseline).  Role-specific probes (_ck_idor)
        # override Cookie/Authorization by passing them explicitly --
        # setdefault below yields to caller-set headers.
        self.scan_headers: dict = {}
        for _name, _s in (ctx.sessions or {}).items():
            if (str(getattr(_s, "status", "")) == "ok"
                    and getattr(_s, "headers", None)):
                self.scan_headers = dict(session_headers(_s))
                break

    def begin_route(self, route: dict) -> None:
        self.route = route
        self.route_key = str(route.get("route_key") or "*")
        self.route_probe_count = 0
        self.route_aborted = False
        self.rate_seen = False
        # OOB prepends one probe per OOB-capable check per probeable
        # target (+1 for the xxe re-probe).  Give the route a bounded
        # headroom so enabling OOB never costs a check that fit within
        # the base cap (T-5.3 parity); still a hard bound: base + O(1).
        if self.ctx.oob:
            n_targets = len(_targets(route))
            self.effective_cap = (MAX_PROBES_PER_ROUTE
                                  + len(OOB_KIND_BY_CHECK)
                                  * max(1, n_targets))
        else:
            self.effective_cap = MAX_PROBES_PER_ROUTE

    def skip(self, check_id: str, reason: str) -> None:
        self.skips.append({"check": check_id, "route_key": self.route_key,
                           "reason": str(reason)})

    def block_reason(self) -> Optional[str]:
        if self.route_aborted:
            return "route_aborted_429"
        if self.route_probe_count >= self.effective_cap:
            return "budget_exhausted"
        return None

    def add_finding(self, route, check_id: str, confidence: str,
                    evidence: dict) -> None:
        meta = _CHECK_BY_ID[check_id]
        self.findings.append({
            "check": check_id,
            "severity": meta["severity"],
            "confidence": confidence,
            "route_key": str(route.get("route_key") or self.route_key),
            "method": _method_of(route),
            "cwe": meta.get("cwe", ""),
            "owasp": meta.get("owasp", ""),
            "evidence": evidence,
        })

    def _fetch(self, url, *, method, data=None, headers=None,
               probe=False) -> Optional[ProbeResponse]:
        if self.route_aborted:
            return None
        if probe and self.route_probe_count >= self.effective_cap:
            return None
        if not _on_scope(url, self.ctx.base_url):
            self.aborts.append({"route_key": self.route_key,
                                "reason": "scope_violation"})
            self.route_aborted = True
            return None
        if self.ctx.rate_limit_s > 0 and self.probed_requests > 0:
            self.ctx.throttle_sleep(self.ctx.rate_limit_s)
        self.probed_requests += 1
        if probe:
            self.route_probe_count += 1
        # authenticated scan session on every request; caller-set headers
        # (Origin, Content-Type, role Cookie) win over the defaults
        _hdrs = dict(headers or {})
        for _k, _v in self.scan_headers.items():
            _hdrs.setdefault(_k, _v)
        try:
            raw = self.ctx.fetch(url, self.ctx.timeout_s, self.ctx.user_agent,
                                 headers=_hdrs, data=data,
                                 method=method)
        except Exception as exc:           # noqa: BLE001 - disclose, continue
            self.aborts.append({"route_key": self.route_key,
                                "reason": f"transport_{type(exc).__name__}"})
            self.route_aborted = True
            return None
        resp = ProbeResponse(
            url=str(getattr(raw, "url", "") or url),
            status=int(getattr(raw, "status", 0) or 0),
            body=str(getattr(raw, "body", "") or ""),
            headers={str(k).lower(): str(v)
                     for k, v in dict(getattr(raw, "headers", None) or {})
                     .items()},
        )
        if resp.status == 429:
            self.aborts.append({"route_key": self.route_key,
                                "reason": "429_backoff"})
            if not self.rate_seen:
                self.rate_seen = True
                self.add_finding(self.route, "dast.rate_limit", "observed", {
                    "observed": "429",
                    "retry_after": resp.headers.get("retry-after", ""),
                    "response_excerpt": _excerpt(resp.body),
                    "request_url": url[:MAX_URL_CHARS],
                })
            self.ctx.backoff_sleep(self.ctx.backoff_s)
            self.route_aborted = True
        return resp


# ---------------------------------------------------------------------------
# Passive checks (read the shared baseline; no extra requests)
# ---------------------------------------------------------------------------

def _ck_security_headers(route, baseline, runner) -> None:
    wanted = ["content-security-policy", "strict-transport-security",
              "x-content-type-options", "x-frame-options"]
    missing = [h for h in wanted if h not in baseline.headers]
    if not missing:
        return
    runner.add_finding(route, "dast.security_headers", "observed", {
        "missing": missing,
        "response_excerpt": _excerpt(baseline.body),
        "request_url": baseline.url[:MAX_URL_CHARS],
    })


def _ck_cors(route, baseline, runner) -> None:
    acao = (baseline.headers.get("access-control-allow-origin") or "").strip()
    acac = (baseline.headers.get("access-control-allow-credentials")
            or "").strip().lower()
    if acao == CORS_ORIGIN or (acao == "*" and acac == "true"):
        runner.add_finding(route, "dast.cors", "observed", {
            "origin": acao,
            "allow_credentials": acac == "true",
            "probe_origin": CORS_ORIGIN,
            "response_excerpt": _excerpt(baseline.body),
            "request_url": baseline.url[:MAX_URL_CHARS],
        })


def _ck_jwt(route, baseline, runner) -> None:
    # Tokens themselves are never stored: only decoded header fields.
    for m in JWT_RE.finditer(baseline.body or ""):
        parts = m.group(0).split(".")
        if len(parts) != 3:
            continue
        header = _b64json(parts[0])
        if header is None:
            continue
        alg = str(header.get("alg") or "").lower()
        payload = _b64json(parts[1]) or {}
        for weakness in ("alg_none", "missing_exp"):
            if weakness == "alg_none" and alg != "none":
                continue
            if weakness == "missing_exp" and "exp" in payload:
                continue
            runner.add_finding(route, "dast.jwt_weaknesses", "observed", {
                "weakness": weakness,
                "alg": alg,
                "response_excerpt": _excerpt(baseline.body),
                "request_url": baseline.url[:MAX_URL_CHARS],
            })


def _ck_rate_limit(route, baseline, runner) -> None:
    ctx = runner.ctx
    if not ctx.aggressive:
        return
    reason = runner.block_reason()
    if reason:
        runner.skip("dast.rate_limit", reason)
        return
    url, method, data = _build_request(ctx, route)
    resp = None
    for _ in range(BURST_N):
        resp = runner._fetch(url, method=method, data=data,
                             headers={"Origin": CORS_ORIGIN}, probe=True)
        if resp is None:
            if not runner.route_aborted:
                runner.skip("dast.rate_limit",
                            runner.block_reason() or "budget_exhausted")
            return
        if resp.status == 429:
            return                          # observed finding added in _fetch
    runner.add_finding(route, "dast.rate_limit", "heuristic", {
        "observed": "no_429",
        "burst": BURST_N,
        "response_excerpt": _excerpt(resp.body if resp else ""),
        "request_url": url[:MAX_URL_CHARS],
    })


# ---------------------------------------------------------------------------
# Probe driver (one finding max per route+check; first hit wins)
# ---------------------------------------------------------------------------

def _probe_check(route, runner, check_id, payloads, detect, *,
                 needs_param=True, post_only=False, extra_body=None,
                 extra_headers=None) -> None:
    ctx = runner.ctx
    if post_only and _method_of(route) != "POST":
        runner.skip(check_id, "requires_post_route")
        return
    targets = _targets(route) if needs_param else [None]
    if not targets:
        runner.skip(check_id, "no_probeable_params")
        return
    reason = runner.block_reason()
    if reason:
        runner.skip(check_id, reason)
        return
    payloads = list(payloads)
    # T-5.4: mint an OOB callback URL and PREPEND it so the token is
    # pending even if a signature probe early-returns.  The URL is a
    # parameter VALUE -- the target fetches it; the callback confirms.
    kind = OOB_KIND_BY_CHECK.get(check_id)
    if ctx.oob and kind:
        oob_url, token = ctx.oob.mint(kind)
        payloads.insert(0, oob_url)
        runner.oob_pending.append({
            "token": token, "kind": kind, "check_id": check_id,
            "route_key": str(route.get("route_key") or runner.route_key),
            "route": route,
        })
    for target in targets:
        for payload in payloads:
            reason = runner.block_reason()
            if reason:
                runner.skip(check_id, reason)
                return
            url, method, data = _build_request(
                ctx, route, target=target, payload=payload,
                extra_body=extra_body)
            headers = {"Origin": CORS_ORIGIN}
            if extra_headers:
                headers.update(extra_headers)
            resp = runner._fetch(url, method=method, data=data,
                                 headers=headers, probe=True)
            if resp is None:
                if not runner.route_aborted:
                    runner.skip(check_id,
                                runner.block_reason() or "budget_exhausted")
                return
            hit = detect(resp, ctx, target, payload)
            if hit:
                confidence, evidence = hit
                evidence = dict(evidence)
                evidence.setdefault("request_url", url[:MAX_URL_CHARS])
                evidence.setdefault("response_excerpt", _excerpt(resp.body))
                if target:
                    evidence.setdefault("param", str(target))
                runner.add_finding(route, check_id, confidence, evidence)
                return


def _detect_sqli(resp, ctx, target, payload):
    m = SQLI_RE.search(resp.body or "")
    if not m:
        return None
    return ("likely", {"signature": m.group(0)[:120],
                       "response_excerpt": _excerpt(resp.body, m.start())})


def _detect_xss(resp, ctx, target, payload):
    body = resp.body or ""
    # The payload IS the tag: only a literal unencoded copy counts.
    # Encoded (&lt;...), URL-encoded (%3C...), and tag-stripped
    # reflections (bare canary text) are safe, not findings.
    if f"<{XSS_CANARY}>" not in body:
        return None
    return ("likely", {})


def _detect_lfi(resp, ctx, target, payload):
    for sig in FILE_READ_SIGS:
        if sig in (resp.body or ""):
            return ("likely", {"signature": sig})
    return None


def _detect_cmdi(resp, ctx, target, payload):
    body = resp.body or ""
    if CMDI_CANARY not in body:
        return None
    if CMDI_OUT_RE.search(body):
        return ("likely", {"canary": CMDI_CANARY})
    # The canary is alphanumeric, so it survives URL-encoding and appears
    # in ANY reflected URL (redirect stubs, search pages).  Remove every
    # copy of the injecting string -- raw, query-encoded, form-encoded --
    # first: a canary that only ever appears INSIDE a reflected payload
    # is plain reflection, while one that SURVIVES the strip (produced
    # elsewhere, e.g. an echo of the executed command line) is tentative
    # evidence of execution.
    stripped = body
    p = str(payload)
    for form in (p, quote(p, safe=_QSAFE), quote_plus(p)):
        if form:
            stripped = stripped.replace(form, "")
    if CMDI_CANARY not in stripped:
        return None
    return ("tentative", {"canary": CMDI_CANARY})


def _detect_ssti(resp, ctx, target, payload):
    body = resp.body or ""
    # The RARE product (645498) must appear standalone: mundane markers
    # like '49' match challenge-number nav labels and CSRF-error pages
    # (both gate FPs), while hex/version fragments fail the word
    # boundaries.  The payload itself must NOT be echoed -- a page
    # printing {{987*654}} as text rendered nothing.
    if _SSTI_MARKER_RE.search(body) and str(payload) not in body:
        return ("likely", {"payload": str(payload)[:80],
                           "marker": "645498"})
    return None


def _detect_redirect(resp, ctx, target, payload):
    loc = resp.headers.get("location", "")
    if not (300 <= resp.status < 400 and loc):
        return None
    absloc = urljoin(resp.url or ctx.base_url, loc)
    host = (urlsplit(absloc).hostname or "").lower()
    base_host = (urlsplit(ctx.base_url).hostname or "").lower()
    if host and host != base_host:
        return ("likely", {"location": loc[:200], "status": resp.status})
    return None


def _detect_ssrf(resp, ctx, target, payload):
    body = resp.body or ""
    for sig in SSRF_SIGS:
        if sig in body:
            if sig == SSRF_ECHO_PRONE and str(payload) in body:
                continue                    # plain reflection is not SSRF
            return ("likely", {"signature": sig})
    return None


def _detect_deser(resp, ctx, target, payload):
    m = DESER_RE.search(resp.body or "")
    if not m:
        return None
    return ("likely", {"signature": m.group(0)[:120],
                       "response_excerpt": _excerpt(resp.body, m.start())})


def _detect_mass(resp, ctx, target, payload):
    if resp.status >= 400:
        return None
    body = resp.body or ""
    echoed = [k for k in MASS_EXTRA if f'"{k}"' in body]
    if not echoed:
        return None
    return ("heuristic", {"injected_fields": sorted(MASS_EXTRA),
                          "echoed": sorted(echoed), "status": resp.status})


def _ck_xxe(route, runner) -> None:
    if _method_of(route) != "POST":
        runner.skip("dast.xxe", "requires_post_route")
        return
    reason = runner.block_reason()
    if reason:
        runner.skip("dast.xxe", reason)
        return
    ctx = runner.ctx
    url, _m, _d = _build_request(ctx, route)
    resp = runner._fetch(
        url, method="POST", data=XXE_PAYLOAD,
        headers={"Origin": CORS_ORIGIN, "Content-Type": "application/xml"},
        probe=True)
    if resp is None:
        if not runner.route_aborted:
            runner.skip("dast.xxe", runner.block_reason() or "budget_exhausted")
        return
    for sig in FILE_READ_SIGS:
        if sig in (resp.body or ""):
            runner.add_finding(route, "dast.xxe", "likely", {
                "signature": sig,
                "request_url": url[:MAX_URL_CHARS],
                "response_excerpt": _excerpt(resp.body),
            })
            return
    # T-5.4: blind XXE -- re-send with an OOB SYSTEM entity; a callback
    # arriving later confirms it.  (Worst-case POST probe count stays <=
    # MAX_PROBES_PER_ROUTE: file probe + oob probe = 2 for this check.)
    if ctx.oob:
        reason = runner.block_reason()
        if reason:
            runner.skip("dast.xxe", reason)
            return
        oob_url, token = ctx.oob.mint("xxe")
        xml = ('<?xml version="1.0"?>'
               f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{oob_url}">]>'
               "<r>&xxe;</r>")
        oob_resp = runner._fetch(
            url, method="POST", data=xml,
            headers={"Origin": CORS_ORIGIN, "Content-Type": "application/xml"},
            probe=True)
        if oob_resp is not None:
            runner.oob_pending.append({
                "token": token, "kind": "xxe", "check_id": "dast.xxe",
                "route_key": str(route.get("route_key") or runner.route_key),
                "route": route,
            })
            for sig in FILE_READ_SIGS:
                if sig in (oob_resp.body or ""):
                    runner.add_finding(route, "dast.xxe", "likely", {
                        "signature": sig,
                        "request_url": url[:MAX_URL_CHARS],
                        "response_excerpt": _excerpt(oob_resp.body),
                    })
                    return


def _ck_idor(route, runner) -> None:
    ctx = runner.ctx
    rr = ctx.role_routes or {}
    sessions = ctx.sessions or {}
    key = str(route.get("route_key") or "")
    if not rr or not sessions:
        runner.skip("dast.idor", "no_role_differential")
        return
    roles = sorted(n for n, keys in rr.items()
                   if key in (keys or []) and n in sessions
                   and str(getattr(sessions[n], "status", "")) == "ok")
    if len(roles) < 2:
        runner.skip("dast.idor", "insufficient_roles")
        return
    if _method_of(route) not in ("GET", "POST"):
        runner.skip("dast.idor", "safe_mode_destructive_verb")
        return
    reason = runner.block_reason()
    if reason:
        runner.skip("dast.idor", reason)
        return
    url, method, data = _build_request(ctx, route)
    results: dict = {}
    for role in roles:
        headers = {"Origin": CORS_ORIGIN}
        headers.update(session_headers(sessions[role]))
        resp = runner._fetch(url, method=method, data=data, headers=headers,
                             probe=True)
        if resp is None:
            if not runner.route_aborted:
                runner.skip("dast.idor",
                            runner.block_reason() or "budget_exhausted")
            return
        results[role] = resp
    ok = sorted(r for r, resp in results.items() if resp.status == 200)
    if len(ok) < 2:
        return
    if len({results[r].body for r in ok}) != 1:
        return
    # Role NAMES and statuses only -- response bodies and auth material
    # never enter the artifact.
    runner.add_finding(route, "dast.idor", "likely", {
        "roles": ok, "status": 200, "identical_body": True,
        "response_excerpt": _excerpt(results[ok[0]].body),
        "request_url": url[:MAX_URL_CHARS],
    })


def _ck_tls(route, runner) -> None:
    """Host-level, runs once, live-only (live path unexercised offline)."""
    if runner.tls_done:
        return
    runner.tls_done = True
    ctx = runner.ctx
    parts = urlsplit(ctx.base_url)
    if parts.scheme != "https":
        runner.skip("dast.tls_grade", "not_https")
        return
    try:
        from cryptography import x509                     # noqa: PLC0415
    except ImportError:
        runner.skip("dast.tls_grade", "tls_needs_cryptography")
        return
    import socket                                        # noqa: PLC0415
    host, port = parts.hostname, parts.port or 443
    try:
        tls_ctx = ssl.create_default_context()
        with socket.create_connection((host, port),
                                      timeout=ctx.timeout_s) as sock:
            with tls_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = x509.load_der_x509_certificate(
                    ssock.getpeercert(binary_form=True))
        not_after = getattr(cert, "not_valid_after_utc", None)
        ts = not_after.timestamp() if not_after else time.time()
        self_signed = cert.issuer == cert.subject
        grade = "T" if self_signed else ("E" if ts < time.time() else "A")
        if grade == "A":
            return
        runner.add_finding(route, "dast.tls_grade", "observed", {
            "grade": grade,
            "self_signed": self_signed,
            "not_after": str(not_after),
            "issuer": str(cert.issuer),
        })
    except Exception as exc:           # noqa: BLE001 - disclose, never raise
        runner.skip("dast.tls_grade", f"tls_probe_failed_{type(exc).__name__}")


_PROBES: dict[str, Callable] = {
    "dast.sqli": lambda r, st: _probe_check(
        r, st, "dast.sqli", SQLI_PAYLOADS, _detect_sqli),
    "dast.xss_reflected": lambda r, st: _probe_check(
        r, st, "dast.xss_reflected", XSS_PAYLOADS, _detect_xss),
    "dast.lfi": lambda r, st: _probe_check(
        r, st, "dast.lfi", LFI_PAYLOADS, _detect_lfi),
    "dast.cmdi": lambda r, st: _probe_check(
        r, st, "dast.cmdi", CMDI_PAYLOADS, _detect_cmdi),
    "dast.ssti": lambda r, st: _probe_check(
        r, st, "dast.ssti", SSTI_PAYLOADS, _detect_ssti),
    "dast.open_redirect": lambda r, st: _probe_check(
        r, st, "dast.open_redirect", REDIRECT_PAYLOADS, _detect_redirect),
    "dast.ssrf": lambda r, st: _probe_check(
        r, st, "dast.ssrf", SSRF_PAYLOADS, _detect_ssrf),
    "dast.deser": lambda r, st: _probe_check(
        r, st, "dast.deser", DESER_PAYLOADS, _detect_deser),
    "dast.xxe": _ck_xxe,
    "dast.idor": _ck_idor,
    "dast.mass_assignment": lambda r, st: _probe_check(
        r, st, "dast.mass_assignment", [None], _detect_mass,
        needs_param=False, post_only=True, extra_body=MASS_EXTRA),
}

_PASSIVE: dict[str, Callable] = {
    "dast.security_headers": _ck_security_headers,
    "dast.cors": _ck_cors,
    "dast.jwt_weaknesses": _ck_jwt,
    "dast.rate_limit": _ck_rate_limit,
    "dast.tls_grade": _ck_tls,
}


def _oob_promote(ctx: CheckContext, runner: "_Runner") -> None:
    """T-5.4: confirm pending OOB tokens and create/promote findings.

    A callback arriving for a minted token is the evidence for a blind
    bug: no interaction -> nothing changes; interaction + no finding ->
    a new ``confirmed`` finding; interaction + an existing finding ->
    that finding is promoted to ``confirmed`` with the interaction
    merged into its evidence.  ``stats["oob_confirmed"]`` counts the
    pending entries whose token produced a matching interaction.

    Interactions are attributed back to their owning entry by the
    callback path (``/{kind}``); a group holding exactly one entry takes
    its first interaction regardless of path, so DNS-only callbacks
    (empty path) still confirm.
    """
    if not ctx.oob or not runner.oob_pending:
        return
    # Group pending entries by token (drain consumes, so one call per
    # token).  A fixed test RNG can mint one token for several checks.
    by_token: dict = {}
    for entry in runner.oob_pending:
        by_token.setdefault(entry["token"], []).append(entry)
    for token in sorted(by_token):
        entries = by_token[token]
        interactions = ctx.oob.collect(token, timeout=ctx.oob_wait_s)
        if not interactions:
            continue
        for i, entry in enumerate(entries):
            want = f"/{entry['kind']}"
            match = next((x for x in interactions
                          if str(x.get("path") or "") == want), None)
            if match is None and len(entries) == 1:
                match = interactions[0]      # DNS-only / single-owner
            if match is None:
                continue
            interactions = [x for x in interactions if x is not match]
            runner.oob_confirmed += 1
            ev = {"oob_interaction": {
                "proto": str(match.get("proto") or ""),
                "host": str(match.get("host") or ""),
                "path": str(match.get("path") or ""),
                "ts": float(match.get("ts") or 0.0),
            }}
            route_key, check_id = entry["route_key"], entry["check_id"]
            hits = [f for f in runner.findings
                    if f["check"] == check_id and f["route_key"] == route_key]
            if hits:
                for f in hits:
                    f["confidence"] = "confirmed"
                    f["evidence"].update(ev)
            else:
                runner.add_finding(entry["route"], check_id, "confirmed",
                                   dict(ev))


def run_checks(ctx: CheckContext) -> dict:
    """Run every active check against the target model.

    Returns the ``rsecopsx.dast_findings/v1`` envelope: findings sorted by
    (route_key, check) plus machine-readable stats (per-check counts,
    skips with reasons, route aborts, probe total).
    """
    runner = _Runner(ctx)
    routes = sorted(list(ctx.routes or []),
                    key=lambda r: str(r.get("route_key") or ""))
    active: list[dict] = []
    for c in CHECKS:
        if c.get("live_only") and not ctx.live:
            runner.skips.append({"check": c["id"], "route_key": "*",
                                 "reason": "live_only"})
        else:
            active.append(c)
    # Host-level check runs once, anchored on the first route (or a stub).
    if any(c["id"] == "dast.tls_grade" for c in active):
        _ck_tls(routes[0] if routes else
                {"route_key": "TLS", "method": "GET", "path": "/"}, runner)
    route_checks = [c for c in active if c["id"] != "dast.tls_grade"]
    passive = [c["id"] for c in route_checks if c["mode"] == "passive"]
    probes = [c["id"] for c in route_checks if c["mode"] == "probe"]

    for route in routes:
        runner.begin_route(route)
        # T-5.5: excluded paths get NO fetch at all -- the baseline would
        # log an authenticated scan out mid-run (DVWA's /logout.php).
        if _excluded_route(route, ctx):
            for c in route_checks:
                runner.skip(c["id"], "excluded_path")
            continue
        # Baseline: the route's own method (GET for destructive routes),
        # sent with a foreign Origin so the CORS check has something to
        # reflect.
        url, method, data = _build_request(ctx, route)
        baseline = runner._fetch(url, method=method, data=data,
                                 headers={"Origin": CORS_ORIGIN})
        if baseline is None:
            for c in route_checks:
                runner.skip(c["id"], "baseline_unreachable")
            continue
        if baseline.status == 429:
            # Observed rate-limit finding + backoff were recorded in
            # _fetch; every other check on this route is disclosed skip.
            for c in route_checks:
                if c["id"] != "dast.rate_limit":
                    runner.skip(c["id"], "route_aborted_429")
            continue
        for cid in passive:
            _PASSIVE[cid](route, baseline, runner)
        if _method_of(route) not in ("GET", "POST"):
            for cid in probes:
                runner.skip(cid, "safe_mode_destructive_verb")
            continue
        for cid in probes:
            reason = runner.block_reason()
            if reason:
                runner.skip(cid, reason)
                continue
            _PROBES[cid](route, runner)

    # T-5.4: confirm OOB callbacks once every route has been probed.
    _oob_promote(ctx, runner)

    findings = sorted(runner.findings,
                      key=lambda f: (f["route_key"], f["check"]))
    by_check: dict[str, int] = {}
    for f in findings:
        by_check[f["check"]] = by_check.get(f["check"], 0) + 1
    return {
        "schema": FINDINGS_SCHEMA,
        "findings": findings,
        "stats": {
            "routes": len(routes),
            "findings": len(findings),
            "probed_requests": runner.probed_requests,
            "by_check": dict(sorted(by_check.items())),
            "skips": runner.skips,
            "aborts": runner.aborts,
            "oob_confirmed": runner.oob_confirmed,
        },
    }


# ---------------------------------------------------------------------------
# Real transport (opt-in; the suite injects its own fetch)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                         # 3xx arrives as HTTPError


def default_probe_fetch(url: str, timeout_s: float, user_agent: str,
                        headers=None, data=None,
                        method: str = "GET") -> ProbeResponse:
    """GET/POST one URL with stdlib urllib.

    Same-origin 3xx are followed (``_redirect_target``, bounded by
    ``MAX_REDIRECT_HOPS``) so canonicalizing targets -- Apache's
    trailing-slash 301, which every DVWA vuln directory issues -- are
    probed for real instead of returning the redirect stub page.
    Method+body are preserved across 301/302/307/308 (we are probing,
    not browsing; 301 directory canonicalization must re-POST to run);
    303 switches to GET per spec.  Cross-origin 3xx are returned
    UNFOLLOWED: that Location IS the open-redirect signal
    (``_detect_redirect`` reads it off the response).
    """
    hdrs = {"User-Agent": user_agent, "Accept": "*/*"}
    hdrs.update({str(k): str(v) for k, v in (headers or {}).items()})
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urlencode(data).encode("utf-8")
            hdrs.setdefault("Content-Type",
                            "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = bytes(data)
    opener = urllib.request.build_opener(_NoRedirect)
    cur_url, cur_method, cur_body = url, (method or "GET"), body
    for _hop in range(MAX_REDIRECT_HOPS + 1):
        req = urllib.request.Request(cur_url, data=cur_body, headers=hdrs,
                                     method=cur_method)
        try:
            with opener.open(req, timeout=timeout_s) as resp:
                raw = resp.read(MAX_SOURCE_BYTES)
                return ProbeResponse(
                    url=cur_url, status=resp.status,
                    headers={k.lower(): v
                             for k, v in resp.headers.items()},
                    body=raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as he:  # 3xx/4xx/5xx/429 as a response
            rhdrs = {k.lower(): v
                     for k, v in (he.headers.items() if he.headers else [])}
            nxt = _redirect_target(he.code, rhdrs, cur_url, url)
            if nxt is not None and _hop < MAX_REDIRECT_HOPS:
                cur_url = nxt
                if he.code == 303:           # See Other: always becomes GET
                    cur_method, cur_body = "GET", None
                continue
            raw = he.read(MAX_SOURCE_BYTES)
            return ProbeResponse(
                url=cur_url, status=he.code, headers=rhdrs,
                body=raw.decode("utf-8", "replace"))
    return ProbeResponse(url=cur_url, status=0, headers={}, body="")


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="python -m analysis.dast.checks",
        description="Run T-5.3 active checks over a target-model JSON.")
    ap.add_argument("--model", required=True,
                    help="target-model JSON from analysis.dast.target_model")
    ap.add_argument("--base-url", default="http://127.0.0.1/",
                    help="probe origin (scope allowlist anchor)")
    ap.add_argument("--profiles", help="T-5.2 auth profiles JSON")
    ap.add_argument("--out", help="write findings JSON here")
    ap.add_argument("--aggressive", action="store_true",
                    help="allow the bounded rate-limit burst probe")
    ap.add_argument("--live", action="store_true",
                    help="allow the live TLS handshake check")
    ap.add_argument("--oob-host", default=None,
                    help="enable OOB callbacks via a listener whose public "
                         "host the target can reach (e.g. oob.example.test)")
    ap.add_argument("--oob-wait", type=float, default=0.0,
                    help="seconds to wait for OOB interactions per token "
                         "(0 = non-blocking drain)")
    args = ap.parse_args(argv)
    path = Path(args.model)
    try:
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("model too large")
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot read model: {exc}")
        return 2
    routes = list(doc.get("routes") or [])
    sessions: dict = {}
    errors: list = []
    if args.profiles:
        profiles, errors = load_profiles(args.profiles)
        sessions = build_sessions(profiles)
    oob = None
    if args.oob_host:
        from analysis.dast.oob import OOBClient                 # noqa: PLC0415
        oob = OOBClient(public_host=args.oob_host)
    ctx = CheckContext(base_url=args.base_url, routes=routes,
                       fetch=default_probe_fetch, sessions=sessions or None,
                       aggressive=args.aggressive, live=args.live,
                       oob=oob, oob_wait_s=args.oob_wait)
    out = run_checks(ctx)
    blob = json.dumps(out, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(blob, "utf-8")
    else:
        print(blob, end="")
    return 1 if errors else 0


if __name__ == "__main__":        # pragma: no cover - CLI entry
    raise SystemExit(main())
