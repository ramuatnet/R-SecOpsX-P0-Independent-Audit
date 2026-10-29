"""T-5.2: DAST authentication -- profiles, sessions, replay, differential.

Five strategies over one profile model:

* ``none``       unauthenticated baseline (the negative control);
* ``bearer``     static ``Authorization: Bearer`` header;
* ``cookie``     pre-supplied cookie jar;
* ``form``       GET the login page (harvest hidden inputs + cookies),
                 POST credentials, absorb Set-Cookie across redirects,
                 optional ``verify_regex`` on the landing body;
* ``oauth2_cc``  client-credentials token grant (Basic or post style);
* ``script``     scripted login hook for exotic flows -- run isolated
                 (``python -I``), time-capped, output-capped, opt-in.

Session REPORTS are redacted by construction: header/cookie NAMES only,
never values -- tokens and passwords must not reach artifacts on disk.
Every failure is a status string (``error:http_401``,
``error:script_timeout``, ...), never an exception.

``SessionReplay`` re-establishes sessions inside the 60s expiry skew;
``differential`` diffs per-role route inventories for the T-5.3
IDOR/broken-access-control work.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import urlencode, urljoin

AUTH_PROFILE_SCHEMA = "rsecopsx.dast_auth_profile/v1"
SESSION_REPORT_SCHEMA = "rsecopsx.dast_auth_session/v1"
DIFFERENTIAL_SCHEMA = "rsecopsx.dast_auth_differential/v1"

DEFAULT_USER_AGENT = "R-SecOpsX-DAST/0.1 (+auth)"
REPLAY_SKEW_S = 60.0
MAX_PROFILE_BYTES = 1024 * 1024
MAX_SCRIPT_OUTPUT = 64 * 1024
MAX_REDIRECTS = 3

STRATEGIES = frozenset(
    {"none", "bearer", "cookie", "form", "oauth2_cc", "script"})

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class ProfileLimits:
    max_bytes: int = MAX_PROFILE_BYTES
    max_script_output: int = MAX_SCRIPT_OUTPUT
    default_script_timeout_s: float = 30.0


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthProfile:
    name: str
    strategy: str
    config: dict = field(default_factory=dict)

    @staticmethod
    def from_dict(d: Mapping) -> tuple[Optional["AuthProfile"], Optional[str]]:
        if not isinstance(d, Mapping):
            return None, "profile is not an object"
        name = str(d.get("name") or "").strip()
        if not name:
            return None, "profile missing name"
        strategy = str(d.get("strategy") or "").strip().lower()
        if strategy not in STRATEGIES:
            return None, f"profile {name!r}: unknown strategy {strategy!r}"
        config = d.get("config")
        if not isinstance(config, dict):
            return None, f"profile {name!r}: config must be an object"
        need = {
            "bearer": ("token",),
            "cookie": ("cookies",),
            "form": ("url", "username", "password"),
            "oauth2_cc": ("token_url", "client_id", "client_secret"),
            "script": ("path",),
            "none": (),
        }[strategy]
        for key in need:
            if not config.get(key):
                return None, f"profile {name!r}: {strategy} requires config.{key}"
        if strategy == "cookie" and not isinstance(config.get("cookies"), dict):
            return None, f"profile {name!r}: config.cookies must be an object"
        return AuthProfile(name=name, strategy=strategy, config=dict(config)), None


def load_profiles(path,
                  limits: Optional[ProfileLimits] = None
                  ) -> tuple[list[AuthProfile], list[str]]:
    """Load a profile file (schema-stamped JSON).  Errors are strings, rows."""
    limits = limits or ProfileLimits()
    p = Path(path)
    try:
        if p.stat().st_size > limits.max_bytes:
            return [], ["toobig"]
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"unreadable:{exc.__class__.__name__}"]
    try:
        doc = json.loads(text)
    except Exception:
        return [], ["parse_error"]
    rows = doc.get("profiles") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        return [], ["parse_error"]
    profiles: list[AuthProfile] = []
    errors: list[str] = []
    for i, row in enumerate(rows):
        prof, err = AuthProfile.from_dict(row)
        if prof is None:
            errors.append(f"profile[{i}]: {err}")
        else:
            profiles.append(prof)
    return profiles, errors


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthSession:
    name: str
    strategy: str
    headers: Mapping[str, str]
    expires_at: Optional[float]
    status: str                      # "ok" | "error:..."
    verified: Optional[bool]         # form login only; None elsewhere

    def report(self) -> dict:
        """REDACTED view: names and metadata only, never values."""
        cookies: list[str] = []
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            name = part.split("=", 1)[0].strip()
            if name:
                cookies.append(name)
        return {
            "schema": SESSION_REPORT_SCHEMA,
            "name": self.name,
            "strategy": self.strategy,
            "status": self.status,
            "verified": self.verified,
            "expires_at": self.expires_at,
            "header_names": sorted(self.headers),
            "cookie_names": sorted(set(cookies)),
        }


def session_headers(session: AuthSession) -> dict:
    """The headers to attach to requests made as this session."""
    return dict(session.headers)


def _ok(name, strategy, headers, expires_at=None, verified=None) -> AuthSession:
    return AuthSession(name=name, strategy=strategy, headers=dict(headers),
                       expires_at=expires_at, status="ok", verified=verified)


def _err(name, strategy, status: str) -> AuthSession:
    return AuthSession(name=name, strategy=strategy, headers={},
                       expires_at=None, status=status, verified=None)


# ---------------------------------------------------------------------------
# Transport (fetch-injected everywhere; urllib only in the default)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthResponse:
    url: str
    status: int
    header_items: list                # [(name, value), ...] -- all pairs
    body: str

    def header(self, name: str) -> Optional[str]:
        lname = name.lower()
        for k, v in self.header_items:
            if str(k).lower() == lname:
                return str(v)
        return None


def default_auth_fetch(url: str, timeout_s: float, user_agent: str,
                       method: str = "GET", data: Optional[dict] = None,
                       headers: Optional[Mapping[str, str]] = None
                       ) -> AuthResponse:
    """stdlib urllib fetch WITHOUT auto-redirect (login flows must see the
    302's Set-Cookie).  Raises on transport failure -- callers disclose."""
    import urllib.error
    import urllib.request

    class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None                # refuse -> HTTPError carries the 3xx

    opener = urllib.request.build_opener(_NoRedirectHandler)
    body = urlencode(data).encode("utf-8") if data is not None else None
    hdrs = {"User-Agent": user_agent}
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            payload = resp.read()
            items = list(resp.headers.items())
            final_url = resp.geturl()
            status = resp.status
    except urllib.error.HTTPError as he:
        # Refused redirect (or real error): HTTPError IS a response.
        payload = he.read()
        items = list(he.headers.items()) if he.headers else []
        final_url = he.geturl() if hasattr(he, "geturl") else url
        status = he.code
    return AuthResponse(url=final_url, status=status, header_items=items,
                        body=payload.decode("utf-8", "replace"))


def _cookie_dict(response: AuthResponse) -> dict:
    """All Set-Cookie pairs -> {name: value} (later hops win)."""
    out: dict = {}
    for k, v in response.header_items:
        if str(k).lower() != "set-cookie":
            continue
        first = str(v).split(";", 1)[0]
        if "=" in first:
            name, _, value = first.partition("=")
            out[name.strip()] = value.strip()
    return out


def _cookie_header(jar: Mapping[str, str]) -> str:
    return "; ".join(f"{k}={jar[k]}" for k in sorted(jar))


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------

_HIDDEN_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r"(\w[\w-]*)\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)


def _hidden_inputs(html: str) -> dict:
    """Hidden form inputs (CSRF tokens etc.) via tag regex -- disclosed:
    regex-level extraction, not a DOM; the scripted hook covers the rest."""
    out: dict = {}
    for tag in _HIDDEN_INPUT_RE.findall(html or ""):
        attrs = dict(_ATTR_RE.findall(tag))
        if str(attrs.get("type", "")).lower() == "hidden" and attrs.get("name"):
            out[attrs["name"]] = attrs.get("value", "")
    return out


def _form_session(p: AuthProfile, fetch, timeout_s: float,
                  ua: str) -> AuthSession:
    cfg = p.config
    jar: dict = {}
    login_url = str(cfg["url"])
    try:
        page = fetch(login_url, timeout_s, ua, method="GET")
    except Exception as exc:                       # noqa: BLE001
        return _err(p.name, p.strategy, f"error:{exc.__class__.__name__}")
    if page.status >= 400:
        return _err(p.name, p.strategy, f"error:http_{page.status}")
    jar.update(_cookie_dict(page))

    data = {
        str(cfg.get("username_field") or "username"): str(cfg["username"]),
        str(cfg.get("password_field") or "password"): str(cfg["password"]),
    }
    extra = cfg.get("extra")
    if isinstance(extra, dict):
        data.update({str(k): str(v) for k, v in extra.items()})
    if cfg.get("csrf_from_page", True):
        data.update(_hidden_inputs(page.body))

    submit_url = str(cfg.get("submit_url") or login_url)
    headers = {"Cookie": _cookie_header(jar)} if jar else {}
    try:
        resp = fetch(submit_url, timeout_s, ua, method="POST",
                     data=data, headers=headers)
    except Exception as exc:                       # noqa: BLE001
        return _err(p.name, p.strategy, f"error:{exc.__class__.__name__}")
    jar.update(_cookie_dict(resp))

    hops = 0
    while resp.status in _REDIRECT_STATUSES and hops < MAX_REDIRECTS:
        location = resp.header("location")
        if not location:
            break
        nxt = urljoin(resp.url or submit_url, location)
        try:
            resp = fetch(nxt, timeout_s, ua,
                         headers={"Cookie": _cookie_header(jar)} if jar else {})
        except Exception as exc:                   # noqa: BLE001
            return _err(p.name, p.strategy, f"error:{exc.__class__.__name__}")
        jar.update(_cookie_dict(resp))
        hops += 1

    if resp.status >= 400:
        return _err(p.name, p.strategy, f"error:http_{resp.status}")

    verified: Optional[bool] = None
    pattern = cfg.get("verify_regex")
    if pattern:
        try:
            verified = re.search(str(pattern), resp.body or "") is not None
        except re.error:
            verified = None                        # bad pattern: disclose via None
    headers_out = {"Cookie": _cookie_header(jar)} if jar else {}
    return _ok(p.name, p.strategy, headers_out, verified=verified)


def _oauth2_session(p: AuthProfile, fetch, timeout_s: float, ua: str,
                    now: Callable[[], float]) -> AuthSession:
    cfg = p.config
    form = {
        "grant_type": "client_credentials",
        "client_id": str(cfg["client_id"]),
        "client_secret": str(cfg["client_secret"]),
    }
    if cfg.get("scope"):
        form["scope"] = str(cfg["scope"])
    if cfg.get("audience"):
        form["audience"] = str(cfg["audience"])
    style = str(cfg.get("auth_style") or "client_secret_basic")
    headers: dict = {}
    if style == "client_secret_basic":
        cred = base64.b64encode(
            f"{cfg['client_id']}:{cfg['client_secret']}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {cred}"
        form.pop("client_secret", None)
        form.pop("client_id", None)
    try:
        resp = fetch(str(cfg["token_url"]), timeout_s, ua, method="POST",
                     data=form, headers=headers)
    except Exception as exc:                       # noqa: BLE001
        return _err(p.name, p.strategy, f"error:{exc.__class__.__name__}")
    if resp.status in (401, 403):
        return _err(p.name, p.strategy, "error:unauthorized")
    if resp.status >= 400:
        return _err(p.name, p.strategy, f"error:http_{resp.status}")
    try:
        doc = json.loads(resp.body)
        token = str(doc["access_token"])
        expires_in = float(doc.get("expires_in", 3600))
    except Exception:
        return _err(p.name, p.strategy, "error:token_response")
    return _ok(p.name, p.strategy,
               {"Authorization": f"Bearer {token}"},
               expires_at=now() + expires_in)


def _script_session(p: AuthProfile, runner, limits: ProfileLimits
                    ) -> AuthSession:
    timeout_s = float(p.config.get("timeout_s") or limits.default_script_timeout_s)
    runner = runner or _default_script_runner
    try:
        doc = runner(str(p.config["path"]), timeout_s)
    except subprocess.TimeoutExpired:
        return _err(p.name, p.strategy, "error:script_timeout")
    except Exception as exc:                              # noqa: BLE001
        msg = str(exc)
        if msg.startswith("script_rc_"):
            return _err(p.name, p.strategy, f"error:{msg}")
        return _err(p.name, p.strategy, "error:script_failed")
    if not isinstance(doc, dict):
        return _err(p.name, p.strategy, "error:script_output")
    headers: dict = {}
    raw_headers = doc.get("headers")
    if isinstance(raw_headers, dict):
        headers.update({str(k): str(v) for k, v in raw_headers.items()})
    cookies = doc.get("cookies")
    if isinstance(cookies, dict) and cookies:
        merged = dict(_parse_cookie_header(headers.get("Cookie", "")))
        merged.update({str(k): str(v) for k, v in cookies.items()})
        headers["Cookie"] = _cookie_header(merged)
    status = str(doc.get("status") or "ok")
    if not status.startswith("error") and status != "ok":
        status = "ok"                              # any other value: usable
    if status.startswith("error"):
        return AuthSession(name=p.name, strategy=p.strategy, headers={},
                           expires_at=None, status=status, verified=None)
    return _ok(p.name, p.strategy, headers)


def _parse_cookie_header(raw: str) -> dict:
    out: dict = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


def _default_script_runner(path: str, timeout_s: float) -> dict:
    """Run the login hook isolated: python -I, bounded output, DEVNULL stdin.

    The hook runs with the invoking user's privileges (same as any
    --test-cmd in this repo) -- opt-in by profile, never auto-discovered.
    """
    proc = subprocess.run(
        [sys.executable, "-I", path],
        capture_output=True, timeout=timeout_s, stdin=subprocess.DEVNULL,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if proc.returncode != 0:
        raise RuntimeError(f"script_rc_{proc.returncode}")
    out = proc.stdout[:ProfileLimits().max_script_output]
    return json.loads(out.decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_session(profile: AuthProfile, *,
                  fetch=None,
                  now: Callable[[], float] = time.time,
                  script_runner=None,
                  timeout_s: float = 10.0,
                  limits: Optional[ProfileLimits] = None) -> AuthSession:
    """Materialize one session.  Never raises -- errors are statuses."""
    limits = limits or ProfileLimits()
    fetch = fetch or default_auth_fetch
    try:
        if profile.strategy == "none":
            return _ok(profile.name, "none", {})
        if profile.strategy == "bearer":
            token = str(profile.config.get("token") or "")
            scheme = str(profile.config.get("scheme") or "Bearer")
            return _ok(profile.name, "bearer",
                       {"Authorization": f"{scheme} {token}"})
        if profile.strategy == "cookie":
            jar = {str(k): str(v)
                   for k, v in profile.config.get("cookies", {}).items()}
            return _ok(profile.name, "cookie",
                       {"Cookie": _cookie_header(jar)} if jar else {})
        if profile.strategy == "form":
            return _form_session(profile, fetch, timeout_s, DEFAULT_USER_AGENT)
        if profile.strategy == "oauth2_cc":
            return _oauth2_session(profile, fetch, timeout_s,
                                   DEFAULT_USER_AGENT, now)
        if profile.strategy == "script":
            return _script_session(profile, script_runner, limits)
        return _err(profile.name, profile.strategy, "error:unknown_strategy")
    except re.error:
        return _err(profile.name, profile.strategy, "error:bad_verify_regex")


def build_sessions(profiles: Iterable[AuthProfile], **kwargs) -> dict:
    """Materialize every profile, isolated: one failure never stops the rest."""
    return {p.name: build_session(p, **kwargs) for p in profiles}


# ---------------------------------------------------------------------------
# Session replay
# ---------------------------------------------------------------------------

class SessionReplay:
    """Cached sessions with 60s expiry skew; errors are never cached."""

    def __init__(self, profiles: Iterable[AuthProfile], *,
                 fetch=None, now: Callable[[], float] = time.time,
                 script_runner=None, timeout_s: float = 10.0,
                 skew_s: float = REPLAY_SKEW_S):
        self._by_name = {p.name: p for p in profiles}
        self._cache: dict[str, AuthSession] = {}
        self._fetch = fetch
        self._now = now
        self._script_runner = script_runner
        self._timeout_s = timeout_s
        self._skew = skew_s

    def session(self, name: str) -> AuthSession:
        profile = self._by_name.get(name)
        if profile is None:
            return _err(name, "none", "error:unknown_profile")
        cached = self._cache.get(name)
        now = self._now()
        if cached is not None:
            fresh = (cached.expires_at is None
                     or now < cached.expires_at - self._skew)
            if cached.status == "ok" and fresh:
                return cached
        session = build_session(profile, fetch=self._fetch, now=self._now,
                                script_runner=self._script_runner,
                                timeout_s=self._timeout_s)
        if session.status == "ok":
            self._cache[name] = session
        else:
            self._cache.pop(name, None)            # retry next call
        return session


# ---------------------------------------------------------------------------
# Multi-role differential
# ---------------------------------------------------------------------------

def differential(role_routes: Mapping[str, Iterable[str]]) -> dict:
    """Diff per-role route inventories (the IDOR/broken-AC seed).

    Pure: takes already-crawled route-key sets per role, returns who can
    see what, what is unique to a role, and what each role is HIDDEN from
    (the routes worth cross-role probing in T-5.3).
    """
    roles = sorted(role_routes)
    sets = {r: set(role_routes[r]) for r in roles}
    universe = sorted(set().union(*sets.values())) if sets else []
    visible_to = {
        k: [r for r in roles if k in sets[r]] for k in universe
    }
    return {
        "schema": DIFFERENTIAL_SCHEMA,
        "roles": roles,
        "routes": len(universe),
        "visible_to": visible_to,
        "role_unique": {
            r: [k for k in universe if visible_to[k] == [r]] for r in roles
        },
        "hidden_from": {
            r: [k for k in universe if r not in visible_to[k]] for r in roles
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="python -m analysis.dast.auth",
        description="Materialize DAST auth sessions (redacted report).")
    ap.add_argument("profiles", help="auth profile JSON file")
    ap.add_argument("--out", default=None, help="write redacted report here")
    args = ap.parse_args(argv)

    profiles, errors = load_profiles(args.profiles)
    sessions = build_sessions(profiles)
    doc = {
        "schema": SESSION_REPORT_SCHEMA,
        "sessions": {n: s.report() for n, s in sessions.items()},
        "errors": errors,
        "stats": {
            "profiles": len(profiles),
            "ok": sum(1 for s in sessions.values() if s.status == "ok"),
            "errors": len(errors) + sum(
                1 for s in sessions.values() if s.status != "ok"),
        },
    }
    text = json.dumps(doc, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"[dast-auth] ok={doc['stats']['ok']} "
              f"errors={doc['stats']['errors']} -> {args.out}")
    else:
        print(text)
    if not profiles or errors or any(
            s.status != "ok" for s in sessions.values()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
