"""Bearer-token authentication + role checks for the serve API (T-9.1).

OIDC/SAML full-flow SSO is NOT adopted: IdP discovery / JWKS round-trips
and SAML XML-DSig verification require network fetches and undeclared
crypto dependencies, which would break the offline/airgap invariant of
this package (petgraph/axum/Rego precedent). The offline-substitutable
subset is implemented instead: operator-issued static bearer tokens
(issued out-of-band, compared with hmac.compare_digest) plus OIDC-style
JWTs validated as HS256 with the stdlib hmac module only -- an operator
who controls the HS256 secret (the deployment's own "IdP") mints
compatible tokens with any OIDC tooling.

Roles (RBAC): "viewer" (read API state) < "editor" (may enqueue scan
jobs) < "admin" (may mutate schedules/webhooks). Health stays OPEN with
auth enabled -- liveness must never depend on credentials.

Tenancy (T-9.2): a token entry may declare ``"tenant": "<name>"`` and a
JWT may carry a ``tenant`` claim; the principal then gains a "tenant"
key and every API read/write is scoped to it.  Credentials WITHOUT a
tenant are UNSCOPED operators (they see every tenant -- single-tenant
deployments therefore behave exactly as before).  A bad tenant in a
JWT claim is invalid_credentials, never a silent fall-back to
unscoped: dropping tenant scope silently would be an escalation.

JWT validation pins (each has a machine reason): header alg MUST be
"HS256" (rejects alg-none and every asymmetric-alg confusion attempt),
"exp" is REQUIRED (a token without an expiry is invalid_credentials),
optional "nbf" yields jwt_not_yet_valid, issuer/audience are checked
only when configured (aud may be a string or a list containing the
configured value), "sub" must be a non-empty string. A token with NO
role claim defaults to "viewer" -- least privilege; map real roles at
the IdP by minting the claim. If a string matches a configured static
token, that wins over JWT parsing.

audit_entry() is a PURE function producing the fixed audit shape
{actor, decision, method, path, reason, role, status, ts} -- one line
per request, allowed and denied alike; callers append it (see
connect.py --audit-log) or forward it (api.py audit_fn). Exceptions
raised by an audit sink PROPAGATE (an audit log that silently fails is
worse than a failed request); this is disclosed in the docstrings.
"""
import base64
import hashlib
import hmac
import json
import pathlib

ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}

_AUDIT_KEYS = frozenset(
    {"actor", "decision", "method", "path", "reason", "role", "status",
     "ts"})


class AuthInvalid(Exception):
    """Auth configuration could not be interpreted; .reason is a machine string."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class AuthConfig:
    """Normalized auth configuration (tokens + optional JWT settings)."""

    __slots__ = ("tokens", "jwt_secret", "jwt_issuer", "jwt_audience")

    def __init__(self, tokens, jwt_secret=None, jwt_issuer=None,
                 jwt_audience=None):
        self.tokens = tuple(tokens)
        self.jwt_secret = jwt_secret
        self.jwt_issuer = jwt_issuer
        self.jwt_audience = jwt_audience


def load_auth_file(path):
    """Load and STRICTLY validate an auth JSON file.

    Every authoring mistake is a loud AuthInvalid with a machine reason:
    a mis-typed role or a token without a name must never silently fall
    back to "allow".
    """
    try:
        raw = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError:
        raise AuthInvalid("auth_file_unreadable") from None
    try:
        doc = json.loads(raw)
    except ValueError:
        raise AuthInvalid("auth_unreadable_json") from None
    if not isinstance(doc, dict):
        raise AuthInvalid("auth_not_object")

    tokens_raw = doc.get("tokens", [])
    if not isinstance(tokens_raw, list):
        raise AuthInvalid("auth_tokens_invalid")
    tokens = []
    for i, item in enumerate(tokens_raw):
        if not isinstance(item, dict):
            raise AuthInvalid(f"token_not_object:{i}")
        for key in ("name", "token", "role"):
            value = item.get(key)
            if not isinstance(value, str) or not value:
                raise AuthInvalid(f"token_missing:{i}:{key}")
        role = item["role"]
        if role not in ROLE_RANK:
            raise AuthInvalid(f"token_bad_role:{i}:{role}")
        entry = {"name": item["name"], "token": item["token"],
                 "role": role}
        if "tenant" in item:
            tenant = item["tenant"]
            if not isinstance(tenant, str) or not tenant:
                raise AuthInvalid(f"tenant_invalid:{i}")
            entry["tenant"] = tenant
        tokens.append(entry)

    jwt_secret = jwt_issuer = jwt_audience = None
    if "jwt" in doc:
        jwt_doc = doc["jwt"]
        if not isinstance(jwt_doc, dict):
            raise AuthInvalid("jwt_invalid")
        if not isinstance(jwt_doc.get("secret"), str) or \
                not jwt_doc.get("secret"):
            raise AuthInvalid("jwt_secret_missing")
        jwt_secret = jwt_doc["secret"]
        for key in ("issuer", "audience"):
            if key not in jwt_doc:
                continue
            value = jwt_doc[key]
            if key == "audience" and isinstance(value, list):
                if not all(isinstance(v, str) for v in value):
                    raise AuthInvalid(f"jwt_bad_field:{key}")
            elif not isinstance(value, str):
                raise AuthInvalid(f"jwt_bad_field:{key}")
            if key == "issuer":
                jwt_issuer = value
            else:
                jwt_audience = value
    return AuthConfig(tokens, jwt_secret=jwt_secret,
                      jwt_issuer=jwt_issuer, jwt_audience=jwt_audience)


def required_role(method, path):
    """Minimum role for a request; None = open (health only)."""
    if path == "/v1/health":
        return None
    if method == "GET":
        return "viewer"
    if method == "POST":
        if path == "/v1/jobs":
            return "editor"
        return "admin"
    return "admin"


def _b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _verify_jwt(config, token, now):
    parts = token.split(".")
    if len(parts) != 3:
        return None, "invalid_credentials"
    head_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(head_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except (ValueError, UnicodeDecodeError):
        return None, "invalid_credentials"
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        return None, "invalid_credentials"
    if not isinstance(claims, dict):
        return None, "invalid_credentials"
    expected = hmac.new(
        config.jwt_secret.encode("utf-8"),
        f"{head_b64}.{payload_b64}".encode("ascii"),
        hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None, "invalid_credentials"
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None, "invalid_credentials"
    if now >= exp:
        return None, "jwt_expired"
    nbf = claims.get("nbf")
    if nbf is not None and not isinstance(nbf, bool) and \
            isinstance(nbf, (int, float)) and now < nbf:
        return None, "jwt_not_yet_valid"
    if config.jwt_issuer is not None and \
            claims.get("iss") != config.jwt_issuer:
        return None, "invalid_credentials"
    if config.jwt_audience is not None:
        aud = claims.get("aud")
        candidates = aud if isinstance(aud, list) else [aud]
        allowed = (config.jwt_audience
                   if isinstance(config.jwt_audience, list)
                   else [config.jwt_audience])
        if not any(a in candidates for a in allowed):
            return None, "invalid_credentials"
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        return None, "invalid_credentials"
    role = claims.get("role", "viewer")
    if role not in ROLE_RANK:
        role = "viewer"
    principal = {"actor": sub, "role": role}
    tenant = claims.get("tenant")
    if tenant is not None:
        # a malformed tenant claim must never degrade to unscoped
        if not isinstance(tenant, str) or not tenant:
            return None, "invalid_credentials"
        principal["tenant"] = tenant
    return principal, None


def verify(config, header, now):
    """Verify an Authorization header value.

    Returns (principal, None) or (None, reason). Reasons:
    missing_credentials, bad_credentials_scheme, invalid_credentials,
    jwt_expired, jwt_not_yet_valid. Never raises on hostile input.
    """
    if not header or not header.strip():
        return None, "missing_credentials"
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        if scheme.lower() != "bearer":
            return None, "bad_credentials_scheme"
        return None, "missing_credentials"
    value = value.strip()
    for entry in config.tokens:
        if hmac.compare_digest(entry["token"], value):
            principal = {"actor": entry["name"], "role": entry["role"]}
            if entry.get("tenant"):      # absent key = unscoped operator
                principal["tenant"] = entry["tenant"]
            return principal, None
    if config.jwt_secret is not None:
        return _verify_jwt(config, value, now)
    return None, "invalid_credentials"


def audit_entry(method, path, status, decision, actor=None, role=None,
                reason=None, ts=0.0):
    """One audit record per request; FIXED key set, canonical when dumped."""
    return {"actor": actor, "decision": decision, "method": method,
            "path": path, "reason": reason, "role": role,
            "status": status, "ts": ts}
