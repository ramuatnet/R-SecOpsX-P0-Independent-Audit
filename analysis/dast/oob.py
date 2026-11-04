"""T-5.4: Interactsh-style OOB callback listener for blind SSRF/XXE/RCE.

Model: the client mints a unique 32-hex correlation token and embeds
``http://{token}.oob.{public_host}/{kind}`` in a probe payload.  When the
vulnerable target resolves that hostname (DNS) or fetches it (HTTP), the
listener records an interaction against the token and the owning check
is confirmed (``confidence: confirmed`` with an ``oob_interaction``
evidence row) -- the callback IS the evidence for blind bugs.

Everything protocol-shaped is pure and offline-testable:

* token minting / URL construction (injected rng);
* ``parse_dns_qname`` / ``build_dns_response`` (byte-level, no sockets);
* ``handle_callback`` / ``handle_dns_query`` (record or reject);
* ``InteractionStore`` (bounded: cap per token, body truncation,
  header allowlist -- resource bounds for untrusted callbacks);
* ``OOBClient.confirm`` (injected clock/sleep; timeout-bounded).

The only socket-bearing pieces are the two live servers assembled by
``OOBService`` (HTTP + UDP DNS), started only by ``serve`` -- they are
not exercised by the offline suite (disclosed, like the T-5.3 live TLS
path).  Tokens are allowlisted at mint time so a hostile party
hammering the listener with well-formed but unissued tokens cannot
grow the store (``404`` / not recorded).

Safety defaults: servers bind 127.0.0.1; the reserved
``oob.example.test`` is the default public host (never resolves
anywhere).  A real engagement points ``--public-host`` at a host the
TARGET can reach (self-hosted listener on a public address, or a
tunnel) and binds accordingly.
"""
from __future__ import annotations
try:
    from analysis.spans import (
    WINDOW_0, WINDOW_12, WINDOW_2, WINDOW_4, WINDOW_6)
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import (
    WINDOW_0, WINDOW_12, WINDOW_2, WINDOW_4, WINDOW_6)

import binascii
import json
import secrets
import time
from typing import Callable, Optional

TOKEN_HEX_LEN = 32
MAX_INTERACTION_BODY = 512
MAX_INTERACTIONS_PER_TOKEN = 20
INTERACTION_HEADER_ALLOW = ("host", "user-agent", "content-type",
                            "content-length")
DEFAULT_PUBLIC_HOST = "oob.example.test"
POLL_INTERVAL_S = 0.05

_TOKEN_LABEL = set("0123456789abcdef")


def _valid_token(s: str) -> bool:
    return (len(s) == TOKEN_HEX_LEN
            and all(c in _TOKEN_LABEL for c in s))


def _token_from_host(host: str) -> Optional[str]:
    host = str(host or "").strip().lower().split(":", 1)[0]
    first = host.split(".", 1)[0]
    return first if _valid_token(first) else None  # sast-ignore LLM06_SENSITIVE_INFORMATION_DISCLOSURE hostname tokeniser, no secret material


def _token_from_path(path: str) -> Optional[str]:
    for seg in str(path or "").split("/"):
        if _valid_token(seg):
            return seg
    return None


class InteractionStore:
    """Token -> bounded interaction list; mint allowlist + drop counters."""

    def __init__(self, now: Callable[[], float] = time.time,
                 max_per_token: int = MAX_INTERACTIONS_PER_TOKEN):
        self._now = now
        self._max = max(1, int(max_per_token))
        self._by_token: dict[str, list[dict]] = {}
        self._issued: set[str] = set()
        self.dropped = 0
        self.on_record: Optional[Callable[[dict], None]] = None

    def issue(self, token: str) -> None:
        self._issued.add(str(token).lower())

    def issued(self, token: str) -> bool:
        return str(token).lower() in self._issued

    def record(self, interaction: dict) -> bool:
        token = str(interaction.get("token") or "")
        if not _valid_token(token):
            return False
        bucket = self._by_token.setdefault(token, [])
        bucket.append(dict(interaction))
        while len(bucket) > self._max:
            bucket.pop(0)
            self.dropped += 1
        if self.on_record:
            self.on_record(dict(interaction))
        return True

    def peek(self, token: str) -> list[dict]:
        return list(self._by_token.get(str(token).lower(), []))

    def drain(self, token: str) -> list[dict]:
        """Consume every pending interaction for ``token`` (deterministic
        order by arrival)."""
        return self._by_token.pop(str(token).lower(), [])


def handle_callback(store: InteractionStore, *, method: str = "GET",
                    path: str = "/", host: str = "", headers=None,
                    body: str = "", client_ip: str = "",
                    now: Callable[[], float] = time.time) -> tuple[int, str]:
    """Pure HTTP-callback entry point: record if the token was minted."""
    token = _token_from_host(host) or _token_from_path(path)
    if not token or not store.issued(token):
        return 404, "unknown token"
    clean = {str(k).lower(): str(v)
             for k, v in dict(headers or {}).items()
             if str(k).lower() in INTERACTION_HEADER_ALLOW}
    store.record({
        "token": token,
        "proto": "http",
        "ts": float(now()),
        "host": str(host or ""),
        "path": str(path or ""),
        "method": str(method or ""),
        "client_ip": str(client_ip or ""),
        "body": str(body or "")[:MAX_INTERACTION_BODY],
        "headers": clean,
    })
    return 200, "ok"


def handle_dns_query(store: InteractionStore, *, qname: str,
                     client_ip: str = "",
                     now: Callable[[], float] = time.time) -> bool:
    """Pure DNS-callback entry point: record if the token was minted."""
    token = str(qname or "").strip(".").lower().split(".", 1)[0]
    if not _valid_token(token) or not store.issued(token):
        return False
    store.record({
        "token": token,
        "proto": "dns",
        "ts": float(now()),
        "host": str(qname or ""),
        "path": "",
        "method": "",
        "client_ip": str(client_ip or ""),
        "body": "",
        "headers": {},
    })
    return True


def parse_dns_qname(query: bytes) -> str:
    """Extract the QNAME from a DNS query datagram (empty if malformed)."""
    try:
        if len(query) < 12 or query[WINDOW_4:WINDOW_6] != b"\x00\x01":
            return ""
        labels: list[str] = []
        i = 12
        while i < len(query):
            n = query[i]
            if n == 0:
                break
            if n & 0xC0:                    # compression pointer: unsupported
                return ""
            i += 1
            labels.append(query[i:i + n].decode("ascii", "replace"))
            i += n
        else:
            return ""
        return ".".join(labels).lower()
    except (IndexError, UnicodeDecodeError):
        return ""


def build_dns_response(query: bytes) -> bytes:
    """Minimal A-record reply: echo id/question, answer 127.0.0.1."""
    try:
        if len(query) < 12:
            return b""
        i = 12
        while i < len(query) and query[i] != 0:
            i += 1 + query[i]
        question_end = i + 1 + 4            # null + qtype + qclass
        if question_end > len(query):
            return b""
        question = query[WINDOW_12:question_end]
        header = (query[WINDOW_0:WINDOW_2]                 # transaction id
                  + b"\x81\x80"              # QR + RD + RA + NOERROR
                  + b"\x00\x01\x00\x01\x00\x00\x00\x00")
        answer = (b"\xc0\x0c"                # pointer to QNAME
                  + b"\x00\x01\x00\x01"      # type A, class IN
                  + b"\x00\x00\x00\x3c"      # ttl 60
                  + b"\x00\x04"              # rdlength
                  + b"\x7f\x00\x00\x01")     # 127.0.0.1
        return header + question + answer
    except IndexError:
        return b""


class OOBClient:
    """Mints correlation tokens and waits for their interactions.

    In-process by design: the client shares the store with a locally
    running ``OOBService``, or -- in tests -- with a simulated callback.
    """

    def __init__(self, public_host: str = DEFAULT_PUBLIC_HOST,
                 store: Optional[InteractionStore] = None,
                 rng: Callable[[int], bytes] = secrets.token_bytes,
                 now: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 poll_interval: float = POLL_INTERVAL_S):
        self.public_host = str(public_host or DEFAULT_PUBLIC_HOST)
        self.store = store if store is not None else InteractionStore(now=now)
        self._rng = rng
        self.now = now
        self.sleep = sleep
        self.poll_interval = float(poll_interval)

    def mint(self, kind: str) -> tuple[str, str]:
        """(payload URL, token) for kind in {ssrf, xxe, rce}.

        The token is a subdomain of ``public_host``; the path names the
        check kind so a callback can be attributed back to it.
        """
        if kind not in ("ssrf", "xxe", "rce"):
            raise ValueError(f"unknown oob kind: {kind!r}")
        token = binascii.hexlify(self._rng(TOKEN_HEX_LEN // 2)) \
            .decode("ascii").lower()
        self.store.issue(token)
        url = f"http://{token}.{self.public_host}/{kind}"
        return url, token

    def collect(self, token: str, timeout: float = 0.0) -> list[dict]:
        """Every pending interaction for ``token`` (poll until first)."""
        deadline = self.now() + max(0.0, float(timeout))
        while True:
            got = self.store.drain(token)
            if got:
                return got
            remaining = deadline - self.now()
            if remaining <= 0:
                return []
            self.sleep(min(self.poll_interval, remaining))

    def confirm(self, token: str, timeout: float = 0.0) -> Optional[dict]:
        """First interaction for ``token``, polling until ``timeout``.

        timeout=0 is a non-blocking drain (the run_checks default; tests
        stay deterministic and never sleep).
        """
        got = self.collect(token, timeout=timeout)
        return got[0] if got else None


# ---------------------------------------------------------------------------
# Live service (opt-in; not exercised by the offline suite)
# ---------------------------------------------------------------------------

class OOBService:
    """HTTP + UDP DNS listeners writing into one store (loopback default)."""

    def __init__(self, store: InteractionStore, bind: str = "127.0.0.1",
                 http_port: int = 0, dns_port: int = 0,
                 now: Callable[[], float] = time.time):
        self.store = store
        self.bind = bind
        self.http_port = http_port
        self.dns_port = dns_port
        self._now = now
        self._httpd = None
        self._dns_sock = None
        self._threads: list = []

    def start(self) -> dict:
        import http.server
        import socket
        import threading

        store, now = self.store, self._now

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):    # noqa: D102 - silence access log
                return

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                length = min(length, MAX_INTERACTION_BODY * 64)
                body = self.rfile.read(length).decode("utf-8", "replace") \
                    if length else ""
                status, msg = handle_callback(
                    store, method=self.command, path=self.path,
                    host=self.headers.get("Host", ""),
                    headers=dict(self.headers.items()), body=body,
                    client_ip=self.client_address[0], now=now)
                payload = msg.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle

        self._httpd = http.server.ThreadingHTTPServer(
            (self.bind, self.http_port), _Handler)
        self.http_port = self._httpd.server_address[1]

        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns.settimeout(0.25)
        dns.bind((self.bind, self.dns_port))
        self._dns_sock = dns
        self.dns_port = dns.getsockname()[1]

        def _dns_loop():
            while self._dns_sock is not None:
                try:
                    data, addr = dns.recvfrom(512)
                except (TimeoutError, OSError):
                    continue
                qname = parse_dns_qname(data)
                handle_dns_query(store, qname=qname,
                                 client_ip=addr[0], now=now)
                reply = build_dns_response(data)
                if reply:
                    try:
                        dns.sendto(reply, addr)
                    except OSError:
                        pass

        t_http = threading.Thread(target=self._httpd.serve_forever,
                                  daemon=True)
        t_dns = threading.Thread(target=_dns_loop, daemon=True)
        t_http.start()
        t_dns.start()
        self._threads = [t_http, t_dns]
        return {"bind": self.bind, "http_port": self.http_port,
                "dns_port": self.dns_port}

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._dns_sock is not None:
            try:
                self._dns_sock.close()
            finally:
                self._dns_sock = None


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="python -m analysis.dast.oob",
        description="Interactsh-style OOB listener / token minter.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint", help="mint one correlation token + URLs")
    m.add_argument("--public-host", default=DEFAULT_PUBLIC_HOST)
    m.add_argument("--kind", default="ssrf", choices=["ssrf", "xxe", "rce"])
    s = sub.add_parser("serve", help="run the HTTP+DNS listeners (live)")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--http-port", type=int, default=0)
    s.add_argument("--dns-port", type=int, default=0)
    s.add_argument("--public-host", default=DEFAULT_PUBLIC_HOST)
    s.add_argument("--jsonl", help="append every interaction as JSONL")
    args = ap.parse_args(argv)

    if args.cmd == "mint":
        client = OOBClient(public_host=args.public_host)
        url, token = client.mint(args.kind)
        print(json.dumps({
            "token": token,
            "kind": args.kind,
            "urls": {k: client.mint(k)[0]
                     for k in ("ssrf", "xxe", "rce")},
            "note": ("payload url printed for kind=%s: %s"
                     % (args.kind, url)),
        }, sort_keys=True))
        return 0

    store = InteractionStore()
    if args.jsonl:
        def _write(inter):
            with open(args.jsonl, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(inter, sort_keys=True) + "\n")
        store.on_record = _write
    svc = OOBService(store, bind=args.bind, http_port=args.http_port,
                     dns_port=args.dns_port)
    info = svc.start()
    info["public_host"] = args.public_host
    print(json.dumps({"listening": info}, sort_keys=True), flush=True)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
    return 0


if __name__ == "__main__":        # pragma: no cover - CLI entry
    raise SystemExit(main())
