"""T-6.1: ASM inventory collector (CLI + pure orchestration).

Produces the additive ``rsecopsx.asm_inventory/v1`` artifact:

    domain / as_of / sources[] / hosts[] / storage / skips[] / stats{}

Design rules (same family as the DAST package):

  * EVERY network stage is opt-in and injectable -- the default CLI run
    (no stage flags) performs zero network I/O, records each stage as
    ``skipped`` with a machine-readable reason, and is byte-identical
    run-to-run.  That default run is the offline half of the
    "reproducible run-to-run" gate; staged live runs are reproducible
    modulo the live state of the target and the explicit ``as_of``
    clock (both recorded in the artifact).
  * Failures never raise out of a stage: a dead DNS resolver, an
    unreachable CT log or a refused port becomes a ``skips`` row.
    Absence-of-data and data-says-absent stay distinct.
  * HTTP bodies travel as BYTES to every stage (icons are binary; utf-8
    decoding them first would poison favicon hashes) -- text consumers
    decode at their edge.
  * Output is sorted at every level -- determinism is structural.
  * ``passive_dns`` is a declared connector with no default provider
    (needs an API key); it reports ``no_provider_configured`` rather
    than pretending to have looked.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from analysis.asm import (adminpaths, ctlog, fingerprint, ports, storage,
                          takeover, tlsinfo)
from analysis.asm.dnsx import (QTYPE_A, QTYPE_AAAA, QTYPE_CNAME, QTYPE_MX,
                               brute_subdomains, resolve_name, udp_send)
from analysis.asm.favicon import favicon_record

ASM_SCHEMA = "rsecopsx.asm_inventory/v1"
MAX_HTTP_BYTES = 1024 * 1024
DEFAULT_TIMEOUT = 5.0
DEFAULT_RATE = 0.0                       # seconds between HTTP fetches
MAX_HOSTS = 512
# Default recursive resolver for the live DNS stage (reachable public
# resolver; offline runs never construct it -- `send` is injectable and
# the default UDP transport is only built when a stage is requested).
DEFAULT_RESOLVER = "1.1.1.1"

DEFAULT_WORDS: tuple[str, ...] = (
    "www", "mail", "smtp", "pop", "imap", "mx", "webmail", "autodiscover",
    "api", "app", "apps", "admin", "portal", "dashboard", "console",
    "dev", "devel", "test", "testing", "staging", "stage", "uat", "qa",
    "demo", "sandbox", "beta", "alpha", "preview",
    "blog", "shop", "store", "cms", "wp", "wordpress",
    "cdn", "static", "assets", "img", "images", "media", "files", "dl",
    "download", "downloads", "upload", "uploads",
    "git", "gitlab", "github", "gitea", "bitbucket", "ci", "cd", "build",
    "jenkins", "argo", "argocd", "registry", "docker", "nexus",
    "grafana", "kibana", "prometheus", "monitor", "metrics", "status",
    "logs", "trace", "elastic", "search",
    "db", "mysql", "postgres", "redis", "mongo", "mssql", "ldap", "db1",
    "vpn", "remote", "gateway", "intranet", "sso", "auth", "oauth", "idp",
    "jump", "bastion", "proxy", "cache", "lb",
    "wiki", "docs", "jira", "confluence", "help", "support", "ticket",
    "ns", "ns1", "ns2", "ftp", "sftp", "ssh", "backup", "old", "new",
    "v1", "v2", "node1", "node2", "node", "prod", "uat2", "cron", "worker",
    "queue", "mq", "kafka", "vault", "consul", "etcd", "kube", "k8s",
)

HttpFetch = Callable[[str], tuple[int, dict, bytes, str]]
# url -> (status, headers_lower, body_BYTES, final_url); raises on error


def http_fetch(url: str, timeout: float = DEFAULT_TIMEOUT,
               rate_s: float = DEFAULT_RATE,
               sleep: Callable[[float], None] = time.sleep,
               user_agent: str = "R-SecOpsX-ASM/1.0") -> tuple[int, dict, bytes, str]:
    """Live default HTTP fetch (follows redirects, size-capped).
    Raises on transport failure -- stages convert to skips."""
    if rate_s > 0:
        sleep(rate_s)
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - opt-in inventory
        raw = resp.read(MAX_HTTP_BYTES + 1)[:MAX_HTTP_BYTES]
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return int(resp.status), headers, raw, resp.geturl()


def _text(raw: bytes) -> str:
    return (raw or b"").decode("utf-8", "replace")


def _skip(stage: str, target: str, reason: str) -> dict:
    return {"stage": stage, "target": target, "reason": reason}


def _now_iso(as_of: datetime | None) -> str:
    dt = as_of or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def resolve_host(host: str, send) -> dict:
    """A/AAAA/CNAME/MX for one host (injectable send).  Returns records
    sorted; transport errors -> empty records (caller records skip)."""
    answers: list[dict] = []
    for qt in (QTYPE_A, QTYPE_AAAA, QTYPE_CNAME, QTYPE_MX):
        try:
            answers.extend(resolve_name(host, qt, send))
        except Exception:                  # noqa: BLE001 - stage-local
            continue
    answers.sort(key=lambda a: (a["name"], a["type_name"], a["data"]))
    addrs = sorted({a["data"] for a in answers
                    if a["type_name"] in ("A", "AAAA")})
    cname = next((a["data"] for a in answers
                  if a["type_name"] == "CNAME"), None)
    return {"addresses": addrs, "cname": cname, "records": answers}


def build_inventory(
    domain: str,
    *,
    as_of: datetime | None = None,
    seed_url: str | None = None,
    stage_resolve: bool = False,
    stage_brute: bool = False,
    stage_ct: bool = False,
    stage_ports: bool = False,
    stage_tls: bool = False,
    stage_http: bool = False,
    stage_storage: bool = False,
    words: tuple[str, ...] | None = None,
    ct_payload: bytes | None = None,      # offline CT input (bytes), else fetch
    send=None,                            # DNS transport (default UDP)
    http: HttpFetch | None = None,        # HTTP transport
    connect=None,                         # port connector
    cert_probe=None,                      # TLS probe (keyword-compatible)
    extra_admin_paths: tuple[str, ...] = (),
    resolver: str = DEFAULT_RESOLVER,
    timeout_s: float = DEFAULT_TIMEOUT,
    rate_s: float = DEFAULT_RATE,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Assemble the ASM inventory.  All stages OFF = deterministic
    offline run (candidates + skips only, no sockets)."""
    domain = str(domain).strip().lower().rstrip(".")
    if not domain or " " in domain or "/" in domain:
        raise ValueError("domain must be a bare hostname")
    as_of_dt = as_of or datetime.now(timezone.utc)
    sources: list[dict] = []
    skips: list[dict] = []
    hosts: dict[str, dict] = {}

    def _host(name: str) -> dict:
        name = (name or "").lower().rstrip(".")
        if not name:
            raise ValueError("empty host")
        if name not in hosts:
            if len(hosts) >= MAX_HOSTS:
                raise ValueError(f"host cap {MAX_HOSTS} exceeded")
            hosts[name] = {
                "host": name,
                "addresses": [],
                "cname": None,
                "records": [],
                "ports": None,
                "tls": None,
                "favicon": None,
                "techs": [],
                "admin": [],
                "takeover": None,
            }
        return hosts[name]

    _host(domain)
    base_url = seed_url or f"http://{domain}/"
    _http = http if http is not None else _default_http(timeout_s, rate_s, sleep)

    def _send():
        return send if send is not None else udp_send(resolver, timeout=timeout_s)

    # ---- passive DNS: declared connector, never invented ----
    skips.append(_skip("passive_dns", domain, "no_provider_configured"))

    # ---- stage: subdomain brute ----
    if stage_brute:
        try:
            result = brute_subdomains(domain, words or DEFAULT_WORDS, _send())
            for h in result["hosts"]:
                entry = _host(h["host"])
                addrs = sorted({r["data"] for r in h["records"]
                                if r["type_name"] in ("A", "AAAA")})
                entry["addresses"] = sorted(set(entry["addresses"]) | set(addrs))
                entry["records"] = entry["records"] + h["records"]
            sources.append({"kind": "dns_brute", "status": "ok",
                            "detail": dict(result["stats"])})
        except Exception as exc:           # noqa: BLE001 - stage-local
            skips.append(_skip("dns_brute", domain,
                               f"{type(exc).__name__}: {exc}"[:200]))
            sources.append({"kind": "dns_brute", "status": "error",
                            "detail": f"{type(exc).__name__}"})
    else:
        skips.append(_skip("dns_brute", domain, "stage_not_requested"))

    # ---- stage: CT logs ----
    if stage_ct:
        try:
            if ct_payload is not None:
                ct = ctlog.parse_crtsh(ct_payload, domain)
                detail = {"input": "file", **ct["stats"]}
            else:
                ct = ctlog.fetch_crtsh(domain, _body_fetch(_http))
                detail = {"input": "crt.sh", **ct["stats"]}
            for n in ct["names"]:
                _host(n)
            sources.append({"kind": "ct_logs", "status": "ok", "detail": detail})
        except Exception as exc:           # noqa: BLE001 - stage-local
            skips.append(_skip("ct_logs", domain,
                               f"{type(exc).__name__}: {exc}"[:200]))
            sources.append({"kind": "ct_logs", "status": "error",
                            "detail": f"{type(exc).__name__}"})
    else:
        skips.append(_skip("ct_logs", domain, "stage_not_requested"))

    # ---- stage: resolution of the assembled host set ----
    if stage_resolve:
        resolved = 0
        for name in sorted(hosts):
            info = resolve_host(name, _send())
            entry = hosts[name]
            entry["addresses"] = sorted(set(entry["addresses"])
                                        | set(info["addresses"]))
            entry["cname"] = info["cname"]
            if info["records"]:
                entry["records"] = info["records"]
            if info["addresses"] or info["records"]:
                resolved += 1
            else:
                skips.append(_skip("resolve", name, "no_records"))
        sources.append({"kind": "resolve", "status": "ok",
                        "detail": {"resolved": resolved, "hosts": len(hosts)}})
    else:
        skips.append(_skip("resolve", domain, "stage_not_requested"))

    # ---- stage: ports (resolved hosts only) ----
    if stage_ports:
        scanned = 0
        for name in sorted(hosts):
            entry = hosts[name]
            if not entry["addresses"]:
                skips.append(_skip("ports", name, "unresolved"))
                continue
            entry["ports"] = ports.scan_ports(
                name, connect=connect, timeout=timeout_s)
            scanned += 1
        sources.append({"kind": "ports", "status": "ok",
                        "detail": {"hosts": scanned}})
    else:
        skips.append(_skip("ports", domain, "stage_not_requested"))

    # ---- stage: TLS certificate inventory (apex + resolved hosts) ----
    if stage_tls:
        probe = cert_probe if cert_probe is not None else tlsinfo.probe_certificate_live
        probed = 0
        for name in sorted(hosts):
            entry = hosts[name]
            if not entry["addresses"] and name != domain:
                skips.append(_skip("tls", name, "unresolved"))
                continue
            try:
                entry["tls"] = probe(host=name, port=443,
                                     timeout=timeout_s, as_of=as_of_dt)
                probed += 1
            except Exception as exc:       # noqa: BLE001 - per-host skip
                skips.append(_skip("tls", name,
                                   f"{type(exc).__name__}: {exc}"[:200]))
        sources.append({"kind": "tls", "status": "ok",
                        "detail": {"hosts": probed}})
    else:
        skips.append(_skip("tls", domain, "stage_not_requested"))

    # ---- stage: HTTP-derived facts (tech, favicon, takeover, admin) ----
    if stage_http:
        root_ok = False
        try:
            status, headers, body, final_url = _http(base_url)
            entry = _host(url_hostname(final_url) or domain)
            entry["techs"] = fingerprint.fingerprint(headers, _text(body))
            entry["favicon"] = favicon_record(final_url, _text(body),
                                              _body_fetch(_http))
            entry["takeover"] = takeover.correlate_takeover(
                entry.get("cname"), _text(body))
            root_ok = True
            sources.append({"kind": "http_root", "status": "ok",
                            "detail": {"status": status}})
        except Exception as exc:           # noqa: BLE001 - stage-local
            skips.append(_skip("http_root", base_url,
                               f"{type(exc).__name__}: {exc}"[:200]))
        # admin panel probes on the seed origin
        if not root_ok:
            skips.append(_skip("admin_probe", base_url, "root_fetch_failed"))
        else:
            base_origin = _origin(base_url)
            kept, dropped = adminpaths.cap_for(
                adminpaths.admin_paths(extra_admin_paths))
            found: list[dict] = []
            for p in kept:
                try:
                    st, hd, bd, _fin = _http(base_origin + p)
                except Exception:          # noqa: BLE001 - per-path skip
                    skips.append(_skip("admin_probe", p, "fetch_failed"))
                    continue
                verdict = adminpaths.classify_admin_response(
                    p, st, hd, _text(bd))
                if verdict:
                    found.append(verdict)
            entry_a = _host(url_hostname(base_url) or domain)
            entry_a["admin"] = sorted(found,
                                      key=lambda v: (v["path"], v["kind"]))
            sources.append({"kind": "admin_paths", "status": "ok",
                            "detail": {"probed": len(kept),
                                       "dropped_by_cap": dropped,
                                       "hits": len(found)}})
    else:
        skips.append(_skip("http_root", base_url, "stage_not_requested"))
        skips.append(_skip("admin_probe", base_url, "stage_not_requested"))

    # ---- stage: cloud storage discovery ----
    if stage_storage:
        tokens = _storage_tokens(domain)
        cands = storage.candidates_with_stats(tokens)
        results: list[dict] = []
        for cand in cands["candidates"]:
            try:
                st, _hd, bd, _fu = _http(cand["url"])
            except urllib.error.HTTPError as exc:    # urllib raises on 4xx
                st = int(exc.code)
                try:
                    bd = exc.read(MAX_HTTP_BYTES)
                except Exception:          # noqa: BLE001
                    bd = b""
            except Exception as exc:                 # noqa: BLE001
                skips.append(_skip("storage", cand["url"],
                                   f"{type(exc).__name__}"[:120]))
                continue
            verdict = storage.classify_storage_response(
                cand["provider"], st, _text(bd))
            if verdict:
                results.append({**cand, **verdict})
        storage_out = {"candidates": cands["candidates"],
                       "results": sorted(results,
                                         key=lambda r: (r["provider"], r["name"])),
                       "stats": cands["stats"]}
        sources.append({"kind": "storage", "status": "ok",
                        "detail": {"probed": len(cands["candidates"]),
                                   "hits": len(results)}})
    else:
        skips.append(_skip("storage", domain, "stage_not_requested"))
        storage_out = {
            "candidates": storage.candidates_with_stats(
                _storage_tokens(domain))["candidates"],
            "results": [], "stats": {"stage": "not_requested"},
        }

    hosts_out = [hosts[h] for h in sorted(hosts)]
    for h in hosts_out:                     # nested sorts for determinism
        h["records"] = sorted(h["records"],
                              key=lambda a: (a["name"], a["type_name"],
                                             a["data"]))
        h["techs"] = sorted(h["techs"], key=lambda t: t["sig_id"])
    skips.sort(key=lambda s: (s["stage"], s["target"], s["reason"]))
    return {
        "schema": ASM_SCHEMA,
        "domain": domain,
        "as_of": _now_iso(as_of_dt),
        "seed_url": base_url,
        "sources": sources,
        "hosts": hosts_out,
        "storage": storage_out,
        "skips": skips,
        "stats": {
            "hosts": len(hosts_out),
            "resolved": sum(1 for h in hosts_out if h["addresses"]),
            "skips": len(skips),
            "sources_ok": sum(1 for s in sources if s["status"] == "ok"),
        },
    }


def _default_http(timeout_s: float, rate_s: float, sleep) -> HttpFetch:
    def _f(url: str):
        return http_fetch(url, timeout=timeout_s, rate_s=rate_s, sleep=sleep)
    return _f


def _body_fetch(inner: HttpFetch) -> Callable[[str], bytes]:
    """Adapter: HttpFetch -> the bytes-only fetch shape ctlog/favicon
    (and any future bytes consumer) expects."""
    def _f(url: str) -> bytes:
        return inner(url)[2]
    return _f


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def url_hostname(url: str) -> str | None:
    return urlsplit(url).hostname


def _storage_tokens(domain: str) -> tuple[str, ...]:
    """Storage name tokens taken from the domain's OWN labels -- never
    invented org guesses."""
    labels = [l for l in domain.split(".") if l and l != "www"]
    public_suffixes = {"com", "net", "org", "io", "co", "gov", "edu", "app",
                       "dev", "cloud", "sh", "ai", "xyz", "info", "biz"}
    base = [l for l in labels if l not in public_suffixes]
    picked = tuple(dict.fromkeys(base[:4])) if base else tuple(labels[:2])
    return picked


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m analysis.asm.collect",
        description="Build the rsecopsx.asm_inventory/v1 artifact. "
                    "No stage flags = offline deterministic run.")
    ap.add_argument("domain", help="apex domain to inventory")
    ap.add_argument("--seed-url", default=None,
                    help="root URL for HTTP-derived facts (default http://domain/)")
    ap.add_argument("--resolve", action="store_true", help="DNS resolution stage")
    ap.add_argument("--brute", action="store_true", help="subdomain brute stage")
    ap.add_argument("--ct", action="store_true", help="CT log stage (crt.sh)")
    ap.add_argument("--ct-file", default=None,
                    help="offline crt.sh JSON file (parsed, no network)")
    ap.add_argument("--ports", action="store_true", help="port scan stage")
    ap.add_argument("--tls", action="store_true", help="TLS certificate stage")
    ap.add_argument("--http", action="store_true",
                    help="HTTP facts: tech + favicon + takeover + admin")
    ap.add_argument("--storage", action="store_true", help="cloud storage stage")
    ap.add_argument("--words", default=None, help="wordlist file for brute")
    ap.add_argument("--as-of", default=None,
                    help="fixed ISO-8601 clock for reproducible output")
    ap.add_argument("--out", default=None, help="write JSON here (default stdout)")
    args = ap.parse_args(argv)

    words = None
    if args.words:
        with open(args.words, "r", encoding="utf-8", errors="replace") as fh:
            words = tuple(fh.read().splitlines())
    ct_payload = None
    if args.ct_file:
        with open(args.ct_file, "rb") as fh:
            ct_payload = fh.read()
    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))

    try:
        doc = build_inventory(
            args.domain,
            as_of=as_of,
            seed_url=args.seed_url,
            stage_resolve=args.resolve or bool(args.ports or args.tls),
            stage_brute=args.brute,
            stage_ct=bool(args.ct or ct_payload is not None),
            stage_ports=args.ports,
            stage_tls=args.tls,
            stage_http=args.http,
            stage_storage=args.storage,
            words=words,
            ct_payload=ct_payload,
        )
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
