"""T-6.1: TCP port/service scan (bounded, injectable, deterministic).

A connect-scan only: SYN scans need raw sockets (root), and a completed
TCP handshake already proves a listener plus lets us read the TLS/HTTP
banner for service identification.  The connector and banner reader are
injected, so tests exercise the scheduler/sort/classify logic with no
sockets; the live default is ``socket.create_connection``.

Bounds (untrusted input = target host + port list):
  * port count capped (``MAX_PORTS``) -- overflow is DISCLOSED in stats,
    never silently dropped;
  * worker pool capped so a huge list cannot open unbounded sockets;
  * per-connection timeout is explicit;
  * results sorted by port, open-first -> byte-identical run-to-run for
    the same live state (port state is inherently live; reproducibility
    of the INVENTORY is proven against fixtures/offline stages).

``TOP_PORTS`` is the default small scan set (curated common services) --
scanning all 65535 ports by default would be a hostile-traffic generator,
not an inventory tool; the full range requires an explicit override and
still hits the cap.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable

MAX_PORTS = 4096
MAX_WORKERS = 64
DEFAULT_TIMEOUT = 2.0

TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 4190, 4280, 4443, 5000,
    5432, 5601, 5672, 5900, 5985, 6379, 6443, 8000, 8008, 8080, 8081,
    8443, 8500, 8888, 9000, 9090, 9200, 9300, 9418, 11211, 15672,
    27017, 50000,
)

# well-known service names for the ports we actually scan (service id is
# a label for humans, not a version claim -- version probes are out of
# scope here and disclosed as such in stats)
SERVICE_BY_PORT: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker-http",
    3000: "dev-http", 3306: "mysql", 3389: "rdp", 4190: "manage-sieve",
    4280: "dvwa-http", 4443: "https-alt", 5000: "flask-http",
    5432: "postgres", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5985: "winrm", 6379: "redis", 6443: "k8s-api", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8500: "consul", 8888: "http-alt", 9000: "minio",
    9090: "prometheus", 9200: "elasticsearch", 9300: "es-transport",
    9418: "git", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 50000: "sap",
}

ConnectFn = Callable[[str, int, float], bool]     # (host, port, timeout) -> open


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Live default connector.  Connection refused / timed out / host
    unreachable all mean 'not open' for inventory purposes -- an
    unreachable network is not an exception, it is an absent service."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports: Iterable[int] | None = None,
               connect: ConnectFn = tcp_connect,
               timeout: float = DEFAULT_TIMEOUT,
               workers: int = MAX_WORKERS,
               cap: int = MAX_PORTS) -> dict:
    """Scan ``host`` for open ports.  Returns a deterministic record:
    open ports sorted ascending, each with its service label (or None =
    unknown), plus stats disclosing caps and refusal count."""
    requested: list[int] = []
    seen: set[int] = set()
    truncated = False
    for p in (TOP_PORTS if ports is None else ports):
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if n < 1 or n > 65535 or n in seen:
            continue
        if len(requested) >= cap:
            truncated = True
            continue
        seen.add(n)
        requested.append(n)
    if not requested:
        return {"host": host, "open": [],
                "stats": {"requested": 0, "open": 0, "cap": cap,
                          "port_cap_hit": truncated, "refused": 0}}

    def _probe(p: int) -> tuple[int, bool]:
        return p, connect(host, p, timeout)

    n_workers = max(1, min(int(workers), MAX_WORKERS, len(requested)))
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        results = list(pool.map(_probe, requested))
    open_ports = sorted(p for p, is_open in results if is_open)
    return {
        "host": host,
        "open": [
            {"port": p, "service": SERVICE_BY_PORT.get(p)}
            for p in open_ports
        ],
        "stats": {
            "requested": len(requested),
            "open": len(open_ports),
            "refused": len(requested) - len(open_ports),
            "cap": cap,
            "port_cap_hit": truncated,
            "workers": n_workers,
            "timeout_s": timeout,
            "version_probes": False,     # disclosed: banner/version not read
        },
    }
