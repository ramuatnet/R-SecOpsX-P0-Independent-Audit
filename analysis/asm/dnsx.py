"""T-6.1: DNS wire codec + subdomain brute-force enumeration.

A minimal, pure DNS client over UDP.  It exists because Python's stdlib
resolves addresses (``socket.getaddrinfo``) but cannot ask for MX/TXT/NS/
CNAME records, and the offline invariant forbids pulling ``dnspython`` as
a required dependency.  The codec (``build_query``/``parse_response``) is
pure bytes-in/bytes-out so it is exhaustively testable offline; the
network is one injectable ``send`` callable (default: UDP to a resolver),
mirroring how the crawler's fetch is injected.

Bounds: names are length-checked (label <=63, wire name <=255), response
packets are size-capped, and the brute-force wordlist is capped and
de-duplicated -- an untrusted wordlist must not be able to make us emit
unbounded queries.
"""
from __future__ import annotations

import random
import socket
import struct
from typing import Callable, Iterable

# record types we ask for (subdomain discovery only needs these)
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_BY_NAME = {
    "A": QTYPE_A, "NS": QTYPE_NS, "CNAME": QTYPE_CNAME,
    "MX": QTYPE_MX, "TXT": QTYPE_TXT, "AAAA": QTYPE_AAAA,
}
NAME_BY_QTYPE = {v: k for k, v in QTYPE_BY_NAME.items()}

MAX_RESPONSE_BYTES = 64 * 1024          # bigger DNS answers are not ours
MAX_WORDLIST = 10_000                   # brute-force cap (disclosed via stats)
MAX_LABEL = 63
MAX_WIRE_NAME = 255


class DnsFormatError(ValueError):
    """A malformed DNS message (bad pointer, truncated label...)."""


def encode_name(name: str) -> bytes:
    """Encode a FQDN into DNS wire labels.  Rejects empty/oversized
    labels instead of emitting a query the peer must drop."""
    labels = [l for l in str(name).rstrip(".").split(".") if l != ""]
    out = bytearray()
    for label in labels:
        if label.isascii():
            raw = label.encode("ascii")
        else:
            try:
                raw = label.encode("idna")
            except UnicodeError as exc:
                raise DnsFormatError(f"bad label in name {name!r}") from exc
        if not raw or len(raw) > MAX_LABEL:
            raise DnsFormatError(f"bad label in name {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > MAX_WIRE_NAME:
        raise DnsFormatError(f"name too long: {name!r}")
    return bytes(out)


def decode_name(buf: bytes, offset: int, _depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) wire name.

    Returns ``(name, end_offset)`` where ``end_offset`` is the byte after
    the name AS IT LAYS in the buffer at ``offset``: labels are consumed
    in place, and a compression pointer ends the in-place run (2 bytes)
    while its target contributes only text.  Callers parsing sequential
    records rely on that cursor rule.

    Pointer loops are the classic DNS parser crash -- depth, self-pointer
    and bounds guards stop them (hostile responses are untrusted input).
    """
    if _depth > 16:
        raise DnsFormatError("compression pointer depth exceeded")
    labels: list[str] = []
    pos = offset
    end: int | None = None
    while True:
        if pos >= len(buf):
            raise DnsFormatError("truncated name")
        b = buf[pos]
        if b == 0:
            end = pos + 1
            break
        if b & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise DnsFormatError("truncated pointer")
            ptr = ((b & 0x3F) << 8) | buf[pos + 1]
            if ptr == pos or ptr >= len(buf):
                raise DnsFormatError("bad compression pointer")
            if end is None:
                end = pos + 2
            sub, _ = decode_name(buf, ptr, _depth + 1)
            labels.append(sub)
            break
        if b & 0xC0:
            raise DnsFormatError("reserved label length bits")
        if pos + 1 + b > len(buf):
            raise DnsFormatError("truncated label")
        labels.append(buf[pos + 1:pos + 1 + b].decode("ascii", "replace"))
        pos += 1 + b
    name = ".".join(l for l in labels if l)
    return name, end


def build_query(name: str, qtype: int, txn_id: int | None = None) -> bytes:
    """Standard recursive query (RD=1).  txn_id is injectable so tests
    can pair responses deterministically."""
    if qtype not in NAME_BY_QTYPE:
        raise DnsFormatError(f"unsupported qtype {qtype}")
    tid = random.randint(0, 0xFFFF) if txn_id is None else (txn_id & 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)  # IN
    return header + question


def _format_rdata(buf: bytes, rtype: int, start: int, end: int) -> str | None:
    rd = buf[start:end]
    try:
        if rtype == QTYPE_A and len(rd) == 4:
            return socket.inet_ntop(socket.AF_INET, rd)
        if rtype == QTYPE_AAAA and len(rd) == 16:
            return socket.inet_ntop(socket.AF_INET6, rd)
        if rtype in (QTYPE_CNAME, QTYPE_NS):
            text, _ = decode_name(buf, start)
            return text
        if rtype == QTYPE_MX and len(rd) >= 2:
            pref = struct.unpack_from(">H", rd, 0)[0]
            text, _ = decode_name(buf, start + 2)
            return f"{pref} {text}"
        if rtype == QTYPE_TXT:
            parts: list[str] = []
            i = 0
            while i < len(rd):
                n = rd[i]
                if i + 1 + n > len(rd):
                    raise DnsFormatError("truncated TXT chunk")
                parts.append(rd[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            return "".join(parts)
    except DnsFormatError:
        return None
    return None


def parse_response(data: bytes, expect_id: int | None = None) -> dict:
    """Parse a DNS response into a plain dict:
    ``{id, rcode, answers: [{name, type, type_name, ttl, data}]}``.

    Truncation (TC) is surfaced as ``truncated`` so callers can retry
    over TCP instead of silently treating a partial answer as the truth.
    """
    if len(data) < 12:
        raise DnsFormatError("response shorter than header")
    if len(data) > MAX_RESPONSE_BYTES:
        raise DnsFormatError("response exceeds size bound")
    tid, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
    if expect_id is not None and tid != (expect_id & 0xFFFF):
        raise DnsFormatError("txn id mismatch")
    rcode = flags & 0x0F
    offset = 12
    for _ in range(qd):
        _, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DnsFormatError("truncated question")
        offset += 4
    answers: list[dict] = []
    for _ in range(an):
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise DnsFormatError("truncated answer")
        rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        if offset + rdlen > len(data):
            raise DnsFormatError("truncated rdata")
        data_str = _format_rdata(data, rtype, offset, offset + rdlen)
        if data_str is not None and rclass == 1:       # IN only
            answers.append({
                "name": name,
                "type": rtype,
                "type_name": NAME_BY_QTYPE.get(rtype, str(rtype)),
                "ttl": ttl,
                "data": data_str,
            })
        offset += rdlen
    return {
        "id": tid,
        "rcode": rcode,
        "truncated": bool(flags & 0x0200),
        "answers": answers,
    }


SendFn = Callable[[bytes], bytes]


def udp_send(resolver: str, port: int = 53, timeout: float = 5.0) -> SendFn:
    """Build the default send: one UDP round-trip per query (no retries
    -- an unresponsive resolver must not stall an inventory run)."""
    def _send(query: bytes) -> bytes:
        fam = socket.AF_INET6 if ":" in resolver else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (resolver, port))
            data, _ = sock.recvfrom(MAX_RESPONSE_BYTES)
            return data
    return _send


def resolve_name(name: str, qtype: int, send: SendFn,
                 txn_id: int | None = None) -> list[dict]:
    """One question, one answer list.  NXDOMAIN/SERVFAIL come back as
    rcode != 0 with answers [] -- absence of a record is a normal result,
    not an error to raise on."""
    query = build_query(name, qtype, txn_id)
    resp = parse_response(send(query), expect_id=query[0] << 8 | query[1])
    return resp["answers"]


def brute_subdomains(domain: str, words: Iterable[str],
                     send: SendFn,
                     qtypes: tuple[int, ...] = (QTYPE_A, QTYPE_AAAA, QTYPE_CNAME),
                     limit: int = MAX_WORDLIST) -> dict:
    """Brute-force subdomains: resolve ``word.domain`` for each word.

    Deterministic: words are normalized/deduped in first-seen order and
    results sorted by hostname, so two runs over the same wordlist emit
    byte-identical output.  ``stats`` reports the word cap so truncation
    is disclosed rather than silent.
    """
    seen: set[str] = set()
    clean: list[str] = []
    truncated = False
    for raw in words:
        w = str(raw).strip().lower().rstrip(".")
        if not w or w.startswith("#") or " " in w or "*" in w:
            continue
        if w in seen:
            continue
        if len(clean) >= limit:
            truncated = True
            continue
        seen.add(w)
        clean.append(w)
    hits: dict[str, list[dict]] = {}
    for w in clean:
        fqdn = f"{w}.{domain}"
        try:
            answers: list[dict] = []
            for qt in qtypes:
                answers.extend(resolve_name(fqdn, qt, send))
        except (DnsFormatError, OSError, socket.timeout):
            continue                     # resolution failure == not found
        if answers:
            hits[fqdn] = sorted(answers, key=lambda a: (a["type_name"], a["data"]))
    return {
        "domain": domain,
        "hosts": [{"host": h, "records": hits[h]} for h in sorted(hits)],
        "stats": {"words": len(clean), "word_cap": limit,
                  "wordlist_truncated": truncated, "found": len(hits)},
    }
