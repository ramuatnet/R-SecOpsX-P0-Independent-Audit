"""Live threat-intelligence feeds: FIRST.org EPSS and the CISA KEV catalog.

Gap register **G-001** and **G-002**.  Before this module existed R-SecOpsX
resolved EPSS from an 8-row table and KEV from two independent hand-typed sets
(9 records in :mod:`analysis.kev_intelligence_engine`, 7 more in
:mod:`analysis.vulnerability_age_engine`) — roughly 0.005% and 0.5% coverage of
the real catalogues, while rendering the values with the authority of live
intelligence.

Design contract
---------------
* **Offline-first.**  Every network operation is wrapped so that a failure,
  a timeout, a proxy block or an air-gapped host degrades to the static seed
  tables rather than raising.  A scan must never fail because a feed is down.
* **Provenance follows the data.**  A value that came from a feed is
  ``LIVE_FEED`` *with* an ``as_of`` timestamp; a value that came from the
  seed table is ``STATIC_REFERENCE``; an absent value is ``NOT_AVAILABLE``.
  A cache hit is still ``LIVE_FEED`` because it is a dated snapshot of the
  live feed, not an opinion — the fetch timestamp travels with it, exactly as
  Dependency-Track and Grype report it.
* **Never upgrade a miss.**  A CVE the live feed does not score does **not**
  become a number, and an offline KEV miss does **not** become "not exploited".
* **Deterministic by default at the engine layer.**  ``enrich_*`` functions
  only consult a feed when the caller passes one, so unit tests and offline
  consumers never reach for the network implicitly.  :func:`default_feed`
  is what :mod:`main` wires in when live feeds are enabled.

Switches
--------
``RSECOPSX_LIVE_FEEDS=0`` disables all network fetches (also readable as
``false``/``no``/``off``).  ``RSECOPSX_LIVE_FEEDS_TIMEOUT`` overrides the
per-request timeout (default 10s).  ``RSECOPSX_LIVE_FEEDS_TTL`` overrides the
cache lifetime in seconds (default 86400, matching FIRST.org's own
``Cache-Control: max-age=86400``).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from analysis.intelligence_provenance import (
    LIVE_FEED,
    NOT_AVAILABLE,
    STATIC_REFERENCE,
)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

USER_AGENT = "R-SecOpsX-INT/1.0"

CACHE_FILE = Path("reports") / ".intel_feed_cache.json"
CACHE_SCHEMA_VERSION = 1

DEFAULT_TIMEOUT = 10
# The KEV catalog is one ~1.7 MB document.  A timeout sized for a small JSON
# API would abort a perfectly legitimate download on a slow link, so it gets
# its own default; RSECOPSX_LIVE_FEEDS_TIMEOUT still overrides both.
KEV_DOWNLOAD_TIMEOUT = 30
DEFAULT_TTL = 86400
# FIRST.org paginates at 100 rows; keep well inside it so one page is enough
# per request regardless of how the API evolves.
EPSS_BATCH_SIZE = 50

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def live_feeds_enabled() -> bool:
    """True unless the operator has explicitly opted out.

    Default is ON: shipping an 8-row table while a one-request live feed
    exists is the defect G-001 describes.
    """
    raw = os.environ.get("RSECOPSX_LIVE_FEEDS")
    if raw is None:
        return True
    return raw.strip().lower() not in _FALSE


def _timeout(kev: bool = False) -> int:
    """Per-request timeout, operator-overridable, feed-aware default."""
    raw = os.environ.get("RSECOPSX_LIVE_FEEDS_TIMEOUT")
    if raw is not None and str(raw).strip():
        try:
            return max(1, int(str(raw).strip()))
        except (TypeError, ValueError):
            pass
    return KEV_DOWNLOAD_TIMEOUT if kev else DEFAULT_TIMEOUT


def _ttl() -> float:
    try:
        return max(0.0, float(os.environ.get("RSECOPSX_LIVE_FEEDS_TTL", "")))
    except (TypeError, ValueError):
        return DEFAULT_TTL


def _now() -> float:
    return time.time()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _read_cache_file(path: Path) -> dict:
    """Load a cache document, refusing anything we do not understand.

    Applied to *every* cache path, not just the default one: a file written by
    a future schema version, truncated by a crash, or simply not ours must be
    treated as empty rather than misread as current intelligence.
    """
    try:
        p = Path(path)
    except TypeError:
        return {}
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    if raw.get("schema_version") != CACHE_SCHEMA_VERSION:
        return {}
    entries = raw.get("entries")
    return entries if isinstance(entries, dict) else {}


def _save_cache_to(path: Path, cache: dict) -> None:
    """Persist a cache document, failing soft on a read-only checkout.

    A scan must never fail over telemetry we cannot write; the next run simply
    refetches.
    """
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(
                {"schema_version": CACHE_SCHEMA_VERSION, "entries": cache},
                indent=1,
                default=str,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass


def _fresh(entry: object, ttl: float) -> bool:
    if not isinstance(entry, dict):
        return False
    fetched = entry.get("fetched_at_epoch")
    if not isinstance(fetched, (int, float)):
        return False
    return (_now() - float(fetched)) < ttl


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _get_json(url: str, timeout: int | None = None) -> dict:
    """GET a JSON document.  Raises on any transport/decoding problem.

    Callers are responsible for the fallback; this helper deliberately does
    not swallow errors so that a caller can tell "feed down" from "feed empty".
    """
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        method="GET",
    )
    with urllib.request.urlopen(
        req, timeout=timeout if timeout is not None else _timeout()
    ) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _chunked(values: list[str], size: int):
    for i in range(0, len(values), size):
        yield values[i:i + size]


# ---------------------------------------------------------------------------
# EPSS (G-001)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EPSSScore:
    cve: str
    score: float | None
    percentile: float | None
    as_of: str | None
    source: str  # "FIRST_ORG_EPSS" | "STATIC_TABLE" | "NONE"
    provenance: str  # LIVE_FEED | STATIC_REFERENCE | NOT_AVAILABLE


class EPSSFeed:
    """Batched FIRST.org EPSS client with a dated on-disk cache."""

    def __init__(self, *, enabled: bool | None = None,
                 cache_path: Path | None = None,
                 ttl: float | None = None,
                 timeout: int | None = None):
        self.enabled = live_feeds_enabled() if enabled is None else bool(enabled)
        self.cache_path = Path(cache_path) if cache_path else CACHE_FILE
        self.ttl = DEFAULT_TTL if ttl is None else float(ttl)
        self.timeout = int(timeout) if timeout is not None else _timeout()
        self._cache: dict | None = None
        # Observability for the summary blocks / reports.
        self.last_error: str | None = None
        self.fetch_attempts = 0
        self.fetch_successes = 0

    # -- cache plumbing (mirrors vulnerability_intel's shape) --------------
    def _entries(self) -> dict:
        if self._cache is None:
            self._cache = _read_cache_file(self.cache_path)
        return self._cache

    def _flush(self) -> None:
        _save_cache_to(self.cache_path, self._entries())

    # -- public ------------------------------------------------------------
    def scores_for(self, cves: list[str]) -> dict[str, EPSSScore]:
        """Resolve every requested CVE, preferring live data, then cache.

        Never raises.  A CVE that cannot be resolved live is returned from the
        cache if the cache holds it, otherwise it is simply absent — the caller
        decides whether absence means ``STATIC_REFERENCE`` or ``NOT_AVAILABLE``.
        """
        wanted = sorted({str(c).strip().upper() for c in cves if c})
        if not wanted:
            return {}

        cache = self._entries()
        result: dict[str, EPSSScore] = {}
        missing: list[str] = []

        for cve in wanted:
            entry = cache.get(f"epss|{cve}")
            if _fresh(entry, self.ttl):
                result[cve] = self._from_cache(cve, entry)
            else:
                missing.append(cve)

        if missing and self.enabled:
            self._fetch(missing, cache)

        for cve in missing:
            if cve in result:
                continue
            entry = cache.get(f"epss|{cve}")
            if isinstance(entry, dict) and entry.get("score") is not None:
                # Stale but real: still a dated snapshot of the live feed, so
                # it keeps LIVE_FEED provenance with its original as_of date.
                result[cve] = self._from_cache(cve, entry, stale=True)

        return result

    # -- internals ---------------------------------------------------------
    def _from_cache(self, cve: str, entry: dict, stale: bool = False) -> EPSSScore:
        return EPSSScore(
            cve=cve,
            score=entry.get("score"),
            percentile=entry.get("percentile"),
            as_of=entry.get("as_of"),
            source="FIRST_ORG_EPSS",
            provenance=LIVE_FEED,
        )

    def _fetch(self, cves: list[str], cache: dict) -> None:
        for batch in _chunked(cves, EPSS_BATCH_SIZE):
            self.fetch_attempts += 1
            url = f"{EPSS_API_URL}?cve=" + ",".join(batch)
            try:
                payload = _get_json(url, timeout=self.timeout)
            except (urllib.error.URLError, urllib.error.HTTPError,
                    TimeoutError, ValueError, OSError) as exc:
                # Expected on air-gapped hosts.  Record it once and fall back.
                self.last_error = f"{type(exc).__name__}: {exc}"
                continue
            except Exception as exc:  # pragma: no cover - defensive
                self.last_error = f"{type(exc).__name__}: {exc}"
                continue

            rows = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                self.last_error = "unexpected EPSS payload shape"
                continue

            self.fetch_successes += 1
            epoch = _now()
            for row in rows:
                if not isinstance(row, dict):
                    continue
                cve = str(row.get("cve") or "").strip().upper()
                if not cve:
                    continue
                try:
                    score = float(row.get("epss"))
                except (TypeError, ValueError):
                    score = None
                try:
                    percentile = float(row.get("percentile"))
                except (TypeError, ValueError):
                    percentile = None
                cache[f"epss|{cve}"] = {
                    "score": score,
                    "percentile": percentile,
                    "as_of": row.get("date"),
                    "fetched_at_epoch": epoch,
                    "fetched_at": _utc_now_iso(),
                }
        self._flush()


# ---------------------------------------------------------------------------
# CISA KEV (G-002)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KEVRecord:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware_use: str
    catalog_version: str
    date_released: str
    provenance: str  # LIVE_FEED (hit or miss) | STATIC_REFERENCE


class KEVFeed:
    """Full-catalog CISA KEV client with a dated on-disk cache.

    Unlike EPSS this is one document, so a miss against a *fetched* catalog is
    genuinely meaningful: ``provenance`` is ``LIVE_FEED`` even when the lookup
    returns ``None``, because the whole 1734-row catalog was consulted.
    """

    def __init__(self, *, enabled: bool | None = None,
                 cache_path: Path | None = None,
                 ttl: float | None = None,
                 timeout: int | None = None):
        self.enabled = live_feeds_enabled() if enabled is None else bool(enabled)
        self.cache_path = Path(cache_path) if cache_path else CACHE_FILE
        self.ttl = DEFAULT_TTL if ttl is None else float(ttl)
        self.timeout = int(timeout) if timeout is not None else _timeout(kev=True)
        self._records: dict[str, dict] | None = None
        self._meta: dict = {}
        # Success and failure are tracked separately: every failure path below
        # assigns ``{}`` to _records, so ``_records is not None`` cannot be
        # used as the "catalog is loaded" test.
        self._attempted = False
        self._catalog_ok = False
        self.last_error: str | None = None
        self.fetch_attempts = 0
        self.fetch_successes = 0

    def _ensure_catalog(self) -> bool:
        """Load the catalog from cache, refreshing when stale.  Never raises.

        The outcome is sticky for the lifetime of the feed instance: one
        attempt, and a failure is remembered rather than retried on every
        ``lookup`` inside a package loop (which would otherwise hammer a feed
        that is already down, once per dependency).

        Recording the result explicitly rather than deriving it from
        ``_records is not None`` matters: an earlier version did the latter,
        and because the failure paths assign ``{}``, a *second* call would have
        reported a loaded catalog and sent the engine down the live path
        against an empty one — marking every single CVE a "live miss" and
        labelling that misstatement ``LIVE_FEED``.
        """
        if self._attempted:
            return self._catalog_ok
        self._attempted = True

        records: dict[str, dict] = {}
        meta: dict = {}

        cache = _read_cache_file(self.cache_path)
        entry = cache.get("kev|catalog")
        if isinstance(entry, dict) and isinstance(entry.get("records"), dict):
            meta = entry
            records = entry["records"]

        if records and _fresh(meta, self.ttl):
            self._records, self._meta = records, meta
            self._catalog_ok = True
            return True

        if not self.enabled:
            # Offline mode still gets to use whatever snapshot we already have;
            # if there is none, the caller falls back to the seed tables.
            self._records, self._meta = records, meta
            self._catalog_ok = bool(records)
            return self._catalog_ok

        self.fetch_attempts += 1
        payload = None
        try:
            payload = _get_json(KEV_FEED_URL, timeout=self.timeout)
        except (urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, ValueError, OSError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # pragma: no cover - defensive
            self.last_error = f"{type(exc).__name__}: {exc}"

        fresh: dict[str, dict] = {}
        if isinstance(payload, dict):
            rows = payload.get("vulnerabilities")
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    cve = str(row.get("cveID") or "").strip().upper()
                    if not cve:
                        continue
                    fresh[cve] = {
                        "vendor": row.get("vendorProject") or "",
                        "product": row.get("product") or "",
                        "name": row.get("vulnerabilityName") or "",
                        "date_added": row.get("dateAdded") or "",
                        "due_date": row.get("dueDate") or "",
                        "ransomware_use": (
                            row.get("knownRansomwareCampaignUse") or "Unknown"
                        ),
                    }
            else:
                self.last_error = "unexpected KEV payload shape"
        elif payload is None:
            pass  # transport failure; last_error already recorded
        else:  # pragma: no cover - defensive
            self.last_error = "unexpected KEV payload shape"

        if fresh:
            self.fetch_successes += 1
            meta = {
                "records": fresh,
                "fetched_at_epoch": _now(),
                "fetched_at": _utc_now_iso(),
                "catalog_version": payload.get("catalogVersion"),
                "date_released": payload.get("dateReleased"),
                "count": payload.get("count"),
            }
            cache["kev|catalog"] = meta
            _save_cache_to(self.cache_path, cache)
            self._records, self._meta = fresh, meta
            self._catalog_ok = True
        else:
            # The fetch failed or was unusable.  A stale snapshot is still a
            # dated view of the catalog and beats having none, so keep it (with
            # its original dateReleased, never re-dated as fresh); with no
            # snapshot at all the caller falls back to the seed tables.
            self._records, self._meta = records, meta
            self._catalog_ok = bool(records)
        return self._catalog_ok

    @property
    def catalog_version(self) -> str | None:
        self._ensure_catalog()
        return self._meta.get("catalog_version")

    @property
    def date_released(self) -> str | None:
        self._ensure_catalog()
        return self._meta.get("date_released")

    @property
    def catalog_size(self) -> int:
        self._ensure_catalog()
        return len(self._records or {})

    @property
    def catalog_loaded(self) -> bool:
        return self._ensure_catalog()

    def lookup(self, cve: str) -> KEVRecord | None:
        """Return the live catalog record, or ``None`` if the catalog was
        consulted and does not list the CVE.

        ``None`` here means "checked against the catalog", which is a materially
        different claim from the old "absent from a 9-row table".  Callers that
        could not consult any catalog at all get :meth:`lookup` returning
        ``None`` too, so they must check :attr:`catalog_loaded` first.
        """
        if not self._ensure_catalog():
            return None
        key = str(cve or "").strip().upper()
        row = (self._records or {}).get(key)
        if not row:
            return None
        return KEVRecord(
            cve=key,
            vendor=row.get("vendor", ""),
            product=row.get("product", ""),
            name=row.get("name", ""),
            date_added=row.get("date_added", ""),
            due_date=row.get("due_date", ""),
            ransomware_use=row.get("ransomware_use", "Unknown"),
            catalog_version=self._meta.get("catalog_version") or "",
            date_released=self._meta.get("date_released") or "",
            provenance=LIVE_FEED,
        )


# ---------------------------------------------------------------------------
# Wiring helper
# ---------------------------------------------------------------------------

@dataclass
class FeedSet:
    """The pair of feeds, plus the reason they are unavailable if they are."""
    epss: EPSSFeed | None = None
    kev: KEVFeed | None = None
    reasons: list[str] = field(default_factory=list)

    @property
    def enabled(self) -> bool:
        return bool(self.epss or self.kev)


_DEFAULT: FeedSet | None = None


def default_feed(*, force: bool = False) -> FeedSet:
    """Process-wide feed pair, built once.

    Returns a :class:`FeedSet` whose members may be ``None``; callers treat
    ``None`` exactly as "fall back to the seed table", which keeps the offline
    contract in one place instead of at every call site.
    """
    global _DEFAULT
    if _DEFAULT is not None and not force:
        return _DEFAULT

    reasons: list[str] = []
    epss: EPSSFeed | None = None
    kev: KEVFeed | None = None

    if not live_feeds_enabled():
        reasons.append("RSECOPSX_LIVE_FEEDS is disabled by the operator")
    else:
        epss = EPSSFeed()
        kev = KEVFeed()

    _DEFAULT = FeedSet(epss=epss, kev=kev, reasons=reasons)
    return _DEFAULT


def reset_default_feed() -> None:
    """Testing hook — drop the process-wide feed so env changes take effect."""
    global _DEFAULT
    _DEFAULT = None
