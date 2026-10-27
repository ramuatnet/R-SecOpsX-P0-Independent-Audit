"""NVD API 2.0 client for CPE-matched secondary enrichment (gap plan 1.5).

The NVD is queried as a SECONDARY source: OSV stays primary, and the NVD
pass exists for the other direction -- CVEs whose CPE applicability
mentions a component's vendor:product where OSV has no record for that
package (name-mismatched or ecosystem-uncovered packages).

Deliberately opt-in (``RSX_NVD_ENRICH=1``). The NVD allows five requests
per 30 seconds without an API key, so an unconditional pass would throttle
a full-corpus scan to a crawl for data OSV mostly already carries. Set
``NVD_API_KEY`` for the 50-per-30-seconds tier; the per-run query budget
is ``RSX_NVD_MAX_QUERIES`` (default 5 unauthenticated, 25 with a key) and
the client spaces its own requests to stay inside the published rate.

Fails open exactly like the OSV path: an outage costs the secondary
source, never the scan, and the absence is disclosed in
``NVD_SERVICE_STATUS`` rather than reading as "no known vulnerabilities".
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_CACHE_FILE = Path("reports") / ".nvd_cache.json"
NVD_CACHE_VERSION = 1

# Disclosed by the last query pass; read the same way ADVISORY_SERVICE_STATUS
# is -- the dangerous outcome is a report that reads "no known CVEs" when the
# truth is "we could not ask".
NVD_SERVICE_STATUS: dict = {}

# Oldest allowed timestamp for the client's own pacing; None = no request
# has been made in this process yet.
_last_request_at: float | None = None


def _nvd_enabled() -> bool:
    return os.environ.get("RSX_NVD_ENRICH", "").strip().lower() in {
        "1", "true", "yes", "on"}


def _nvd_query_budget() -> int:
    raw = os.environ.get("RSX_NVD_MAX_QUERIES", "").strip()
    if raw.isdigit():
        return int(raw)
    return 25 if os.environ.get("NVD_API_KEY", "").strip() else 5


def _nvd_headers() -> dict:
    headers = {"User-Agent": "R-SecOpsX-SCA"}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _respect_rate_limit() -> None:
    """Space requests to the NVD's published budget.

    Unauthenticated: 5 requests / 30s. Authenticated: 50 / 30s. Sleeping
    here is the price of asking at all; the caller's per-run budget is what
    keeps that price bounded.
    """
    global _last_request_at
    window = 30.0
    allowance = 50 if os.environ.get("NVD_API_KEY", "").strip() else 5
    wait = window / allowance
    if _last_request_at is not None:
        delta = time.monotonic() - _last_request_at
        if delta < wait:
            time.sleep(wait - delta)
    _last_request_at = time.monotonic()


def _load_nvd_cache() -> dict:
    if not NVD_CACHE_FILE.exists():
        return {}
    try:
        raw = json.loads(NVD_CACHE_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("entries"), dict):
            return raw["entries"]
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _save_nvd_cache(cache: dict) -> None:
    try:
        NVD_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        NVD_CACHE_FILE.write_text(
            json.dumps({"schema_version": NVD_CACHE_VERSION,
                        "source": "NVD", "entries": cache}, indent=2),
            encoding="utf-8")
    except Exception:
        pass


def _nvd_severity(cve_obj: dict) -> str:
    metrics = cve_obj.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not isinstance(entries, list) or not entries:
            continue
        primary = next(
            (e for e in entries
             if isinstance(e, dict) and e.get("type") == "Primary"),
            entries[0] if isinstance(entries[0], dict) else None)
        if not primary:
            continue
        data = primary.get("cvssData") or {}
        sev = str(data.get("baseSeverity")
                  or primary.get("baseSeverity") or "").strip()
        if sev:
            return sev.capitalize()
    return "Unknown"


def _nvd_cvss(cve_obj: dict):
    metrics = cve_obj.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not isinstance(entries, list) or not entries:
            continue
        primary = next(
            (e for e in entries
             if isinstance(e, dict) and e.get("type") == "Primary"),
            entries[0] if isinstance(entries[0], dict) else None)
        if not primary:
            continue
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score), str(data.get("version") or ""), \
                str(data.get("vectorString") or "")
    return None, "", ""


def normalize_nvd_cve(item: dict, cpe: str) -> dict:
    """Map one NVD API vulnerability object onto the advisory record shape.

    The result is intentionally shaped like ``normalize_osv_vulnerability``'s
    output so every downstream consumer (severity ranking, dedup, reporting,
    CDX export) handles NVD records without a special case. The provenance
    fields distinguish it: ``source``/``advisory_origin`` = NVD,
    ``provider`` = NVD, and ``matching_method`` states that identity came
    from a CPE virtual match, NOT an exact package-version query -- an
    NVD CPE match can cover a version range, so that distinction must
    survive to the report.
    """
    cve_obj = item.get("cve") or {}
    cve_id = str(cve_obj.get("id") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return {}

    summary = ""
    for desc in cve_obj.get("descriptions") or []:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            summary = str(desc.get("value") or "")
            break

    score, cvss_version, vector = _nvd_cvss(cve_obj)
    fixed = str(cve_obj.get("vulnStatus") or "")

    return {
        "id": cve_id,
        "cve": cve_id,
        "advisory_id": cve_id,
        "aliases": [],
        "summary": summary,
        "details": summary,
        "severity": _nvd_severity(cve_obj),
        "cvss": score,
        "cvss_version": cvss_version,
        "cvss_vector": vector,
        "cvss_preferred_score": score,
        "cvss_alternate_assessments": [],
        "published": cve_obj.get("published"),
        "modified": cve_obj.get("lastModified"),
        "fixed_versions": [],
        "vuln_status": fixed,
        "source": "NVD",
        "advisory_origin": "NVD",
        "provider": "NVD",
        "matching_method": "nvd_cpe_virtual_match",
        "matched_cpe": cpe,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def query_nvd_by_cpe(cpe: str) -> list[dict]:
    """CVEs whose CPE applicability covers ``cpe``'s vendor:product.

    Fails open. A transport error, a rate-limit body, or a JSON surprise
    returns ``[]`` and records the reason in ``NVD_SERVICE_STATUS`` --
    never an exception into the scan, and never a silent "clean" without
    disclosure.
    """
    global _last_request_at
    cpe = str(cpe or "").strip()
    if not cpe.startswith("cpe:2.3:a:"):
        return []

    cache = _load_nvd_cache()
    if cpe in cache and isinstance(cache.get(cpe), list):
        NVD_SERVICE_STATUS.setdefault("from_cache", 0)
        NVD_SERVICE_STATUS["from_cache"] += 1
        return cache[cpe]

    # The NVD wants a wildcard version to match every version of a product.
    base_fields = cpe.split(":")
    wildcard = ":".join(base_fields[:5] + ["*"] * 8)

    url = f"{NVD_CVES_URL}?virtualMatchString={urllib.parse.quote(wildcard)}&resultsPerPage=50"

    status = NVD_SERVICE_STATUS
    status.setdefault("service", "NVD")
    status.setdefault("endpoint", NVD_CVES_URL)
    status.setdefault("available", True)
    status.setdefault("queries_attempted", 0)
    status.setdefault("queries_answered", 0)
    status.setdefault("failures", [])

    status["queries_attempted"] += 1
    _respect_rate_limit()

    req = urllib.request.Request(url, headers=_nvd_headers(), method="GET")
    try:
                # Match the working NVD connection: TLS 1.2 only.
        # Default certificate verification remains enabled.
        _nvd_ssl_context = ssl.create_default_context()
        _nvd_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        _nvd_ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        with urllib.request.urlopen(
                req, timeout=20, context=_nvd_ssl_context) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError,
            ValueError) as exc:
        status["available"] = False
        status["failures"].append({
            "cpe": wildcard,
            "reason": str(exc)[:300],
            "error_type": type(exc).__name__,
        })
        return []

    vulns = body.get("vulnerabilities") if isinstance(body, dict) else None
    if not isinstance(vulns, list):
        # The NVD OMITS the array entirely when a query matches nothing;
        # a present 'totalResults' proves the service answered, so an empty
        # match is data (cache it) rather than a shape error. Only a body
        # with neither field is an actual protocol violation.
        if isinstance(body, dict) and "totalResults" in body:
            status["queries_answered"] += 1
            if len(cache) >= 4096:
                cache.clear()
            cache[cpe] = []
            _save_nvd_cache(cache)
            return []
        status["available"] = False
        status["failures"].append({
            "cpe": wildcard,
            "reason": "response had no 'vulnerabilities' list",
            "error_type": "UnexpectedResponseShape",
        })
        return []

    status["queries_answered"] += 1

    records = []
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        record = normalize_nvd_cve(entry, wildcard)
        if record:
            records.append(record)

    if len(cache) >= 4096:
        cache.clear()
    cache[cpe] = records
    _save_nvd_cache(cache)
    return records
