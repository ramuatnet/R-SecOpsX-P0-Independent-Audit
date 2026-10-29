"""T-5.1: DAST crawler & target model (PHASE 5 entry point).

``model``     the normalized route/method/param model + SAST merge;
``sources``   offline parsers: OpenAPI/Swagger, Postman, HAR, HTML,
              JS, sitemap, robots (size-capped, disclosure on skip);
``crawler``   opt-in scope-bounded GET-only BFS crawl (robots-aware,
              rate-limited, deterministic) -- no network unless asked;
``target_model``  auto-detect + parse + optional crawl + merge with
              ``scanner.apibom`` (the in-product SAST route model);
``auth``      T-5.2 login strategies, sessions, multi-role differential;
``checks``    T-5.3 active checks: safe-mode probes (scope allowlist,
              GET/POST only, rate limit, 429 backoff, per-route budget)
              emitting the additive ``rsecopsx.dast_findings/v1``
              artifact -- separate from SAST finding rows, so the scan
              oracles stay untouched until T-5.5 correlation.
"""
from analysis.dast.auth import (  # noqa: F401
    AuthProfile,
    AuthSession,
    build_session,
    build_sessions,
    differential,
    load_profiles,
    session_headers,
    SessionReplay,
)
from analysis.dast.checks import (  # noqa: F401
    CHECKS,
    CheckContext,
    default_probe_fetch,
    FINDINGS_SCHEMA,
    ProbeResponse,
    run_checks,
)
from analysis.dast.crawler import CrawlConfig, FetchResponse, crawl  # noqa: F401
from analysis.dast.model import (  # noqa: F401
    MODEL_SCHEMA,
    make_entry,
    merge_entries,
    merge_with_sast,
    normalize_path,
    route_key,
)
from analysis.dast.target_model import build_target_model  # noqa: F401
