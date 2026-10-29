"""T-5.1: DAST crawler & target model (PHASE 5 entry point).

``model``     the normalized route/method/param model + SAST merge;
``sources``   offline parsers: OpenAPI/Swagger, Postman, HAR, HTML,
              JS, sitemap, robots (size-capped, disclosure on skip);
``crawler``   opt-in scope-bounded GET-only BFS crawl (robots-aware,
              rate-limited, deterministic) -- no network unless asked;
``target_model``  auto-detect + parse + optional crawl + merge with
              ``scanner.apibom`` (the in-product SAST route model).

T-5.2..T-5.5 (auth, active checks, OOB, correlation) build on this
package; nothing here emits findings, so the scan oracles are untouched.
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
