"""T-6.1: subdomain-takeover detection (pure match core).

Takeover = a DNS record (usually CNAME) points at a third-party hosting
provider while the resource on that provider is UNCLAIMED, so an
attacker can claim it and serve content on the victim's subdomain.

Two independent signals, deliberately separated:

  * ``match_cname``   -- the name POINTS at a known provider.  By itself
    that is ``tentative``: pointing at GitHub Pages with a claimed site
    is perfectly normal.  It becomes a finding only when paired with an
    unclaimed-response marker (``match_body`` -> ``likely``/``confirmed``),
    which is what ``correlate_takeover`` requires.
  * ``match_body``    -- the HTTP body carries the provider's "no such
    site" fingerprint.  ``confirmed`` needs both signals agreeing on the
    SAME provider; a body marker alone is ``likely`` (could be a proxy
    page borrowing the wording).

All tables are data, all matching is pure -- the probes that feed them
run in the collector (network, opt-in, injected).
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_80
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_80

import re

# CNAME/NS suffix -> provider (lowercase, matched on label boundaries)
PROVIDER_BY_SUFFIX: dict[str, str] = {
    "github.io": "GitHub Pages",
    "githubusercontent.com": "GitHub",
    "herokuapp.com": "Heroku",
    "herokussl.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure",
    "blob.core.windows.net": "Azure Blob",
    "azurestaticapps.net": "Azure Static Web Apps",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "awsapps.com": "AWS WorkDocs",
    "amplifyapp.com": "AWS Amplify",
    "digitalocean-spaces.com": "DigitalOcean Spaces",
    "herokudns.com": "Heroku",
    "fastly.net": "Fastly",
    "edgekey.net": "Akamai",
    "akamaized.net": "Akamai",
    "pantheonsite.io": "Pantheon",
    "wpengine.com": "WP Engine",
    "wordpress.com": "WordPress.com",
    "tumblr.com": "Tumblr",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "wixdns.net": "Wix",
    "wixsite.com": "Wix",
    "squarespace.com": "Squarespace",
    "sqsp.net": "Squarespace",
    "ghost.io": "Ghost",
    "netlify.com": "Netlify",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket Pages",
    "zendesk.com": "Zendesk",
    "readthedocs.io": "Read the Docs",
    "helpjuice.com": "Helpjuice",
    "helpscoutdocs.com": "HelpScout",
    "statuspage.io": "Atlassian Statuspage",
    "unbounce.com": "Unbounce",
    "cargocollective.com": "Cargo Collective",
    "feedpress.me": "FeedPress",
    "freshdesk.com": "Freshdesk",
    "desk.com": "Desk",
    "teamwork.com": "Teamwork",
    "thinkific.com": "Thinkific",
    "kajabi.com": "Kajabi",
    "teachable.com": "Teachable",
    "mailchi.mp": "Mailchimp",
}

# S3 website endpoints carry the region in the label
# (bucket.s3-website-us-east-1.amazonaws.com / ...s3-website.eu-west-1...):
# suffix equality can't express that, so match_cname special-cases it.
_S3_WEBSITE_RE = re.compile(r"(^|\.)s3[.-]website[.-]", re.I)

# body marker -> (provider, confidence).  Markers are the providers' own
# words; a match here means the hosted resource was never claimed.
BODY_MARKERS: tuple[tuple[str, str, str], ...] = (
    (r"there isn'?t a github pages site here", "GitHub Pages", "confirmed"),
    (r"repository not found", "GitHub", "likely"),
    (r"if you'?re the owner of this site,", "GitHub Pages", "confirmed"),
    (r"heroku\s*\|\s*no such app", "Heroku", "confirmed"),
    (r"no such app", "Heroku", "likely"),
    (r"there is no app configured at that hostname", "Heroku", "likely"),
    (r"azurewebsites\.net.*not found", "Azure App Service", "likely"),
    (r"this web app (has not|is not) been created", "Azure App Service", "confirmed"),
    (r"blob core windows net.*not found", "Azure Blob", "likely"),
    (r"no such bucket", "AWS S3", "confirmed"),
    (r"fastly error: unknown domain", "Fastly", "confirmed"),
    (r"digitalocean spaces.*not found", "DigitalOcean Spaces", "likely"),
    (r"repository not archived", "Pantheon", "likely"),
    (r"do you want to register", "Pantheon", "likely"),
    (r"sorry, (yet another )?ghost site", "Ghost", "likely"),
    (r"domain is not configured", "Shopify", "likely"),
    (r"publish your site with wix", "Wix", "confirmed"),
    (r"site is not published yet", "Wix", "likely"),
    (r"squarespace.*no such account", "Squarespace", "likely"),
    (r"view our 404 page", "Squarespace", "likely"),
    (r"helpjuice.*we could not find this page", "Helpjuice", "confirmed"),
    (r"helpscout.*no help desk configured", "HelpScout", "confirmed"),
    (r"statuspage.*not found", "Atlassian Statuspage", "likely"),
    (r"unbounce.*page not found", "Unbounce", "confirmed"),
    (r"you haven'?t set up your (website|domain) yet", "Vercel", "likely"),
    (r"the deployment could not be found", "Netlify", "likely"),
    (r"domain (name)? (is )?(not|no longer) (yet )?(registered|configured)",
     "Generic", "tentative"),
)

_PROVIDER_RE = tuple(
    (re.compile(pat, re.I), provider, conf)
    for pat, provider, conf in BODY_MARKERS
)


def match_cname(target: str | None) -> dict | None:
    """Does the CNAME/NS target point at a known provider?
    Suffix match on LABEL BOUNDARY ('evilgithub.io' must not match
    'github.io').  Returns {'provider','confidence':'tentative'}."""
    if not target:
        return None
    host = str(target).strip().lower().rstrip(".")
    if _S3_WEBSITE_RE.search(host):
        return {"provider": "AWS S3 website", "confidence": "tentative",
                "evidence": f"cname->{host}"}
    best: tuple[int, str] | None = None
    for suffix, provider in PROVIDER_BY_SUFFIX.items():
        if host == suffix or host.endswith("." + suffix):
            if best is None or len(suffix) > best[0]:
                best = (len(suffix), provider)
    if best is None:
        return None
    return {"provider": best[1], "confidence": "tentative",
            "evidence": f"cname->{host}"}


def match_body(body: str | None) -> list[dict]:
    """Provider unclaimed-response markers found in a response body."""
    if not body:
        return []
    text = str(body)[:512 * 1024]
    out: list[dict] = []
    seen: set[str] = set()
    for rx, provider, conf in _PROVIDER_RE:
        if rx.search(text) and provider not in seen:
            seen.add(provider)
            out.append({"provider": provider, "confidence": conf,
                        "evidence": rx.pattern[:WINDOW_80]})
    return out


def correlate_takeover(cname: str | None, body: str | None) -> dict | None:
    """Join the two signals.  Returns the strongest single finding:
    both agreeing on a provider -> ``likely`` (body marker may already be
    ``confirmed``); cname alone -> NO finding (normal setup), recorded by
    the collector as context; body alone -> ``tentative`` (can't rule out
    borrowed wording) -- never emitted as confirmed without BOTH."""
    c = match_cname(cname)
    bodies = match_body(body)
    if c and bodies:
        for b in bodies:
            if b["provider"] == c["provider"]:
                return {
                    "provider": c["provider"],
                    "confidence": b["confidence"],
                    "evidence": [c["evidence"], b["evidence"]],
                }
        # providers disagree (cname -> A, body marker -> B): report the
        # body's stronger marker but keep both for the analyst
        b = bodies[0]
        return {
            "provider": b["provider"],
            "confidence": "tentative",
            "evidence": [c["evidence"], b["evidence"],
                         f"cname_provider={c['provider']}"],
        }
    if bodies:
        b = bodies[0]
        return {"provider": b["provider"], "confidence": "tentative",
                "evidence": [b["evidence"], "no_matching_cname"]}
    return None                            # cname-only: caller keeps context
