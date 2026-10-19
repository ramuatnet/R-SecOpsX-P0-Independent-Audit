"""V4: truthful AIBOM identity enrichment (OWASP aibom-generator run).

Context: the real OWASP aibom-generator completeness scorer (run
2026-10-19; evidence in HANDOFF_remaining_work.md) scored the emitted
AIBOM 22/100 -- required document fields all present, but the
component-level purl/description/licenses/externalReferences fields the
profile scores were absent, although they are truthfully derivable for
the SDK/framework components the detection rules bind to.
reporting/cyclonedx_bom_export.py now emits them from the sourced
``_AI_ENRICHMENT`` table (PyPI distribution metadata + upstream GitHub
repository API, cross-checked).

These tests pin:
  * a known component gets exactly its curated identity fields
  * an unknown component gets NOTHING (absence beats invention)
  * every AI_RULES component has an enrichment entry, so future rules
    must consider package identity
  * enrichment values stay internally consistent (pypi purls, SPDX
    shaped licenses, https homepages)
  * HF-stated model licenses ride as CycloneDX licenses (id vs name)
  * the existing rsecopsx:* provenance properties are untouched
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from reporting.cyclonedx_bom_export import (  # noqa: E402
    _AI_ENRICHMENT,
    build_cyclonedx_aibom,
)


def _item(**kw):
    base = {
        "provider": "OpenAI",
        "component": "OpenAI SDK / API",
        "file": "app.py",
        "line": 3,
        "risk": "MEDIUM",
        "recommendation": "r",
    }
    base.update(kw)
    return base


def test_known_component_gets_curated_identity():
    doc = build_cyclonedx_aibom([_item()], "t", "1")
    comp = doc["components"][0]
    assert comp["purl"] == "pkg:pypi/openai"
    assert comp["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    assert comp["externalReferences"][0]["type"] == "website"
    assert comp["externalReferences"][0]["url"].startswith("https://github.com/")
    assert comp["description"]


def test_unknown_component_is_not_enriched():
    doc = build_cyclonedx_aibom(
        [_item(component="Something We Never Heard Of")], "t", "1")
    comp = doc["components"][0]
    for key in ("purl", "licenses", "externalReferences", "description"):
        assert key not in comp, key


def test_every_ai_rules_component_has_an_enrichment_entry():
    from scanner.aibom import AI_RULES
    missing = [
        r["component"] for r in AI_RULES
        if r["component"] not in _AI_ENRICHMENT
    ]
    assert not missing, missing


def test_enrichment_entries_are_internally_consistent():
    for name, ident in _AI_ENRICHMENT.items():
        purl = ident.get("purl")
        if purl:
            assert purl.startswith("pkg:pypi/"), (name, purl)
        lic = ident.get("license")
        if lic:
            assert lic == lic.strip() and " " not in lic, (name, lic)
        url = ident.get("homepage")
        if url:
            assert url.startswith("https://"), (name, url)


def test_hf_license_rides_as_cyclonedx_license():
    doc = build_cyclonedx_aibom(
        [_item(provider="HuggingFace", component="Some Model",
               hf_enrichment={"license": "apache-2.0"})], "t", "1")
    assert doc["components"][0]["licenses"] == [{"license": {"id": "apache-2.0"}}]

    doc2 = build_cyclonedx_aibom(
        [_item(provider="HuggingFace", component="Some Model",
               hf_enrichment={"license": "Free for non-commercial use"})], "t", "1")
    lic = doc2["components"][0]["licenses"][0]["license"]
    assert lic == {"name": "Free for non-commercial use"}


def test_provenance_properties_are_untouched():
    doc = build_cyclonedx_aibom([_item(model_hint="gpt-4o")], "t", "1")
    comp = doc["components"][0]
    props = {p["name"] for p in comp["properties"]}
    assert {"rsecopsx:provider", "rsecopsx:file", "rsecopsx:line",
            "rsecopsx:risk", "rsecopsx:recommendation"} <= props
    assert comp["version"] == "gpt-4o"
