"""Phase 4.3: AI-BOM completeness scoring (G7/NTIA minimum elements) and
HuggingFace hub metadata enrichment.

The gap plan row 4.3 asks for "a completeness score per model component"
against the NTIA minimum-elements list adapted for AI models. The scorer
names what is present, what is missing, and -- in the spirit of the
Phase-2 quality scoring -- what source scanning can NEVER establish
(digital signatures, training-data provenance live with the model
artifact, not in application code), so those are disclosed as
not-computable rather than silently counting as ordinary misses.

HF enrichment converts license/release-date/model-type into computable
elements for hub-hosted models. It must be fail-open, cached, disabled
via RSX_HF_ENRICH=0, and must never let hostile model ids out of scanned
source reach the network beyond the hub API path.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reporting.cyclonedx_bom_export import build_cyclonedx_aibom  # noqa: E402
from scanner.aibom import (  # noqa: E402
    _aibom_element_status,
    _aibom_apply_completeness,
    enrich_hf_metadata,
    generate_aibom,
    scan_file,
)


def _item(provider="OpenAI", component="OpenAI SDK / API", **over) -> dict:
    item = {
        "bom_type": "AI-BOM",
        "provider": provider,
        "component": component,
        "model_hint": "",
        "file": "app.py",
        "line": 3,
        "evidence": "client = OpenAI()",
        "risk": "MEDIUM",
        "recommendation": "review",
    }
    item.update(over)
    return item


HF_CARD = json.dumps({
    "id": "acme/bert-base",
    "pipeline_tag": "fill-mask",
    "license": "apache-2.0",
    "createdAt": "2022-11-30T19:00:00Z",
}).encode()


# --------------------------------------------------------------------------
# Source-only scoring
# --------------------------------------------------------------------------

def test_bare_provider_scores_the_source_establishable_elements():
    status = _aibom_element_status(_item())
    # provider + model_type + dependencies + deployment_environment.
    assert status["score"] == 0.4
    assert status["elements_total"] == 10
    assert "model_name" in status["elements_missing"]
    assert "license" in status["elements_missing"]
    assert status["element_values"]["provider"] == "OpenAI"
    assert status["element_values"]["deployment_environment"] == "vendor-api"


def test_model_hint_adds_name_and_dated_version():
    status = _aibom_element_status(
        _item(model_hint="gpt-4o-2024-05-13"))
    assert status["score"] == 0.6
    assert "model_name" in status["elements_present"]
    assert "model_version" in status["elements_present"]


def test_model_name_without_version_counts_once():
    # "gpt-4o" is a name, not a version; only the name element is added.
    status = _aibom_element_status(_item(model_hint="gpt-4o"))
    assert status["score"] == 0.5
    assert "model_version" in status["elements_missing"]


def test_provider_maps_model_type_and_environment_values():
    ollama = _aibom_element_status(
        _item(provider="Ollama", component="Ollama Local LLM"))
    assert ollama["element_values"]["model_type"] == "local-llm-runtime"
    assert ollama["element_values"]["deployment_environment"] == "local"


def test_not_computable_elements_are_always_disclosed():
    status = _aibom_element_status(_item())
    assert status["not_computable_from_source"] == [
        "digital_signature", "training_data_provenance"]


def test_apply_completeness_covers_every_dict_item():
    out = _aibom_apply_completeness([_item(), "not-a-dict", _item()])
    assert "completeness" in out[0] and "completeness" in out[2]
    assert out[1] == "not-a-dict"          # non-dicts pass through untouched


# --------------------------------------------------------------------------
# HF enrichment contract
# --------------------------------------------------------------------------

def test_hf_enrichment_applies_card_and_recomputes_score(tmp_path):
    item = _item(provider="HuggingFace", component="HuggingFace Transformers",
                 model_hint="acme/bert-base")
    calls = []

    def opener(url, timeout):
        calls.append(url)
        return HF_CARD

    enrich_hf_metadata([item], opener=opener,
                       cache_path=tmp_path / "hf.json")
    assert calls == ["https://huggingface.co/api/models/acme%2Fbert-base"]
    assert item["hf_enrichment"]["status"] == "ok"
    assert item["hf_enrichment"]["license"] == "apache-2.0"

    status = item["completeness"]
    # provider + name + type(fill-mask) + license + release_date
    # + dependencies + deployment = 7/10.
    assert status["score"] == 0.7
    assert "license" in status["elements_enriched"]
    assert "release_date" in status["elements_enriched"]
    assert status["element_values"]["model_type"] == "fill-mask"
    assert status["element_values"]["release_date"] == "2022-11-30"


def test_hf_enrichment_fails_open_and_keeps_source_score(tmp_path):
    item = _item(provider="HuggingFace", component="HuggingFace Transformers",
                 model_hint="acme/bert-base")

    def opener(url, timeout):
        raise OSError("hub unreachable")

    enrich_hf_metadata([item], opener=opener,
                       cache_path=tmp_path / "hf.json")
    assert item["hf_enrichment"]["status"] == "unavailable"
    assert item["completeness"]["score"] == 0.5   # name + type only


def test_hf_enrichment_never_fetches_hostile_ids(tmp_path):
    for hostile in ("../etc/passwd", "https://evil.example/x",
                    "acme/../..", "", "acme/bert?x=1"):
        item = _item(provider="HuggingFace",
                     component="HuggingFace Transformers",
                     model_hint=hostile)
        calls = []

        def opener(url, timeout):
            calls.append(url)
            return HF_CARD

        enrich_hf_metadata([item], opener=opener,
                           cache_path=tmp_path / "hf.json")
        assert calls == [], hostile
        assert "hf_enrichment" not in item, hostile


def test_hf_enrichment_env_gate_disables_fetch(tmp_path, monkeypatch):
    monkeypatch.setenv("RSX_HF_ENRICH", "0")
    item = _item(provider="HuggingFace", component="HuggingFace Transformers",
                 model_hint="acme/bert-base")

    def opener(url, timeout):
        raise AssertionError("must not fetch when disabled")

    enrich_hf_metadata([item], opener=opener,
                       cache_path=tmp_path / "hf.json")
    assert "hf_enrichment" not in item


def test_hf_enrichment_uses_cache_across_runs(tmp_path):
    cache = tmp_path / "hf.json"
    calls = []

    def opener(url, timeout):
        calls.append(url)
        return HF_CARD

    for _ in range(2):
        item = _item(provider="HuggingFace",
                     component="HuggingFace Transformers",
                     model_hint="acme/bert-base")
        enrich_hf_metadata([item], opener=opener, cache_path=cache)
        assert item["hf_enrichment"]["status"] == "ok"

    assert len(calls) == 1   # second run served from cache


def test_hf_enrichment_skips_items_without_model_id(tmp_path):
    item = _item(provider="HuggingFace", component="HuggingFace Transformers")
    _aibom_apply_completeness([item])    # scan pipeline attaches this first

    def opener(url, timeout):
        raise AssertionError("no model id -> no fetch")

    enrich_hf_metadata([item], opener=opener,
                       cache_path=tmp_path / "hf.json")
    assert "hf_enrichment" not in item
    assert item["completeness"]["score"] == 0.4


# --------------------------------------------------------------------------
# Pipeline integration
# --------------------------------------------------------------------------

def test_scan_file_attaches_completeness(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "r = client.chat.completions.create(model='gpt-4o-2024-05-13')\n",
        encoding="utf-8")
    items = scan_file(str(src))
    assert items
    for item in items:
        status = item["completeness"]
        assert 0 < status["score"] <= 1
        assert status["not_computable_from_source"] == [
            "digital_signature", "training_data_provenance"]


def test_generate_aibom_scores_every_final_item(tmp_path):
    (tmp_path / "a.py").write_text("import anthropic\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import ollama\n", encoding="utf-8")
    items = generate_aibom(str(tmp_path))
    assert items
    assert all("completeness" in i for i in items)


def test_export_surfaces_completeness_and_hf_properties():
    item = _item(provider="HuggingFace", component="HuggingFace Transformers",
                 model_hint="acme/bert-base")
    item["completeness"] = _aibom_element_status(item)
    item["hf_enrichment"] = {"model_id": "acme/bert-base", "status": "ok",
                             "license": "apache-2.0"}
    # Recompute as enrichment would.
    item["completeness"] = _aibom_element_status(item)

    doc = build_cyclonedx_aibom([item], "t", "1")
    props = {p["name"]: p["value"] for p in doc["components"][0]["properties"]}
    assert props["rsecopsx:completeness_score"] == str(
        item["completeness"]["score"])
    assert "provider" in props["rsecopsx:completeness_elements"]
    assert "release_date" in props["rsecopsx:missing_elements"]
    assert "digital_signature" in props["rsecopsx:not_computable_from_source"]
    assert props["rsecopsx:hf_status"] == "ok"
    assert props["rsecopsx:hf_license"] == "apache-2.0"
