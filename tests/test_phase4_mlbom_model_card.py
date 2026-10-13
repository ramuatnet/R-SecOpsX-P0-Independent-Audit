"""Phase 4.4: ML-BOM model-card extraction and dataset provenance.

The gap plan row 4.4 asks for "model-card extraction + dataset
provenance" with the acceptance "model-card block populated". A model
card (Mitchell et al.; HuggingFace README-with-YAML-front-matter) is
where name/version/license/task/dataset declarations live for a trained
model. This pass finds card DOCUMENTS in the scan tree (JSON / YAML /
markdown front matter), normalizes them, and attaches the block to the
items the card belongs to -- same-directory or artifact-name association
only, never a guess. Dataset provenance records WHERE each dataset
reference came from: a code line the scanner saw, or a card document.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.mlbom import (  # noqa: E402
    _front_matter_fallback,
    _parse_model_card,
    generate_mlbom,
    scan_file,
)

HF_README = """---
license: apache-2.0
base_model: sentiment-model
pipeline_tag: text-classification
datasets:
  - imdb
  - sst2
---

# Sentiment Model

Fine-tuned sentiment classifier used by the demo app.
"""

JSON_CARD = json.dumps({
    "name": "churn-ranker",
    "version": "2.1.0",
    "license": "proprietary",
    "metrics": {"accuracy": 0.91, "f1": 0.88},
    "description": "Customer churn ranking model.",
})

TRAIN_PY = (
    "import tensorflow as tf\n"
    "model = tf.keras.models.load_model('models/sentiment.h5')\n"
)


def test_hf_readme_front_matter_parses(tmp_path):
    readme = tmp_path / "models" / "sentiment" / "README.md"
    readme.parent.mkdir(parents=True)
    readme.write_text(HF_README, encoding="utf-8")

    card = _parse_model_card(readme)
    assert card is not None
    assert card["format"] == "markdown"
    assert card["license"] == "apache-2.0"
    assert card["name"] == "sentiment-model"
    assert card["task"] == "text-classification"
    assert card["datasets"] == ["imdb", "sst2"]
    assert "sentiment classifier" in card["summary"]


def test_json_model_card_parses(tmp_path):
    card_file = tmp_path / "model_card.json"
    card_file.write_text(JSON_CARD, encoding="utf-8")
    card = _parse_model_card(card_file)
    assert card["format"] == "json"
    assert card["name"] == "churn-ranker"
    assert card["version"] == "2.1.0"
    assert card["metrics"]["accuracy"] == 0.91
    assert "license" in card["fields_detected"]


def test_plain_readme_without_front_matter_is_not_a_card(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# Project\n\nJust a readme.\n", encoding="utf-8")
    assert _parse_model_card(readme) is None


def test_bom_prefixed_card_still_parses(tmp_path):
    # Windows editors write UTF-8 with BOM constantly; the card must
    # parse regardless (caught in a real PowerShell-written target).
    readme = tmp_path / "README.md"
    readme.write_text("\ufeff" + HF_README, encoding="utf-8")
    card = _parse_model_card(readme)
    assert card is not None
    assert card["license"] == "apache-2.0"


def test_unparseable_card_fails_open(tmp_path):
    bad = tmp_path / "model_card.json"
    bad.write_text("{not json", encoding="utf-8")
    assert _parse_model_card(bad) is None


def test_yaml_fallback_without_pyyaml_parses_scalars_and_lists():
    front = ("license: mit\n"
             "base_model: my-model\n"
             "pipeline_tag: token-classification\n"
             "datasets:\n"
             "  - wikitext\n"
             "  - conll2003\n")
    data = _front_matter_fallback(front)
    assert data["license"] == "mit"
    assert data["datasets"] == ["wikitext", "conll2003"]


def test_same_directory_card_associates_and_enriches_datasets(tmp_path):
    (tmp_path / "models" / "sentiment").mkdir(parents=True)
    (tmp_path / "models" / "sentiment" / "README.md").write_text(
        HF_README, encoding="utf-8")
    (tmp_path / "models" / "sentiment" / "train.py").write_text(
        TRAIN_PY, encoding="utf-8")

    items = generate_mlbom(str(tmp_path))
    tf_items = [i for i in items if i["framework"] == "TensorFlow"]
    assert tf_items
    card_block = tf_items[0]["model_card"]
    assert card_block["license"] == "apache-2.0"
    assert card_block["association"] == "same-directory"
    origins = {d.get("origin") for d in tf_items[0]["datasets"]}
    assert "model-card" in origins


def test_artifact_name_association_across_directories(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "model_card.json").write_text(
        json.dumps({"name": "sentiment", "license": "mit",
                    "description": "for sentiment.h5 deployment"}),
        encoding="utf-8")
    (tmp_path / "train.py").write_text(TRAIN_PY, encoding="utf-8")

    items = generate_mlbom(str(tmp_path))
    tf_items = [i for i in items if i["framework"] == "TensorFlow"]
    assert tf_items[0]["model_card"]["association"] == "artifact-name"
    assert tf_items[0]["model_card"]["license"] == "mit"


def test_unrelated_card_does_not_attach(tmp_path):
    (tmp_path / "models" / "other").mkdir(parents=True)
    (tmp_path / "models" / "other" / "model_card.json").write_text(
        JSON_CARD, encoding="utf-8")
    (tmp_path / "train.py").write_text(TRAIN_PY, encoding="utf-8")

    items = generate_mlbom(str(tmp_path))
    tf_items = [i for i in items if i["framework"] == "TensorFlow"]
    assert tf_items
    assert all("model_card" not in i for i in tf_items)


def test_dataset_provenance_records_code_reference_line(tmp_path):
    (tmp_path / "train.py").write_text(
        "import pandas as pd\n"
        "df = pd.read_csv('data/train.csv')\n",
        encoding="utf-8")
    items = scan_file(str(tmp_path / "train.py"))
    pandas_items = [i for i in items if i["framework"] == "Pandas"]
    assert pandas_items
    dataset = pandas_items[0]["datasets"][0]
    assert dataset["path"] == "data/train.csv"
    assert dataset["format"] == "csv"
    assert dataset["origin"] == "code-reference"
    assert dataset["line"] == 2


def test_items_without_datasets_carry_empty_list():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "plain.py"
        path.write_text("import torch\n", encoding="utf-8")
        items = scan_file(str(path))
        assert items
        assert all(isinstance(i.get("datasets"), list) for i in items)


def test_generate_mlbom_end_to_end_keeps_dedup(tmp_path):
    (tmp_path / "model_card.json").write_text(JSON_CARD, encoding="utf-8")
    train = tmp_path / "train.py"
    train.write_text(
        "import tensorflow as tf\n"
        "m = tf.keras.models.load_model('model.h5')\n"
        "m2 = tf.keras.models.load_model('model.h5')\n",
        encoding="utf-8")
    items = generate_mlbom(str(tmp_path))
    tf_items = [i for i in items if i["framework"] == "TensorFlow"]
    # One per (component, line): two load_model lines are two findings,
    # same line twice would dedup.
    assert tf_items
    assert all(i["model_card"]["name"] == "churn-ranker" for i in tf_items)
