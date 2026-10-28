from __future__ import annotations

import json
import re
from pathlib import Path

try:  # PyYAML is a repo dependency; degrade to a line parser without it.
    import yaml
except ImportError:  # pragma: no cover - defensive
    yaml = None

from scanner.sast import _skip
# T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
from core import file_index


SCANNABLE_EXT = {
    ".py", ".r", ".R", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".json", ".yml", ".yaml", ".toml",
    ".ini", ".config", ".txt", ".ipynb"
}


ML_RULES = [
    {
        "framework": "TensorFlow",
        "component": "TensorFlow / Keras",
        "patterns": [
            r"\bimport\s+tensorflow\b",
            r"\bfrom\s+tensorflow\b",
            r"\btf\.keras\b",
            r"\bkeras\.models\.load_model\b",
            r"\btf\.keras\.models\.load_model\b",
            r"\.h5[\"']",
            r"\.keras[\"']",
        ],
        "category": "ML Framework",
        "risk": "MEDIUM",
        "recommendation": "Validate model provenance, unsafe model loading, dependency trust, and dataset governance."
    },
    {
        "framework": "PyTorch",
        "component": "PyTorch",
        "patterns": [
            r"\bimport\s+torch\b",
            r"\bfrom\s+torch\b",
            r"\btorch\.load\s*\(",
            r"\.pt[\"']",
            r"\.pth[\"']",
        ],
        "category": "ML Framework",
        "risk": "HIGH",
        "recommendation": "Avoid loading untrusted PyTorch models with torch.load; verify provenance and signatures."
    },
    {
        "framework": "Scikit-Learn",
        "component": "Scikit-Learn",
        "patterns": [
            r"\bimport\s+sklearn\b",
            r"\bfrom\s+sklearn\b",
            r"\bscikit-learn\b",
            r"\bsklearn\.",
        ],
        "category": "ML Framework",
        "risk": "MEDIUM",
        "recommendation": "Validate training data lineage, model provenance, and serialized model loading."
    },
    {
        "framework": "XGBoost",
        "component": "XGBoost",
        "patterns": [
            r"\bimport\s+xgboost\b",
            r"\bfrom\s+xgboost\b",
            r"\bxgb\.",
            r"\bXGBClassifier\b",
            r"\bXGBRegressor\b",
            r"\bxgboost\s*\(",
        ],
        "category": "ML Framework",
        "risk": "MEDIUM",
        "recommendation": "Validate model provenance, feature lineage, and training data governance."
    },
    {
        "framework": "LightGBM",
        "component": "LightGBM",
        "patterns": [
            r"\bimport\s+lightgbm\b",
            r"\bfrom\s+lightgbm\b",
            r"\blgb\.",
            r"\bLGBMClassifier\b",
            r"\bLGBMRegressor\b",
        ],
        "category": "ML Framework",
        "risk": "MEDIUM",
        "recommendation": "Validate model provenance, feature lineage, and training data governance."
    },
    {
        "framework": "Pandas",
        "component": "Pandas Dataset Processing",
        "patterns": [
            r"\bimport\s+pandas\b",
            r"\bfrom\s+pandas\b",
            r"\bpd\.read_csv\s*\(",
            r"\bpd\.read_excel\s*\(",
            r"\bpd\.read_parquet\s*\(",
            r"\bpd\.read_sql\s*\(",
        ],
        "category": "Data Processing",
        "risk": "LOW",
        "recommendation": "Classify datasets and validate PII/PHI/PCI exposure in training or inference data."
    },
    {
        "framework": "NumPy",
        "component": "NumPy Feature Processing",
        "patterns": [
            r"\bimport\s+numpy\b",
            r"\bfrom\s+numpy\b",
            r"\bnp\.array\s*\(",
            r"\bnumpy\.array\s*\(",
        ],
        "category": "Feature Processing",
        "risk": "LOW",
        "recommendation": "Validate feature sources, transformations, and sensitive data handling."
    },
    {
        "framework": "Joblib",
        "component": "Joblib Model Loading",
        "patterns": [
            r"\bimport\s+joblib\b",
            r"\bfrom\s+joblib\b",
            r"\bjoblib\.load\s*\(",
            r"\.joblib[\"']",
        ],
        "category": "Model Serialization",
        "risk": "HIGH",
        "recommendation": "Do not load untrusted joblib files; verify model signatures and trusted storage."
    },
    {
        "framework": "Pickle",
        "component": "Pickle Model Loading",
        "patterns": [
            r"\bimport\s+pickle\b",
            r"\bpickle\.load\s*\(",
            r"\bpickle\.loads\s*\(",
            r"\.pkl[\"']",
            r"\.pickle[\"']",
        ],
        "category": "Unsafe Model Serialization",
        "risk": "CRITICAL",
        "recommendation": "Avoid pickle for untrusted ML models; use safe formats and signed artifacts."
    },
    {
        "framework": "ONNX",
        "component": "ONNX Model Runtime",
        "patterns": [
            r"\bimport\s+onnx\b",
            r"\bimport\s+onnxruntime\b",
            r"\bInferenceSession\s*\(",
            r"\.onnx[\"']",
        ],
        "category": "Model Runtime",
        "risk": "MEDIUM",
        "recommendation": "Validate ONNX model provenance, runtime version, and input validation controls."
    },
    {
        "framework": "MLflow",
        "component": "MLflow Tracking / Registry",
        "patterns": [
            r"\bimport\s+mlflow\b",
            r"\bfrom\s+mlflow\b",
            r"\bmlflow\.",
            r"\bMLFLOW_TRACKING_URI\b",
        ],
        "category": "ML Lifecycle Platform",
        "risk": "MEDIUM",
        "recommendation": "Validate MLflow tracking server access, model registry permissions, and artifact integrity."
    },
    {
        "framework": "R caret",
        "component": "R caret ML Framework",
        "patterns": [
            r"\blibrary\s*\(\s*caret\s*\)",
            r"\brequire\s*\(\s*caret\s*\)",
            r"\btrain\s*\(",
        ],
        "category": "R ML Framework",
        "risk": "MEDIUM",
        "recommendation": "Validate R model provenance, dataset lineage, and serialized model handling."
    },
    {
        "framework": "R randomForest",
        "component": "R Random Forest",
        "patterns": [
            r"\blibrary\s*\(\s*randomForest\s*\)",
            r"\brandomForest\s*\(",
        ],
        "category": "R ML Framework",
        "risk": "MEDIUM",
        "recommendation": "Validate model training data, feature sensitivity, and model governance."
    },
    {
        "framework": "R XGBoost",
        "component": "R XGBoost",
        "patterns": [
            r"\blibrary\s*\(\s*xgboost\s*\)",
            r"\bxgboost\s*\(",
        ],
        "category": "R ML Framework",
        "risk": "MEDIUM",
        "recommendation": "Validate model training data, feature sensitivity, and model governance."
    },
    {
        "framework": "R Serialized Model",
        "component": "RDS Model Loading",
        "patterns": [
            r"\breadRDS\s*\(",
            r"\bsaveRDS\s*\(",
            r"\.rds[\"']",
        ],
        "category": "Model Serialization",
        "risk": "HIGH",
        "recommendation": "Validate RDS model provenance and avoid loading untrusted serialized artifacts."
    },
]


MODEL_FILE_RE = re.compile(
    r"[\"']([^\"']+\.(?:h5|keras|pt|pth|pkl|pickle|joblib|onnx|rds))[\"']",
    re.IGNORECASE
)

DATASET_HINT_RE = re.compile(
    r"[\"']([^\"']+\.(?:csv|xlsx|xls|parquet|json|jsonl|feather))[\"']",
    re.IGNORECASE
)


def _should_scan(path: Path) -> bool:
    """
    ML-BOM source-scope filter.

    ML-BOM is intended to identify ML frameworks, model loading,
    serialization, and dataset usage in application/source code.
    Third-party dependency trees and generated/build artifacts must
    not be treated as application ML assets.

    Reuse the canonical R-SecOpsX SAST exclusion policy so ML-BOM,
    SAST, and other source-oriented scanners have consistent scope.
    """
    if not path.is_file():
        return False

    if _skip(path):
        return False

    return path.suffix.lower() in {x.lower() for x in SCANNABLE_EXT}


def _line_for_offset(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


def _nearby_hint(lines: list[str], line_no: int, regex: re.Pattern) -> tuple[str, int]:
    """Search the bounded window around a finding; return (value, line).

    Line is 1-based where the hint was found, 0 when absent -- dataset
    provenance records WHERE the reference lives, not just that one
    exists somewhere near the finding.
    """
    start = max(0, line_no - 4)
    end = min(len(lines), line_no + 3)
    window = "\n".join(lines[start:end])

    match = regex.search(window)

    if match:
        offset_in_window = window[:match.start()].count("\n")
        return match.group(1), start + offset_in_window + 1

    return "", 0


def _dataset_format(path: str) -> str:
    return Path(path).suffix.lower().lstrip(".") or "unknown"


def _make_mlbom_item(
    rule: dict,
    filepath: str,
    line: int,
    evidence: str,
    model_artifact: str = "",
    dataset_hint: str = "",
    dataset_line: int = 0,
) -> dict:
    datasets: list[dict] = []
    if dataset_hint:
        datasets.append({
            "path": dataset_hint,
            "format": _dataset_format(dataset_hint),
            "line": dataset_line,
            "origin": "code-reference",
        })
    return {
        "bom_type": "ML-BOM",
        "framework": rule["framework"],
        "component": rule["component"],
        "category": rule["category"],
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "model_artifact": model_artifact,
        "dataset_hint": dataset_hint,
        "datasets": datasets,
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
    }


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)

    if not _should_scan(path):
        return []

    try:
        source = file_index.read_source(path)
    except OSError:
        return []
    if source is None:
        return []

    findings = []
    lines = source.splitlines()

    for rule in ML_RULES:
        compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in rule["patterns"]
        ]

        for pattern in compiled_patterns:
            for match in pattern.finditer(source):
                line_no = _line_for_offset(source, match.start())
                evidence = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""

                if evidence.lstrip().startswith(("#", "//", "*")):
                    continue

                model_artifact, _ = _nearby_hint(
                    lines,
                    line_no,
                    MODEL_FILE_RE
                )

                dataset_hint, dataset_line = _nearby_hint(
                    lines,
                    line_no,
                    DATASET_HINT_RE
                )

                findings.append(
                    _make_mlbom_item(
                        rule,
                        str(path),
                        line_no,
                        evidence,
                        model_artifact,
                        dataset_hint,
                        dataset_line
                    )
                )

    return deduplicate(findings)


def deduplicate(items: list[dict]) -> list[dict]:
    seen = set()
    final = []

    for item in items:
        key = (
            item.get("framework"),
            item.get("component"),
            item.get("file"),
            item.get("line"),
            item.get("evidence"),
        )

        if key in seen:
            continue

        seen.add(key)
        final.append(item)

    return final


# ---------------------------------------------------------------------------
# Phase 4.4 -- model-card extraction and dataset provenance
# ---------------------------------------------------------------------------
# A model card (Mitchell et al. "Model Cards for Model Reporting", and
# the HuggingFace README-with-YAML-front-matter convention that grew out
# of it) is where name/version/license/task/dataset declarations live
# for a trained model. The scanner already knew model artifact files and
# dataset file references in CODE; this pass additionally finds card
# DOCUMENTS in the tree, parses them (JSON / YAML / markdown front
# matter), and attaches the normalized block to the ML-BOM items the
# card belongs to. Items with no associated card carry no block --
# association is same-directory or artifact-name, never a guess.
# ---------------------------------------------------------------------------

MODEL_CARD_FILENAMES = {
    "model_card.md", "model-card.md", "modelcard.md",
    "model_card.json", "model-card.json", "modelcard.json",
    "model_card.yml", "model-card.yml", "modelcard.yml",
    "model_card.yaml", "model-card.yaml", "modelcard.yaml",
}

# A README.md counts as a model card only when its YAML front matter
# carries model-card keys -- the HuggingFace convention.
_HF_CARD_KEYS = {"license", "base_model", "pipeline_tag", "datasets", "tags"}

_CARD_READ_CAP = 262_144       # 256 KB: cards are prose, not data dumps
_CARD_RAW_CAP = 200_000        # raw text kept for artifact-name matching
_CARD_SUMMARY_CAP = 300
_CARD_DATASETS_CAP = 50


def _front_matter_fallback(text: str) -> dict:
    """Line-based YAML-subset parser for front matter (no PyYAML).

    Handles `key: value` scalars and `key:` + `- item` lists -- the shape
    HuggingFace card front matter actually uses.
    """
    data: dict = {}
    current_list_key = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") or stripped == "-":
            if current_list_key:
                data.setdefault(current_list_key, []).append(
                    stripped[2:].strip().strip("'\""))
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", stripped)
        if not match:
            current_list_key = None
            continue
        key, value = match.group(1), match.group(2).strip()
        if value:
            data[key] = value.strip("'\"")
            current_list_key = None
        else:
            data[key] = []
            current_list_key = key
    return data


def _yaml_load(text: str) -> dict:
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return _front_matter_fallback(text)


def _card_block(meta: dict, *, source_file: str, fmt: str,
                summary: str, datasets: list, metrics, fields) -> dict:
    def _text(value) -> str:
        return str(value).strip()[:_CARD_SUMMARY_CAP] if value else ""

    return {
        "source_file": source_file,
        "format": fmt,
        "name": _text(meta.get("model_name") or meta.get("name")
                      or meta.get("base_model")),
        "version": _text(meta.get("version") or meta.get("model_version")),
        "license": _text(meta.get("license") or meta.get("license_name")),
        "task": _text(meta.get("pipeline_tag") or meta.get("task")
                      or meta.get("type")),
        "datasets": [str(d).strip() for d in datasets[:_CARD_DATASETS_CAP]],
        "metrics": metrics if isinstance(metrics, dict) else {},
        "summary": summary,
        "fields_detected": sorted(fields),
    }


def _parse_model_card(path: Path) -> dict | None:
    """Parse one candidate card document. Fail-open on malformed input."""
    try:
        raw = file_index.read_source(path)
    except OSError:
        return None
    if raw is None:
        return None
    text = raw[:_CARD_READ_CAP]

    # Windows repos are full of UTF-8-BOM files; a card must parse
    # regardless of which editor wrote it.
    text = text.lstrip("\ufeff")

    name = path.name.lower()
    source_file = str(path)

    if name.endswith(".json"):
        try:
            data = json.loads(text)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        datasets = data.get("datasets") or []
        if isinstance(datasets, str):
            datasets = [datasets]
        summary = str(data.get("description") or data.get("summary") or "")
        return _card_block(
            data, source_file=source_file, fmt="json",
            summary=summary[:_CARD_SUMMARY_CAP], datasets=datasets,
            metrics=data.get("metrics"), fields=set(data.keys()))

    if name.endswith((".yml", ".yaml")):
        data = _yaml_load(text)
        if not data:
            return None
        datasets = data.get("datasets") or []
        if isinstance(datasets, str):
            datasets = [datasets]
        return _card_block(
            data, source_file=source_file, fmt="yaml",
            summary=str(data.get("description") or "")[:_CARD_SUMMARY_CAP],
            datasets=datasets, metrics=data.get("metrics"),
            fields=set(data.keys()))

    # markdown: HuggingFace-style YAML front matter between --- fences,
    # plus the document title/first paragraph as summary.
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    front = text[3:end].strip()
    body = text[end + 4:]
    meta = _yaml_load(front)
    if not meta or not (_HF_CARD_KEYS & set(meta.keys())):
        return None

    datasets = meta.get("datasets") or []
    if isinstance(datasets, (str,)):
        datasets = [datasets]

    summary = ""
    for para in re.split(r"\n\s*\n", body):
        para = para.strip()
        if not para or para.startswith("#"):
            continue          # skip headings; summary is the first prose
        summary = para[:_CARD_SUMMARY_CAP]
        break

    return _card_block(
        meta, source_file=source_file, fmt="markdown", summary=summary,
        datasets=datasets, metrics=meta.get("metrics"),
        fields=set(meta.keys()))


def _extract_model_cards(target: Path) -> list[dict]:
    """All parseable model cards under the scan target."""
    cards: list[dict] = []
    # T-0.2: index query replaces target.rglob; the skip policy is walk-time.
    for path in file_index.index_for(target).files():
        lower = path.name.lower()
        if lower in MODEL_CARD_FILENAMES or lower == "readme.md":
            card = _parse_model_card(path)
            if card:
                card["dir"] = str(path.parent)
                card["raw"] = _safe_read_prefix(path)
                cards.append(card)
    return cards


def _safe_read_prefix(path: Path, cap: int = _CARD_RAW_CAP) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(cap)
    except OSError:
        return ""


def _associate_model_cards(items: list[dict], cards: list[dict]) -> list[dict]:
    """Attach parsed cards to the items they belong to.

    Association is same-directory or artifact-name mention only. A repo
    with one card and unrelated framework files elsewhere stays
    unassociated: a guessed card is worse than no card.
    """
    if not cards:
        return items

    for item in items:
        artifact = str(item.get("model_artifact") or "")
        artifact_name = Path(artifact).name if artifact else ""
        item_dir = str(Path(str(item.get("file") or "")).parent)

        for card in cards:
            reason = None
            if artifact_name and artifact_name in card.get("raw", ""):
                reason = "artifact-name"
            elif item_dir and card.get("dir") == item_dir:
                reason = "same-directory"
            if not reason:
                continue

            block = {k: v for k, v in card.items()
                     if k not in ("raw", "dir")}
            block["association"] = reason
            item["model_card"] = block

            existing = item.get("datasets")
            if not isinstance(existing, list):
                existing = []
            for dataset in card.get("datasets") or []:
                entry = {"name": str(dataset), "origin": "model-card",
                         "source_file": block["source_file"]}
                if entry not in existing:
                    existing.append(entry)
            item["datasets"] = existing
            break

    return items


# ---------------------------------------------------------------------------
# END Phase 4.4 model cards / dataset provenance
# ---------------------------------------------------------------------------


def generate_mlbom(target_path: str) -> list[dict]:
    target = Path(target_path)

    results = []

    if target.is_file():
        if _skip(target):
            return []
        return scan_file(str(target))

    if not target.exists():
        return []

    # Phase 4.4: parse model-card documents first so findings can be
    # associated as the final step (association needs the whole set).
    cards = _extract_model_cards(target)

    # T-0.2: index query replaces target.rglob; the skip policy is walk-time.
    for path in file_index.index_for(target).files(pred=_should_scan):
        results.extend(scan_file(str(path)))

    return _associate_model_cards(deduplicate(results), cards)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", default="mlbom.json")
    args = parser.parse_args()

    mlbom = generate_mlbom(args.target)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(mlbom, f, indent=2)

    print(f"[ML-BOM] Items found: {len(mlbom)}")
    print(f"[ML-BOM] Output written: {args.output}")