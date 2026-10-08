from __future__ import annotations

import re
from pathlib import Path
from scanner.sast import _skip


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


def _nearby_hint(lines: list[str], line_no: int, regex: re.Pattern) -> str:
    start = max(0, line_no - 4)
    end = min(len(lines), line_no + 3)
    window = "\n".join(lines[start:end])

    match = regex.search(window)

    if match:
        return match.group(1)

    return ""


def _make_mlbom_item(
    rule: dict,
    filepath: str,
    line: int,
    evidence: str,
    model_artifact: str = "",
    dataset_hint: str = ""
) -> dict:
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
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
    }


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)

    if not _should_scan(path):
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
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

                model_artifact = _nearby_hint(
                    lines,
                    line_no,
                    MODEL_FILE_RE
                )

                dataset_hint = _nearby_hint(
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
                        dataset_hint
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


def generate_mlbom(target_path: str) -> list[dict]:
    target = Path(target_path)

    results = []

    if target.is_file():
        if _skip(target):
            return []
        return scan_file(str(target))

    if not target.exists():
        return []

    for path in target.rglob("*"):
        if _skip(path):
            continue

        if _should_scan(path):
            results.extend(scan_file(str(path)))

    return deduplicate(results)


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