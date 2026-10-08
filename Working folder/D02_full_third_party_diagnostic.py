import importlib.util
import tempfile
from pathlib import Path
import json

ROOT = Path(r"D:\data\Code test\R-SecOpsX_V11")
ENGINE_PATH = ROOT / "analysis" / "privacy_data_exposure_engine.py"

spec = importlib.util.spec_from_file_location("d02_full_diag", ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

source = "requests.post('https://example.invalid', json={'email': user.email})\n"

with tempfile.TemporaryDirectory(prefix="RSECOPSX_D02_DIAG_") as td:
    root = Path(td)
    path = root / "third_party_transfer.py"
    path.write_text(source, encoding="utf-8")

    print("=" * 72)
    print("D-02 FULL PIPELINE THIRD-PARTY TRANSFER DIAGNOSTIC")
    print("=" * 72)

    print("\n[SOURCE]")
    print(source)

    print("[DIRECT PII]")
    print(engine._privacy_pii_hits_fast(source, path, root))

    print("\n[DIRECT EXPOSURE]")
    print(engine._privacy_exposure_hits_fast(source))

    print("\n[DIRECT CLASSIFIER]")
    exposure_hits = engine._privacy_exposure_hits_fast(source)
    print(engine._classify_exposure(source, exposure_hits))

    print("\n[FULL ENGINE]")
    result = engine.enrich_privacy_data_exposure(str(root))

    matches = [
        x for x in result.get("indicators", [])
        if str(x.get("file", "")).endswith("third_party_transfer.py")
    ]

    for item in matches:
        print(json.dumps(item, indent=2, ensure_ascii=False, default=str))

    print("\n[SUMMARY]")
    print(json.dumps({
        "total_indicators": len(matches),
        "states": sorted({
            str(x.get("privacy_evidence_state"))
            for x in matches
        }),
        "indicators": [
            {
                "indicator": x.get("indicator"),
                "pii_types": x.get("pii_types"),
                "privacy_evidence_state": x.get("privacy_evidence_state"),
                "static_exposure_confirmed": x.get("static_exposure_confirmed"),
                "privacy_exposure_confirmed": x.get("privacy_exposure_confirmed"),
                "third_party_transfer_hint": x.get("third_party_transfer_hint"),
                "snippet": x.get("snippet"),
            }
            for x in matches
        ],
    }, indent=2, ensure_ascii=False, default=str))

    print("=" * 72)
