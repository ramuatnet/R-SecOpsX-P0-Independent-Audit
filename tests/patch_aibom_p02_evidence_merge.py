from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

text = SOURCE.read_text(encoding="utf-8-sig")

BACKUP_DIR.mkdir(parents=True, exist_ok=True)
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"aibom.py.before_p02_evidence_merge_{stamp}.py"
backup.write_text(text, encoding="utf-8")

old = '''def deduplicate(items: list[dict]) -> list[dict]:
    seen = set()
    final = []

    for item in items:
        key = (
            item.get("provider"),
            item.get("component"),
            item.get("file"),
            item.get("line"),
            item.get("evidence"),
        )

        if key in seen:
            # Preserve AST-derived import resolution when the same
            # finding was already discovered by legacy regex.
            for existing in final:
                existing_key = (
                    existing.get("provider"),
                    existing.get("component"),
                    existing.get("file"),
                    existing.get("line"),
                    existing.get("evidence"),
                )

                if existing_key == key:
                    resolution = item.get("import_resolution")

                    if resolution and not existing.get(
                        "import_resolution"
                    ):
                        existing["import_resolution"] = resolution

                    break

            continue

        seen.add(key)
        final.append(item)

    return final
'''

new = '''def deduplicate(items: list[dict]) -> list[dict]:
    seen = set()
    final = []

    for item in items:
        key = (
            item.get("provider"),
            item.get("component"),
            item.get("file"),
            item.get("line"),
            item.get("evidence"),
        )

        if key in seen:
            # --------------------------------------------------------
            # V11 P0.2:
            # Preserve the strongest evidence when regex and
            # AST/import discovery identify the same semantic finding.
            # --------------------------------------------------------
            for existing in final:
                existing_key = (
                    existing.get("provider"),
                    existing.get("component"),
                    existing.get("file"),
                    existing.get("line"),
                    existing.get("evidence"),
                )

                if existing_key != key:
                    continue

                # Preserve import resolution.
                resolution = item.get("import_resolution")
                if resolution and not existing.get("import_resolution"):
                    existing["import_resolution"] = resolution

                # Merge evidence provenance.
                existing_types = set(
                    existing.get("evidence_type") or []
                )
                item_types = set(
                    item.get("evidence_type") or []
                )
                merged_types = existing_types | item_types

                if merged_types:
                    existing["evidence_type"] = sorted(merged_types)

                # Merge detection modes.
                existing_modes = set(
                    str(existing.get("detection_mode", "")).split("+")
                )
                item_modes = set(
                    str(item.get("detection_mode", "")).split("+")
                )

                existing_modes.discard("")
                item_modes.discard("")

                merged_modes = existing_modes | item_modes

                if merged_modes:
                    existing["detection_mode"] = "+".join(
                        sorted(merged_modes)
                    )

                # Preserve the stronger confidence.
                confidence_rank = {
                    "LOW": 1,
                    "MEDIUM": 2,
                    "HIGH": 3,
                    "VERY_HIGH": 4,
                }

                existing_confidence = str(
                    existing.get("confidence", "LOW")
                ).upper()

                item_confidence = str(
                    item.get("confidence", "LOW")
                ).upper()

                if confidence_rank.get(
                    item_confidence, 0
                ) > confidence_rank.get(
                    existing_confidence, 0
                ):
                    existing["confidence"] = item_confidence

                    score = item.get("confidence_score")
                    if isinstance(score, (int, float)):
                        existing["confidence_score"] = float(score)

                # If the incoming item has stronger AST/import evidence,
                # preserve its score even when confidence labels match.
                elif (
                    item.get("confidence_score") is not None
                    and existing.get("confidence_score") is not None
                    and float(item["confidence_score"])
                    > float(existing["confidence_score"])
                ):
                    existing["confidence_score"] = float(
                        item["confidence_score"]
                    )

                break

            continue

        seen.add(key)
        final.append(item)

    return final
'''

if old not in text:
    raise SystemExit(
        "ERROR: Expected deduplicate() P0.2 block was not found. "
        "No source change made."
    )

text = text.replace(old, new, 1)
SOURCE.write_text(text, encoding="utf-8")

print("[PASS] P0.2 evidence provenance merge added")
print("[PASS] AST/import evidence preserved during deduplication")
print("[PASS] Detection mode merge added")
print("[PASS] Confidence preservation added")
print(f"[BACKUP] {backup}")
