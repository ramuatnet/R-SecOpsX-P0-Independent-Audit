from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import aibom


def scan(source):
    d = Path(tempfile.mkdtemp(prefix="aibom_p02_"))
    p = d / "case.py"
    p.write_text(source, encoding="utf-8")
    return aibom.scan_file(str(p))


def show(name, rows):
    print()
    print("=" * 80)
    print(name)
    print("=" * 80)
    print("COUNT =", len(rows))

    for row in rows:
        print(
            "provider=", row.get("provider"),
            "| component=", row.get("component"),
            "| line=", row.get("line"),
            "| component_id=", row.get("component_id"),
            "| evidence_type=", row.get("evidence_type"),
            "| confidence=", row.get("confidence"),
            "| confidence_score=", row.get("confidence_score"),
            "| import_resolution=", row.get("import_resolution"),
        )


def main():

    # ------------------------------------------------------------
    # Direct detection
    # ------------------------------------------------------------
    direct = scan(
        "import openai\n"
        "client = openai.OpenAI()\n"
    )

    show("openai_direct", direct)

    assert direct, "No OpenAI finding"

    resolved = [
        x for x in direct
        if x.get("import_resolution")
    ]

    assert resolved, "AST/import finding missing"

    row = resolved[0]

    assert row.get("component_id", "").startswith(
        "AIBOM-COMP-"
    ), row

    assert isinstance(
        row.get("evidence_type"),
        list
    ), row

    assert "IMPORT_RESOLUTION" in row[
        "evidence_type"
    ], row

    assert row.get("confidence") in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "VERY_HIGH",
    }, row

    assert isinstance(
        row.get("confidence_score"),
        float
    ), row

    # ------------------------------------------------------------
    # Alias
    # ------------------------------------------------------------
    alias = scan(
        "from openai import OpenAI as AIClient\n"
        "client = AIClient()\n"
    )

    show("openai_alias", alias)

    alias_resolved = [
        x for x in alias
        if x.get("import_resolution")
    ]

    assert alias_resolved, alias

    alias_row = alias_resolved[0]

    assert "IMPORT_RESOLUTION" in alias_row[
        "evidence_type"
    ], alias_row

    # Same semantic provider/component -> same identity.
    assert row["component_id"] == alias_row[
        "component_id"
    ], (
        row,
        alias_row,
    )

    # ------------------------------------------------------------
    # Line independence
    # ------------------------------------------------------------
    shifted = scan(
        "\n\n\n\n"
        "from openai import OpenAI as AIClient\n"
        "client = AIClient()\n"
    )

    show("openai_shifted", shifted)

    shifted_resolved = [
        x for x in shifted
        if x.get("import_resolution")
    ]

    assert shifted_resolved

    assert alias_row["component_id"] == (
        shifted_resolved[0]["component_id"]
    ), (
        alias_row,
        shifted_resolved[0],
    )

    # ------------------------------------------------------------
    # Negative case
    # ------------------------------------------------------------
    negative = scan(
        "# openai.OpenAI()\n"
        "text = 'openai.OpenAI()'\n"
    )

    show("negative", negative)

    # Existing regex behavior is intentionally not changed here.
    # P0.2 is an identity/evidence contract, not a regex-noise
    # remediation milestone.
    assert all(
        "component_id" in x
        for x in negative
    ), negative

    print()
    print("=" * 80)
    print("AIBOM_P0_2_IDENTITY_EVIDENCE_ACCEPTED")
    print("=" * 80)


if __name__ == "__main__":
    main()
