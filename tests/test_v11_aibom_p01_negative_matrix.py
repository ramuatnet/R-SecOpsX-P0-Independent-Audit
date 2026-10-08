from pathlib import Path
from tempfile import TemporaryDirectory

from scanner import aibom


CASES = {
    "negative_comment": (
        """# import openai
# client = openai.OpenAI()
""",
        0,
    ),

    "negative_string": (
        """text = "openai.OpenAI()"
""",
        0,
    ),

    "negative_documentation": (
        '''"""
Example:
from openai import OpenAI
client = OpenAI()
"""
x = 1
''',
        0,
    ),

    "negative_unrelated_openai_variable": (
        """OpenAI = "not the SDK"
value = OpenAI
""",
        0,
    ),

    "negative_unrelated_agent": (
        """class Agent:
    pass

x = Agent()
""",
        0,
    ),

    "negative_unrelated_model": (
        """model = "gpt-5"
""",
        0,
    ),

    "negative_unrelated_pipeline": (
        """pipeline = create_pipeline()
""",
        0,
    ),

    "positive_openai": (
        """from openai import OpenAI
client = OpenAI()
""",
        1,
    ),

    "positive_openai_alias": (
        """from openai import OpenAI as AIClient
client = AIClient()
""",
        1,
    ),

    "positive_crewai_alias": (
        """from crewai import Agent as CrewAgent
agent = CrewAgent(role="analyst", goal="analyze")
""",
        1,
    ),

    "positive_anthropic_alias": (
        """from anthropic import Anthropic as Claude
client = Claude()
""",
        1,
    ),
}


def run_case(name, source, expected_ast_count):

    with TemporaryDirectory(prefix="aibom_negative_v11_") as td:

        path = Path(td) / f"{name}.py"
        path.write_text(source, encoding="utf-8")

        rows = aibom.scan_file(str(path))

        print()
        print("=" * 80)
        print(name)
        print("=" * 80)

        print("TOTAL FINDINGS =", len(rows))

        for row in rows:
            print(
                "provider=", row.get("provider"),
                "| component=", row.get("component"),
                "| line=", row.get("line"),
                "| resolution=", row.get("import_resolution"),
                "| detection=", row.get("detection_mode"),
            )

        ast_rows = [
            row
            for row in rows
            if row.get("import_resolution")
        ]

        actual = len(ast_rows)

        print("AST/IMPORT FINDINGS =", actual)

        assert actual == expected_ast_count, (
            f"{name}: expected {expected_ast_count} "
            f"AST/import findings, got {actual}"
        )

        if expected_ast_count:
            for row in ast_rows:
                assert row.get("provider"), (
                    f"{name}: resolved finding missing provider"
                )
                assert row.get("component"), (
                    f"{name}: resolved finding missing component"
                )
                assert row.get("import_resolution"), (
                    f"{name}: resolved finding missing import_resolution"
                )

        print("[PASS] AST/import expected behavior")


def main():

    print("=" * 80)
    print("R-SECOPSX V11 AI-BOM P0.1 NEGATIVE / NOISE MATRIX")
    print("=" * 80)

    for name, values in CASES.items():
        run_case(name, *values)

    print()
    print("=" * 80)
    print("AIBOM_P0_1_NEGATIVE_MATRIX_ACCEPTED")
    print("=" * 80)


if __name__ == "__main__":
    main()
