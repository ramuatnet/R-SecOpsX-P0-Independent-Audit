from pathlib import Path
from tempfile import TemporaryDirectory

from scanner import aibom


CASES = {
    "openai_direct": (
        """import openai
client = openai.OpenAI()
""",
        "OpenAI",
        "OpenAI SDK / API",
        "OpenAI -> openai",
    ),

    "openai_alias": (
        """from openai import OpenAI as MyClient
client = MyClient()
""",
        "OpenAI",
        "OpenAI SDK / API",
        "MyClient -> openai.OpenAI",
    ),

    "crewai_alias": (
        """from crewai import Agent as CrewAgent
agent = CrewAgent(role='analyst', goal='analyze')
""",
        "CrewAI",
        "CrewAI Agent Framework",
        "CrewAgent -> crewai.Agent",
    ),

    "llamaindex_method_alias": (
        """from llama_index.core.agent import ReActAgent as RAgent
agent = RAgent.from_tools([])
""",
        "LlamaIndex",
        "LlamaIndex Framework",
        "RAgent -> llama_index.core.agent.ReActAgent",
    ),

    "huggingface_alias": (
        """from transformers import AutoModel as Model
model = Model.from_pretrained("org/model")
""",
        "HuggingFace",
        "HuggingFace Transformers",
        "Model -> transformers.AutoModel",
    ),

    "anthropic_alias": (
        """from anthropic import Anthropic as Claude
client = Claude()
""",
        "Anthropic",
        "Anthropic Claude SDK / API",
        "Claude -> anthropic.Anthropic",
    ),
}


def run_case(
    name,
    source,
    expected_provider,
    expected_component,
    expected_resolution,
):

    with TemporaryDirectory(prefix="aibom_ast_v11_") as td:

        path = Path(td) / f"{name}.py"
        path.write_text(source, encoding="utf-8")

        rows = aibom.scan_file(str(path))

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
                "| resolution=", row.get("import_resolution"),
            )

        # ----------------------------------------------------------
        # Only AST/import-resolved findings are candidates here.
        # Ignore legacy regex-only findings.
        # ----------------------------------------------------------

        matches = [
            row
            for row in rows
            if row.get("provider") == expected_provider
            and row.get("component") == expected_component
            and row.get("import_resolution")
        ]

        assert matches, (
            f"{name}: expected AST/import finding not found"
        )

        resolutions = {
            row.get("import_resolution")
            for row in matches
        }

        assert expected_resolution in resolutions, (
            f"{name}: expected resolution "
            f"{expected_resolution!r} not found; "
            f"actual={resolutions}"
        )

        print("[PASS] AST/import resolution")


def main():

    print("=" * 80)
    print("R-SECOPSX V11 AI-BOM P0.1 AST / IMPORT / ALIAS VALIDATION")
    print("=" * 80)

    for name, values in CASES.items():
        run_case(name, *values)

    print()
    print("=" * 80)
    print("AIBOM_P0_1_AST_IMPORT_ACCEPTED")
    print("=" * 80)


if __name__ == "__main__":
    main()
