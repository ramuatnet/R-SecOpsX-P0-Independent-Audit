from pathlib import Path
import re
import shutil

path = Path(r".\scanner\aibom_abom_correlation.py")

text = path.read_text(encoding="utf-8-sig")

backup = path.with_name(path.name + ".bak_p1_semantic_linkage")
shutil.copy2(path, backup)

# ---------------------------------------------------------------------
# 1. Add semantic normalization helpers before correlate()
# ---------------------------------------------------------------------

marker = "\ndef correlate(\n"

if marker not in text:
    raise SystemExit("[ERROR] correlate() insertion marker not found.")

helpers = r'''
def _normalize_identity(value: Any) -> str | None:
    """Normalize an identity value for deterministic semantic matching."""
    if value is None:
        return None

    value = str(value).strip()
    if not value:
        return None

    return value.casefold()


def _model_identity_values(model: dict[str, Any]) -> set[str]:
    """Return explicit model identities exposed by an AI-BOM model."""
    values: set[str] = set()

    for key in (
        "model_id",
        "model_reference",
        "model_name",
        "model",
    ):
        normalized = _normalize_identity(model.get(key))
        if normalized:
            values.add(normalized)

    return values


def _agent_model_identity_values(agent: dict[str, Any]) -> set[str]:
    """
    Return model identities explicitly associated with an ABOM agent.

    No inference is performed from arbitrary text.
    """
    values: set[str] = set()

    for key in (
        "model_id",
        "model_reference",
        "model_name",
        "model",
    ):
        value = agent.get(key)

        if isinstance(value, (list, tuple, set)):
            for item in value:
                normalized = _normalize_identity(item)
                if normalized:
                    values.add(normalized)
        else:
            normalized = _normalize_identity(value)
            if normalized:
                values.add(normalized)

    return values


def _agent_provider_identity_values(agent: dict[str, Any]) -> set[str]:
    """Return explicit provider identities from an ABOM agent."""
    values: set[str] = set()

    for key in (
        "provider_id",
        "provider_reference",
        "provider_name",
    ):
        value = agent.get(key)

        if isinstance(value, (list, tuple, set)):
            for item in value:
                normalized = _normalize_identity(item)
                if normalized:
                    values.add(normalized)
        else:
            normalized = _normalize_identity(value)
            if normalized:
                values.add(normalized)

    return values


def _model_provider_identity_values(model: dict[str, Any]) -> set[str]:
    """Return explicit provider identities from an AI-BOM model."""
    values: set[str] = set()

    for key in (
        "provider_id",
        "provider_reference",
        "provider_name",
    ):
        normalized = _normalize_identity(model.get(key))
        if normalized:
            values.add(normalized)

    return values


def _semantically_matches_agent_model(
    agent: dict[str, Any],
    model: dict[str, Any],
) -> bool:
    """
    Determine whether an ABOM agent is explicitly associated with an AI-BOM model.

    Matching is intentionally conservative.

    A resolved model alone is NOT sufficient to create an Agent -> Model edge.
    """

    agent_models = _agent_model_identity_values(agent)
    model_identities = _model_identity_values(model)

    # Strongest evidence:
    # explicit Agent model identity matches AI-BOM model identity.
    if agent_models and model_identities:
        if agent_models & model_identities:
            return True

        # Explicit model identity exists on both sides but does not match.
        return False

    # Provider-only evidence is insufficient.
    #
    # For example:
    #   Agent -> OpenAI
    #   Model -> GPT-5 / OpenAI
    #
    # does NOT prove that this particular agent uses GPT-5.
    #
    # Therefore do not create an edge here.
    return False

'''

text = text.replace(marker, "\n" + helpers + marker, 1)

# ---------------------------------------------------------------------
# 2. Replace the existing Agent -> Model broad association block.
# ---------------------------------------------------------------------

pattern = re.compile(
    r"""
    \n\s*#\s*AGENT\s*->\s*MODEL
    .*?
    (?=\n\s*return\s+_deduplicate\(relationships\))
    """,
    re.DOTALL | re.IGNORECASE | re.VERBOSE,
)

replacement = r'''
    # AGENT -> MODEL
    #
    # Semantic hardening:
    #
    # A resolved model is NOT automatically associated with every agent.
    # The ABOM agent must expose an explicit model identity that matches
    # the AI-BOM model identity.
    #
    # This prevents cross-association when an application contains:
    #
    #   Agent-001 -> GPT-5
    #   Agent-002 -> GPT-4.1
    #
    # from becoming:
    #
    #   Agent-001 -> GPT-5
    #   Agent-001 -> GPT-4.1   [FALSE]
    #   Agent-002 -> GPT-5     [FALSE]
    #   Agent-002 -> GPT-4.1
    #
    for agent in agents:
        for model in models:
            resolution = (
                model.get("model_resolution")
                or model.get("resolution")
            )

            if resolution not in {"RESOLVED", "resolved"}:
                continue

            if not model.get("model_id"):
                continue

            if not _semantically_matches_agent_model(agent, model):
                continue

            relationships.append(
                _relationship(
                    source_id=str(agent["component_id"]),
                    source_type="ABOM_AGENT",
                    relationship_type=REL_USES,
                    target_id=str(model["model_id"]),
                    target_type="AI_BOM_MODEL",
                    source=agent,
                    target=model,
                )
            )

'''

match = pattern.search(text)

if not match:
    raise SystemExit(
        "[ERROR] Existing AGENT -> MODEL association block not found. "
        "No production modification made."
    )

text = text[:match.start()] + replacement + text[match.end():]

path.write_text(text, encoding="utf-8")

print("[PASS] AI-BOM <-> ABOM semantic linkage hardening applied")
print(f"[BACKUP] {backup}")
