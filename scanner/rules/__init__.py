"""FND-06: the declarative rule home (YAML + loader).

``scanner/rules/*.yaml`` is the source of truth for every sast rule;
``scanner.rules.loader`` validates it against ``schema_v1.json`` and
adapts it to the legacy table shapes scanner.sast still consumes.
``core.rule_loader`` re-exports the same names for historical importers.
"""
