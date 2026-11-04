"""FND-06 back-compat shim: the declarative loader moved home.

The implementation lives beside its data in ``scanner/rules/loader.py``
(ftasks FND-06); every historical ``core.rule_loader`` name re-exports
from there so importers (scanner.sast, taint_engine, rust_engine,
analysis.ufib_brain, the rule tests) did not have to move.  New code
should import ``scanner.rules.loader`` directly.
"""
from __future__ import annotations

from scanner.rules.loader import (  # noqa: F401
    RuleFormatError,
    load_barrier_overrides,
    load_contract_refs,
    load_disabled_ids,
    load_enterprise_rules,
    load_regex_rules,
    load_sanitizer_overrides,
    load_sink_categories,
    load_yaml_entries,
    validate_doc,
)
