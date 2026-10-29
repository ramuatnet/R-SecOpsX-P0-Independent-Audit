//! Finding assembly: the EXISTING finding schema (sast._make_finding).
//!
//! Every static field (title, severity, cwe, owasp, remediation, ...)
//! was precomputed by Python and travels in `rule.static_finding`; this
//! module fills only the per-match fields and stamps honest provenance
//! (`engine`) so a native finding is never mistaken for a Python one.

use serde_json::{Map, Value};

use crate::config::RuleConfig;

/// Fields `_make_finding` derives from the match -- Python pops these
/// off the static copy and Rust fills them here.
pub fn make_finding(
    rule: &RuleConfig,
    file: &str,
    line: usize,
    snippet: &str,
    language: &str,
) -> Value {
    let mut m: Map<String, Value> = rule.static_finding.clone();
    if !m.contains_key("rule_id") {
        m.insert("rule_id".into(), Value::String(rule.id.clone()));
    }
    // Language-dependent remediation edge (js-yaml) computed by Python.
    if let Some(rem) = rule.remediation_by_lang.get(language) {
        m.insert("remediation".into(), json_value(rem));
    }
    m.insert("file".into(), Value::String(file.to_string()));
    m.insert("line".into(), Value::from(line as u64));
    m.insert("snippet".into(), Value::String(snippet.to_string()));
    m.insert("language".into(), Value::String(language.to_string()));
    m.insert(
        "evidence".into(),
        Value::String(format!("{file}:{line}: {snippet}")),
    );
    // group_key mirrors Python: f"{rule_id}|{file}|{line}|{snippet[:120]}"
    // -- slicing is by CODEPOINTS in Python, so take 120 chars, not bytes.
    let rule_id = m
        .get("rule_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let short: String = snippet.chars().take(120).collect();
    m.insert(
        "group_key".into(),
        Value::String(format!("{rule_id}|{file}|{line}|{short}")),
    );
    // Honest provenance: same schema, different engine.
    m.insert("engine".into(), Value::String("rsecopsx_core.rust".into()));
    Value::Object(m)
}

fn json_value<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}
