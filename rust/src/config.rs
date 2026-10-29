//! The scan config: everything the Rust engine needs, computed by
//! Python (scanner/rust_engine.py) so the rule program and every policy
//! list have ONE source of truth on the Python side.

// BTreeMap, not HashMap: the compiled rule program is a byte-stable
// artifact (same config -> same bytes), and HashMap iteration order is
// randomised per instance.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Raw scan config as Python builds it (policy lists + rule table).
pub const SCAN_CONFIG_SCHEMA: &str = "rsecopsx.rust_scan_config/v1";
/// Compiled rule program (T-1.3): the same document with every rule's
/// literal set computed -- produced by `compile_rules`, consumed by `scan`.
pub const RULE_PROGRAM_SCHEMA: &str = "rsecopsx.rule_program/v1";

fn default_flags() -> String {
    // core.rule_loader._DEFAULT_FLAGS -- i/m/s, matching scanner.sast._F.
    "ims".to_string()
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RuleConfig {
    pub id: String,
    /// Raw pattern source (re.Pattern.pattern on the Python side).
    pub pattern: String,
    /// Flag letters from {i, m, s}; default "ims" like the loader.
    #[serde(default = "default_flags")]
    pub flags: String,
    /// Language gate: None/empty = every language.
    #[serde(default)]
    pub langs: Option<Vec<String>>,
    /// Table of origin: "regex" (REGEX_RULES) or "enterprise"
    /// (COMPILED_ENTERPRISE_RULES). Carried as data for tests and
    /// consumers; the engine decides nothing on it.
    pub kind: String,
    #[serde(default)]
    pub vuln_type: Option<String>,
    /// UFIB family contract binding (rule YAML `contract_ref`; T-1.3
    /// ships it as part of the rule program for downstream validators).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_ref: Option<String>,
    /// Sink category from the rule YAML (T-1.3: sql/xss/file/...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_category: Option<String>,
    /// Declarative gate: never evaluate this rule on the file names in
    /// `skip_file_names` (compared lowercased, any depth). The loader
    /// derives the entries -- the engine carries no per-rule logic.
    #[serde(default)]
    pub skip_file_names: Vec<String>,
    /// Declarative gate: apply the config's non-executable-data language
    /// list to this rule (the loader derives it from the rule's class;
    /// see scanner/sast.py, the REGEX_RULES matching loop).
    #[serde(default)]
    pub data_file_gate: bool,
    /// Precomputed mandatory-literal set (the compiled rule program).
    /// `None` = not yet compiled: `scan` extracts at startup (raw scan
    /// config); `Some` = trust it, an empty vec means the rule is
    /// unprefilterable (runs on every line, fail-safe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub literals: Option<Vec<String>>,
    /// Precomputed `_make_finding` statics (everything except
    /// file/line/snippet/evidence/group_key/language).
    #[serde(default)]
    pub static_finding: serde_json::Map<String, serde_json::Value>,
    /// `_remediation`'s language-dependent edge (js-yaml) precomputed per
    /// language, applied by the engine when it has an entry.
    #[serde(default)]
    pub remediation_by_lang: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize, Serialize)]
pub struct ScanConfig {
    pub schema: String,
    /// Lowercased file names that are never scanned (file_index.EXCLUDED_FILES).
    #[serde(default)]
    pub excluded_files: Vec<String>,
    /// Lowercased directory names that are never descended
    /// (file_index.EXCLUDED_DIRS).
    #[serde(default)]
    pub excluded_dirs: Vec<String>,
    /// file_index.LANG_BY_EXT, keys lowercased.
    #[serde(default)]
    pub lang_by_ext: BTreeMap<String, String>,
    /// Lowercased SCANNABLE_EXT entries used as suffix matchers.
    #[serde(default)]
    pub scannable_ext: Vec<String>,
    /// Exact-case SCANNABLE_EXT name entries (e.g. "Dockerfile").
    #[serde(default)]
    pub scannable_names: Vec<String>,
    /// file_index.MAX_DEPTH.
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    /// .sastignore path rules (file_index._load_sastignore_rules).
    #[serde(default)]
    pub sastignore_rules: Vec<String>,
    /// Line-comment prefixes per language (scanner.sast._LINE_COMMENT_PREFIXES).
    #[serde(default)]
    pub line_comment_prefixes: BTreeMap<String, Vec<String>>,
    /// Languages where a leading '*' continues a block comment
    /// (scanner.sast._BLOCK_COMMENT_DELIMS keys).
    #[serde(default)]
    pub block_comment_langs: Vec<String>,
    /// scanner.sast.NON_EXECUTABLE_DATA_LANGUAGES: eval()/exec() shapes
    /// cannot occur in a data file.
    #[serde(default)]
    pub non_executable_data_langs: Vec<String>,
    /// The rule program, already in scan order (REGEX_RULES then
    /// COMPILED_ENTERPRISE_RULES), disabled ids removed.
    pub rules: Vec<RuleConfig>,
}

fn default_max_depth() -> usize {
    10_000
}
