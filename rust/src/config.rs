//! The scan config: everything the Rust engine needs, computed by
//! Python (scanner/rust_engine.py) so the rule program and every policy
//! list have ONE source of truth on the Python side.

use std::collections::HashMap;

use serde::Deserialize;

pub const SCAN_CONFIG_SCHEMA: &str = "rsecopsx.rust_scan_config/v1";

fn default_flags() -> String {
    // core.rule_loader._DEFAULT_FLAGS -- i/m/s, matching scanner.sast._F.
    "ims".to_string()
}

#[derive(Deserialize, Clone)]
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
    /// "regex" (REGEX_RULES) or "enterprise" (COMPILED_ENTERPRISE_RULES);
    /// matters for the code_injection/json data-file gate only.
    pub kind: String,
    #[serde(default)]
    pub vuln_type: Option<String>,
    /// Precomputed `_make_finding` statics (everything except
    /// file/line/snippet/evidence/group_key/language).
    #[serde(default)]
    pub static_finding: serde_json::Map<String, serde_json::Value>,
    /// `_remediation`'s language-dependent edge (js-yaml) precomputed per
    /// language, applied by the engine when it has an entry.
    #[serde(default)]
    pub remediation_by_lang: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
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
    pub lang_by_ext: HashMap<String, String>,
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
    pub line_comment_prefixes: HashMap<String, Vec<String>>,
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
