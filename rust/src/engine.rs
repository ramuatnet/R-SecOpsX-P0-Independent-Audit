//! T-1.2: the scan engine -- one pass per file:
//!
//!   walk -> read -> language gate -> per-line aho-corasick prefilter
//!        -> regex crate on CANDIDATE LINES ONLY -> comment check -> finding
//!
//! Degradations are counted and DISCLOSED in the envelope status:
//! unsupported patterns (regex crate rejects Python-only syntax),
//! unprefilterable rules (they still run -- on every line), skipped
//! files. Nothing is silently dropped.

use std::collections::HashSet;
use std::path::Path;

use regex::RegexBuilder;
use serde_json::{json, Value};

use crate::config::{RuleConfig, ScanConfig};
use crate::findings::make_finding;
use crate::prefilter::Prefilter;
use crate::scanner_result::{is_scanner_result_json, is_scanner_result_xml};
use crate::walk;

pub const ENGINE_VERSION: &str = "rsecopsx rust core v0.1.0 (walk+prefilter+regex)";
pub const ENVELOPE_SCHEMA: &str = "rsecopsx.rust_findings/v1";

/// Python's `_F`: re.IGNORECASE | re.MULTILINE | re.DOTALL (ims).
fn compile(rule: &RuleConfig) -> Result<regex::Regex, String> {
    RegexBuilder::new(&rule.pattern)
        .case_insensitive(rule.flags.contains('i'))
        .multi_line(rule.flags.contains('m'))
        .dot_matches_new_line(rule.flags.contains('s'))
        .build()
        .map_err(|e| e.to_string())
}

fn language_of(path: &Path, cfg: &ScanConfig) -> String {
    if path.file_name().map(|n| n == "Dockerfile").unwrap_or(false) {
        return "dockerfile".into();
    }
    let suffix = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if let Some(lang) = cfg.lang_by_ext.get(&suffix) {
        return lang.clone();
    }
    let bare = suffix.trim_start_matches('.').to_string();
    if bare.is_empty() {
        "unknown".into()
    } else {
        bare
    }
}

/// Mirror of scanner.sast._should_scan = scannable suffix/name AND not
/// _skip (= file_index.skip_path): excluded name, ANY path part in
/// EXCLUDED_DIRS, or a scanner-result JSON export. The parts check uses
/// the ABSOLUTE path -- Python does too, so a parent directory outside
/// the scan root still vetoes, exactly as on the Python side.
fn should_scan(path: &Path, cfg: &ScanConfig) -> bool {
    let suffix = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let scannable = (suffix.len() > 1 && cfg.scannable_ext.contains(&suffix))
        || name
            .as_deref()
            .map(|n| cfg.scannable_names.iter().any(|c| c == n))
            .unwrap_or(false);
    if !scannable {
        return false;
    }
    if let Some(n) = &name {
        if cfg.excluded_files.iter().any(|e| e == &n.to_lowercase()) {
            return false;
        }
    }
    let any_dir_part = path
        .components()
        .any(|c| cfg.excluded_dirs.iter().any(|d| d == &c.as_os_str().to_string_lossy().to_lowercase()));
    if any_dir_part {
        return false;
    }
    !is_scanner_result_json(path)
}

/// Python `_is_comment` (line-level): prefix check per language, plus
/// a leading '*' only where `*` continues a C-style block comment.
fn is_comment(snippet: &str, language: &str, cfg: &ScanConfig) -> bool {
    let s = snippet.trim();
    if s.is_empty() {
        return true;
    }
    let lang = language.to_lowercase();
    if let Some(prefixes) = cfg.line_comment_prefixes.get(&lang) {
        if prefixes.iter().any(|p| s.starts_with(p.as_str())) {
            return true;
        }
    }
    s.starts_with('*') && cfg.block_comment_langs.iter().any(|l| l == &lang)
}

/// Which rules may fire on this file at all (language gates).
fn eligible(rule: &RuleConfig, language: &str, cfg: &ScanConfig) -> bool {
    if let Some(langs) = &rule.langs {
        if !langs.is_empty() && !langs.iter().any(|l| l == language) {
            return false;
        }
    }
    // scanner.sast applies the data-file gate to REGEX_RULES only
    // (`vuln_type == "code_injection"`): eval()/exec() semantics cannot
    // occur in a data file.
    if rule.kind == "regex"
        && rule.vuln_type.as_deref() == Some("code_injection")
        && cfg.non_executable_data_langs.iter().any(|l| l == language)
    {
        return false;
    }
    true
}

pub fn scan_root(root: &str, cfg: &ScanConfig) -> Value {
    // 1. Compile every pattern; unsupported syntax is DISCLOSED, not fatal.
    let mut compiled: Vec<Option<regex::Regex>> = Vec::with_capacity(cfg.rules.len());
    let mut unsupported: Vec<Value> = Vec::new();
    for rule in &cfg.rules {
        match compile(rule) {
            Ok(re) => compiled.push(Some(re)),
            Err(reason) => {
                unsupported.push(json!({"id": rule.id, "reason": reason}));
                compiled.push(None);
            }
        }
    }

    // 2. Literal prefilter over the same rule list.
    let prefilter = Prefilter::build(&cfg.rules);

    // 3. Walk under the Python-equivalent policy.
    let (files, walk_status) = walk::walk(Path::new(root), cfg);

    let mut findings: Vec<Value> = Vec::new();
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;
    let mut hits: HashSet<u32> = HashSet::new();

    for wf in &files {
        let path = &wf.abs;
        if !should_scan(path, cfg) {
            files_skipped += 1;
            continue;
        }
        if is_scanner_result_xml(path) {
            files_skipped += 1;
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            files_skipped += 1;
            continue;
        };
        let source = String::from_utf8_lossy(&bytes);
        let language = language_of(path, cfg);
        let file_str = wf.abs.to_string_lossy().to_string();
        let lines: Vec<&str> = source.lines().collect();
        files_scanned += 1;
        // Python: package-lock.json is not the source for npm lifecycle
        // script rules (package.json only) -- by FILE NAME at any depth.
        let is_package_lock = path
            .file_name()
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("package-lock.json"))
            .unwrap_or(false);

        for (ri, rule) in cfg.rules.iter().enumerate() {
            if compiled[ri].is_none() || !eligible(rule, &language, cfg) {
                continue;
            }
            if rule.id == "NPM_SUPPLY_CHAIN_SCRIPT" && is_package_lock {
                continue;
            }
            let re = compiled[ri].as_ref().expect("checked above");
            let pf = &prefilter.rules[ri];

            for (li, line) in lines.iter().enumerate() {
                if pf.gated {
                    prefilter.hits(line, &mut hits);
                    if !pf.literal_ids.iter().any(|id| hits.contains(id)) {
                        continue; // candidate lines only reach the regex
                    }
                }
                if !re.is_match(line) {
                    continue;
                }
                let snippet = line.trim();
                if is_comment(snippet, &language, cfg) {
                    continue;
                }
                findings.push(make_finding(
                    rule,
                    &file_str,
                    li + 1,
                    snippet,
                    &language,
                ));
            }
        }
    }

    let status = json!({
        "engine": ENGINE_VERSION,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "walk": {
            "files": walk_status.files,
            "excluded_dirs": walk_status.excluded_dirs,
            "excluded_files": walk_status.excluded_files,
            "scanner_result_skipped": walk_status.scanner_result_skipped,
            "sastignore_skipped": walk_status.sastignore_skipped,
            "symlink_files_outside_root": walk_status.symlink_files_outside_root,
        },
        "rules_total": cfg.rules.len(),
        "rules_unsupported": unsupported,
        "rules_unprefilterable": prefilter.unprefilterable,
        // Known v1 divergences from the Python engine (pre-parity,
        // measured by T-1.5): disclose them, never hide them.
        "limits": [
            "line-based matching: matches spanning multiple lines are not found",
            "multi-match per line collapses to one row (Python emits one row per match; group_key is identical)",
            "no in-string / trailing-comment match suppression (Python's _match_starts_in_* validators are not ported)",
            "rule-specific validators are not ported (placeholder credentials, md5/sha1 aliasing, PEM body, client-side SSRF context, rate-limit presence)",
            "snippet is the matched line stripped (Python's focus-pattern evidence targeting is not ported)",
            "taint engine, AST validators and Java J5 integration are not run: this engine covers the regex + enterprise rule tables only",
            "symlinked directories are not descended",
        ],
    });

    json!({
        "schema": ENVELOPE_SCHEMA,
        "findings": findings,
        "status": status,
    })
}
